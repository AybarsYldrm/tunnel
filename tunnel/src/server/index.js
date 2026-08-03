'use strict';
// Tünel sunucusu — bağlama katmanı.
//
// Kendi iş mantığı yoktur; parçaları birbirine takar ve yaşam döngüsünü
// yönetir:
//
//   DtlsServer (mTLS, OCSP/CRL)  → Tunnel      her istemci için bir durum makinesi
//   PortAllocator                → Tunnel      genel port havuzu
//   Guard                        → genel yüzey saldırı yüzeyinin sınırları
//   Store (@fitfak/database)     → her yer     uygulama tanımları, denetim, ölçüm
//   AdminServer                  → 127.0.1.3   yönetim arayüzü
//
// Kimliğin tek kaynağı istemci sertifikasıdır. Sunucu, bağlanan tarafın kim
// olduğunu ne HELLO'daki addan ne IP'den çıkarır: yalnızca trust.fitfak.net'in
// imzaladığı ve iptal durumu doğrulanmış sertifikadan.

const { EventEmitter } = require('node:events');
const fsp = require('node:fs/promises');
const path = require('node:path');

const dtls = require('../../../index.js');
const { createLogger } = require('../common/log.js');
const { loadTrustAnchor } = require('../common/trust.js');
const { TIMING } = require('../protocol/constants.js');
const { Tunnel } = require('./tunnel.js');
const { PortAllocator } = require('./ports.js');
const { Guard } = require('./guard.js');
const { PeerRegistry } = require('./peers.js');
const { createStore } = require('./store.js');
const { normalizeApp, appToPublic, invalid } = require('./app-model.js');
const { loadServerConfig } = require('./config.js');

class TunnelServer extends EventEmitter {
  constructor(config) {
    super();
    this.options = config;
    this.limits = config.limits;
    this.log = createLogger('tunnel:server');

    this.ports = new PortAllocator({
      min: config.portMin,
      max: config.portMax,
      lingerMs: config.portLingerMs,
      log: this.log.child('ports'),
    });
    this.guard = new Guard(config.guard, this.log.child('guard'));
    this.peers = new PeerRegistry({
      log: this.log.child('peers'),
      maxPeers: config.guard.maxConnectionsGlobal * 2,
    });

    this.store = null;
    this.dtls = null;
    this.admin = null;

    /** tunnelId -> Tunnel */
    this.tunnels = new Map();
    /** clientId -> Tunnel (aynı sertifikayla tek canlı tünel) */
    this.byClient = new Map();

    this.startedAt = 0;
    this.stats = { tunnelsAccepted: 0, tunnelsRejected: 0, handshakeFailures: 0 };
    this._metricsTimer = null;
    this._stopping = false;
  }

  // =========================================================================
  async start() {
    this.startedAt = Date.now();
    this.store = await createStore({ config: this.options.db, log: this.log.child('store') });

    // Elle konan engeller yeniden başlatmayı atlatmalı: bir yöneticinin
    // "bu adres giremez" kararının, sunucu güncellemesiyle sessizce
    // kaybolması kabul edilemez.
    const blocks = await this.store.listBlocks().catch(() => []);
    const restored = this.guard.loadBlocks(blocks);
    if (restored) this.log.info('engel listesi yüklendi', { adres: restored });

    const secure = await this._loadCredentials();

    this.dtls = dtls.createServer({
      cert: secure.cert,
      key: secure.key,
      ca: secure.ca,

      // mTLS: sertifikasız istemci HİÇBİR koşulda kabul edilmez. Tünel
      // istemcisi ağın içine doğrudan yol açtığı için burada
      // `rejectUnauthorized: false` diye bir seçenek yok.
      requestCert: true,
      rejectUnauthorized: true,
      checkPurpose: true,
      revocation: this.options.revocation,

      mtu: this.options.mtu,
      // Şifreleme paketi tercihi: politika adı ('balanced', 'chacha20', ...)
      // ya da açık suite listesi. Sunucunun sırası bağlayıcıdır.
      cipherSuites: this.options.cipher,
      reliable: {
        // Sıra kararı akış BAŞINA veriliyor (mux her gönderimde açıkça
        // belirtiyor), kanal genelinde değil.
        ordered: false,
        maxTrackedPackets: 8192,
        maxRetransmits: 15,
        // Tıkanıklık denetimi — varsayılan BBRv3.
        congestionControl: this.options.congestionControl,
      },

      // DTLS seviyesinde DoS: cookie takası (varsayılan açık) el sıkışma
      // maliyetine girmeden önce kaynak adresini doğrular; hız sınırı ve
      // oturum tavanı geri kalanı bağlar.
      cookie: true,
      maxSessions: this.options.maxTunnels,
      rateLimitBurst: 30,
      rateLimitPerSec: 15,
      idleTimeout: 0, // boşta kalma bizim kalp atışımızla yönetiliyor
    });

    this.dtls.on('secureConnection', (socket) => this._onSecureConnection(socket));
    this.dtls.on('sessionError', (err, socket) => {
      this.stats.handshakeFailures++;
      this.log.warn('oturum hatası', {
        peer: socket ? `${socket.remoteAddress}:${socket.remotePort}` : '?',
        err: err.message,
      });
    });
    this.dtls.on('ratelimit', (rinfo) => this.log.debug('el sıkışma hız sınırı', { ip: rinfo.address }));
    this.dtls.on('overload', () => this.log.warn('oturum tavanı doldu, yeni tünel reddedildi'));
    this.dtls.on('error', (err) => this.log.error('DTLS sunucu hatası', { err: err.message }));
    this.dtls.on('log', (level, msg, meta) => {
      if (this.log[level]) this.log[level](msg, meta);
    });

    const addr = await this.dtls.listen(this.options.port, this.options.host);
    this.log.info('tünel sunucusu dinliyor', {
      dtls: `${addr.address}:${addr.port}`,
      genelHavuz: `${this.options.portMin}-${this.options.portMax}`,
      genelAdres: this.options.publicHost,
      iptalDenetimi: this.options.revocation,
      sifreleme: this.options.cipher,
      tikaniklik: this.options.congestionControl,
      kalicilik: this.store.mode,
      yapilandirma: this.options.configFile || 'ortam değişkenleri',
    });

    if (this.options.admin.enabled) {
      // Yönetim yüzeyi döngüsel bağımlılık üretmesin diye burada yükleniyor.
      // eslint-disable-next-line global-require
      const { AdminServer } = require('./admin/server.js');
      this.admin = new AdminServer({ server: this, config: this.options.admin });
      await this.admin.start();
    }

    this._metricsTimer = setInterval(() => this._sampleMetrics(), this.options.metricsIntervalMs);
    if (this._metricsTimer.unref) this._metricsTimer.unref();

    await this.store.recordEvent({
      kind: 'server.start', actor: 'system', subject: `${addr.address}:${addr.port}`,
      detail: JSON.stringify({ portPool: [this.options.portMin, this.options.portMax] }),
      at: Date.now(),
    }).catch(() => {});

    return addr;
  }

  async _loadCredentials() {
    const { certPath, keyPath, caPath } = this.options;
    if (!certPath || !keyPath) {
      throw new Error(
        'Sunucu sertifikası eksik: FITFAK_TUNNEL_CERT ve FITFAK_TUNNEL_KEY gerekli.\n'
        + '  Bu sertifika trust.fitfak.net\'ten (ACME ya da /device/certificate) alınır.',
      );
    }
    const cert = await fsp.readFile(certPath);
    const key = await fsp.readFile(keyPath);

    // Güven çıpası: dosyadan ya da yayın adresinden. İkincisi düz HTTP'dir ve
    // gerekçesi common/trust.js'in başındadır.
    const anchor = await loadTrustAnchor({
      file: caPath || undefined,
      url: caPath ? undefined : this.options.trustAnchorUrl,
      expectedFingerprint: process.env.FITFAK_TUNNEL_ROOT_CA_FINGERPRINT,
      allowUnpinned: !process.env.FITFAK_TUNNEL_ROOT_CA_FINGERPRINT,
      cacheFile: path.join(this.options.dataDir, 'root.crt'),
      log: this.log,
    });
    this.log.info('güven çıpası yüklendi', {
      subject: anchor.subject, fingerprint256: anchor.fingerprint256, kaynak: anchor.source,
    });
    return { cert, key, ca: anchor.pem };
  }

  // =========================================================================
  // Tünel yaşam döngüsü
  // =========================================================================

  _onSecureConnection(socket) {
    if (this._stopping) { socket.destroy(); return; }

    const tunnel = new Tunnel({ socket, server: this, log: this.log.child('tunnel') });
    this.tunnels.set(tunnel.tunnelId, tunnel);
    this.stats.tunnelsAccepted++;

    tunnel.once('closed', (reason) => this._onTunnelClosed(tunnel, reason));
    this.emit('tunnel', tunnel);
  }

  /**
   * HELLO tamamlandığında çağrılır: kimlik kaydedilir, uygulama tablosu
   * yüklenir ve portlar bağlanır.
   */
  async onTunnelReady(tunnel) {
    const id = tunnel.identity;

    const known = await this.store.getClient(tunnel.clientId).catch(() => null);
    if (known?.blocked) {
      // Sertifika hâlâ geçerli olabilir; bu yerel ve anında etki eden kapı.
      // İptal (OCSP/CRL) daha güçlüdür ama yayılması zaman alır.
      throw Object.assign(new Error('bu istemci yönetim tarafından engellenmiş'), { policy: true });
    }

    // Aynı sertifikayla ikinci bir tünel: eskisi yerini yenisine bırakır.
    // İkisini birden yaşatmak, iki tünelin AYNI uygulamalara aynı portları
    // bağlamaya çalışması demek olurdu.
    const prev = this.byClient.get(tunnel.clientId);
    if (prev && prev !== tunnel) {
      this.log.info('aynı kimlikle yeni tünel geldi, eskisi kapatılıyor', {
        eski: prev.tunnelId, yeni: tunnel.tunnelId,
      });
      await prev.shutdown(0, 'yeni bağlantı yerini aldı');
    }
    this.byClient.set(tunnel.clientId, tunnel);

    await this.store.upsertClient({
      clientId: tunnel.clientId,
      commonName: id?.commonName || '',
      displayName: tunnel.clientInfo?.name || '',
      email: id?.email || '',
      organization: id?.organization || '',
      lastSeenAt: Date.now(),
      lastAddress: `${tunnel.remoteAddress}:${tunnel.remotePort}`,
      certSerial: id?.serialNumber || '',
      certNotAfter: id?.validTo ? Date.parse(id.validTo) || 0 : 0,
    }).catch((e) => this.log.warn('istemci kaydı yazılamadı', { err: e.message }));

    await this.store.startSession({
      tunnelId: tunnel.tunnelId,
      clientId: tunnel.clientId,
      remoteAddress: tunnel.remoteAddress,
      startedAt: tunnel.startedAt,
      protocol: tunnel.socket.protocol,
      cipher: tunnel.socket.cipher,
      certSerial: id?.serialNumber || '',
    }).catch((e) => this.log.warn('oturum kaydı yazılamadı', { err: e.message }));

    const rows = await this.store.listAppsForClient(tunnel.clientId).catch((e) => {
      this.log.warn('uygulama tanımları okunamadı', { err: e.message });
      return [];
    });

    for (const row of rows) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await tunnel.addApp(normalizeApp(row, { source: row.source, clientId: tunnel.clientId }), {
          persist: false, announce: false,
        });
      } catch (err) {
        // Tek bir uygulamanın portu bağlanamadıysa tünelin tamamını
        // düşürmek yanlış olurdu: diğerleri çalışabilir ve panelde sebebi
        // görünür.
        this.log.warn('uygulama başlatılamadı', { app: row.name, err: err.message });
      }
    }
    tunnel.syncApps();

    await this.store.recordEvent({
      kind: 'tunnel.connect',
      actor: id?.commonName || tunnel.clientId,
      subject: tunnel.tunnelId,
      detail: JSON.stringify({ address: tunnel.remoteAddress, apps: rows.length }),
      at: Date.now(),
    }).catch(() => {});
  }

  async _onTunnelClosed(tunnel, reason) {
    this.tunnels.delete(tunnel.tunnelId);
    if (this.byClient.get(tunnel.clientId) === tunnel) this.byClient.delete(tunnel.clientId);
    // Tünel gitti: arkasındaki dinleyiciler kapandı, dolayısıyla o tünele ait
    // ziyaretçi kayıtları da artık canlı değil.
    this.peers.dropTunnel(tunnel.tunnelId);

    const snap = tunnel.mux.snapshot();
    await this.store.endSession(tunnel.tunnelId, {
      endedAt: Date.now(),
      bytesIn: snap.bytesIn,
      bytesOut: snap.bytesOut,
      closeReason: reason || '',
      streamsOpened: snap.streamsOpened,
    }).catch(() => {});
    await this.store.recordEvent({
      kind: 'tunnel.disconnect',
      actor: tunnel.identity?.commonName || tunnel.clientId,
      subject: tunnel.tunnelId,
      detail: JSON.stringify({ reason, uptimeMs: Date.now() - tunnel.startedAt }),
      at: Date.now(),
    }).catch(() => {});
    this.emit('tunnelClosed', tunnel, reason);
  }

  // =========================================================================
  // Yönetim yüzeyinin kullandığı işlemler
  // =========================================================================

  getTunnel(tunnelId) { return this.tunnels.get(tunnelId) || null; }
  getTunnelByClient(clientId) { return this.byClient.get(clientId) || null; }

  /**
   * Uygulama tanımı ekler. Tünel bağlıysa hemen yayına alınır, değilse kayıt
   * saklanır ve istemci bağlandığında uygulanır — panelin, istemci o an
   * çevrimdışıyken de yapılandırılabilmesi gerekir.
   */
  async createApp(raw, { actor }) {
    const app = normalizeApp(raw, { source: 'admin' });
    if (!app.clientId) throw invalid('clientId gerekli');

    const tunnel = this.byClient.get(app.clientId);
    if (tunnel) {
      await tunnel.addApp(app, { persist: true });
    } else {
      await this.store.saveApp(app);
    }
    await this.store.recordEvent({
      kind: 'app.create', actor, subject: app.appId,
      detail: JSON.stringify({
        name: app.name, clientId: app.clientId, local: `${app.localHost}:${app.localPort}`,
      }),
      at: Date.now(),
    }).catch(() => {});
    return this.describeApp(app.appId);
  }

  async updateApp(appId, patch, { actor }) {
    const stored = await this.store.getApp(appId);
    if (!stored) throw Object.assign(new Error('uygulama bulunamadı'), { status: 404, code: 'not_found' });
    const tunnel = this.byClient.get(stored.clientId);

    // Tünel bağlıysa canlı kayıt yetkilidir (çalışma zamanı alanlarını taşır);
    // değilse yalnızca saklanan tanım güncellenir ve istemci bağlandığında
    // uygulanır.
    let result;
    if (tunnel && tunnel.apps.has(appId)) {
      result = await tunnel.updateApp(appId, patch);
    } else {
      result = normalizeApp({ ...stored, ...patch, appId }, {
        source: stored.source, clientId: stored.clientId,
      });
      result.endpoint = null;
      await this.store.saveApp(result);
    }
    await this.store.recordEvent({
      kind: 'app.update', actor, subject: appId, detail: JSON.stringify(patch), at: Date.now(),
    }).catch(() => {});
    return appToPublic(result, {
      publicHost: this.options.publicHostname || this.options.publicHost,
    });
  }

  async deleteApp(appId, { actor }) {
    const stored = await this.store.getApp(appId);
    if (!stored) throw Object.assign(new Error('uygulama bulunamadı'), { status: 404, code: 'not_found' });
    const tunnel = this.byClient.get(stored.clientId);
    if (tunnel && tunnel.apps.has(appId)) await tunnel.removeApp(appId, { persist: true });
    else await this.store.deleteApp(appId);
    await this.store.recordEvent({
      kind: 'app.delete', actor, subject: appId, detail: stored.name, at: Date.now(),
    }).catch(() => {});
    return { deleted: true };
  }

  async describeApp(appId) {
    const publicHost = this.options.publicHostname || this.options.publicHost;
    for (const tunnel of this.tunnels.values()) {
      const live = tunnel.apps.get(appId);
      if (live) return appToPublic(live, { publicHost });
    }
    const stored = await this.store.getApp(appId);
    return stored ? appToPublic({ ...stored, endpoint: null }, { publicHost }) : null;
  }

  /** Bağlı ve bağlı olmayan tüm uygulamalar birlikte. */
  async listApps() {
    const publicHost = this.options.publicHostname || this.options.publicHost;
    const out = new Map();
    for (const row of await this.store.listApps()) {
      out.set(row.appId, appToPublic({ ...row, endpoint: null }, { publicHost }));
    }
    for (const tunnel of this.tunnels.values()) {
      for (const app of tunnel.apps.values()) {
        out.set(app.appId, { ...appToPublic(app, { publicHost }), online: true, tunnelId: tunnel.tunnelId });
      }
    }
    return [...out.values()];
  }

  async disconnectTunnel(tunnelId, { actor, reason = 'yönetici tarafından kapatıldı' }) {
    const tunnel = this.tunnels.get(tunnelId);
    if (!tunnel) throw Object.assign(new Error('tünel bulunamadı'), { status: 404, code: 'not_found' });
    await this.store.recordEvent({
      kind: 'tunnel.kick', actor, subject: tunnelId, detail: reason, at: Date.now(),
    }).catch(() => {});
    await tunnel.shutdown(0, reason);
    return { closed: true };
  }

  // ---- ziyaretçiler (genel yüzeye dışarıdan bağlananlar) ------------------

  /** Tek bir dış bağlantıyı kapatır. Adres engellenmez — bu bir "at", "yasakla" değil. */
  async kickPeer(peerId, { actor }) {
    const peer = this.peers.get(peerId);
    if (!peer) throw Object.assign(new Error('bağlantı bulunamadı'), { status: 404, code: 'not_found' });
    const info = peer.toJSON();
    this.peers.kick(peerId);
    await this.store.recordEvent({
      kind: 'peer.kick',
      actor,
      subject: `${info.address}:${info.port}`,
      detail: JSON.stringify({ app: info.appName, publicPort: info.publicPort }),
      at: Date.now(),
    }).catch(() => {});
    return { kicked: true, peer: info };
  }

  /**
   * Bir kaynak adresi genel yüzeyden engeller ve o adrese ait açık bağlantıları
   * kapatır. Engellemek ama açık bağlantıyı bırakmak, engeli bir sonraki
   * bağlantıya kadar etkisiz kılardı.
   */
  async blockAddress(address, { ttlMs = 0, reason = '', actor }) {
    const record = this.guard.blockAddress(address, { ttlMs, reason, actor });
    const dropped = this.peers.kickAddress(record.address);
    await this.store.saveBlock(record).catch((e) => this.log.warn('engel kaydedilemedi', { err: e.message }));
    await this.store.recordEvent({
      kind: 'peer.block',
      actor,
      subject: record.address,
      detail: JSON.stringify({ reason: record.reason, ttlMs, dropped }),
      at: Date.now(),
    }).catch(() => {});
    return { ...record, droppedConnections: dropped };
  }

  async unblockAddress(address, { actor }) {
    const removed = this.guard.unblockAddress(address);
    await this.store.deleteBlock(address).catch(() => {});
    await this.store.recordEvent({
      kind: 'peer.unblock', actor, subject: address, detail: '', at: Date.now(),
    }).catch(() => {});
    return { address, blocked: false, removed };
  }

  async setClientBlocked(clientId, blocked, { actor }) {
    await this.store.upsertClient({ clientId, blocked });
    const tunnel = this.byClient.get(clientId);
    if (blocked && tunnel) await tunnel.shutdown(0, 'istemci engellendi');
    await this.store.recordEvent({
      kind: blocked ? 'client.block' : 'client.unblock', actor, subject: clientId, detail: '', at: Date.now(),
    }).catch(() => {});
    return { clientId, blocked };
  }

  overview() {
    const tunnels = [...this.tunnels.values()];
    let rateIn = 0;
    let rateOut = 0;
    let bytesIn = 0;
    let bytesOut = 0;
    let streams = 0;
    let apps = 0;
    let boundApps = 0;
    let rttSum = 0;
    let rttN = 0;
    let congestionControl = null;

    for (const t of tunnels) {
      const s = t.mux.snapshot();
      rateIn += s.rateIn; rateOut += s.rateOut;
      bytesIn += s.bytesIn; bytesOut += s.bytesOut;
      streams += s.streams;
      apps += t.apps.size;
      for (const a of t.apps.values()) if (a.boundPort) boundApps++;
      if (s.rttMs != null) { rttSum += s.rttMs; rttN++; }
      if (!congestionControl && s.congestionControl) congestionControl = s.congestionControl;
    }
    const peerStats = this.peers.snapshot();

    return {
      startedAt: this.startedAt,
      uptimeMs: Date.now() - this.startedAt,
      persistence: this.store.mode,
      tunnels: {
        online: tunnels.length,
        accepted: this.stats.tunnelsAccepted,
        handshakeFailures: this.stats.handshakeFailures,
        dtls: this.dtls ? this.dtls.stats : null,
      },
      apps: { total: apps, published: boundApps },
      streams,
      traffic: {
        bytesIn, bytesOut, rateIn, rateOut,
      },
      link: {
        avgRttMs: rttN ? Math.round(rttSum / rttN) : null,
        congestionControl,
      },
      peers: {
        active: peerStats.active,
        total: peerStats.total,
        blocked: this.guard.blocks.size,
        avgRttMs: peerStats.avgRttMs,
      },
      ports: this.ports.stats(),
      guard: this.guard.snapshot(),
      listener: this.dtls ? this.dtls.address() : null,
      publicHost: this.options.publicHostname || this.options.publicHost,
    };
  }

  // =========================================================================
  async _sampleMetrics() {
    const now = Date.now();
    for (const tunnel of this.tunnels.values()) {
      if (!tunnel.ready) continue;
      const s = tunnel.mux.snapshot();
      try {
        // eslint-disable-next-line no-await-in-loop
        await this.store.saveMetric({
          clientId: tunnel.clientId,
          appId: '',
          at: now,
          bytesIn: s.bytesIn,
          bytesOut: s.bytesOut,
          rateIn: s.rateIn,
          rateOut: s.rateOut,
          rttMs: s.rttMs || 0,
          connections: s.streams,
          lossPpm: s.packetsSent ? Math.round((s.packetsLost / s.packetsSent) * 1e6) : 0,
        });
      } catch (err) {
        this.log.debug('ölçüm yazılamadı', { err: err.message });
      }
    }
  }

  async stop() {
    if (this._stopping) return;
    this._stopping = true;
    this.log.info('kapanıyor…');

    if (this._metricsTimer) clearInterval(this._metricsTimer);
    if (this.admin) await this.admin.stop().catch(() => {});

    await Promise.all([...this.tunnels.values()].map((t) => t.shutdown(0, 'sunucu kapanıyor').catch(() => {})));
    if (this.dtls) await this.dtls.close().catch(() => {});

    this.ports.stop();
    this.guard.stop();
    await this.store?.close().catch(() => {});
    this.log.info('kapandı');
  }
}

/** Ortam değişkenlerinden yapılandırıp başlatır. */
async function startTunnelServer(overrides = {}) {
  const config = loadServerConfig(overrides);
  const server = new TunnelServer(config);
  await server.start();
  return server;
}

module.exports = { TunnelServer, startTunnelServer, loadServerConfig };
