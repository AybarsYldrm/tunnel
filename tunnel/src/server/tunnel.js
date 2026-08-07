'use strict';
// Sunucu tarafında BİR istemcinin tüneli.
//
// Yaşam döngüsü:
//
//   DTLS el sıkışması (mTLS)  -> kimlik sertifikadan gelir, biz seçmeyiz
//   HELLO / HELLO_OK          -> sürüm ve pencere anlaşması
//   APP_SYNC                  -> yönetim panelindeki uygulama tablosu
//   port bağlama              -> her etkin uygulama için genel dinleyici
//   ... trafik ...
//   kopma                     -> dinleyiciler kapanır, portlar LINGER'a düşer
//
// Bir tünelin kimliği İSTEMCİ SERTİFİKASIDIR. İstemcinin HELLO'da bildirdiği
// ad yalnızca görüntülemek içindir ve hiçbir yetki kararında kullanılmaz —
// kullanılsaydı, istemcinin kendi kendini adlandırması yetki iddia etmesi
// anlamına gelirdi. Yetki kaynağı tektir: trust.fitfak.net'in imzaladığı,
// iptal durumu OCSP/CRL ile doğrulanmış sertifika.

const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');

const {
  PROTO, PROTO_NAME, DELIVERY, CTRL, DGRAM, ERR_CODE, RST_CODE, TIMING, LIMITS,
  PROTOCOL_VERSION,
} = require('../protocol/constants.js');
const frames = require('../protocol/frames.js');
const { Mux } = require('../common/mux.js');
const { bindSocketToStream } = require('../common/pipe.js');
const { TokenBucket, RateMeter } = require('../common/rate.js');
const { PublicTcpEndpoint } = require('./public-tcp.js');
const { PublicUdpEndpoint } = require('./public-udp.js');
const {
  normalizeApp, attachRuntime, applyRates, appToWire, appToPublic,
} = require('./app-model.js');

/** X.509 subject dizesinden bir alanı okur ("CN=a,O=b" ya da satır ayrılmış). */
function subjectField(subject, key) {
  if (!subject) return '';
  const re = new RegExp(`(?:^|[,\\n/])\\s*${key}=([^,\\n/]+)`, 'i');
  const m = re.exec(subject);
  return m ? m[1].trim() : '';
}

function identityFromSocket(socket) {
  const cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  if (!cert) return null;
  const fingerprint = String(cert.fingerprint256 || '').replace(/:/g, '').toLowerCase();
  return {
    clientId: fingerprint,
    commonName: subjectField(cert.subject, 'CN') || fingerprint.slice(0, 16),
    email: subjectField(cert.subject, 'emailAddress') || subjectField(cert.subject, 'E'),
    organization: subjectField(cert.subject, 'O'),
    issuer: cert.issuer || '',
    serialNumber: String(cert.serialNumber || ''),
    fingerprint256: fingerprint,
    validFrom: cert.validFrom || null,
    validTo: cert.validTo || null,
  };
}

let nextTunnelSeq = 1;

class Tunnel extends EventEmitter {
  constructor({ socket, server, log }) {
    super();
    this.seq = nextTunnelSeq++;
    this.tunnelId = crypto.randomBytes(9).toString('base64url');
    this.socket = socket;
    this.server = server;
    this.state = 'greeting';
    this.startedAt = Date.now();
    this.closedAt = 0;
    this.closeReason = null;

    this.identity = identityFromSocket(socket);
    this.clientId = this.identity ? this.identity.clientId : `anon-${this.tunnelId}`;
    this.log = log.child(this.identity ? this.identity.commonName : this.tunnelId);

    this.remoteAddress = socket.remoteAddress;
    this.remotePort = socket.remotePort;

    /** Tünel geneli çıkış sınırı — panelden ayarlanır, 0 = sınırsız. */
    this.egressBucket = new TokenBucket({ ratePerSec: server.options.defaultTunnelEgressBps || 0 });

    this.mux = new Mux({
      socket,
      role: 'server',
      log: this.log.child('mux'),
      limits: server.limits,
      egressBucket: this.egressBucket,
    });

    this.apps = new Map();     // appId -> app
    this.byIdx = new Map();    // appIdx -> app
    this.flows = new Map();    // flowId -> PublicUdpEndpoint
    this.nextAppIdx = 1;

    this.clientInfo = null;
    this.clientStats = null;
    this.meterIn = new RateMeter();
    this.meterOut = new RateMeter();

    this.lastAlive = Date.now();
    this._heartbeatTimer = null;
    this._greetTimer = null;

    this.mux.on('control', (msg) => this._onControl(msg));
    this.mux.on('datagram', (msg) => this._onDatagram(msg));
    this.mux.on('peerAlive', () => { this.lastAlive = Date.now(); });
    this.mux.on('closed', () => this._teardown('mux kapandı'));
    this.mux.on('protocolError', (err) => this.close(1, `protokol hatası: ${err.message}`));

    socket.on('error', (err) => this.log.debug('DTLS soket hatası', { err: err.message }));
    socket.once('close', () => this._teardown('DTLS oturumu kapandı'));

    // İstemci HELLO göndermezse tüneli açık tutmanın anlamı yok: kaynak
    // ayıran ama hiç konuşmayan bir bağlantı, en ucuz kaynak tüketme yolu.
    this._greetTimer = setTimeout(() => {
      if (this.state === 'greeting') this.close(ERR_CODE.INVALID_REQUEST, 'HELLO gelmedi');
    }, 15_000);
    if (this._greetTimer.unref) this._greetTimer.unref();
  }

  get certificate() { return this.identity; }
  get revocation() { return this.socket.peerRevocation || null; }
  get ready() { return this.state === 'ready'; }

  /** Panelde ve ziyaretçi defterinde gösterilecek ad. */
  get displayName() {
    return this.clientInfo?.name || this.identity?.commonName || this.clientId.slice(0, 16);
  }

  // =========================================================================
  // Denetim düzlemi
  // =========================================================================

  _onControl(msg) {
    this.lastAlive = Date.now();
    switch (msg.type) {
      case CTRL.HELLO: return this._onHello(msg);
      case CTRL.BIND_REQ: return this._onBindReq(msg);
      case CTRL.UNBIND: return this._onUnbind(msg);
      case CTRL.STATS: return this._onStats(msg);
      case CTRL.SHUTDOWN:
        this.log.info('istemci kapanış bildirdi', { code: msg.code, message: msg.message });
        return this.close(0, 'istemci kapattı');
      default:
        this.log.debug('beklenmeyen denetim mesajı', { type: msg.type });
        return undefined;
    }
  }

  async _onHello(msg) {
    if (this.state !== 'greeting') return;
    if (msg.version !== PROTOCOL_VERSION) {
      this.mux.sendControl(frames.encodeHelloErr({
        code: ERR_CODE.PROTO_UNSUPPORTED,
        message: `sunucu protokol sürümü ${PROTOCOL_VERSION}, istemci ${msg.version}`,
      }));
      this.close(ERR_CODE.PROTO_UNSUPPORTED, 'protokol sürümü uyuşmuyor');
      return;
    }

    this.state = 'starting';
    if (this._greetTimer) clearTimeout(this._greetTimer);
    this.clientInfo = {
      agent: msg.agent, hostname: msg.hostname, name: msg.clientName, features: msg.features,
    };

    const limits = this.server.limits;
    this.mux.sendControl(frames.encodeHelloOk({
      tunnelId: this.tunnelId,
      heartbeatMs: TIMING.HEARTBEAT_MS,
      maxStreams: limits.maxStreams,
      streamWindow: limits.streamWindow,
      connectionWindow: limits.connectionWindow,
      segmentBytes: limits.segmentBytes,
    }));

    this.log.info('tünel açıldı', {
      cn: this.identity?.commonName,
      serial: this.identity?.serialNumber,
      peer: `${this.remoteAddress}:${this.remotePort}`,
      protocol: this.socket.protocol,
      cipher: this.socket.cipher,
      revocation: this.revocation ? (this.revocation.ok ? 'ok' : this.revocation.error) : 'off',
      agent: msg.agent,
    });

    try {
      await this.server.onTunnelReady(this);
    } catch (err) {
      // Politika reddi bir arıza değildir: engellenmiş bir istemcinin
      // bağlanamaması sistemin DOĞRU çalıştığının işareti. Onu ERROR olarak
      // basmak, gerçek arızaları gürültüde kaybettirir.
      if (err.policy) this.log.warn('tünel reddedildi', { sebep: err.message });
      else this.log.error('tünel hazırlanamadı', { err: err.message });
      this.close(err.policy ? ERR_CODE.UNAUTHORIZED : ERR_CODE.UNSPECIFIED, err.message);
      return;
    }
    if (this.state !== 'starting') return;

    this.state = 'ready';
    this._startHeartbeat();
    this.emit('ready');
  }

  async _onBindReq(msg) {
    const fail = (code, message) => this.mux.sendControl(frames.encodeBindErr({ reqId: msg.reqId, code, message }));

    if (!this.server.options.allowClientBinds) {
      return fail(ERR_CODE.POLICY, 'bu sunucuda uygulamalar yalnızca yönetim panelinden tanımlanır');
    }
    if (this.apps.size >= LIMITS.MAX_APPS) return fail(ERR_CODE.APP_LIMIT, 'uygulama tavanı doldu');

    let app;
    try {
      app = normalizeApp({
        clientId: this.clientId,
        name: msg.name,
        proto: msg.proto,
        delivery: msg.delivery,
        ordered: msg.ordered,
        localHost: msg.localHost,
        localPort: msg.localPort,
        publicPort: msg.desiredPublicPort,
        createdBy: `client:${this.identity?.commonName || this.clientId}`,
      }, { source: 'client', clientId: this.clientId });
    } catch (err) {
      return fail(ERR_CODE.INVALID_REQUEST, err.message);
    }

    // İstemcinin istediği SABİT genel port yalnızca panelden verilebilir:
    // istemciye port seçtirmek, ilk gelenin komşusunun portunu kapmasına ve
    // "neden benim adresim değişti" sorusuna yol açar.
    if (app.publicPort && !this.server.options.allowClientPortChoice) app.publicPort = 0;

    try {
      await this.addApp(app, { persist: true });
    } catch (err) {
      return fail(err.code || ERR_CODE.UNSPECIFIED, err.message);
    }

    return this.mux.sendControl(frames.encodeBindOk({
      reqId: msg.reqId,
      appIdx: app.appIdx,
      appId: app.appId,
      publicHost: this.server.options.publicHostname || this.server.options.publicHost,
      publicPort: app.boundPort,
      proto: app.proto,
      delivery: app.delivery,
      ordered: app.ordered,
    }));
  }

  _onUnbind(msg) {
    const app = this.byIdx.get(msg.appIdx);
    if (!app) return;
    if (app.source !== 'client') {
      this.log.warn('istemci, panelden tanımlı bir uygulamayı kaldırmaya çalıştı', { appId: app.appId });
      return;
    }
    this.removeApp(app.appId, { persist: true });
  }

  _onStats(msg) {
    this.clientStats = { ...msg.stats, at: Date.now() };
  }

  // =========================================================================
  // Uygulamalar ve genel dinleyiciler
  // =========================================================================

  _allocAppIdx() {
    for (let i = 0; i < LIMITS.MAX_APPS * 2; i++) {
      const idx = this.nextAppIdx;
      this.nextAppIdx = (this.nextAppIdx % 0xfffe) + 1;
      if (!this.byIdx.has(idx)) return idx;
    }
    return 0;
  }

  /**
   * Uygulamayı tünele ekler, portu bağlar ve istemciye bildirir.
   * @param {object} app normalizeApp'ten geçmiş kayıt
   */
  async addApp(app, { persist = false, announce = true } = {}) {
    if (this.apps.has(app.appId)) return this.apps.get(app.appId);

    attachRuntime(app);
    app.appIdx = this._allocAppIdx();
    if (!app.appIdx) {
      const err = new Error('uygulama indeksi tükendi');
      err.code = ERR_CODE.APP_LIMIT;
      throw err;
    }

    this.apps.set(app.appId, app);
    this.byIdx.set(app.appIdx, app);

    if (app.enabled) {
      try {
        await this._bindApp(app);
      } catch (err) {
        this.apps.delete(app.appId);
        this.byIdx.delete(app.appIdx);
        throw err;
      }
    }

    if (persist) await this.server.store.saveApp(app).catch((e) => this.log.warn('uygulama kaydedilemedi', { err: e.message }));
    if (announce) this.syncApps();
    this.emit('appsChanged');
    return app;
  }

  async removeApp(appId, { persist = false } = {}) {
    const app = this.apps.get(appId);
    if (!app) return;
    await this._unbindApp(app, { immediate: true });
    this.apps.delete(appId);
    this.byIdx.delete(app.appIdx);
    if (persist) await this.server.store.deleteApp(appId).catch((e) => this.log.warn('uygulama silinemedi', { err: e.message }));
    this.syncApps();
    this.emit('appsChanged');
  }

  /** Panelden gelen değişiklikleri uygular; gerekiyorsa portu yeniden bağlar. */
  async updateApp(appId, patch) {
    const app = this.apps.get(appId);
    if (!app) throw Object.assign(new Error('uygulama bulunamadı'), { status: 404, code: 'not_found' });

    const rebindNeeded = ['proto', 'delivery', 'publicPort', 'enabled', 'ordered']
      .some((k) => patch[k] !== undefined && patch[k] !== app[k]);

    const merged = normalizeApp({ ...app, ...patch, appId: app.appId }, {
      source: app.source, clientId: app.clientId,
    });
    Object.assign(app, merged);
    applyRates(app);

    if (rebindNeeded) {
      await this._unbindApp(app, { immediate: !app.sticky });
      if (app.enabled) await this._bindApp(app);
    }

    await this.server.store.saveApp(app).catch((e) => this.log.warn('uygulama kaydedilemedi', { err: e.message }));
    this.syncApps();
    this.emit('appsChanged');
    return app;
  }

  async _bindApp(app) {
    const { ports, guard } = this.server;
    const host = this.server.options.publicHost;

    // Tercih sırası: panelden verilen sabit port > bu istemcinin linger'daki
    // eski portu > havuzdan rastgele.
    let preferred = app.publicPort || ports.findByHolder(app.proto, this.clientId, app.appId);

    for (let attempt = 0; attempt < 8; attempt++) {
      const port = ports.pick(app.proto, { preferred, holder: this.clientId });
      preferred = 0;
      if (!port) {
        const err = new Error('havuzda boş port kalmadı');
        err.code = ERR_CODE.NO_PORT_AVAILABLE;
        throw err;
      }
      if (app.publicPort && port !== app.publicPort) {
        const err = new Error(`istenen port ${app.publicPort} kullanımda`);
        err.code = ERR_CODE.PORT_IN_USE;
        throw err;
      }
      if (!ports.reserve(app.proto, port, {
        holder: this.clientId, appId: app.appId, tunnelId: this.tunnelId, sticky: app.sticky,
      })) continue;

      const Endpoint = app.proto === PROTO.UDP ? PublicUdpEndpoint : PublicTcpEndpoint;
      const endpoint = new Endpoint({
        app, tunnel: this, guard, host, port, log: this.log.child(`app:${app.name}`),
      });

      try {
        await endpoint.listen();
        app.endpoint = endpoint;
        app.boundPort = port;
        app.lastError = null;
        this.log.info('uygulama yayında', {
          app: app.name,
          proto: PROTO_NAME[app.proto],
          public: `${host}:${port}`,
          local: `${app.localHost}:${app.localPort}`,
          delivery: app.delivery === DELIVERY.RELIABLE ? 'reliable' : 'unreliable',
        });
        this.server.emit('appBound', this, app);
        return;
      } catch (err) {
        ports.release(app.proto, port, { immediate: true });
        if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
          // Havuzdaki bir portu sistemde başkası tutuyor. Bir daha denememek
          // için işaretle ve sıradakine geç.
          ports.markUnusable(app.proto, port);
          if (app.publicPort) {
            app.lastError = `port ${port}: ${err.code}`;
            const e = new Error(`port ${port} bağlanamadı (${err.code})`);
            e.code = ERR_CODE.PORT_IN_USE;
            throw e;
          }
          continue;
        }
        app.lastError = err.message;
        throw err;
      }
    }
    const err = new Error('port bağlanamadı (deneme sınırı)');
    err.code = ERR_CODE.NO_PORT_AVAILABLE;
    throw err;
  }

  async _unbindApp(app, { immediate = false } = {}) {
    if (!app.endpoint) return;
    const port = app.boundPort;
    const endpoint = app.endpoint;
    app.endpoint = null;
    app.boundPort = 0;
    try { await endpoint.close(); } catch { /* kapanmışsa sorun değil */ }
    if (port) this.server.ports.release(app.proto, port, { immediate: immediate && !app.sticky });
  }

  /** Güncel uygulama tablosunu istemciye bildirir. */
  syncApps() {
    if (!this.mux || this.mux.closed) return;
    if (this.state !== 'ready' && this.state !== 'starting') return;
    this.mux.sendControl(frames.encodeAppSync([...this.apps.values()].map(appToWire)));
  }

  /** Yönetim panelinden gelen tünel geneli sınır değişikliği. */
  applyConfig({ egressBps }) {
    if (egressBps !== undefined) {
      this.mux.setEgressRate(egressBps);
      this.mux.sendControl(frames.encodeConfig({ egressBps }));
    }
  }

  // =========================================================================
  // Veri düzlemi
  // =========================================================================

  /**
   * Dışarıdan gelen bir bağlantı için mantıksal akış açar ve istemciye
   * duyurur. Duyuru akışın İLK mesajıdır; veri hemen arkasına yazılabilir.
   *
   * @returns {import('../common/mux.js').TunnelStream|null}
   */
  openPublicConnection(app, {
    remoteAddress, remotePort, socket = null, peer = null,
  }) {
    if (!this.ready || !app.enabled) return null;
    if (app.maxConns && app.activeConnections >= app.maxConns) {
      app.refusedConnections++;
      return null;
    }

    const stream = this.mux.openStream({
      appId: app.appId, remoteAddress, remotePort, qos: app.qos,
    });
    if (!stream) { app.refusedConnections++; return null; }

    app.activeConnections++;
    app.totalConnections++;

    this.mux.sendOpen(stream, { appIdx: app.appIdx, remoteAddress, remotePort });

    // Yerel hedefe hiç ulaşılamıyorsa istemci OPEN_ACK göndermez ve akış
    // sonsuza kadar açık kalırdı; dışarıdaki istemci de öylece beklerdi.
    let acked = false;
    const openTimer = setTimeout(() => {
      if (!acked && !stream.closed) stream.reset(RST_CODE.TIMEOUT);
    }, TIMING.OPEN_TIMEOUT_MS);
    if (openTimer.unref) openTimer.unref();
    stream.once('openAck', () => { acked = true; clearTimeout(openTimer); });
    stream.once('close', () => {
      clearTimeout(openTimer);
      app.activeConnections = Math.max(0, app.activeConnections - 1);
    });

    if (socket) {
      bindSocketToStream(socket, stream, {
        ingressBucket: app.bucketIn,
        egressBucket: app.bucketOut,
        idleMs: app.idleMs,
        onBytes: (dir, bytes) => {
          if (dir === 'in') {
            app.meterIn.add(bytes);
            this.meterIn.add(bytes);
            // Ziyaretçiden gelen bayt: pasif tur süresi örneği burada doğar.
            if (peer) this.server.peers.noteIn(peer, bytes);
          } else {
            app.meterOut.add(bytes);
            this.meterOut.add(bytes);
            if (peer) this.server.peers.noteOut(peer, bytes);
          }
        },
      });
    }
    return stream;
  }

  sendDatagram(frame) { return this.mux.sendDatagram(frame); }

  trackFlow(flowId, endpoint) { this.flows.set(flowId, endpoint); }
  untrackFlow(flowId) { this.flows.delete(flowId); }

  _onDatagram(msg) {
    const endpoint = this.flows.get(msg.flowId);
    if (!endpoint) return;
    switch (msg.type) {
      case DGRAM.UDP:
        endpoint.deliver(msg.flowId, msg.payload);
        return;
      case DGRAM.UDP_CLOSE:
        endpoint.closeFlowById(msg.flowId);
        return;
      default:
        // UDP_NEW yalnızca sunucudan istemciye gider: istemci bir akış
        // başlatamaz, çünkü dış dünyayla konuşan taraf o değil.
    }
  }

  // =========================================================================
  // Kalp atışı, ölçüm, kapanış
  // =========================================================================

  _startHeartbeat() {
    this._heartbeatTimer = setInterval(() => {
      if (Date.now() - this.lastAlive > TIMING.HEARTBEAT_TIMEOUT_MS) {
        this.log.warn('kalp atışı zaman aşımı, tünel kapatılıyor', {
          sessizlikMs: Date.now() - this.lastAlive,
        });
        this.close(ERR_CODE.UNSPECIFIED, 'kalp atışı yok');
        return;
      }
      this.mux.ping();
    }, TIMING.HEARTBEAT_MS);
    if (this._heartbeatTimer.unref) this._heartbeatTimer.unref();
  }

  snapshot() {
    const mux = this.mux.snapshot();
    const now = Date.now();
    return {
      tunnelId: this.tunnelId,
      clientId: this.clientId,
      state: this.state,
      name: this.clientInfo?.name || this.identity?.commonName || this.clientId.slice(0, 16),
      agent: this.clientInfo?.agent || null,
      hostname: this.clientInfo?.hostname || null,
      remoteAddress: this.remoteAddress,
      remotePort: this.remotePort,
      startedAt: this.startedAt,
      uptimeMs: (this.closedAt || now) - this.startedAt,
      transport: {
        protocol: this.socket.protocol,
        cipher: this.socket.cipher,
        mtu: this.server.options.mtu,
      },
      certificate: this.identity ? {
        commonName: this.identity.commonName,
        organization: this.identity.organization,
        email: this.identity.email,
        issuer: this.identity.issuer,
        serialNumber: this.identity.serialNumber,
        fingerprint256: this.identity.fingerprint256,
        validFrom: this.identity.validFrom,
        validTo: this.identity.validTo,
        authorized: this.socket.authorized,
        authorizationError: this.socket.authorizationError,
      } : null,
      revocation: this.revocation ? {
        ok: this.revocation.ok,
        error: this.revocation.error,
        results: (this.revocation.results || []).map((r) => ({
          subject: r.subject, method: r.method, status: r.status, error: r.error,
        })),
      } : null,
      link: {
        rttMs: mux.rttMs,
        minRttMs: mux.minRttMs,
        appRttMs: mux.appRttMs,
        congestionControl: mux.congestionControl,
        ccState: mux.ccState,
        bandwidthBps: mux.bandwidthBps,
        pacingRateBps: mux.pacingRateBps,
        congestionWindow: mux.congestionWindow,
        bytesInFlight: mux.bytesInFlight,
        // Sıralamanın gerçekten işleyip işlemediği buradan okunur: kanal
        // kuyruğu izin verilenin sınırındaysa besleme doğru frenleniyor
        // demektir; bandlara göre dağılım da hangi sınıfın beklediğini gösterir.
        channelQueuedBytes: mux.channelQueuedBytes,
        queueAllowanceBytes: mux.queueAllowanceBytes,
        queuedByBand: mux.queuedByBand,
        // Hız şekillendiricinin patlama payı ve onu belirleyen zamanlayıcı
        // ölçümü. Bu iki sayı, "hat boş ve kayıp yok ama hız düşük" arızasının
        // TEK teşhis noktasıdır: `timerLagMs` yüksekken `pacingBurstMs` de
        // yükselmemişse şekillendirici hattı kendi kendine kısıyordur.
        pacingBurstBytes: mux.pacingBurstBytes,
        pacingBurstMs: mux.pacingBurstMs,
        timerLagMs: mux.timerLagMs,
        packetsSent: mux.packetsSent,
        packetsLost: mux.packetsLost,
        retransmits: mux.retransmits,
        congestionEvents: mux.congestionEvents,
        lossRate: mux.packetsSent ? +(mux.packetsLost / mux.packetsSent).toFixed(5) : 0,
      },
      traffic: {
        bytesIn: mux.bytesIn,
        bytesOut: mux.bytesOut,
        rateIn: mux.rateIn,
        rateOut: mux.rateOut,
        payloadIn: this.meterIn.total,
        payloadOut: this.meterOut.total,
        egressLimitBps: this.egressBucket.ratePerSec,
      },
      streams: {
        open: mux.streams,
        active: mux.activeStreams,
        opened: mux.streamsOpened,
        closed: mux.streamsClosed,
        resets: mux.resets,
        outstandingBytes: mux.outstandingBytes,
        connSendWindow: mux.connSendWindow,
        connRecvWindow: mux.connRecvWindow,
        flowViolations: mux.flowViolations,
      },
      datagrams: {
        in: mux.datagramsIn, out: mux.datagramsOut, dropped: mux.datagramsDropped,
      },
      apps: [...this.apps.values()].map((a) => appToPublic(a, {
        publicHost: this.server.options.publicHostname || this.server.options.publicHost,
      })),
      clientStats: this.clientStats,
    };
  }

  /** Düzgün kapanış: istemciye sebebi söyler, sonra oturumu kapatır. */
  close(code = 0, reason = '') {
    if (this.state === 'closed' || this.state === 'closing') return;
    this.state = 'closing';
    this.closeReason = reason;
    try { this.mux.sendControl(frames.encodeShutdown({ code, message: reason })); } catch { /* zaten kapalı */ }
    // Kapanış mesajının yola çıkması için kısa bir soluk; ardından oturum
    // her hâlükârda kapanır.
    setTimeout(() => { try { this.socket.close(); } catch { this.socket.destroy(); } }, 50).unref?.();
    setTimeout(() => this._teardown(reason), 500).unref?.();
  }

  /** Kapanışın TAMAMLANMASINI bekler — portlar serbest kalmadan dönmez. */
  shutdown(code = 0, reason = '') {
    if (this.state === 'closed') return Promise.resolve();
    return new Promise((resolve) => {
      this.once('closed', resolve);
      this.close(code, reason);
    });
  }

  async _teardown(reason) {
    if (this.state === 'closed') return;
    this.state = 'closed';
    this.closedAt = Date.now();
    this.closeReason = this.closeReason || reason;

    if (this._heartbeatTimer) clearInterval(this._heartbeatTimer);
    if (this._greetTimer) clearTimeout(this._greetTimer);

    for (const app of this.apps.values()) {
      // Portlar LINGER'a düşer: kısa bir kopmadan sonra dönen istemci AYNI
      // adresi geri alır. Hemen bırakmak, dışarıdaki her yapılandırmayı
      // (DNS kaydı, güvenlik duvarı kuralı) geçersiz kılardı.
      await this._unbindApp(app, { immediate: false });
    }
    this.flows.clear();
    this.mux.destroy(null);

    this.log.info('tünel kapandı', {
      reason: this.closeReason,
      uptimeMs: this.closedAt - this.startedAt,
      bytesIn: this.meterIn.total,
      bytesOut: this.meterOut.total,
    });
    this.emit('closed', this.closeReason);
  }
}

module.exports = { Tunnel, identityFromSocket, subjectField };
