'use strict';
// Tünel istemcisi.
//
// Yaptığı iş tek cümlede: sunucudan gelen "şu dış bağlantı geldi" bildirimlerine
// karşılık YEREL ağda bir soket açmak ve ikisini birbirine bağlamak. Dışarıya
// hiçbir port açmaz — bağlantıyı o kurar, dolayısıyla NAT'ın ya da güvenlik
// duvarının arkasında olması sorun değil. Cloudflare Tunnel'ın çalışma mantığı
// budur ve buradaki fark taşımanın DTLS 1.3 + mTLS olması.
//
// Yeniden bağlanma tam-jitter'lı üstel geri çekilmeyle yapılır. Sabit aralık,
// sunucu yeniden başladığında bağlı olan HERKESİN aynı anda dönmesine yol açar
// ve sunucuyu ikinci kez düşürür.

const net = require('node:net');
const dgram = require('node:dgram');
const os = require('node:os');
const { EventEmitter } = require('node:events');

const dtls = require('../../../index.js');
const {
  PROTO, PROTO_NAME, DELIVERY, CTRL, DGRAM, RST_CODE, TIMING, LIMITS,
  PROTOCOL_VERSION,
} = require('../protocol/constants.js');
const frames = require('../protocol/frames.js');
const { Mux } = require('../common/mux.js');
const { bindSocketToStream } = require('../common/pipe.js');
const { frameDatagram, DatagramDeframer } = require('../common/dgram-frame.js');
const { createLogger } = require('../common/log.js');
const { loadTrustAnchor } = require('../common/trust.js');

const AGENT = `fitfak-tunnel/${require('../../../package.json').version}`;

class TunnelClient extends EventEmitter {
  /**
   * @param {object} o
   * @param {string} o.host sunucu adresi
   * @param {number} o.port
   * @param {string} o.servername SNI + hostname doğrulaması
   * @param {{certPem:string, privateKeyPem:string}} o.identity
   * @param {string} o.caPem güven çıpası (kök CA)
   * @param {Array} [o.binds] istemcinin kendi istediği uygulamalar
   */
  constructor(options) {
    super();
    this.options = {
      revocation: 'soft-fail',
      // 1200 bayt: IPv6'nın asgari MTU'su (1280) eksi IPv6+UDP başlıkları.
      // Yol MTU keşfine güvenmeden HER yolda parçalanmadan geçen değer;
      // parçalanmış bir UDP datagramı tek bir parça kaybında tamamen ölür.
      mtu: 1200,
      /** Şifreleme paketi tercihi — politika adı ya da suite listesi. */
      cipher: 'balanced',
      /** Tıkanıklık denetimi: 'bbr3' (varsayılan) ya da 'newreno'. */
      congestionControl: 'bbr3',
      reconnect: true,
      maxBackoffMs: 30_000,
      name: os.hostname(),
    };
    // DİKKAT: nesne yayılımı (`{...defaults, ...options}`) kullanılmıyor.
    // Çağıran `{ mtu: undefined }` geçtiğinde — ki CLI'da verilmeyen her
    // seçenek tam olarak böyle gelir — yayılım varsayılanı `undefined` ile
    // EZER. Sonuç, MTU'su tanımsız bir istemci olur ve hata el sıkışmanın
    // ortasında, bambaşka bir yerde patlar.
    for (const [k, v] of Object.entries(options || {})) {
      if (v !== undefined) this.options[k] = v;
    }
    this.log = createLogger('tunnel:client');

    this.socket = null;
    this.mux = null;
    this.state = 'idle';
    this.tunnelId = null;

    /** appIdx -> uygulama tanımı (sunucu yetkilidir) */
    this.apps = new Map();
    /** appId -> appIdx */
    this.appIdsByIdx = new Map();
    /** flowId -> { socket, appIdx, lastSeen } — güvenilir olmayan UDP akışları */
    this.udpFlows = new Map();

    this._reconnectAttempt = 0;
    this._reconnectTimer = null;
    this._statsTimer = null;
    this._udpSweepTimer = null;
    this._pendingBinds = new Map(); // reqId -> {resolve, reject}
    this._nextReqId = 1;
    this._stopped = false;
  }

  get connected() { return this.state === 'ready'; }

  // =========================================================================
  async start() {
    this._stopped = false;
    await this._connect();
    return this;
  }

  async _connect() {
    const o = this.options;
    this.state = 'connecting';

    this.log.info('tünel sunucusuna bağlanılıyor', {
      hedef: `${o.host}:${o.port}`,
      servername: o.servername,
      iptalDenetimi: o.revocation,
      sifreleme: o.cipher,
      tikaniklik: o.congestionControl,
      mtu: o.mtu,
    });

    let socket;
    try {
      socket = await dtls.connect({
        host: o.host,
        port: o.port,
        servername: o.servername,
        ca: o.caPem,
        cert: o.identity.certPem,
        key: o.identity.privateKeyPem,
        revocation: o.revocation,
        mtu: o.mtu,
        cipherSuites: o.cipher,
        rejectUnauthorized: true,
        reliable: {
          ordered: false,        // sıra kararı akış başına veriliyor
          maxTrackedPackets: 8192,
          maxRetransmits: 15,
          congestionControl: o.congestionControl,
        },
      });
    } catch (err) {
      this.state = 'error';
      this.log.error('bağlanılamadı', { err: err.message });
      this.emit('error', err);
      this._scheduleReconnect();
      return;
    }

    this.socket = socket;
    this.mux = new Mux({
      socket, role: 'client', log: this.log.child('mux'), limits: o.limits || {},
    });

    this.mux.on('control', (msg) => this._onControl(msg));
    this.mux.on('datagram', (msg) => this._onDatagram(msg));
    this.mux.on('streamOpen', (stream, info) => this._onStreamOpen(stream, info));
    this.mux.on('closed', () => this._onDisconnected());

    socket.on('error', (err) => this.log.debug('DTLS soket hatası', { err: err.message }));
    socket.once('close', () => this._onDisconnected());

    this.log.info('DTLS oturumu kuruldu', {
      protocol: socket.protocol,
      cipher: socket.cipher,
      sunucu: socket.getPeerCertificate()?.subject,
      iptal: socket.peerRevocation ? (socket.peerRevocation.ok ? 'ok' : socket.peerRevocation.error) : 'kapalı',
    });

    this.state = 'greeting';
    this.mux.sendControl(frames.encodeHello({
      agent: AGENT,
      hostname: os.hostname(),
      clientName: o.name,
    }));
  }

  // =========================================================================
  // Denetim düzlemi
  // =========================================================================

  _onControl(msg) {
    switch (msg.type) {
      case CTRL.HELLO_OK: return this._onHelloOk(msg);
      case CTRL.HELLO_ERR:
        this.log.error('sunucu bağlantıyı reddetti', { code: msg.code, message: msg.message });
        this.options.reconnect = false; // sürüm/politika hatası tekrar denemekle düzelmez
        return this._close(msg.message);
      case CTRL.APP_SYNC: return this._onAppSync(msg.apps);
      case CTRL.BIND_OK: return this._onBindOk(msg);
      case CTRL.BIND_ERR: return this._onBindErr(msg);
      case CTRL.CONFIG: return this._onConfig(msg.config);
      case CTRL.SHUTDOWN:
        this.log.warn('sunucu tüneli kapatıyor', { code: msg.code, message: msg.message });
        return this._close(msg.message || 'sunucu kapattı');
      default:
        return undefined;
    }
  }

  _onHelloOk(msg) {
    if (msg.version !== PROTOCOL_VERSION) {
      this.log.error('protokol sürümü uyuşmuyor', { sunucu: msg.version, istemci: PROTOCOL_VERSION });
      this.options.reconnect = false;
      this._close('protokol sürümü uyuşmuyor');
      return;
    }
    this.tunnelId = msg.tunnelId;
    this.mux.applyPeerWindows(msg);
    this.state = 'ready';
    this._reconnectAttempt = 0;

    this.log.info('tünel hazır', {
      tunnelId: msg.tunnelId,
      akisPenceresi: msg.streamWindow,
      tunelPenceresi: msg.connectionWindow,
      segment: msg.segmentBytes,
    });

    // CLI'dan istenen uygulamalar. Panelden tanımlı olanlar zaten APP_SYNC ile
    // gelir; bunlar yalnızca bu oturuma özgüdür.
    for (const bind of this.options.binds || []) this.requestBind(bind).catch((err) => {
      this.log.error('uygulama bağlanamadı', { local: `${bind.localHost}:${bind.localPort}`, err: err.message });
    });

    this._startTimers();
    this.emit('ready', { tunnelId: msg.tunnelId });
  }

  _onAppSync(apps) {
    this.apps.clear();
    this.appIdsByIdx.clear();
    for (const app of apps) {
      this.apps.set(app.appIdx, app);
      this.appIdsByIdx.set(app.appId, app.appIdx);
    }
    this.log.info('uygulama tablosu güncellendi', {
      sayi: apps.length,
      uygulamalar: apps.map((a) => `${PROTO_NAME[a.proto]}:${a.publicPort || '?'} → ${a.localHost}:${a.localPort}${a.enabled ? '' : ' (kapalı)'}`),
    });
    this.emit('apps', apps);
  }

  _onBindOk(msg) {
    const pending = this._pendingBinds.get(msg.reqId);
    this._pendingBinds.delete(msg.reqId);
    this.log.info('uygulama yayında', {
      appId: msg.appId,
      genel: `${msg.publicHost || ''}:${msg.publicPort}/${PROTO_NAME[msg.proto]}`,
    });
    if (pending) pending.resolve(msg);
    this.emit('bound', msg);
  }

  _onBindErr(msg) {
    const pending = this._pendingBinds.get(msg.reqId);
    this._pendingBinds.delete(msg.reqId);
    const err = new Error(msg.message || `bağlama reddedildi (kod ${msg.code})`);
    err.code = msg.code;
    if (pending) pending.reject(err); else this.log.error('bağlama reddedildi', { err: err.message });
  }

  _onConfig(config) {
    if (config.egressBps !== undefined) {
      this.log.info('sunucu çıkış sınırı bildirdi', { bytesPerSec: config.egressBps });
      this.mux.setEgressRate(config.egressBps);
    }
  }

  /**
   * Sunucudan bir uygulama tanımı ister (CLI kullanımı).
   * @returns {Promise<object>} BIND_OK gövdesi
   */
  requestBind({
    proto = PROTO.TCP, delivery, ordered = true, localHost = '127.0.0.1', localPort,
    publicPort = 0, name = '',
  }) {
    if (!this.mux || this.state !== 'ready') return Promise.reject(new Error('tünel hazır değil'));
    const reqId = (this._nextReqId = (this._nextReqId + 1) >>> 0) || 1;
    const resolvedDelivery = delivery
      ?? (proto === PROTO.UDP ? DELIVERY.UNRELIABLE : DELIVERY.RELIABLE);

    return new Promise((resolve, reject) => {
      this._pendingBinds.set(reqId, { resolve, reject });
      const timer = setTimeout(() => {
        if (this._pendingBinds.delete(reqId)) reject(new Error('bağlama isteği zaman aşımına uğradı'));
      }, 15_000);
      if (timer.unref) timer.unref();

      this.mux.sendControl(frames.encodeBindReq({
        reqId,
        proto,
        delivery: resolvedDelivery,
        ordered,
        localHost,
        localPort,
        desiredPublicPort: publicPort,
        name,
      }));
    });
  }

  // =========================================================================
  // Veri düzlemi — TCP
  // =========================================================================

  _onStreamOpen(stream, info) {
    const app = this.apps.get(info.appIdx);
    if (!app || !app.enabled) {
      stream.reset(RST_CODE.APP_DISABLED);
      return;
    }
    // Güvenilir kipteki UDP uygulaması da bir AKIŞ üzerinden gelir, ama
    // ucundaki soket TCP değil UDP'dir.
    if (app.proto === PROTO.UDP) { this._openReliableUdp(stream, app); return; }

    const socket = net.connect({ host: app.localHost, port: app.localPort });
    socket.setNoDelay(true);

    // Yerel soket bağlanana kadar tünelden veri GELEBİLİR: OPEN ile veri aynı
    // sıralı akıştadır ve gönderen onay beklemez (bir tur kazanmanın bedeli
    // budur). Gelen ilk baytları tutmazsak HTTP'nin istek satırı ya da TLS'in
    // ClientHello'su kaybolur. Pencere zaten üst sınırı koyuyor.
    const early = [];
    let earlyEnd = false;
    const onEarlyData = (chunk) => early.push(chunk);
    const onEarlyEnd = () => { earlyEnd = true; };
    stream.on('data', onEarlyData);
    stream.on('end', onEarlyEnd);

    let settled = false;
    const fail = (code, reason) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (!stream.closed) stream.reset(code);
      this.log.debug('yerel bağlantı kurulamadı', {
        hedef: `${app.localHost}:${app.localPort}`, sebep: reason,
      });
    };

    socket.once('error', (err) => fail(
      err.code === 'ECONNREFUSED' ? RST_CODE.LOCAL_REFUSED : RST_CODE.LOCAL_ERROR,
      err.message,
    ));

    socket.once('connect', () => {
      if (settled) { socket.destroy(); return; }
      settled = true;
      stream.removeListener('data', onEarlyData);
      stream.removeListener('end', onEarlyEnd);

      this.mux.sendOpenAck(stream);
      bindSocketToStream(socket, stream, { idleMs: app.idleMs || 0 });

      for (const chunk of early) {
        socket.write(chunk, () => stream.consumed(chunk.length));
      }
      if (earlyEnd) socket.end();

      this.emit('connection', {
        appId: app.appId,
        remote: `${info.remoteAddress}:${info.remotePort}`,
        local: `${app.localHost}:${app.localPort}`,
      });
    });

    stream.once('close', () => { if (!socket.destroyed) socket.destroy(); });
  }

  /**
   * Kayıpsız teslim seçilmiş bir UDP uygulaması: taşıma güvenilir akış,
   * uçlar hâlâ UDP soketi. Datagram sınırları uzunluk önekiyle korunur —
   * akış katmanı yazıları bölebilir/birleştirebilir.
   */
  _openReliableUdp(stream, app) {
    const socket = dgram.createSocket(app.localHost.includes(':') ? 'udp6' : 'udp4');
    const deframer = new DatagramDeframer();
    let closed = false;

    const shutdown = (code) => {
      if (closed) return;
      closed = true;
      try { socket.close(); } catch { /* zaten kapalı */ }
      if (!stream.closed && code != null) stream.reset(code);
    };

    socket.on('message', (payload) => {
      if (stream.closed) return;
      stream.write(frameDatagram(payload));
    });
    socket.on('error', (err) => {
      this.log.debug('yerel UDP soket hatası', { err: err.message });
      shutdown(RST_CODE.LOCAL_ERROR);
    });

    stream.on('data', (chunk) => {
      let datagrams;
      try { datagrams = deframer.push(chunk); } catch (err) {
        this.log.warn('bozuk datagram çerçevesi', { err: err.message });
        shutdown(RST_CODE.FLOW_VIOLATION);
        return;
      }
      for (const payload of datagrams) {
        socket.send(payload, app.localPort, app.localHost, (err) => {
          if (err) this.log.debug('yerel UDP gönderilemedi', { err: err.message });
        });
      }
      stream.consumed(chunk.length);
    });
    stream.on('end', () => shutdown(null));
    stream.on('close', () => shutdown(null));

    this.mux.sendOpenAck(stream);
  }

  // =========================================================================
  // Veri düzlemi — UDP (güvenilir olmayan)
  // =========================================================================

  _onDatagram(msg) {
    switch (msg.type) {
      case DGRAM.UDP_NEW: return this._onUdpNew(msg);
      case DGRAM.UDP: return this._onUdpData(msg);
      case DGRAM.UDP_CLOSE: return this._closeUdpFlow(msg.flowId);
      default: return undefined;
    }
  }

  _onUdpNew(msg) {
    let flow = this.udpFlows.get(msg.flowId);
    if (flow) { this._sendLocalUdp(flow, msg.payload); return; }

    const app = this.apps.get(msg.appIdx);
    if (!app || !app.enabled) return;
    if (this.udpFlows.size >= 4096) return;

    const socket = dgram.createSocket(app.localHost.includes(':') ? 'udp6' : 'udp4');
    flow = {
      id: msg.flowId, socket, app, lastSeen: Date.now(), bytesIn: 0, bytesOut: 0,
    };

    socket.on('message', (payload) => {
      flow.lastSeen = Date.now();
      flow.bytesOut += payload.length;
      if (payload.length > LIMITS.MAX_DATAGRAM) return;
      this.mux.sendDatagram(frames.frameUdp({ flowId: flow.id, payload }));
    });
    socket.on('error', (err) => {
      this.log.debug('yerel UDP soket hatası', { err: err.message });
      this._closeUdpFlow(flow.id);
    });

    this.udpFlows.set(msg.flowId, flow);
    this._sendLocalUdp(flow, msg.payload);
  }

  _onUdpData(msg) {
    const flow = this.udpFlows.get(msg.flowId);
    // Bilinmeyen akış: UDP_NEW kaybolmuş olabilir. Sunucu, karşı taraftan
    // yanıt görene kadar UDP_NEW göndermeye devam eder, bu yüzden burada
    // yapılacak bir şey yok — bir sonraki paket akışı kuracak.
    if (!flow) return;
    this._sendLocalUdp(flow, msg.payload);
  }

  _sendLocalUdp(flow, payload) {
    flow.lastSeen = Date.now();
    flow.bytesIn += payload.length;
    flow.socket.send(payload, flow.app.localPort, flow.app.localHost, (err) => {
      if (err) this.log.debug('yerel UDP gönderilemedi', { err: err.message });
    });
  }

  _closeUdpFlow(flowId) {
    const flow = this.udpFlows.get(flowId);
    if (!flow) return;
    this.udpFlows.delete(flowId);
    try { flow.socket.close(); } catch { /* zaten kapalı */ }
  }

  // =========================================================================
  // Zamanlayıcılar, kapanış, yeniden bağlanma
  // =========================================================================

  _startTimers() {
    this._statsTimer = setInterval(() => {
      if (!this.mux || this.mux.closed) return;
      const s = this.mux.snapshot();
      this.mux.sendControl(frames.encodeStats({
        streams: s.streams,
        udpFlows: this.udpFlows.size,
        bytesIn: s.bytesIn,
        bytesOut: s.bytesOut,
        rateIn: s.rateIn,
        rateOut: s.rateOut,
        rttMs: s.rttMs,
        cwnd: s.congestionWindow,
        lost: s.packetsLost,
        resent: s.retransmits,
        mem: Math.round(process.memoryUsage().rss / 1048576),
      }));
    }, TIMING.STATS_INTERVAL_MS * 2);
    if (this._statsTimer.unref) this._statsTimer.unref();

    this._udpSweepTimer = setInterval(() => {
      const now = Date.now();
      for (const [id, flow] of this.udpFlows) {
        if (now - flow.lastSeen > TIMING.UDP_FLOW_IDLE_MS) this._closeUdpFlow(id);
      }
    }, 15_000);
    if (this._udpSweepTimer.unref) this._udpSweepTimer.unref();
  }

  _stopTimers() {
    if (this._statsTimer) clearInterval(this._statsTimer);
    if (this._udpSweepTimer) clearInterval(this._udpSweepTimer);
    this._statsTimer = null;
    this._udpSweepTimer = null;
  }

  _onDisconnected() {
    if (this.state === 'closed' || this.state === 'disconnected') return;
    const wasReady = this.state === 'ready';
    this.state = 'disconnected';
    this._stopTimers();
    for (const id of [...this.udpFlows.keys()]) this._closeUdpFlow(id);
    for (const [, pending] of this._pendingBinds) pending.reject(new Error('tünel koptu'));
    this._pendingBinds.clear();
    if (wasReady) this.log.warn('tünel koptu');
    this.emit('disconnected');
    this._scheduleReconnect();
  }

  _scheduleReconnect() {
    if (this._stopped || !this.options.reconnect || this._reconnectTimer) return;
    this._reconnectAttempt++;
    // Tam jitter (AWS'nin "Exponential Backoff and Jitter" yazısındaki biçim):
    // sabit aralık, sunucu yeniden başladığında herkesin AYNI anda dönmesine
    // ve sunucuyu ikinci kez düşürmesine yol açar.
    const ceiling = Math.min(this.options.maxBackoffMs, 500 * (2 ** Math.min(this._reconnectAttempt, 7)));
    const delay = Math.floor(Math.random() * ceiling) + 250;
    this.log.info('yeniden bağlanılacak', { deneme: this._reconnectAttempt, gecikmeMs: delay });
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this._connect().catch((err) => {
        this.log.error('yeniden bağlanma hatası', { err: err.message });
        this._scheduleReconnect();
      });
    }, delay);
    if (this._reconnectTimer.unref) this._reconnectTimer.unref();
  }

  _close(reason) {
    this._stopTimers();
    if (this.mux && !this.mux.closed) this.mux.destroy(null);
    if (this.socket) { try { this.socket.close(); } catch { this.socket.destroy(); } }
    this.emit('closed', reason);
  }

  async stop(reason = 'istemci kapanıyor') {
    this._stopped = true;
    this.options.reconnect = false;
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    if (this.mux && !this.mux.closed) {
      try { this.mux.sendControl(frames.encodeShutdown({ code: 0, message: reason })); } catch { /* kapalı */ }
      await new Promise((r) => setTimeout(r, 50));
    }
    this.state = 'closed';
    this._close(reason);
  }

  snapshot() {
    return {
      state: this.state,
      tunnelId: this.tunnelId,
      apps: [...this.apps.values()],
      udpFlows: this.udpFlows.size,
      link: this.mux ? this.mux.snapshot() : null,
    };
  }
}

/**
 * Uçtan uca kolaylık: kök sertifikayı alır, kimliği hazırlar (gerekirse cihaz
 * kodu akışını çalıştırır) ve bağlanır.
 */
async function startTunnelClient(config) {
  const log = createLogger('tunnel:client');

  const anchor = await loadTrustAnchor({
    file: config.caPath,
    url: config.caPath ? undefined : config.rootCaUrl,
    expectedFingerprint: config.rootCaFingerprint,
    allowUnpinned: !config.rootCaFingerprint,
    cacheFile: config.dataDir ? require('node:path').join(config.dataDir, 'root.crt') : undefined,
    log,
  });
  log.info('güven çıpası', { subject: anchor.subject, fingerprint256: anchor.fingerprint256 });

  // eslint-disable-next-line global-require
  const { ensureIdentity } = require('./identity.js');
  const identity = config.identity || await ensureIdentity({
    idpUrl: config.idpUrl,
    trustUrl: config.trustUrl,
    oauthClientId: config.oauthClientId,
    dataDir: config.dataDir,
    commonName: config.commonName,
    onPrompt: config.onPrompt,
    log,
  });

  const client = new TunnelClient({
    host: config.host,
    port: config.port,
    servername: config.servername,
    caPem: anchor.pem,
    identity,
    revocation: config.revocation,
    mtu: config.mtu,
    cipher: config.cipher,
    congestionControl: config.congestionControl,
    name: config.name,
    binds: config.binds,
    limits: config.limits,
    reconnect: config.reconnect,
  });
  await client.start();
  return client;
}

module.exports = { TunnelClient, startTunnelClient };
