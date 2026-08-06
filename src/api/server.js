'use strict';
// DtlsServer — tek bir UDP soketi üzerinde çok sayıda DTLS oturumu.
//
//   const server = dtls.createServer({ cert, key, ca, requestCert: true });
//   server.on('secureConnection', (sock) => { ... });
//   await server.listen(4444);

const { EventEmitter } = require('node:events');
const { UdpEndpoint } = require('../transport/udp.js');
const { Session } = require('../session/session.js');
const { CookieMinter } = require('../handshake/cookie.js');
const { RateLimiter } = require('../session/rate-limit.js');
const { attachKeyLog } = require('../session/keylog.js');
const { normalizeOptions } = require('../options.js');
const { CONTENT_TYPE, HS_TYPE } = require('../constants.js');
const { demuxPacket } = require('../record/srtp.js');

const SWEEP_INTERVAL_MS = 15_000;

class DtlsServer extends EventEmitter {
  constructor(rawOptions = {}) {
    super();
    this.options = normalizeOptions('server', rawOptions);
    this.sessions = new Map();          // "ip:port" -> Session
    this.transport = null;
    this._sweepTimer = null;
    this._closed = false;

    // Cookie sırrı tüm oturumlarda ortaktır — stateless doğrulamanın temeli.
    this.cookieMinter = new CookieMinter();
    this.limiter = new RateLimiter({
      capacity: rawOptions.rateLimitBurst ?? 30,
      refillPerSec: rawOptions.rateLimitPerSec ?? 15,
    });

    this.stats = { accepted: 0, rejected: 0, rateLimited: 0, handshakeFailures: 0 };
  }

  /**
   * @param {number} [port]
   * @param {string} [host]
   * @returns {Promise<{address:string,port:number}>}
   */
  async listen(port = 0, host = '0.0.0.0') {
    if (this.transport) throw new Error('sunucu zaten dinliyor');
    this.transport = new UdpEndpoint({
      logComponent: 'dtls:udp',
      type: host.includes(':') ? 'udp6' : 'udp4',
      recvBufferSize: this.options.recvBufferSize || (1 << 20),
      sendBufferSize: this.options.sendBufferSize || 0,
    });
    this.transport.on('error', (e) => this.emit('error', e));
    this.transport.on('datagram', (dg, rinfo) => this._onDatagram(dg, rinfo));

    const addr = await this.transport.bind(port, host);
    this._sweepTimer = setInterval(() => this._sweep(), SWEEP_INTERVAL_MS);
    if (this._sweepTimer.unref) this._sweepTimer.unref();
    this.emit('listening', addr);
    return addr;
  }

  address() { return this.transport ? this.transport.address() : null; }

  async close() {
    if (this._closed) return;
    this._closed = true;
    if (this._sweepTimer) clearInterval(this._sweepTimer);
    for (const s of this.sessions.values()) { try { s.destroy(null); } catch { /* yoksay */ } }
    this.sessions.clear();
    if (this.transport) await this.transport.close();
    this.emit('close');
  }

  // ==========================================================================
  _onDatagram(dg, rinfo) {
    if (this._closed || dg.length === 0) return;
    const key = `${rinfo.address}:${rinfo.port}`;
    let session = this.sessions.get(key);

    if (session) {
      session.handleDatagram(dg, rinfo);
      return;
    }

    // Bilinmeyen kaynaktan gelen DTLS dışı trafik (ICE/STUN vb.) uygulamaya bırakılır.
    if (demuxPacket(dg) !== 'dtls') {
      this.emit('unhandled', dg, rinfo);
      return;
    }
    if (!looksLikeClientHello(dg)) { this.stats.rejected++; return; }

    // Yeni oturum kurmak pahalıdır (ECDHE + imza): önce hız sınırı.
    if (!this.limiter.allow(key)) {
      this.stats.rateLimited++;
      this.emit('ratelimit', rinfo);
      return;
    }
    if (this.sessions.size >= this.options.maxSessions) {
      this.stats.rejected++;
      this.emit('overload', rinfo);
      return;
    }

    session = this._createSession(key, rinfo);
    session.handleDatagram(dg, rinfo);
  }

  _createSession(key, rinfo) {
    const session = new Session({
      role: 'server',
      transport: this.transport,
      peer: { address: rinfo.address, port: rinfo.port },
      options: this.options,
      cookieMinter: this.cookieMinter,
    });
    session.sessionKey = key;
    this.sessions.set(key, session);
    session.startHandshakeTimer();

    if (this.options.keylogFile) attachKeyLog(session, this.options.keylogFile);

    session.on('log', (lvl, msg, meta) => this.emit('log', lvl, msg, { peer: key, ...meta }));
    session.on('error', (e) => {
      if (!session.handshakeComplete) this.stats.handshakeFailures++;
      this.emit('sessionError', e, session);
    });
    session.on('close', () => {
      if (this.sessions.get(key) === session) this.sessions.delete(key);
    });
    session.once('connect', () => {
      this.stats.accepted++;
      this.emit('secureConnection', session);
      this.emit('session', session); // alternatif ad
    });

    this.emit('connection', session); // handshake ÖNCESİ — istatistik/log için
    return session;
  }

  _sweep() {
    const now = Date.now();
    const idle = this.options.idleTimeout;
    for (const [key, s] of this.sessions) {
      if (s.closed) { this.sessions.delete(key); continue; }
      if (idle > 0 && now - s.lastActivity > idle) {
        s.destroy(new Error('boşta kalma zaman aşımı'));
        this.sessions.delete(key);
      }
    }
    this.limiter.sweep(now);
  }
}

/** Yeni oturum açmadan önce ucuz bir geçerlilik ön kontrolü. */
function looksLikeClientHello(dg) {
  // DTLSPlaintext: type(1) version(2) epoch(2) seq(6) length(2) | handshake
  if (dg.length < 13 + 12) return false;
  if (dg[0] !== CONTENT_TYPE.HANDSHAKE) return false;
  if (dg.readUInt16BE(3) !== 0) return false;           // epoch 0 olmalı
  return dg[13] === HS_TYPE.CLIENT_HELLO;
}

module.exports = { DtlsServer };
