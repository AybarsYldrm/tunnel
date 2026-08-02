'use strict';
// DTLS Session — sürümden bağımsız ortak çekirdek.
//
// Bu sınıf taşımayı, kayıt katmanını, uçuş (flight) yönetimini, yeniden gönderimi,
// alarmları, uygulama verisini, SRTP ve güvenilir kanal eklentilerini yönetir.
// Handshake mantığı mixin olarak gelir:
//   handshake.js → DTLS 1.3 (RFC 9147) + DTLS 1.2 (RFC 6347), tek dosyada
//   negotiate.js → sürüm müzakeresi, ClientHello üretimi, SNI/ALPN/SRTP seçimi
//
// Tek bir `this` üzerinde çalışırlar; ortak durum burada tanımlıdır.

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

const {
  CONTENT_TYPE, VERSION, HS_TYPE, EPOCH, NAMES, ALERT_LEVEL, ALERT_DESC,
} = require('../constants.js');
const { encodePlaintext, decodePlaintext } = require('../record/plaintext.js');
const {
  protectRecord, unprotectRecord, protectRecord12, unprotectRecord12,
} = require('../record/protected.js');
const { ReplayWindow } = require('../record/replay-window.js');
const { buildAck, parseAck } = require('../record/ack.js');
const { HsReassembler } = require('../handshake/reassembler.js');
const { decodeHandshake } = require('../handshake/framing.js');
const { CookieMinter } = require('../handshake/cookie.js');
const { ReliableChannel } = require('../reliable/channel.js');
const { createSrtpPair, demuxPacket } = require('../record/srtp.js');
const { exportSrtpKeyingMaterial, exportKeyingMaterial } = require('../crypto/exporter.js');

const HS_HEADER_LEN = 12;
const MAX_RETRANSMITS = 6;
const BASE_RETRANSMIT_MS = 400;   // RTT ölçülene kadarki taban (RFC 6347 §4.2.4.1: 1 s, biz daha atak)
const MIN_RETRANSMIT_MS = 40;     // ölçülen RTT'nin altına inebileceği sınır
const MAX_RETRANSMIT_MS = 12_000;

// Kayıt ek yükü: unified header (1..5) + AEAD tag (16) + inner content type (1)
// + emniyet payı. Handshake parçalama bütçesi buradan çıkar.
const RECORD_OVERHEAD = 40;

class Session extends EventEmitter {
  /**
   * @param {object} o
   * @param {'client'|'server'} o.role
   * @param {object} o.transport  send(buf, peer) sağlayan uç nokta
   * @param {{address:string,port:number}} o.peer
   * @param {object} o.options    normalizeOptions() çıktısı
   * @param {CookieMinter} [o.cookieMinter]  sunucuda paylaşılan cookie üreticisi
   */
  constructor({ role, transport, peer = null, options, cookieMinter = null }) {
    super();
    this.role = role;
    this.transport = transport;
    this.peer = peer;
    this.options = options;
    this.ctx = options.secureContext;     // SNI ile değişebilir (sunucu)

    // --- durum
    this.version = null;                  // müzakere bitene kadar bilinmez
    this.suite = null;
    this.state = role === 'client' ? 'START' : 'WAIT_CH';
    this.handshakeComplete = false;
    this.createdAt = Date.now();
    this.lastActivity = this.createdAt;
    this.closed = false;

    // --- kimlik / doğrulama sonucu
    this.servername = role === 'client' ? options.servername : null;
    this.alpnProtocol = null;
    this.authorized = false;
    this.authorizationError = null;
    this.peerCertificate = null;
    this.peerCertificateChain = null;
    this.peerCertificatePath = null;    // doğrulanmış yol (leaf → güven çıpası)
    this.peerRevocation = null;         // OCSP/CRL denetim sonucu
    this.peerOcspStaple = null;         // karşı tarafın zımbaladığı OCSP yanıtı
    this.peerWantsOcsp = false;         // (sunucu) istemci status_request gönderdi mi

    // --- handshake defterleri
    this.messageSeq = 0;
    this.rxReassembler = new HsReassembler();
    this._nextRxSeq = 0;              // sırayla işlenecek bir sonraki message_seq
    this._pendingMsgs = new Map();    // erken gelen (ileri seq'li) mesajlar
    this._chain = Promise.resolve();  // datagram/kayıt işlemeyi sıraya sokar
    this._lastDupRetransmit = 0;
    this.transcript = null;
    this.clientRandom = null;
    this.serverRandom = null;
    this.cookieMinter = cookieMinter || (role === 'server' ? new CookieMinter() : null);

    // --- gönderme tarafı kayıt durumu
    this.sendEpoch = EPOCH.INITIAL;
    this.sendSeq = new Map([[0, 0]]);

    // --- alma tarafı kayıt durumu
    this.recvEpoch = EPOCH.INITIAL;
    this.recvLastSeq = new Map([[0, -1]]);
    this.recvReplay = new Map([[0, new ReplayWindow(options.replayWindow)]]);

    // --- anahtar malzemesi
    this.handshakeKeys = null;   // 1.3
    this.appKeys = null;         // 1.3
    this.keys12 = null;          // 1.2: { client:{key,salt}, server:{key,salt} }
    this.masterSecret = null;    // 1.2

    // --- uçuş / yeniden gönderim
    this._flight = null;
    this._buffering = false;
    this._retransmitTimer = null;
    this._handshakeRtt = null;   // ölçülen uçuş gidiş-dönüş süresi (ms)
    this.pendingAcks = [];

    // --- eklentiler
    this.srtp = null;            // { read, write, profile }
    this.reliable = null;
    this._handshakeTimer = null;
  }

  // ==========================================================================
  // Yaşam döngüsü
  // ==========================================================================
  startHandshakeTimer() {
    if (!this.options.handshakeTimeout) return;
    this._handshakeTimer = setTimeout(() => {
      if (!this.handshakeComplete) {
        this.destroy(new Error(`handshake zaman aşımı (${this.options.handshakeTimeout}ms)`));
      }
    }, this.options.handshakeTimeout);
    if (this._handshakeTimer.unref) this._handshakeTimer.unref();
  }

  _clearHandshakeTimer() {
    if (this._handshakeTimer) { clearTimeout(this._handshakeTimer); this._handshakeTimer = null; }
  }

  /** İstemci tarafı başlangıcı. */
  start() {
    if (this.role !== 'client') throw new Error('start() yalnızca istemci içindir');
    this.startHandshakeTimer();
    return this.h_clientStart();
  }

  destroy(err) {
    if (this.closed) return;
    this.closed = true;
    this.state = 'CLOSED';
    this._cancelRetransmit();
    this._clearHandshakeTimer();
    if (this.reliable) this.reliable.close(err);
    // Dinleyicisi olmayan 'error' EventEmitter'da fırlatılır ve tüm süreci
    // düşürür. Bozuk paket gönderen bir peer host uygulamayı çökertemez;
    // hata her hâlükârda 'close' argümanı olarak da taşınır.
    if (err && this.listenerCount('error') > 0) this.emit('error', err);
    this.emit('close', err || null);
  }

  /** Düzgün kapanış — close_notify gönderir. */
  async close() {
    if (this.closed) return;
    try {
      if (this.sendEpoch > 0) {
        await this.sendAlert(ALERT_LEVEL.WARNING, ALERT_DESC.CLOSE_NOTIFY, 'close()');
      }
    } catch { /* soket zaten kapanmış olabilir */ }
    this.destroy(null);
  }

  // ==========================================================================
  // Gelen datagram
  // ==========================================================================
  handleDatagram(datagram, rinfo) {
    if (this.closed || datagram.length === 0) return;
    this.lastActivity = Date.now();
    if (this.role === 'server' && !this.peer && rinfo) {
      this.peer = { address: rinfo.address, port: rinfo.port };
    }

    // SRTP modunda aynı soketten medya da akar (RFC 7983 demux).
    if (this.srtp && this.options.srtp.demux) {
      const kind = demuxPacket(datagram);
      if (kind === 'rtp')  return this._onMedia(datagram, false);
      if (kind === 'rtcp') return this._onMedia(datagram, true);
      if (kind !== 'dtls') return; // STUN/TURN üst katmanın işi
    }

    // Kayıt işleme KESİN SIRALIDIR: bir datagramdaki ilk kayıt (ör. ServerHello)
    // anahtar kurar, sonraki kayıtlar (EncryptedExtensions, Certificate, ...) o
    // anahtarla çözülür. İşleyiciler async olduğu için hepsini tek bir zincire
    // dizmezsek aynı datagramın kalanı çözülemeden düşerdi — her handshake'e
    // gereksiz bir yeniden gönderim turu eklenirdi.
    this._chain = this._chain
      .then(() => this._readRecords(datagram))
      .catch((e) => {
        // Tek bozuk datagram oturumu düşürmemeli — DoS vektörü olur.
        this._log('warn', 'datagram işlenemedi', { err: e.message });
      });
  }

  async _readRecords(datagram) {
    let offset = 0;
    while (offset < datagram.length && !this.closed) {
      const first = datagram[offset];

      if ((first & 0b11100000) === 0b00100000) {
        // DTLS 1.3 korumalı kayıt (unified header)
        const consumed = await this._readProtected13(datagram, offset);
        if (consumed <= 0) return;
        offset += consumed;
        continue;
      }

      if (first < CONTENT_TYPE.CHANGE_CIPHER_SPEC || first > CONTENT_TYPE.ACK) {
        this._log('debug', 'tanınmayan kayıt baytı, datagram bırakıldı', { byte: first });
        return;
      }

      const rec = decodePlaintext(datagram, offset);
      offset += rec.bytesConsumed;

      if (rec.epoch > 0) await this._readProtected12(rec);
      else await this._onPlaintextRecord(rec);
    }
  }

  async _readProtected13(datagram, offset) {
    const epochLow = datagram[offset] & 0b11;
    const keys = this._readKeys13(epochLow);
    if (!keys) return -1;

    const epoch = this._epochForLow(epochLow);
    const lastSeq = this.recvLastSeq.get(epoch) ?? -1;

    let rec;
    try {
      rec = unprotectRecord({
        record: datagram, offset,
        readKey: keys.key, readIv: keys.iv, snKey: keys.sn,
        aeadAlg: this.suite.aead, snCipher: this.suite.sn_cipher, tagLen: this.suite.tagLen,
        lastSeq: Math.max(0, lastSeq), epoch,
        cidLength: 0,
      });
    } catch (e) {
      this._log('warn', 'kayıt çözülemedi', { epoch, err: e.message });
      return -1;
    }
    if (!rec) return -1;

    const win = this.recvReplay.get(epoch);
    if (win && !win.accept(rec.fullSeq)) {
      this._log('debug', 'replay reddedildi', { epoch, seq: rec.fullSeq });
      return rec.bytesConsumed;
    }
    if (rec.fullSeq > (this.recvLastSeq.get(epoch) ?? -1)) this.recvLastSeq.set(epoch, rec.fullSeq);

    // ACK yalnızca handshake kayıtları için tutulur (RFC 9147 §7). Uygulama
    // verisini de biriktirmek uzun ömürlü oturumlarda sınırsız bellek büyümesi
    // demek olurdu.
    if (rec.contentType === CONTENT_TYPE.HANDSHAKE && this.pendingAcks.length < 64) {
      this.pendingAcks.push({ epoch, seq: rec.fullSeq });
    }

    await this._dispatchContent(rec.contentType, rec.content);
    return rec.bytesConsumed;
  }

  async _readProtected12(rec) {
    if (!this.keys12) { this._log('debug', 'şifreli 1.2 kaydı geldi ama anahtar yok'); return; }
    const dir = this.role === 'client' ? 'server' : 'client';
    const k = this.keys12[dir];

    const win = this.recvReplay.get(rec.epoch);
    if (win && !win.check(rec.sequenceNumber)) {
      this._log('debug', 'replay reddedildi (1.2)', { seq: rec.sequenceNumber });
      return;
    }

    let out;
    try {
      out = unprotectRecord12({
        record: rec, suite: this.suite, key: k.key, salt: k.salt, version: VERSION.DTLS_1_2,
      });
    } catch (e) {
      this._log('warn', '1.2 kaydı çözülemedi', { seq: rec.sequenceNumber, err: e.message });
      return;
    }
    if (win) win.mark(rec.sequenceNumber);
    await this._dispatchContent(out.contentType, out.content);
  }

  _onPlaintextRecord(rec) {
    switch (rec.type) {
      case CONTENT_TYPE.HANDSHAKE: return this._onHandshakeBytes(rec.fragment);
      case CONTENT_TYPE.ALERT: return this._onAlert(rec.fragment);
      case CONTENT_TYPE.ACK: return this._onAck(rec.fragment);
      case CONTENT_TYPE.CHANGE_CIPHER_SPEC: return this._onChangeCipherSpec();
      default:
        this._log('debug', 'beklenmedik plaintext kayıt', { type: rec.typeName });
    }
  }

  _dispatchContent(contentType, content) {
    switch (contentType) {
      case CONTENT_TYPE.HANDSHAKE: return this._onHandshakeBytes(content);
      case CONTENT_TYPE.APPLICATION_DATA: return this._onApplicationData(content);
      case CONTENT_TYPE.ALERT: return this._onAlert(content);
      case CONTENT_TYPE.ACK: return this._onAck(content);
      case CONTENT_TYPE.CHANGE_CIPHER_SPEC: return this._onChangeCipherSpec();
      default:
        this._log('debug', 'bilinmeyen içerik tipi', { contentType });
    }
  }

  _onApplicationData(buf) {
    if (this.reliable) this.reliable.onData(buf);
    else this.emit('data', buf);
  }

  async _onHandshakeBytes(buf) {
    let o = 0;
    while (o + HS_HEADER_LEN <= buf.length) {
      let hs;
      try { hs = decodeHandshake(buf, o); }
      catch (e) { this._log('warn', 'handshake çözümlenemedi', { err: e.message }); return; }
      o += hs.bytesConsumed;

      const r = this.rxReassembler.add({
        msgType: hs.msgType, length: hs.length, messageSeq: hs.messageSeq,
        fragmentOffset: hs.fragmentOffset, fragmentLength: hs.fragmentLength, body: hs.body,
      });
      if (!r.complete) continue;

      // Zaten işlenmiş bir message_seq → karşı taraf uçuşumuzu almamış demektir.
      if (r.messageSeq < this._nextRxSeq) { this._onDuplicateFlight(); continue; }
      // İleri seq'li mesajlar sıraları gelene kadar bekletilir (RFC 9147 §5.2).
      if (!this._pendingMsgs.has(r.messageSeq)) {
        const wire = rebuildSingleFragmentWire(r.msgType, r.messageSeq, r.body);
        this._pendingMsgs.set(r.messageSeq,
          { msgType: r.msgType, body: r.body, messageSeq: r.messageSeq, wire });
      }
    }
    await this._drainHandshakeMessages();
  }

  async _drainHandshakeMessages() {
    while (this._pendingMsgs.has(this._nextRxSeq) && !this.closed) {
      const m = this._pendingMsgs.get(this._nextRxSeq);
      this._pendingMsgs.delete(this._nextRxSeq);
      this._nextRxSeq++;
      await this._runHandshake(m);
    }
  }

  /** Yinelenen uçuş — son uçuşumuzu tekrar gönder, ama amplifikasyona izin verme. */
  _onDuplicateFlight() {
    const now = Date.now();
    if (now - this._lastDupRetransmit < 200) return;
    this._lastDupRetransmit = now;
    this.retransmitNow().catch(() => {});
  }

  async _runHandshake(m) {
    if (this.closed) return;
    this._log('debug', `<< ${NAMES.HS_TYPE[m.msgType] || m.msgType}`,
              { seq: m.messageSeq, len: m.body.length });
    try {
      await (this.version === null ? this._negotiateVersion(m) : this._handleHandshake(m));
    } catch (e) {
      this._fatal(e);
    }
  }

  _handleHandshake(m) {
    return this.version === VERSION.DTLS_1_3 ? this.h13_handle(m) : this.h12_handle(m);
  }

  _fatal(err) {
    this._log('error', 'handshake hatası', { err: err.message });
    const desc = err.alertDescription ?? ALERT_DESC.INTERNAL_ERROR;
    Promise.resolve(this.sendAlert(ALERT_LEVEL.FATAL, desc, err.message)).catch(() => {});
    this.destroy(err);
  }

  _onAlert(body) {
    if (body.length < 2) return;
    const level = body[0];
    const desc = body[1];
    const descName = NAMES.ALERT_DESC[desc] || `UNKNOWN(${desc})`;
    this.emit('alert', { level, description: desc, descriptionName: descName });

    if (desc === ALERT_DESC.CLOSE_NOTIFY) {
      this._log('info', 'peer close_notify gönderdi');
      return this.destroy(null);
    }
    if (level === ALERT_LEVEL.FATAL) {
      const e = new Error(`peer fatal alert: ${descName}`);
      e.alertDescription = desc;
      return this.destroy(e);
    }
    this._log('warn', 'uyarı alarmı', { desc: descName });
  }

  _onAck(body) {
    try { parseAck(body); } catch { return; }
    // ACK gelen uçuşun ulaştığını kanıtlar.
    this._cancelRetransmit();
  }

  _onChangeCipherSpec() {
    if (this.version === VERSION.DTLS_1_2) return this.h12_onChangeCipherSpec();
    // DTLS 1.3'te CCS yalnızca middlebox uyumluluğu içindir; yoksayılır.
  }

  // ==========================================================================
  // Anahtar seçimi
  // ==========================================================================
  _readKeys13(epochLow) {
    const other = this.role === 'client' ? 'server' : 'client';
    if (epochLow === (EPOCH.HANDSHAKE & 0b11) && this.handshakeKeys && this.recvEpoch <= 2) {
      return this.handshakeKeys[other + 'Handshake'];
    }
    if (this.appKeys && this.recvEpoch >= 3 && epochLow === (this.recvEpoch & 0b11)) {
      return this.appKeys[other + 'Application'];
    }
    // Handshake epoch'u hâlâ geçerli olabilir (peer geç kalmış kayıt gönderdi).
    if (epochLow === 2 && this.handshakeKeys) return this.handshakeKeys[other + 'Handshake'];
    return null;
  }

  _epochForLow(epochLow) {
    if (this.recvEpoch >= 3 && epochLow === (this.recvEpoch & 0b11)) return this.recvEpoch;
    return epochLow;
  }

  _writeKeys13() {
    const r = this.role;
    if (this.sendEpoch === 2 && this.handshakeKeys) return this.handshakeKeys[r + 'Handshake'];
    if (this.sendEpoch >= 3 && this.appKeys) return this.appKeys[r + 'Application'];
    return null;
  }

  // ==========================================================================
  // Gönderme
  // ==========================================================================
  _nextSeq(epoch) {
    const s = this.sendSeq.get(epoch) ?? 0;
    this.sendSeq.set(epoch, s + 1);
    return s;
  }

  _sendRaw(buf) {
    return this.transport.send(buf, this.peer);
  }

  /** Uçuşa yaz ya da doğrudan gönder. */
  _emitRecord(rec) {
    if (this._buffering) { this._flight.records.push(rec); return; }
    return this._sendRaw(rec);
  }

  sendPlaintextRecord(contentType, fragment) {
    const rec = encodePlaintext({
      type: contentType, epoch: 0, sequenceNumber: this._nextSeq(0), fragment,
    });
    return this._emitRecord(rec);
  }

  /** Sürüme göre korumalı kayıt üretir. */
  sendProtectedRecord(contentType, content) {
    if (this.version === VERSION.DTLS_1_2) {
      if (!this.keys12) throw new Error('1.2 yazma anahtarı yok');
      const k = this.keys12[this.role];
      const rec = protectRecord12({
        contentType, content, epoch: this.sendEpoch, recordSeq: this._nextSeq(this.sendEpoch),
        suite: this.suite, key: k.key, salt: k.salt, version: VERSION.DTLS_1_2,
      });
      return this._emitRecord(rec);
    }

    const keys = this._writeKeys13();
    if (!keys) throw new Error('yazma anahtarı yok');
    const rec = protectRecord({
      contentType, content,
      recordSeq: this._nextSeq(this.sendEpoch), epoch: this.sendEpoch,
      writeKey: keys.key, writeIv: keys.iv, snKey: keys.sn,
      aeadAlg: this.suite.aead, snCipher: this.suite.sn_cipher, tagLen: this.suite.tagLen,
    });
    return this._emitRecord(rec);
  }

  /**
   * Handshake mesajını transcript'e ekler ve (gerekiyorsa parçalayarak) gönderir.
   */
  async sendHandshakeMessage(msgType, body, { encrypted = false, transcript = true } = {}) {
    const messageSeq = this.messageSeq++;
    const fullWire = rebuildSingleFragmentWire(msgType, messageSeq, body);
    if (transcript) this._appendTranscript(fullWire);
    this._log('debug', `>> ${NAMES.HS_TYPE[msgType] || msgType}`, { seq: messageSeq, len: body.length });

    const budget = this.options.mtu - RECORD_OVERHEAD - HS_HEADER_LEN;
    if (body.length <= budget) {
      const send = encrypted
        ? this.sendProtectedRecord(CONTENT_TYPE.HANDSHAKE, fullWire)
        : this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, fullWire);
      await send;
      return fullWire;
    }

    for (let off = 0; off < body.length; off += budget) {
      const take = Math.min(budget, body.length - off);
      const wire = buildFragmentWire(msgType, messageSeq, body, off, take);
      const send = encrypted
        ? this.sendProtectedRecord(CONTENT_TYPE.HANDSHAKE, wire)
        : this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, wire);
      await send;
    }
    return fullWire;
  }

  _appendTranscript(wire) {
    if (!this.transcript) return;
    if (this.version === VERSION.DTLS_1_2) this.transcript.append(wire);
    else this.transcript.appendDtls(wire);
  }

  async sendAlert(level, description, reason) {
    if (this.closed && level === ALERT_LEVEL.FATAL) return;
    this._log(level === ALERT_LEVEL.FATAL ? 'error' : 'warn', 'alarm gönderiliyor',
              { desc: NAMES.ALERT_DESC[description] || description, reason });
    const body = Buffer.from([level, description]);
    const wasBuffering = this._buffering;
    this._buffering = false;
    try {
      if (this.sendEpoch > 0 && (this.handshakeKeys || this.appKeys || this.keys12)) {
        await this.sendProtectedRecord(CONTENT_TYPE.ALERT, body);
      } else {
        await this.sendPlaintextRecord(CONTENT_TYPE.ALERT, body);
      }
    } finally {
      this._buffering = wasBuffering;
    }
  }

  async flushAcks() {
    if (this.version !== VERSION.DTLS_1_3) { this.pendingAcks.length = 0; return; }
    if (this.pendingAcks.length === 0 || this.sendEpoch < 2) return;
    const body = buildAck(this.pendingAcks);
    this.pendingAcks = [];
    await this.sendProtectedRecord(CONTENT_TYPE.ACK, body);
  }

  // ==========================================================================
  // Uygulama verisi
  // ==========================================================================
  /**
   * Veri gönderir. `reliable` açıksa kayıp toleranslı kanal üzerinden,
   * değilse doğrudan tek DTLS kaydı olarak.
   */
  send(data, opts) {
    if (!this.handshakeComplete) return Promise.reject(new Error('handshake tamamlanmadı'));
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (this.reliable) {
      if (opts && opts.reliable === false) return Promise.resolve(this.reliable.sendUnreliable(buf));
      return this.reliable.sendMessage(buf, opts);
    }
    return Promise.resolve(this.sendProtectedRecord(CONTENT_TYPE.APPLICATION_DATA, buf));
  }

  // Geriye dönük ad
  sendApplicationData(data) { return this.send(data); }

  // ==========================================================================
  // Uçuş yönetimi ve yeniden gönderim (RFC 9147 §5.8, RFC 6347 §4.2.4)
  // ==========================================================================
  beginFlight() {
    this._cancelRetransmit();
    this._flight = { records: [], datagrams: [], attempts: 0, sentAt: 0 };
    this._buffering = true;
  }

  /** Uçuşu MTU'ya göre datagramlara paketleyip gönderir ve zamanlayıcıyı kurar. */
  async endFlight({ arm = true } = {}) {
    this._buffering = false;
    const f = this._flight;
    if (!f || f.records.length === 0) return;

    const max = this.options.mtu;
    let cur = [];
    let curLen = 0;
    for (const rec of f.records) {
      if (curLen > 0 && curLen + rec.length > max) {
        f.datagrams.push(Buffer.concat(cur, curLen));
        cur = []; curLen = 0;
      }
      cur.push(rec); curLen += rec.length;
    }
    if (curLen > 0) f.datagrams.push(Buffer.concat(cur, curLen));
    f.records = [];

    f.sentAt = Date.now();
    for (const dg of f.datagrams) {
      try { await this._sendRaw(dg); }
      catch (e) { this._log('warn', 'uçuş gönderilemedi', { err: e.message }); }
    }
    if (arm) this._armRetransmit();
  }

  /**
   * Yeniden gönderim zamanlayıcısı — RFC 9147 §5.8.2.
   *
   * Sabit 400 ms yerine ÖLÇÜLEN gidiş-dönüş süresini temel alırız: bir handshake
   * uçuşu cevaplandığında RTT örneği alınır ve sonraki bekleme buna göre kurulur.
   * Aynı makinedeki (~1 ms) iki uç, kayıp bir datagramı 400 ms değil ~50 ms'de
   * kurtarır; uydu bağlantısında ise taban değer gereğinden erken tetiklenmez.
   * Katlanarak artış (RFC'nin şartı) korunur.
   */
  _armRetransmit() {
    const f = this._flight;
    if (!f || f.datagrams.length === 0 || this.closed) return;
    const base = this._handshakeRtt === null
      ? BASE_RETRANSMIT_MS
      : Math.min(BASE_RETRANSMIT_MS, Math.max(MIN_RETRANSMIT_MS, Math.round(this._handshakeRtt * 3)));
    const delay = Math.min(base * (1 << f.attempts), MAX_RETRANSMIT_MS);
    this._retransmitTimer = setTimeout(() => this._doRetransmit(), delay);
    if (this._retransmitTimer.unref) this._retransmitTimer.unref();
  }

  /** Uçuş cevaplandı — RTT örneğini güncelle (yeniden gönderilmemiş uçuşlarda). */
  _sampleHandshakeRtt() {
    const f = this._flight;
    if (!f || f.sentAt === 0 || f.attempts > 0) return;   // Karn: belirsiz örnek alma
    const sample = Date.now() - f.sentAt;
    if (sample < 0 || sample > 60_000) return;
    this._handshakeRtt = this._handshakeRtt === null
      ? sample
      : 0.875 * this._handshakeRtt + 0.125 * sample;
  }

  async _doRetransmit() {
    this._retransmitTimer = null;
    const f = this._flight;
    if (!f || this.closed) return;
    if (f.attempts >= MAX_RETRANSMITS) {
      return this.destroy(new Error(`uçuş ${MAX_RETRANSMITS} denemede teslim edilemedi`));
    }
    f.attempts++;
    this._log('debug', 'uçuş yeniden gönderiliyor', { attempt: f.attempts });
    for (const dg of f.datagrams) {
      try { await this._sendRaw(dg); } catch { /* geçici ağ hatası */ }
    }
    this._armRetransmit();
  }

  /** Karşı taraftan beklenen cevap geldi — yeniden gönderimi durdur. */
  _cancelRetransmit() {
    this._sampleHandshakeRtt();
    if (this._retransmitTimer) { clearTimeout(this._retransmitTimer); this._retransmitTimer = null; }
    this._flight = null;
    this._buffering = false;
  }

  /** Son uçuşu ANINDA tekrar gönder (yinelenen peer mesajı geldiğinde). */
  async retransmitNow() {
    const f = this._flight;
    if (!f || f.datagrams.length === 0) return;
    for (const dg of f.datagrams) {
      try { await this._sendRaw(dg); } catch { /* yoksay */ }
    }
  }

  // ==========================================================================
  // Handshake tamamlandı
  // ==========================================================================
  _finishHandshake() {
    this.handshakeComplete = true;
    this.state = 'ESTABLISHED';
    this._clearHandshakeTimer();
    this._setupSrtp();
    this._setupReliable();
    this.emit('connect');
    this.emit('handshake'); // geriye dönük ad
  }

  // ==========================================================================
  // SRTP
  // ==========================================================================
  _exportContext() {
    if (this.version === VERSION.DTLS_1_3) {
      return { version13: true, hash: this.suite.hash, exporterSecret: this.appKeys.exporterSecret };
    }
    return {
      version13: false, hash: this.suite.hash, masterSecret: this.masterSecret,
      clientRandom: this.clientRandom, serverRandom: this.serverRandom,
    };
  }

  /**
   * RFC 5705 / RFC 8446 §7.5 anahtar dışa aktarımı — uygulama katmanına açık.
   */
  exportKeyingMaterial(label, context, length) {
    if (!this.handshakeComplete) throw new Error('handshake tamamlanmadı');
    return exportKeyingMaterial(this._exportContext(), label, context ?? null, length);
  }

  _setupSrtp() {
    if (!this.negotiatedSrtpProfile) return;
    try {
      const km = exportSrtpKeyingMaterial(this._exportContext(), this.negotiatedSrtpProfile);
      const pair = createSrtpPair(km, this.role);
      this.srtp = { ...pair, profile: this.negotiatedSrtpProfile, name: pair.read.name };
      this._log('info', 'SRTP hazır', { profile: pair.read.name });
      this.emit('srtp', { profile: this.negotiatedSrtpProfile, name: pair.read.name });
    } catch (e) {
      this._log('error', 'SRTP anahtarları türetilemedi', { err: e.message });
      this.emit('error', e);
    }
  }

  _onMedia(pkt, isRtcp) {
    if (!this.srtp) return;
    try {
      const plain = isRtcp ? this.srtp.read.unprotectRtcp(pkt) : this.srtp.read.unprotectRtp(pkt);
      this.emit(isRtcp ? 'rtcp' : 'media', plain);
    } catch (e) {
      // Bozuk/yeniden oynatılmış medya paketi sessizce düşer — normal çalışma koşulu.
      this._log('debug', 'SRTP paketi reddedildi', { err: e.message });
    }
  }

  /** Ham RTP paketini SRTP ile koruyup gönderir. */
  sendMedia(rtpPacket) {
    if (!this.srtp) throw new Error('SRTP müzakere edilmedi');
    return this._sendRaw(this.srtp.write.protectRtp(rtpPacket));
  }

  /** Ham RTCP paketini SRTCP ile koruyup gönderir. */
  sendRtcp(rtcpPacket) {
    if (!this.srtp) throw new Error('SRTP müzakere edilmedi');
    return this._sendRaw(this.srtp.write.protectRtcp(rtcpPacket));
  }

  // ==========================================================================
  // Güvenilir kanal
  // ==========================================================================
  _setupReliable() {
    const cfg = this.options.reliable;
    if (!cfg) return;
    this.reliable = new ReliableChannel({
      ...cfg,
      send: (buf) => this.sendProtectedRecord(CONTENT_TYPE.APPLICATION_DATA, buf),
    });
    this.reliable.on('message', (data, meta) => this.emit('data', data, meta));
    this.reliable.on('unreliable', (data) => this.emit('data', data, { reliable: false }));
    this.reliable.on('error', (e) => this.emit('error', e));
    this.reliable.on('gap', (info) => this.emit('gap', info));
  }

  // ==========================================================================
  // Yardımcılar
  // ==========================================================================
  _log(level, msg, meta) {
    // Dinleyici yoksa meta nesnesini bile kurmayalım — hot path.
    if (this.listenerCount('log') === 0) return;
    this.emit('log', level, msg, meta);
  }

  getPeerCertificate() { return this.peerCertificate; }

  // --- node:net/tls'e benzeyen genel yüzey
  get remoteAddress() { return this.peer ? this.peer.address : null; }
  get remotePort()    { return this.peer ? this.peer.port : null; }
  get localPort()     { return this.transport.address ? this.transport.address().port : null; }
  get protocol() {
    return this.version === VERSION.DTLS_1_3 ? 'DTLSv1.3'
         : this.version === VERSION.DTLS_1_2 ? 'DTLSv1.2' : null;
  }
  get cipher() { return this.suite ? this.suite.name : null; }
  get srtpProfile() { return this.srtp ? this.srtp.name : null; }

  write(data, opts) { return this.send(data, opts); }
  end() { return this.close(); }

  /** node:tls'in socket bilgilerine benzeyen özet. */
  getInfo() {
    return {
      protocol: this.version === VERSION.DTLS_1_3 ? 'DTLSv1.3'
              : this.version === VERSION.DTLS_1_2 ? 'DTLSv1.2' : null,
      cipher: this.suite ? this.suite.name : null,
      servername: this.servername,
      alpnProtocol: this.alpnProtocol,
      authorized: this.authorized,
      authorizationError: this.authorizationError,
      srtpProfile: this.srtp ? this.srtp.name : null,
      reliable: !!this.reliable,
      peer: this.peer,
    };
  }
}

// ===== ortak yardımcı fonksiyonlar =====
function rebuildSingleFragmentWire(msgType, messageSeq, body) {
  const out = Buffer.allocUnsafe(HS_HEADER_LEN + body.length);
  const len = body.length;
  out[0] = msgType;
  out[1] = (len >> 16) & 0xff; out[2] = (len >> 8) & 0xff; out[3] = len & 0xff;
  out.writeUInt16BE(messageSeq, 4);
  out[6] = 0; out[7] = 0; out[8] = 0;                          // fragment_offset = 0
  out[9] = (len >> 16) & 0xff; out[10] = (len >> 8) & 0xff; out[11] = len & 0xff;
  body.copy(out, HS_HEADER_LEN);
  return out;
}

function buildFragmentWire(msgType, messageSeq, body, offset, length) {
  const out = Buffer.allocUnsafe(HS_HEADER_LEN + length);
  const total = body.length;
  out[0] = msgType;
  out[1] = (total >> 16) & 0xff; out[2] = (total >> 8) & 0xff; out[3] = total & 0xff;
  out.writeUInt16BE(messageSeq, 4);
  out[6] = (offset >> 16) & 0xff; out[7] = (offset >> 8) & 0xff; out[8] = offset & 0xff;
  out[9] = (length >> 16) & 0xff; out[10] = (length >> 8) & 0xff; out[11] = length & 0xff;
  body.copy(out, HS_HEADER_LEN, offset, offset + length);
  return out;
}

// Sürüme özgü handshake mantığı — `this` üzerinde çalışan mixin'ler.
Object.assign(Session.prototype, require('./handshake.js'));
Object.assign(Session.prototype, require('./negotiate.js'));

module.exports = { Session, rebuildSingleFragmentWire, buildFragmentWire, RECORD_OVERHEAD };
