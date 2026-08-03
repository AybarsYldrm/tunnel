'use strict';
// Güvenilir / sırasız veri kanalı — DTLS application_data üzerine oturan,
// QUIC (RFC 9002) kayıp kurtarma modelini izleyen bir çerçeveleme katmanı.
//
// TASARIM NOTU: bu katman DTLS'in kendi yapısına HİÇ dokunmaz. Kayıt katmanı,
// epoch'lar, replay penceresi ve handshake aynen kalır; her şey
// application_data'nın İÇİNDEDİR. `reliable` kapalıyken tek bayt bile
// eklenmez — kanal hiç kurulmaz.
//
// Sağladıkları:
//   • RFC 9002 kayıp tespiti (paket eşiği + zaman eşiği) ve PTO sondaları
//   • Takılabilir tıkanıklık denetimi — BBRv3 (varsayılan) ya da NewReno,
//     BBR ile birlikte paketleri zamana yayan hız şekillendirme (pacing)
//   • SIRASIZ teslim (varsayılan) — tamamlanan mesaj anında yukarı çıkar,
//     öndeki kayıp arkadakini BEKLETMEZ (head-of-line blocking yok)
//   • Sıralı teslim (`ordered:true`) — akış (streamId) başına sıra korunur
//   • MTU'ya göre parçalama ve yeniden birleştirme
//   • Güvenilirlik istemeyen veri için sıfır maliyetli RAW çerçevesi
//
// QUIC'ten devralınan kural: yeniden gönderilen veri YENİ PAKET NUMARASI alır.
// Paket numarası "hangi gönderim" sorusunu, (streamId, msgId, idx) üçlüsü ise
// "hangi veri" sorusunu yanıtlar. Bu ayrım sayesinde RTT örnekleri belirsiz
// olmaz ve alıcı yinelenen veriyi paket numarasından bağımsız eleyebilir.
//
// Çerçeve biçimleri (ilk bayt = tip; pn/aralıklar 48 bit — DTLS ile aynı):
//   RAW  0x00 | payload
//   DATA 0x01 | flags(1) | pn(6) | streamId(2) | msgId(4) | idx(2) | count(2) | payload
//   ACK  0x02 | ackDelayMs(2) | rangeCount(1) | [start(6) end(6)]*
//   PING 0x03 | pn(6) | token(4)
//   PONG 0x04 | token(4)

const { EventEmitter } = require('node:events');
const { LossRecovery, DEFAULT_CONGESTION_CONTROL } = require('./recovery.js');

const FRAME = Object.freeze({ RAW: 0x00, DATA: 0x01, ACK: 0x02, PING: 0x03, PONG: 0x04 });
const DATA_HEADER_LEN = 18;
const PING_LEN = 11;
const ACK_HEADER_LEN = 4;
const ACK_RANGE_LEN = 12;
const FLAG_ORDERED = 0x01;

const DEFAULTS = Object.freeze({
  mtu: 1100,               // DTLS kayıt ek yükü düşülmüş güvenli yük boyutu
  ordered: false,          // varsayılan SIRASIZ (QUIC datagram tarzı)
  initialRtt: 333,         // ms — RFC 9002 §6.2.2
  minPto: 5,               // ms
  maxPto: 8_000,           // ms
  maxAckDelay: 25,         // ms — karşı tarafa bildirdiğimiz azami ACK gecikmesi
  ackDelay: 10,            // ms — ACK'leri toplu göndermek için gecikme
  maxRetransmits: 12,      // parça başına vazgeçme sınırı
  maxTrackedPackets: 4096, // bellek tavanı (tıkanıklık penceresinin üstünde sert sınır)
  maxReassembly: 256,      // eşzamanlı yeniden birleştirilen mesaj sayısı
  maxOrderedBuffer: 128,   // sıralı modda bekletilecek mesaj sayısı
  maxDedupeEntries: 8192,  // teslim edilmiş mesaj kimlikleri (yineleme eleme)
  maxAckRanges: 32,
  /** 'bbr3' | 'newreno' — gerekçeler reliable/congestion.js başında. */
  congestionControl: DEFAULT_CONGESTION_CONTROL,
  /** Hız şekillendirme; verilmezse denetleyici karar verir (BBR: açık). */
  pacing: undefined,
  /** BBR ince ayarları (congestion.js BBR_DEFAULTS). */
  bbr: undefined,
});

/** Hız şekillendirici beklerken zamanlayıcının aşmayacağı süre. */
const MAX_PACING_TIMER_MS = 250;

// Alıcı, iki ACK bekleyen paketten sonra ACK'i geciktirmeden gönderir
// (RFC 9000 §13.2.1) — kurtarma turunu kısaltan en ucuz iyileştirme.
const ACK_ELICITING_THRESHOLD = 2;

let nextChannelId = 1;

class ReliableChannel extends EventEmitter {
  /**
   * @param {object} o
   * @param {(buf:Buffer)=>Promise|void} o.send  şifreli application_data gönderici
   */
  constructor(o) {
    super();
    if (typeof o.send !== 'function') throw new TypeError('ReliableChannel: send() zorunlu');
    this.send = o.send;

    // DİKKAT: nesne yayılımı (`{...DEFAULTS, ...o}`) o'daki açık `undefined`
    // değerlerin varsayılanları EZMESİNE yol açar.
    this.opts = { ...DEFAULTS };
    for (const [k, v] of Object.entries(o)) if (v !== undefined) this.opts[k] = v;
    this.defaultOrdered = this.opts.ordered === true;
    this.closed = false;
    this.id = nextChannelId++;

    this.recovery = new LossRecovery({
      maxDatagramSize: this.opts.mtu,
      maxAckDelay: this.opts.maxAckDelay,
      initialRtt: this.opts.initialRtt,
      minPto: this.opts.minPto,
      maxPto: this.opts.maxPto,
      congestionControl: this.opts.congestionControl,
      pacing: this.opts.pacing,
      bbr: this.opts.bbr,
    });

    // --- gönderici durumu
    this.nextPn = 1;
    this.nextMsgId = new Map();      // streamId -> sonraki mesaj numarası
    this.chunks = new Map();         // chunkKey -> parça kaydı
    this.messages = new Map();       // msgKey  -> { pending, resolve, reject, settled, bytes }
    this.sendQueue = [];             // gönderilmeyi bekleyen chunkKey'ler
    this.queued = new Set();         // sendQueue üyelik indeksi (O(1) sorgu)
    this.timer = null;
    this.timerAt = 0;
    this.pacingTimer = null;

    // --- alıcı durumu
    this.ackRanges = [];             // [[start,end], ...] artan, birleştirilmiş
    this.ackTimer = null;
    this.ackElicitingSinceAck = 0;
    this.largestReceived = -1;
    this.largestReceivedAt = 0;
    this.reassembly = new Map();     // "stream:msg" -> parça toplayıcı
    this.orderedState = new Map();   // streamId -> { next, buffer }
    this.delivered = new Set();      // "stream:msg" -> teslim edildi (yineleme eleme)

    this.stats = {
      sent: 0, resent: 0, acked: 0, received: 0, duplicates: 0,
      bytesSent: 0, bytesReceived: 0, giveUps: 0, probes: 0, lost: 0,
    };
  }

  get inFlight() { return this.recovery.sent.size; }
  get rttMs() { return this.recovery.hasRttSample ? Math.round(this.recovery.smoothedRtt) : null; }
  get congestionWindow() { return this.recovery.congestionWindow; }
  /** Hedef gönderim hızı (bayt/s) — şekillendirme kapalıysa null. */
  get pacingRate() { return this.recovery.pacingRate; }
  /** Yürürlükteki tıkanıklık denetleyicisinin adı. */
  get congestionControl() { return this.recovery.congestionControl; }

  /** Ayrıntılı kurtarma/tıkanıklık durumu — teşhis ve ölçüm için. */
  getStats() {
    return { ...this.stats, ...this.recovery.snapshot(), queued: this.sendQueue.length };
  }

  // ==========================================================================
  // Gönderme
  // ==========================================================================
  /**
   * Güvenilir mesaj gönderir. Tüm parçalar ACK'lenince çözülen Promise döner.
   * @param {Buffer} data
   * @param {{ordered?:boolean, streamId?:number}} [opt]
   */
  sendMessage(data, opt = {}) {
    if (this.closed) return Promise.reject(new Error('kanal kapalı'));
    const ordered = opt.ordered ?? this.defaultOrdered;
    const streamId = (opt.streamId ?? 0) & 0xffff;

    // Mesaj numarası AKIŞ BAŞINA artar: sıralı teslim akış içinde işler,
    // farklı akışlar birbirini bekletmez.
    const msgId = this.nextMsgId.get(streamId) ?? 1;
    this.nextMsgId.set(streamId, (msgId + 1) >>> 0);

    const payloadMax = this.opts.mtu - DATA_HEADER_LEN;
    if (payloadMax <= 0) return Promise.reject(new Error('mtu çok küçük'));
    const count = Math.max(1, Math.ceil(data.length / payloadMax));
    if (count > 0xffff) return Promise.reject(new Error('mesaj çok büyük (65535 parça sınırı)'));

    const msgKey = `${streamId}:${msgId}`;
    const record = { pending: count, settled: false, resolve: null, reject: null, bytes: data.length };
    const promise = new Promise((res, rej) => { record.resolve = res; record.reject = rej; });
    this.messages.set(msgKey, record);

    for (let i = 0; i < count; i++) {
      const chunkKey = `${msgKey}:${i}`;
      this.chunks.set(chunkKey, {
        key: chunkKey, msgKey, streamId, msgId, idx: i, count, ordered,
        payload: data.subarray(i * payloadMax, Math.min((i + 1) * payloadMax, data.length)),
        attempts: 0,
      });
      this.sendQueue.push(chunkKey);
      this.queued.add(chunkKey);
    }

    this._pump();
    return promise;
  }

  /** Güvenilirlik istemeyen veri — kayıp olursa yeniden gönderilmez. */
  sendUnreliable(data) {
    if (this.closed) throw new Error('kanal kapalı');
    const frame = Buffer.allocUnsafe(1 + data.length);
    frame[0] = FRAME.RAW;
    data.copy(frame, 1);
    this.stats.bytesSent += frame.length;
    return this._write(frame);
  }

  /** RTT ölçümü / keepalive — ACK bekleyen bir paket olarak izlenir. */
  ping(token = (Math.random() * 0xffffffff) >>> 0) {
    if (this.closed) throw new Error('kanal kapalı');
    const pn = this.nextPn++;
    const frame = Buffer.allocUnsafe(PING_LEN);
    frame[0] = FRAME.PING;
    frame.writeUIntBE(pn, 1, 6);
    frame.writeUInt32BE(token >>> 0, 7);
    this.recovery.onPacketSent({ pn, bytes: frame.length, ackEliciting: true, meta: null });
    this.stats.sent++;
    this.stats.bytesSent += frame.length;
    const r = this._write(frame);
    this._rearmTimer();
    return r;
  }

  /**
   * Kuyruğu tıkanıklık penceresinin VE hız şekillendiricinin izin verdiği
   * ölçüde boşaltır.
   *
   * İki ayrı fren vardır ve karıştırılmamalıdır:
   *   • pencere dolu   → ACK beklenir; zamanlayıcı kurulmaz, ACK yeniden pompalar
   *   • hız sınırı     → zaman beklenir; kısa bir zamanlayıcı kurulur
   * İkincisini de "ACK'i bekle" diye ele almak, hattı gereksiz yere boş
   * bırakır: gönderecek veri var, pencere de müsait, yalnızca sıra gelmemiş.
   */
  _pump() {
    if (this.closed) return;
    const now = Date.now();

    while (this.sendQueue.length) {
      const key = this.sendQueue[0];
      const chunk = this.chunks.get(key);
      if (!chunk) { this._dequeue(); continue; }

      const size = DATA_HEADER_LEN + chunk.payload.length;
      if (!this.recovery.hasCongestionRoom(size)) break;
      if (this.recovery.sent.size >= this.opts.maxTrackedPackets) break;

      const wait = this.recovery.pacingDelay(size, now);
      if (wait > 0) { this._armPacingTimer(wait); break; }

      this._dequeue();
      this._transmit(chunk);
    }

    // Kuyruk boşaldı: bundan sonraki teslim hızı örnekleri AĞIN değil
    // uygulamanın hızını ölçer. İşaretlenmezse BBR, veri veremediğimiz için
    // boş kalan hattı yavaş bir hat sanar ve tahmini kalıcı olarak düşer.
    if (this.sendQueue.length === 0) this.recovery.markAppLimited();

    this._rearmTimer();
  }

  _armPacingTimer(ms) {
    if (this.pacingTimer || this.closed) return;
    const delay = Math.max(1, Math.min(Math.ceil(ms), MAX_PACING_TIMER_MS));
    this.pacingTimer = setTimeout(() => { this.pacingTimer = null; this._pump(); }, delay);
    if (this.pacingTimer.unref) this.pacingTimer.unref();
  }

  _dequeue() {
    const key = this.sendQueue.shift();
    this.queued.delete(key);
    return key;
  }

  _transmit(chunk) {
    const pn = this.nextPn++;
    const frame = Buffer.allocUnsafe(DATA_HEADER_LEN + chunk.payload.length);
    frame[0] = FRAME.DATA;
    frame[1] = chunk.ordered ? FLAG_ORDERED : 0;
    frame.writeUIntBE(pn, 2, 6);
    frame.writeUInt16BE(chunk.streamId, 8);
    frame.writeUInt32BE(chunk.msgId, 10);
    frame.writeUInt16BE(chunk.idx, 14);
    frame.writeUInt16BE(chunk.count, 16);
    chunk.payload.copy(frame, DATA_HEADER_LEN);

    if (chunk.attempts > 0) this.stats.resent++;
    chunk.attempts++;
    this.stats.sent++;
    this.stats.bytesSent += frame.length;

    this.recovery.onPacketSent({ pn, bytes: frame.length, ackEliciting: true, meta: chunk.key });
    this._write(frame);
  }

  _write(frame) {
    try {
      const r = this.send(frame);
      if (r && typeof r.catch === 'function') r.catch((e) => this._softError(e));
      return r;
    } catch (e) {
      this._softError(e);
      return undefined;
    }
  }

  _softError(e) {
    // Taşıma hatası kanalı düşürmez: DTLS oturumu kendi hata yolunu işletir.
    if (this.listenerCount('error') > 0) this.emit('error', e);
  }

  // ==========================================================================
  // Zamanlayıcı — RFC 9002 §6.2
  // ==========================================================================
  _rearmTimer() {
    if (this.closed) return;
    const at = this.recovery.getLossDetectionTime();
    if (at === null) { this._clearTimer(); return; }
    if (this.timer && this.timerAt === at) return;

    this._clearTimer();
    this.timerAt = at;
    const delay = Math.max(1, at - Date.now());
    this.timer = setTimeout(() => { this.timer = null; this._onTimeout(); }, delay);
    if (this.timer.unref) this.timer.unref();
  }

  _clearTimer() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    this.timerAt = 0;
  }

  _onTimeout() {
    if (this.closed) return;
    const now = Date.now();
    const { lost, probes } = this.recovery.onLossDetectionTimeout(now);

    if (lost.length) this._handleLost(lost);
    if (probes > 0) {
      this.stats.probes += probes;
      this._sendProbes(probes);
    }
    this._pump();
  }

  /**
   * PTO sondası: kayıp ilan etmeden, en eski teslim edilmemiş parçaları yeni
   * paket numaralarıyla tekrar gönderir. Amaç ACK üretmek ve kurtarmayı
   * yeniden başlatmaktır (§6.2.4).
   */
  _sendProbes(count) {
    // Öncelik: kuyrukta bekleyen yeni veri (zaten gönderilecekti).
    let sent = 0;
    while (sent < count && this.sendQueue.length) {
      const chunk = this.chunks.get(this._dequeue());
      if (!chunk) continue;
      this._transmit(chunk);
      sent++;
    }
    if (sent >= count) return;

    // Kalanı: uçuştaki en eski paketlerin verisini tekrarla.
    const oldest = [...this.recovery.sent.values()]
      .filter((e) => e.meta && this.chunks.has(e.meta))
      .sort((a, b) => a.sentTime - b.sentTime);

    const seen = new Set();
    for (const entry of oldest) {
      if (sent >= count) break;
      if (seen.has(entry.meta)) continue;
      seen.add(entry.meta);
      const chunk = this.chunks.get(entry.meta);
      if (!chunk) continue;
      if (this._giveUpIfExhausted(chunk)) continue;
      this._transmit(chunk);
      sent++;
    }
  }

  _handleLost(lost) {
    this.stats.lost += lost.length;
    // Kayıp paketlerin taşıdığı veriyi yeniden kuyruğa al — YENİ paket
    // numarasıyla gidecek. Kuyruğun BAŞINA konur: kurtarma yeni veriden önceliklidir.
    const requeue = [];
    for (const entry of lost) {
      const key = entry.meta;
      if (!key) continue;
      const chunk = this.chunks.get(key);
      if (!chunk) continue;                       // bu arada ACK'lenmiş
      if (this._giveUpIfExhausted(chunk)) continue;
      if (this.queued.has(key)) continue;         // zaten sırada
      this.queued.add(key);
      requeue.push(key);
    }
    if (requeue.length) this.sendQueue.unshift(...requeue);
  }

  _giveUpIfExhausted(chunk) {
    if (chunk.attempts <= this.opts.maxRetransmits) return false;
    this.stats.giveUps++;
    this._settleMessage(chunk.msgKey, new Error(
      `güvenilir gönderim başarısız (stream=${chunk.streamId} msg=${chunk.msgId} ` +
      `parça=${chunk.idx}, ${chunk.attempts} deneme)`));
    return true;
  }

  /** Mesajın tüm parçalarını bırakır ve promise'ini sonuçlandırır. */
  _settleMessage(msgKey, err) {
    const record = this.messages.get(msgKey);
    const prefix = `${msgKey}:`;

    for (const key of [...this.chunks.keys()]) {
      if (key.startsWith(prefix)) this.chunks.delete(key);
    }
    if (this.queued.size) {
      this.sendQueue = this.sendQueue.filter((k) => !k.startsWith(prefix));
      for (const k of [...this.queued]) if (k.startsWith(prefix)) this.queued.delete(k);
    }
    // Bu mesaja ait uçuştaki paketleri kurtarma defterinden düş; aksi hâlde
    // asla ACK'lenmeyecek kayıtlar bytesInFlight'ı kalıcı olarak şişirir.
    for (const [pn, entry] of this.recovery.sent) {
      if (typeof entry.meta === 'string' && entry.meta.startsWith(prefix)) {
        this.recovery.sent.delete(pn);
        if (entry.inFlight) this.recovery.bytesInFlight -= entry.bytes;
      }
    }

    if (!record || record.settled) return;
    record.settled = true;
    this.messages.delete(msgKey);
    if (err) record.reject(err); else record.resolve(record.bytes);
  }

  // ==========================================================================
  // Alma
  // ==========================================================================
  /** Çözülmüş application_data yükünü besler. */
  onData(buf) {
    if (this.closed || buf.length === 0) return;
    this.stats.bytesReceived += buf.length;
    switch (buf[0]) {
      case FRAME.RAW:  this.emit('unreliable', buf.subarray(1)); return;
      case FRAME.DATA: this._onDataFrame(buf); return;
      case FRAME.ACK:  this._onAckFrame(buf); return;
      case FRAME.PING: this._onPing(buf); return;
      case FRAME.PONG:
        if (buf.length >= 5) this.emit('pong', buf.readUInt32BE(1));
        return;
      default:
        this._softError(new Error(`bilinmeyen reliable frame tipi: ${buf[0]}`));
    }
  }

  _onPing(buf) {
    if (buf.length < PING_LEN) return;
    const pn = buf.readUIntBE(1, 6);
    this._recordReceived(pn, true);
    const pong = Buffer.allocUnsafe(5);
    pong[0] = FRAME.PONG;
    buf.copy(pong, 1, 7, 11);
    this._write(pong);
  }

  _onDataFrame(buf) {
    if (buf.length < DATA_HEADER_LEN) return;
    const ordered = (buf[1] & FLAG_ORDERED) !== 0;
    const pn = buf.readUIntBE(2, 6);
    const streamId = buf.readUInt16BE(8);
    const msgId = buf.readUInt32BE(10);
    const idx = buf.readUInt16BE(14);
    const count = buf.readUInt16BE(16);
    if (count === 0 || idx >= count) return;

    this.stats.received++;
    // Paket numarası her gönderimde yenidir; ACK bilgisi için kaydedilir,
    // ama YİNELEME ELEME veri kimliği (stream, msg, idx) üzerinden yapılır.
    this._recordReceived(pn, true);

    const key = `${streamId}:${msgId}`;
    if (this.delivered.has(key)) { this.stats.duplicates++; return; }

    const payload = buf.subarray(DATA_HEADER_LEN);
    if (count === 1) { this._markDelivered(key); this._deliver(streamId, msgId, payload, ordered); return; }

    let m = this.reassembly.get(key);
    if (!m) {
      if (this.reassembly.size >= this.opts.maxReassembly) {
        // En eskiyi düşür — bellek tükenmesine karşı sert sınır.
        this.reassembly.delete(this.reassembly.keys().next().value);
      }
      m = { chunks: new Array(count), have: 0, count, ordered, bytes: 0 };
      this.reassembly.set(key, m);
    }
    if (m.chunks[idx] !== undefined) { this.stats.duplicates++; return; }
    m.chunks[idx] = payload;
    m.have++;
    m.bytes += payload.length;
    if (m.have === m.count) {
      this.reassembly.delete(key);
      this._markDelivered(key);
      this._deliver(streamId, msgId, Buffer.concat(m.chunks, m.bytes), m.ordered);
    }
  }

  _markDelivered(key) {
    if (this.delivered.size >= this.opts.maxDedupeEntries) {
      // Set ekleme sırasını korur: en eski yarıyı at.
      const drop = Math.floor(this.opts.maxDedupeEntries / 2);
      let n = 0;
      for (const k of this.delivered) { this.delivered.delete(k); if (++n >= drop) break; }
    }
    this.delivered.add(key);
  }

  _deliver(streamId, msgId, data, ordered) {
    if (!ordered) {
      // SIRASIZ: tamamlanan mesaj anında yukarı çıkar (head-of-line blocking yok).
      this.emit('message', data, { streamId, msgId, ordered: false });
      return;
    }
    let st = this.orderedState.get(streamId);
    if (!st) { st = { next: 1, buffer: new Map() }; this.orderedState.set(streamId, st); }

    if (msgId < st.next) return;                  // geç kalmış yineleme
    st.buffer.set(msgId, data);
    if (st.buffer.size > this.opts.maxOrderedBuffer) {
      // Sıra hiç kapanmıyorsa (kalıcı kayıp) en küçük bekleyene atla.
      const lowest = Math.min(...st.buffer.keys());
      st.next = lowest;
      this.emit('gap', { streamId, skippedTo: lowest });
    }
    while (st.buffer.has(st.next)) {
      const d = st.buffer.get(st.next);
      st.buffer.delete(st.next);
      this.emit('message', d, { streamId, msgId: st.next, ordered: true });
      st.next++;
    }
  }

  // ==========================================================================
  // ACK üretimi
  // ==========================================================================
  /** @returns {boolean} bu paket numarası ilk kez mi görüldü */
  _recordReceived(pn, ackEliciting) {
    const now = Date.now();
    if (pn > this.largestReceived) { this.largestReceived = pn; this.largestReceivedAt = now; }

    const isNew = this._insertRange(pn);
    if (!ackEliciting) return isNew;

    this.ackElicitingSinceAck++;
    // Sırasız geliş veya eşik aşımı → ACK'i geciktirme (RFC 9000 §13.2.1).
    if (this.ackElicitingSinceAck >= ACK_ELICITING_THRESHOLD || pn !== this.largestReceived) {
      this._flushAck();
    } else {
      this._scheduleAck();
    }
    return isNew;
  }

  _insertRange(pn) {
    const r = this.ackRanges;
    for (let i = 0; i < r.length; i++) {
      if (pn >= r[i][0] && pn <= r[i][1]) return false;
      if (pn === r[i][0] - 1) {
        r[i][0] = pn;
        if (i > 0 && r[i - 1][1] + 1 >= r[i][0]) { r[i - 1][1] = r[i][1]; r.splice(i, 1); }
        return true;
      }
      if (pn === r[i][1] + 1) {
        r[i][1] = pn;
        if (i + 1 < r.length && r[i + 1][0] - 1 <= r[i][1]) { r[i][1] = r[i + 1][1]; r.splice(i + 1, 1); }
        return true;
      }
      if (pn < r[i][0]) { r.splice(i, 0, [pn, pn]); return true; }
    }
    r.push([pn, pn]);
    // Aralık listesi patlarsa en eskileri at — karşı taraf onları zaten bırakmıştır.
    if (r.length > this.opts.maxAckRanges) r.splice(0, r.length - this.opts.maxAckRanges);
    return true;
  }

  _scheduleAck() {
    if (this.ackTimer || this.closed) return;
    this.ackTimer = setTimeout(() => { this.ackTimer = null; this._flushAck(); }, this.opts.ackDelay);
    if (this.ackTimer.unref) this.ackTimer.unref();
  }

  _flushAck() {
    if (this.ackTimer) { clearTimeout(this.ackTimer); this.ackTimer = null; }
    if (this.closed || this.ackRanges.length === 0) return;
    this.ackElicitingSinceAck = 0;

    // En yeni aralıklar en değerlisidir (gönderen onlara göre kayıp çıkarır).
    const ranges = this.ackRanges.slice(-16);
    const ackDelay = Math.min(0xffff, Math.max(0, Date.now() - this.largestReceivedAt));

    const frame = Buffer.allocUnsafe(ACK_HEADER_LEN + ranges.length * ACK_RANGE_LEN);
    frame[0] = FRAME.ACK;
    frame.writeUInt16BE(ackDelay, 1);
    frame[3] = ranges.length;
    let o = ACK_HEADER_LEN;
    for (const [s, e] of ranges) {
      frame.writeUIntBE(s, o, 6); o += 6;
      frame.writeUIntBE(e, o, 6); o += 6;
    }
    this._write(frame);
  }

  _onAckFrame(buf) {
    if (buf.length < ACK_HEADER_LEN) return;
    const ackDelay = buf.readUInt16BE(1);
    const n = buf[3];
    if (buf.length < ACK_HEADER_LEN + n * ACK_RANGE_LEN) return;

    const ranges = [];
    let o = ACK_HEADER_LEN;
    for (let i = 0; i < n; i++) {
      const start = buf.readUIntBE(o, 6); o += 6;
      const end = buf.readUIntBE(o, 6); o += 6;
      if (end >= start) ranges.push([start, end]);
    }
    if (ranges.length === 0) return;

    const { acked, lost } = this.recovery.onAckReceived({ ranges, ackDelay, now: Date.now() });

    for (const entry of acked) {
      if (!entry.meta) continue;
      const chunk = this.chunks.get(entry.meta);
      if (!chunk) continue;                       // aynı veri başka pn ile de ACK'lenmiş
      this.chunks.delete(entry.meta);
      this.stats.acked++;

      const record = this.messages.get(chunk.msgKey);
      if (record && !record.settled && --record.pending === 0) {
        this._settleMessage(chunk.msgKey, null);
      }
    }

    if (lost.length) this._handleLost(lost);
    this._pump();
  }

  // ==========================================================================
  close(err) {
    if (this.closed) return;
    this.closed = true;
    this._clearTimer();
    if (this.ackTimer) { clearTimeout(this.ackTimer); this.ackTimer = null; }
    if (this.pacingTimer) { clearTimeout(this.pacingTimer); this.pacingTimer = null; }

    const e = err || new Error('kanal kapandı');
    for (const [msgKey, record] of this.messages) {
      if (record.settled) continue;
      record.settled = true;
      record.reject(e);
      this.messages.delete(msgKey);
    }
    this.chunks.clear();
    this.sendQueue.length = 0;
    this.queued.clear();
    this.reassembly.clear();
    this.orderedState.clear();
    this.delivered.clear();
    this.recovery.reset();
  }
}

module.exports = {
  ReliableChannel, LossRecovery, FRAME,
  DATA_HEADER_LEN, ACK_HEADER_LEN, ACK_RANGE_LEN, PING_LEN, DEFAULTS,
};
