'use strict';
// Çoklayıcı: tek bir DTLS güvenilir kanalı üzerinde binlerce mantıksal bağlantı.
//
// Altta node-dtls'in ReliableChannel'ı var. O katman bir mesajı MTU'ya bölüp
// kaybolanı yeniden gönderiyor ve NewReno ile ağın taşıyabileceği hızı buluyor.
// Doğrudan ona yazmak iki şeyi yanlış yapardı:
//
//  1. BAŞ TIKANMASI. Kanalın gönderim kuyruğu TEK bir FIFO'dur. 200 MB'lık bir
//     dosya aktarımını tek `sendMessage` ile verirseniz, o mesajın bütün
//     parçaları kuyruğa birlikte girer ve arkasındaki SSH oturumu dosya bitene
//     kadar tek bayt geçiremez. Burada trafik 16 KiB'lik segmentlere bölünüp
//     akışlar arasında açık farklı sıralı dağıtımla (DRR) sırayla veriliyor.
//
//  2. SINIRSIZ BELLEK. Tıkanıklık penceresi AĞIN kapasitesini söyler,
//     ALICININ kapasitesini değil. 1 Gbit'ten 10 Mbit'lik bir yerel servise
//     pompalayınca fark tünel sürecinin belleğinde birikir. Kredi tabanlı
//     pencere bunu kapatır: alıcı yerel sokete yazamadığı sürece kredi
//     yollamaz, kredi gelmeyince gönderen durur, geri basınç uçtaki TCP'ye
//     kadar iner.
//
// Kanala aynı anda verilen bayt miktarı da tıkanıklık penceresine göre
// sınırlanır (`_budget`). Amaç kanalı aç bırakmadan kuyruğunu kısa tutmak:
// kuyruk ne kadar kısaysa, yeni bir akışın ilk baytı o kadar çabuk çıkar.

const { EventEmitter } = require('node:events');

const {
  STREAM, CTRL, DATA, LIMITS, RST_CODE,
} = require('../protocol/constants.js');
const frames = require('../protocol/frames.js');
const { CONNECTION_STREAM } = frames;
const { TokenBucket, RateMeter } = require('./rate.js');

/** Bir akışın sırası geldiğinde kazandığı bayt hakkı (DRR kuantumu). */
const SCHED_QUANTUM = 32 * 1024;
/** Yazma kuyruğu bu boyutu aşınca `write()` false döner (geri basınç sinyali). */
const STREAM_HIGH_WATER = 512 * 1024;
/** Biriken kredileri toplu göndermek için bekleme. */
const CREDIT_FLUSH_MS = 20;
/** UDP_NEW başlığının en kötü durumdaki boyutu (IPv6 ile). */
const DATAGRAM_HEADER_MAX = 32;

let nextMuxId = 1;

// ===========================================================================
// Mantıksal akış
// ===========================================================================

class TunnelStream extends EventEmitter {
  constructor(mux, id, meta) {
    super();
    this.mux = mux;
    this.id = id;
    this.meta = meta || {};

    // --- gönderim tarafı
    this.queue = [];
    this.queuedBytes = 0;
    this.sendWindow = mux.peerStreamWindow;
    this.deficit = 0;
    this.inActive = false;
    this.creditedThisRound = false;
    this.finQueued = false;
    this.finSent = false;
    this.writable = true;
    this.needsDrain = false;

    // --- alım tarafı
    this.recvWindow = mux.localStreamWindow;
    this.pendingCredit = 0;
    this.readable = true;
    this.finReceived = false;

    this.closed = false;
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.openedAt = Date.now();
  }

  /**
   * @returns {boolean} false → kuyruk doldu, kaynak soket duraklatılmalı.
   *   Bu dönüş değeri yok sayılırsa geri basınç zinciri kırılır ve bellek
   *   tüketimi karşı tarafın hızına değil gönderenin hızına bağlanır.
   */
  write(chunk) {
    if (!this.writable || this.closed || chunk.length === 0) return this.writable && !this.closed;
    this.queue.push(chunk);
    this.queuedBytes += chunk.length;
    this.mux._activate(this);
    this.mux._pump();
    if (this.queuedBytes >= STREAM_HIGH_WATER) { this.needsDrain = true; return false; }
    return true;
  }

  /** Bu yönden EOF. Kuyruktaki her şey gittikten SONRA gönderilir. */
  end() {
    if (!this.writable || this.closed) return;
    this.writable = false;
    this.finQueued = true;
    this.mux._activate(this);
    this.mux._pump();
  }

  /** Anormal sonlandırma — kuyruk atılır. */
  reset(code = RST_CODE.UNSPECIFIED) {
    if (this.closed) return;
    this.queue.length = 0;
    this.queuedBytes = 0;
    this.writable = false;
    this.mux._sendOnStream(this, frames.frameRst(code), 0);
    this.mux._destroyStream(this, code, 'local-reset');
  }

  /**
   * Alınan baytların GERÇEKTEN tüketildiğini bildirir (yerel sokete yazıldı).
   *
   * Kredinin `'data'` olayında değil burada üretilmesi bilinçli: veriyi alır
   * almaz kredi vermek pencereyi anlamsızlaştırır — gönderene "yetişiyorum"
   * demiş oluruz, oysa henüz kimseye teslim etmedik.
   */
  consumed(bytes) {
    if (bytes <= 0 || this.closed) return;
    this.pendingCredit += bytes;
    this.mux._noteConsumed(this, bytes);
  }

  get bufferedBytes() { return this.queuedBytes; }

  _maybeDrain() {
    if (this.needsDrain && this.queuedBytes < STREAM_HIGH_WATER / 2) {
      this.needsDrain = false;
      this.emit('drain');
    }
  }
}

// ===========================================================================
// Çoklayıcı
// ===========================================================================

class Mux extends EventEmitter {
  /**
   * @param {object} o
   * @param {object} o.socket DtlsSocket (reliable açık)
   * @param {'server'|'client'} o.role akış numarasını YALNIZCA sunucu tahsis eder
   * @param {object} o.log
   */
  constructor({
    socket, role, log, limits = {}, egressBucket = null,
  }) {
    super();
    this.id = nextMuxId++;
    this.socket = socket;
    this.role = role;
    this.log = log;
    this.closed = false;

    this.segmentBytes = limits.segmentBytes || LIMITS.SEGMENT_BYTES;
    this.localStreamWindow = limits.streamWindow || LIMITS.STREAM_WINDOW;
    this.localConnectionWindow = limits.connectionWindow || LIMITS.CONNECTION_WINDOW;
    this.maxStreams = limits.maxStreams || LIMITS.MAX_STREAMS;

    // Karşı tarafın bize bildirdiği pencereler. HELLO/HELLO_OK ile öğrenilir;
    // öğrenilene kadar varsayılan kullanılır ki el sıkışma trafiği akabilsin.
    this.peerStreamWindow = LIMITS.STREAM_WINDOW;
    this.peerConnectionWindow = LIMITS.CONNECTION_WINDOW;

    this.connSendWindow = this.peerConnectionWindow;
    this.connRecvWindow = this.localConnectionWindow;
    this.connPendingCredit = 0;

    this.streams = new Map();
    this.active = [];          // DRR sırası
    this.pumping = false;
    this.outstandingBytes = 0; // kanala verilmiş ama henüz ACK'lenmemiş
    this.rateTimer = null;
    this.creditTimer = null;

    /** Tünel geneli çıkış şekillendirici (yönetim panelinden ayarlanır). */
    this.egressBucket = egressBucket || new TokenBucket({ ratePerSec: 0 });

    // --- akış numarası tahsisi (yalnızca sunucu)
    this.nextStreamId = STREAM.MIN_DATA;
    this.freeStreams = [];     // karantinası dolmuş, yeniden kullanılabilir
    this.quarantine = [];      // { id, until }
    this.poisoned = new Set(); // sıra atlaması yaşamış: bir daha kullanılmaz

    this.meterIn = new RateMeter();
    this.meterOut = new RateMeter();
    this.counters = {
      streamsOpened: 0, streamsClosed: 0, resets: 0,
      controlIn: 0, controlOut: 0,
      datagramsIn: 0, datagramsOut: 0, datagramsDropped: 0,
      flowViolations: 0, sendFailures: 0,
    };

    this.rttMs = null;
    this._pingNonce = 1;
    this._pendingPing = null;

    this._onData = this._onData.bind(this);
    this._onGap = this._onGap.bind(this);
    socket.on('data', this._onData);
    socket.on('gap', this._onGap);
    socket.once('close', () => this.destroy(new Error('DTLS oturumu kapandı')));
  }

  // -------------------------------------------------------------------------
  // Pencere anlaşması — el sıkışmada bir kez, akış açılmadan önce
  // -------------------------------------------------------------------------
  applyPeerWindows({
    streamWindow, connectionWindow, segmentBytes, maxStreams,
  } = {}) {
    if (streamWindow > 0) this.peerStreamWindow = streamWindow;
    if (connectionWindow > 0) {
      this.peerConnectionWindow = connectionWindow;
      this.connSendWindow = connectionWindow;
    }
    if (segmentBytes > 0) this.segmentBytes = Math.min(segmentBytes, LIMITS.SEGMENT_BYTES);
    if (maxStreams > 0) this.maxStreams = Math.min(maxStreams, LIMITS.MAX_STREAMS);
  }

  setEgressRate(bytesPerSec) {
    this.egressBucket.setRate(bytesPerSec, Math.max(this.segmentBytes * 4, bytesPerSec / 4));
    this._pump();
  }

  // -------------------------------------------------------------------------
  // Akış yaşam döngüsü
  // -------------------------------------------------------------------------

  /** Yalnızca sunucu çağırır. @returns {TunnelStream|null} */
  openStream(meta) {
    if (this.closed) return null;
    if (this.streams.size >= this.maxStreams) return null;
    const id = this._allocStreamId();
    if (id === null) return null;
    const stream = new TunnelStream(this, id, meta);
    this.streams.set(id, stream);
    this.counters.streamsOpened++;
    return stream;
  }

  /** Yalnızca istemci çağırır: sunucunun OPEN ile bildirdiği akışı kabul eder. */
  acceptStream(id, meta) {
    if (this.closed) return null;
    if (id < STREAM.MIN_DATA || id > STREAM.MAX_DATA) return null;
    if (this.streams.has(id)) return null;
    if (this.streams.size >= this.maxStreams) return null;
    const stream = new TunnelStream(this, id, meta);
    this.streams.set(id, stream);
    this.counters.streamsOpened++;
    return stream;
  }

  getStream(id) { return this.streams.get(id) || null; }

  _allocStreamId() {
    const now = Date.now();
    while (this.quarantine.length && this.quarantine[0].until <= now) {
      const { id } = this.quarantine.shift();
      if (!this.poisoned.has(id)) this.freeStreams.push(id);
    }
    if (this.freeStreams.length) return this.freeStreams.shift();
    while (this.nextStreamId <= STREAM.MAX_DATA) {
      const id = this.nextStreamId++;
      if (!this.poisoned.has(id)) return id;
    }
    // Numara uzayı tükendi ve karantinadakiler henüz serbest değil. Yeni
    // bağlantıyı reddetmek, henüz kapanmış bir akışın numarasını hemen geri
    // vermekten iyidir: geciken bir çerçeve yeni bağlantıya karışırdı.
    return null;
  }

  _releaseStreamId(id) {
    if (this.poisoned.has(id)) return;
    this.quarantine.push({ id, until: Date.now() + LIMITS.STREAM_QUARANTINE_MS });
  }

  _destroyStream(stream, code, reason) {
    if (stream.closed) return;
    stream.closed = true;
    stream.writable = false;
    stream.readable = false;
    stream.queue.length = 0;
    stream.queuedBytes = 0;
    this._deactivate(stream);
    this.streams.delete(stream.id);
    if (this.role === 'server') this._releaseStreamId(stream.id);
    this.counters.streamsClosed++;

    // Bu akışın tükettiği tünel penceresini geri ver. Verilmezse tünel geneli
    // pencere her kapanan akışta biraz daha küçülür ve tünel yavaşça kilitlenir
    // — teşhis edilmesi en zor arıza türü tam olarak budur.
    const owed = this.localStreamWindow - stream.recvWindow;
    if (owed > 0) {
      this.connPendingCredit += owed;
      stream.pendingCredit = 0;
      this._armCreditTimer();
    }

    stream.emit('close', { code, reason });
  }

  /** Her iki yön de kapandıysa akışı bitir. */
  _maybeFinish(stream) {
    if (stream.finSent && stream.finReceived && !stream.closed) {
      this._destroyStream(stream, 0, 'half-close tamamlandı');
    }
  }

  // -------------------------------------------------------------------------
  // Zamanlayıcı (DRR + tıkanıklık bütçesi + hız şekillendirme)
  // -------------------------------------------------------------------------

  _activate(stream) {
    if (stream.inActive || stream.closed) return;
    stream.inActive = true;
    this.active.push(stream);
  }

  _deactivate(stream) {
    if (!stream.inActive) return;
    stream.inActive = false;
    stream.creditedThisRound = false;
    stream.deficit = 0;
    const i = this.active.indexOf(stream);
    if (i >= 0) this.active.splice(i, 1);
  }

  /**
   * Kanala aynı anda verilecek azami bayt.
   *
   * Tıkanıklık penceresinin iki katı: bir pencere yolda, bir pencere kanalın
   * kuyruğunda beklesin ki ACK gelir gelmez gönderilecek veri hazır olsun
   * (kanalı aç bırakmamak), ama daha fazlası kuyrukta beklemesin (diğer
   * akışların ilk baytını geciktirmemek).
   */
  _budget() {
    const cwnd = this.socket.reliable ? this.socket.reliable.congestionWindow : 64 * 1024;
    return Math.max(this.segmentBytes * 2, Math.min(cwnd * 2, 4 * 1024 * 1024));
  }

  _pump() {
    if (this.pumping || this.closed) return;
    this.pumping = true;
    try { this._pumpLoop(); } finally { this.pumping = false; }
  }

  _pumpLoop() {
    let blocked = 0;
    let rateWaitMs = 0;

    while (this.active.length > 0) {
      if (this.outstandingBytes >= this._budget()) break;

      const stream = this.active[0];

      if (stream.closed) { this._deactivate(stream); blocked = 0; continue; }

      if (stream.queuedBytes === 0) {
        if (stream.finQueued) {
          // FIN pencere harcamaz: sıradaki son iş, hemen gider.
          stream.finQueued = false;
          stream.finSent = true;
          this._sendOnStream(stream, frames.frameFin(), 0);
          this._deactivate(stream);
          stream.emit('finSent');
          this._maybeFinish(stream);
        } else {
          this._deactivate(stream);
        }
        blocked = 0;
        continue;
      }

      if (!stream.creditedThisRound) {
        stream.deficit += SCHED_QUANTUM;
        stream.creditedThisRound = true;
      }

      const allowance = Math.min(
        this.segmentBytes,
        stream.deficit,
        stream.queuedBytes,
        stream.sendWindow,
        this.connSendWindow,
      );

      if (allowance <= 0) {
        if (stream.sendWindow <= 0) {
          // Bu akışın penceresi kapalı: kredi gelene kadar sıradan çıkar.
          this._deactivate(stream);
          blocked = 0;
          continue;
        }
        if (this.connSendWindow <= 0) break; // tünel geneli pencere: kimse ilerleyemez
        // deficit tükendi: sıranın sonuna.
        stream.creditedThisRound = false;
        this._rotate();
        if (++blocked >= this.active.length) break;
        continue;
      }

      const granted = this.egressBucket.takePartial(allowance);
      if (granted <= 0) {
        rateWaitMs = this.egressBucket.msUntil(1);
        break; // hız sınırı tünel genelinde: hiçbir akış ilerleyemez
      }

      blocked = 0;
      const payload = this._takeFromQueue(stream, granted);
      stream.sendWindow -= payload.length;
      this.connSendWindow -= payload.length;
      stream.deficit -= payload.length;
      stream.bytesOut += payload.length;

      this._sendOnStream(stream, frames.frameBytes(payload), payload.length);
      stream._maybeDrain();

      if (stream.deficit <= 0) {
        stream.creditedThisRound = false;
        this._rotate();
      }
    }

    if (rateWaitMs > 0) this._armRateTimer(rateWaitMs);
  }

  _rotate() {
    if (this.active.length < 2) return;
    this.active.push(this.active.shift());
  }

  _armRateTimer(ms) {
    if (this.rateTimer || this.closed) return;
    this.rateTimer = setTimeout(() => {
      this.rateTimer = null;
      this._pump();
    }, Math.min(Math.max(ms, 1), 100));
    if (this.rateTimer.unref) this.rateTimer.unref();
  }

  /** Kuyruğun başından en çok `n` bayt alır; gerekiyorsa parçayı böler. */
  _takeFromQueue(stream, n) {
    const first = stream.queue[0];
    if (first.length === n) {
      stream.queue.shift();
      stream.queuedBytes -= n;
      return first;
    }
    if (first.length > n) {
      stream.queue[0] = first.subarray(n);
      stream.queuedBytes -= n;
      return first.subarray(0, n);
    }
    const parts = [];
    let got = 0;
    while (got < n && stream.queue.length) {
      const head = stream.queue[0];
      const want = n - got;
      if (head.length <= want) {
        parts.push(head);
        got += head.length;
        stream.queue.shift();
      } else {
        parts.push(head.subarray(0, want));
        stream.queue[0] = head.subarray(want);
        got += want;
      }
    }
    stream.queuedBytes -= got;
    return parts.length === 1 ? parts[0] : Buffer.concat(parts, got);
  }

  // -------------------------------------------------------------------------
  // Gönderim
  // -------------------------------------------------------------------------

  _sendOnStream(stream, frame, accountedBytes) {
    if (this.closed) return;
    this.outstandingBytes += accountedBytes;
    this.meterOut.add(frame.length);

    let promise;
    try {
      promise = this.socket.send(frame, { streamId: stream.id, ordered: true, reliable: true });
    } catch (err) {
      this.outstandingBytes -= accountedBytes;
      this.counters.sendFailures++;
      this._destroyStream(stream, RST_CODE.LOCAL_ERROR, `gönderim hatası: ${err.message}`);
      return;
    }
    if (!promise || typeof promise.then !== 'function') {
      this.outstandingBytes -= accountedBytes;
      return;
    }
    promise.then(
      () => {
        this.outstandingBytes -= accountedBytes;
        stream._maybeDrain();
        this._pump();
      },
      (err) => {
        this.outstandingBytes -= accountedBytes;
        this.counters.sendFailures++;
        // Kanal bu parçadan vazgeçti: veri kalıcı olarak kayboldu. Akışı
        // sürdürmek, karşı tarafa eksik bir bayt dizisini bütünmüş gibi
        // teslim etmek olurdu.
        if (!stream.closed) this._destroyStream(stream, RST_CODE.TIMEOUT, `teslim edilemedi: ${err.message}`);
        this._pump();
      },
    );
  }

  /**
   * Akışı karşı tarafa duyurur. Akışın İLK mesajıdır; hemen ardından yazılan
   * veri onun arkasına sıralanır, yani açılış onayını beklemeye gerek yoktur.
   */
  sendOpen(stream, { appIdx, remoteAddress, remotePort }) {
    this._sendOnStream(stream, frames.frameOpen({ appIdx, remoteAddress, remotePort }), 0);
  }

  sendOpenAck(stream) {
    this._sendOnStream(stream, frames.frameOpenAck(), 0);
  }

  /** Denetim mesajı — her zaman akış 0, sıralı. */
  sendControl(frame) {
    if (this.closed) return Promise.resolve();
    this.counters.controlOut++;
    this.meterOut.add(frame.length);
    try {
      const p = this.socket.send(frame, { streamId: STREAM.CONTROL, ordered: true, reliable: true });
      if (p && typeof p.catch === 'function') {
        return p.catch((err) => {
          this.counters.sendFailures++;
          this.log.debug('denetim mesajı teslim edilemedi', { err: err.message });
        });
      }
      return Promise.resolve();
    } catch {
      this.counters.sendFailures++;
      return Promise.resolve();
    }
  }

  /** Güvenilir olmayan datagram — tek atım, tek DTLS kaydına sığmalı. */
  sendDatagram(frame) {
    if (this.closed) return false;
    if (frame.length > LIMITS.MAX_DATAGRAM + DATAGRAM_HEADER_MAX) {
      this.counters.datagramsDropped++;
      return false;
    }
    if (this.egressBucket.take(frame.length) === 0) {
      // Kayıp toleranslı trafikte hız sınırına takılanı KUYRUKLAMAK yanlış
      // olurdu: geciken bir ses paketi, düşen bir ses paketinden kötüdür.
      this.counters.datagramsDropped++;
      return false;
    }
    try {
      this.socket.send(frame, { reliable: false });
      this.counters.datagramsOut++;
      this.meterOut.add(frame.length);
      return true;
    } catch {
      this.counters.datagramsDropped++;
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Alım
  // -------------------------------------------------------------------------

  _onData(buf, meta) {
    if (this.closed) return;
    this.meterIn.add(buf.length);

    if (meta && meta.reliable === false) {
      this.counters.datagramsIn++;
      let msg;
      try { msg = frames.decodeDatagram(buf); } catch {
        this.counters.datagramsDropped++;
        return;
      }
      this.emit('datagram', msg);
      return;
    }

    const streamId = meta ? meta.streamId : STREAM.CONTROL;
    if (streamId === STREAM.CONTROL) {
      this.counters.controlIn++;
      let msg;
      try { msg = frames.decodeControl(buf); } catch (err) {
        this.log.warn('bozuk denetim çerçevesi', { err: err.message });
        this.emit('protocolError', err);
        return;
      }
      this._handleControl(msg);
      return;
    }

    const stream = this.streams.get(streamId);
    if (!stream) {
      this._onUnknownStream(streamId, buf);
      return;
    }

    let msg;
    try { msg = frames.decodeData(buf); } catch (err) {
      this._destroyStream(stream, RST_CODE.FLOW_VIOLATION, `bozuk veri çerçevesi: ${err.message}`);
      return;
    }

    switch (msg.type) {
      case DATA.OPEN:
        // Aynı akışta ikinci bir OPEN: protokol ihlali.
        this._destroyStream(stream, RST_CODE.FLOW_VIOLATION, 'yinelenen OPEN');
        return;
      case DATA.OPEN_ACK:
        stream.emit('openAck');
        return;
      case DATA.BYTES: {
        const len = msg.payload.length;
        if (len > stream.recvWindow || len > this.connRecvWindow) {
          // Karşı taraf bildirdiğimiz pencereyi aştı. Tolere etmek, pencerenin
          // bellek tavanı olma özelliğini tamamen ortadan kaldırırdı.
          this.counters.flowViolations++;
          stream.reset(RST_CODE.FLOW_VIOLATION);
          return;
        }
        stream.recvWindow -= len;
        this.connRecvWindow -= len;
        stream.bytesIn += len;
        if (!stream.readable) {
          // Yerel taraf kapandı ama karşı taraf hâlâ yolluyor: krediyi hemen
          // iade et, yoksa pencere kapanır ve tünel yavaşça kilitlenir.
          stream.consumed(len);
          return;
        }
        stream.emit('data', msg.payload);
        return;
      }
      case DATA.FIN:
        if (stream.finReceived) return;
        stream.finReceived = true;
        stream.readable = false;
        stream.emit('end');
        this._maybeFinish(stream);
        return;
      case DATA.RST:
        this.counters.resets++;
        this._destroyStream(stream, msg.code, 'remote-reset');
        return;
      default:
    }
  }

  /**
   * Tanınmayan bir akış numarasına gelen çerçeve.
   *
   * İki meşru sebebi var ve ikisi çok farklı: ya karşı taraf YENİ bir akış
   * açıyor (ilk mesaj OPEN'dır), ya da bu, biz kapattıktan sonra yola çıkmış
   * geç kalmış bir çerçeve. İkincisini sessizce atmak doğru — karantina zaten
   * numaranın hemen yeniden kullanılmasını engelliyor.
   */
  _onUnknownStream(streamId, buf) {
    if (buf[0] !== DATA.OPEN) return;

    let msg;
    try { msg = frames.decodeData(buf); } catch { return; }

    const stream = this.acceptStream(streamId, {
      appIdx: msg.appIdx, remoteAddress: msg.remoteAddress, remotePort: msg.remotePort,
    });
    if (!stream) {
      // Kabul edilemedi (tavan doldu ya da numara geçersiz). Karşı tarafa
      // açıkça söylemek gerekir: sessizlik, orada bir bağlantının süresiz
      // beklemesi demek olurdu.
      try {
        const p = this.socket.send(frames.frameRst(RST_CODE.RATE_LIMITED), {
          streamId, ordered: true, reliable: true,
        });
        if (p && typeof p.catch === 'function') p.catch(() => {});
      } catch { /* oturum kapanmış */ }
      return;
    }
    this.emit('streamOpen', stream, msg);
  }

  _handleControl(msg) {
    // Kredi ve kalp atışı çoklayıcının kendi işidir; gerisi üst katmana gider.
    switch (msg.type) {
      case CTRL.CREDIT:
        this._applyCredit(msg.entries);
        return;
      case CTRL.PING:
        this.sendControl(frames.encodePong({ nonce: msg.nonce, sentAt: msg.sentAt }));
        this.emit('peerAlive');
        return;
      case CTRL.PONG:
        if (this._pendingPing && this._pendingPing.nonce === msg.nonce) {
          this.rttMs = Math.max(0, Date.now() - this._pendingPing.sentAt);
          this._pendingPing = null;
        }
        this.emit('peerAlive');
        return;
      default:
        this.emit('control', msg);
    }
  }

  _applyCredit(entries) {
    for (const [streamId, delta] of entries) {
      if (streamId === CONNECTION_STREAM) {
        this.connSendWindow = Math.min(this.peerConnectionWindow, this.connSendWindow + delta);
        continue;
      }
      const s = this.streams.get(streamId);
      if (!s) continue;
      s.sendWindow = Math.min(this.peerStreamWindow, s.sendWindow + delta);
      if (s.queuedBytes > 0 || s.finQueued) this._activate(s);
    }
    this._pump();
  }

  _noteConsumed(stream, bytes) {
    this.connPendingCredit += bytes;

    const streamThreshold = this.localStreamWindow * LIMITS.CREDIT_THRESHOLD;
    const connThreshold = this.localConnectionWindow * LIMITS.CREDIT_THRESHOLD;

    if (stream.pendingCredit >= streamThreshold || this.connPendingCredit >= connThreshold) {
      this._flushCredits();
      return;
    }
    this._armCreditTimer();
  }

  _armCreditTimer() {
    if (this.creditTimer || this.closed) return;
    this.creditTimer = setTimeout(() => {
      this.creditTimer = null;
      this._flushCredits();
    }, CREDIT_FLUSH_MS);
    if (this.creditTimer.unref) this.creditTimer.unref();
  }

  _flushCredits() {
    if (this.creditTimer) { clearTimeout(this.creditTimer); this.creditTimer = null; }
    if (this.closed) return;

    const entries = [];
    for (const stream of this.streams.values()) {
      if (stream.pendingCredit <= 0) continue;
      const delta = stream.pendingCredit;
      stream.pendingCredit = 0;
      stream.recvWindow = Math.min(this.localStreamWindow, stream.recvWindow + delta);
      entries.push([stream.id, delta]);
      if (entries.length >= 254) break;
    }
    if (this.connPendingCredit > 0) {
      const delta = this.connPendingCredit;
      this.connPendingCredit = 0;
      this.connRecvWindow = Math.min(this.localConnectionWindow, this.connRecvWindow + delta);
      entries.push([CONNECTION_STREAM, delta]);
    }
    if (entries.length === 0) return;
    this.sendControl(frames.encodeCredit(entries));
  }

  _onGap(info) {
    // Kanal bir akışta sırayı zorla atladı: o akıştaki veri bütünlüğü artık
    // garanti değil. Numara bir daha kullanılmaz ve akış düşürülür.
    const stream = this.streams.get(info.streamId);
    this.poisoned.add(info.streamId);
    this.log.warn('akışta sıra atlandı, akış düşürülüyor', info);
    if (stream) this._destroyStream(stream, RST_CODE.FLOW_VIOLATION, 'sıra atlaması');
  }

  // -------------------------------------------------------------------------
  // Kalp atışı ve ölçüm
  // -------------------------------------------------------------------------

  ping() {
    if (this.closed) return;
    this._pingNonce = ((this._pingNonce + 1) >>> 0) || 1;
    const nonce = this._pingNonce;
    const sentAt = Date.now();
    this._pendingPing = { nonce, sentAt };
    this.sendControl(frames.encodePing({ nonce, sentAt }));
  }

  snapshot() {
    const channel = this.socket.reliable ? this.socket.reliable.getStats() : null;
    const now = Date.now();
    return {
      streams: this.streams.size,
      activeStreams: this.active.length,
      outstandingBytes: this.outstandingBytes,
      connSendWindow: this.connSendWindow,
      connRecvWindow: this.connRecvWindow,
      bytesIn: this.meterIn.total,
      bytesOut: this.meterOut.total,
      rateIn: Math.round(this.meterIn.sample(now)),
      rateOut: Math.round(this.meterOut.sample(now)),
      /** Denetim düzlemi gidiş-dönüşü — kuyruklanmayı da içerir. */
      appRttMs: this.rttMs,
      /** RFC 9002 yumuşatılmış RTT — saf ağ gecikmesi. */
      rttMs: channel && channel.smoothedRtt ? Math.round(channel.smoothedRtt) : null,
      minRttMs: channel && channel.minRtt != null ? Math.round(channel.minRtt) : null,
      /** Yürürlükteki tıkanıklık denetleyicisi ve modelinin durumu. */
      congestionControl: channel ? channel.cc : null,
      ccState: channel ? channel.state : null,
      /** BBR'ın ölçtüğü darboğaz bant genişliği (bayt/s) — NewReno'da null. */
      bandwidthBps: channel ? (channel.bandwidthBps || null) : null,
      pacingRateBps: channel ? (channel.pacingRateBps || null) : null,
      congestionWindow: channel ? channel.congestionWindow : null,
      bytesInFlight: channel ? channel.bytesInFlight : null,
      packetsLost: channel ? channel.packetsLost : null,
      packetsSent: channel ? channel.packetsSent : null,
      retransmits: channel ? channel.resent : null,
      congestionEvents: channel ? channel.congestionEvents : null,
      channelQueued: channel ? channel.queued : null,
      ...this.counters,
    };
  }

  destroy(err) {
    if (this.closed) return;
    this.closed = true;
    if (this.rateTimer) clearTimeout(this.rateTimer);
    if (this.creditTimer) clearTimeout(this.creditTimer);
    this.socket.removeListener('data', this._onData);
    this.socket.removeListener('gap', this._onGap);
    for (const stream of [...this.streams.values()]) {
      stream.closed = true;
      stream.writable = false;
      stream.readable = false;
      stream.queue.length = 0;
      stream.queuedBytes = 0;
      stream.emit('close', { code: RST_CODE.TUNNEL_CLOSING, reason: 'tünel kapandı' });
    }
    this.streams.clear();
    this.active.length = 0;
    this.emit('closed', err || null);
  }
}

module.exports = {
  Mux, TunnelStream, SCHED_QUANTUM, STREAM_HIGH_WATER,
};
