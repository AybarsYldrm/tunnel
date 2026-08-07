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
  STREAM, CTRL, DATA, LIMITS, RST_CODE, QOS, FEATURES,
} = require('../protocol/constants.js');
const frames = require('../protocol/frames.js');
const { CONNECTION_STREAM } = frames;
const { TokenBucket, RateMeter } = require('./rate.js');

/** Bir akışın sırası geldiğinde kazandığı bayt hakkı (DRR kuantumu). */
const SCHED_QUANTUM = 32 * 1024;
/** Gerçek zamanlı bantta kuantum: küçük, çünkü paketler de küçük. */
const REALTIME_QUANTUM = 8 * 1024;
/**
 * Alt bant bu kadar süredir hiç sıra alamadıysa, üst bant dolu olsa bile bir
 * kuantumluk hak verilir.
 *
 * Katı öncelik doğru cevaptır ama TEK BAŞINA tehlikelidir: "gerçek zamanlı"
 * işaretlenmiş yanlış yapılandırılmış (ya da kötü niyetli) bir uygulama hattı
 * sonsuza kadar sahiplenebilir. Bu koruma, en kötü durumda bile alt bandın
 * ilerlemesini garanti eder; bedeli, üst banda eklenen en fazla bir kuantumluk
 * gecikmedir.
 */
const STARVATION_GUARD_MS = 50;
/**
 * Gerçek zamanlı bandın kanal kuyruğu payı, diğerlerinin kaç katı.
 *
 * Gerçek zamanlı yük tanımı gereği küçüktür; ona geniş bir pay vermek hacimli
 * trafiği geciktirmez ama küçük bir paketin "kuyruk dolu" diye bekletilmesini
 * engeller.
 */
const REALTIME_QUEUE_FACTOR = 4;
/**
 * Henüz tek bayt göndermemiş bir akışın kanal kuyruğu payı, diğerlerinin kaç
 * katı.
 *
 * Bir bağlantının İLK segmenti, ömrü boyunca göndereceği en kritik segmenttir:
 * HTTP istek satırı, TLS ClientHello, SSH sürüm dizesi. O segment "kanal
 * kuyruğu dolu" diye bekletildiğinde kaybedilen şey bant genişliği değil,
 * bağlantının KURULMA süresidir. Payı ikiye katlamak, süren bir aktarım
 * kuyruğu tam sınırda tutarken bile yeni akışın ilk segmentine yer bırakır.
 *
 * Neden sınırsız değil: ayrıcalık akış başına BİR KEREdir (ilk bayt gidince
 * biter) ama eşzamanlı yeni akış sayısı sınırsız olabilir. Çarpan, en kötü
 * durumda bile kuyruğun `maxOutstandingBytes` tavanının altında kalmasını
 * garanti eder.
 */
const FRESH_QUEUE_FACTOR = 2;
/**
 * Yeni akışların bandın başına dizilirken taranacak azami eleman sayısı.
 *
 * Yeni akış, bandın başına ama KENDİNDEN ÖNCE gelen diğer yeni akışların
 * arkasına girer (yeniler arasında FIFO — aksi hâlde bir bağlantı seli
 * ilk gelenleri en sona atardı). Taramayı sınırlamak, eşzamanlı binlerce
 * açılışta ekleme maliyetinin O(n²)'ye çıkmasını engeller; sınır aşılırsa
 * davranış "biraz daha geriye ekle"ye yumuşakça bozulur.
 */
const FRESH_SCAN_LIMIT = 64;
/**
 * Kanal kuyruğu tabanının segment üstüne eklediği pay (MTU katı).
 *
 * Taban tam olarak bir segmente eşit olsaydı, bir segment kuyruğa girer girmez
 * besleme durur ve kanal, o segmentin ACK'i gelene kadar SIRADAKİ akıştan tek
 * bayt alamazdı: DRR turu, ağ turu hızında ilerlerdi. Bir MTU'luk pay bu
 * kilitlenmeyi açar — kuyrukta her zaman "bir segment + biraz" yer kalır,
 * yani bir akışın segmenti kuyruktayken diğeri kendi segmentini verebilir.
 */
const QUEUE_FLOOR_MTUS = 1;
/**
 * Pencere tükendiği kanıtlandığında alım penceresinin çıkabileceği azami
 * BDP katı.
 *
 * Tükenme sinyali "hız tahminim takıldı" der; "hat sonsuz" demez. Katlamayı
 * ölçülmüş BDP'ye bağlamazsak alım penceresi tıkanıklık penceresinden
 * bağımsız büyür ve kendisi bir tampon şişmesi kaynağı olur. Dört BDP,
 * uçuştaki veriyi, yoldaki krediyi ve bir yoklama turunun fazlasını birlikte
 * karşılar.
 */
const STARVED_BDP_CAP = 4;
/** Kanalın MTU'su okunamazsa kullanılan güvenli varsayım. */
const ASSUMED_MTU = 1200;
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
    /**
     * Hizmet sınıfı — zamanlayıcının hangi bantta sıraya koyacağını belirler.
     * Uygulamadan gelir (panelden ayarlanabilir); verilmezse etkileşimli.
     */
    this.priority = normalizePriority(meta && meta.qos);

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
    // Kanal, "üst katmanın elinde veri var mı" sorusunu BU sayaçtan okur;
    // sayaç O(1) tutulmalı, akışlar taranarak değil (gerekçe: `pendingBytes`).
    this.mux.pendingBytes += chunk.length;
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
    this.mux.pendingBytes -= this.queuedBytes;
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
    /**
     * Hizmet sınıfı başına bir DRR sırası. Bantlar arasında KATI ÖNCELİK,
     * bant içinde açık farklı sıralı dağıtım (DRR).
     *
     * Neden iki katman? Bant, "kim önce" sorusunu yanıtlar (gecikmeye duyarlı
     * yük hacimli yükün önünde). DRR, "aynı sınıftakiler arasında kim ne kadar"
     * sorusunu yanıtlar (tek bir indirme, aynı sınıftaki diğer bağlantıları
     * aç bırakamaz). Yalnızca DRR olsaydı oyun paketi web indirmesiyle
     * bant genişliğini yarı yarıya bölüşürdü — oysa ihtiyacı bant genişliği
     * değil, SIRADA BEKLEMEMEK.
     */
    this.bands = [[], [], [], []];
    this.bandLastServed = [0, 0, 0, 0];
    this.pumping = false;
    this.outstandingBytes = 0; // kanala verilmiş ama henüz ACK'lenmemiş
    this.rateTimer = null;
    this.creditTimer = null;

    /**
     * Kanalın kuyruğunda tutulmasına izin verilen azami GECİKME.
     *
     * Bu tek sayı, "web indirmesi sürerken sayfa 15 saniyede açılıyor"
     * sorununun merkezindeydi. Eski sürüm kanala bayt cinsinden bir bütçe
     * (4 MiB'e kadar) veriyordu; 5 Mbit'lik bir hatta 4 MiB, ALTI SANİYELİK
     * baş-tıkanması demektir. Bütçeyi zamana bağlamak bu sayıyı hattın hızından
     * bağımsız hâle getiriyor: hız ne olursa olsun kuyruk bu kadar sürer.
     */
    this.targetQueueMs = limits.targetQueueMs || LIMITS.TARGET_QUEUE_MS;
    /** ACK bekleyen toplam veri için sert bellek tavanı. */
    this.maxOutstandingBytes = limits.maxOutstandingBytes || LIMITS.MAX_OUTSTANDING_BYTES;

    /** Tünel geneli çıkış şekillendirici (yönetim panelinden ayarlanır). */
    this.egressBucket = egressBucket || new TokenBucket({ ratePerSec: 0 });

    // --- akış numarası tahsisi (yalnızca sunucu)
    this.nextStreamId = STREAM.MIN_DATA;
    this.freeStreams = [];     // karantinası dolmuş, yeniden kullanılabilir
    this.quarantine = [];      // { id, until }
    this.poisoned = new Set(); // sıra atlaması yaşamış: bir daha kullanılmaz

    /**
     * Kanala VERİLMEMİŞ ama akış kuyruklarında bekleyen toplam bayt.
     *
     * Kanal, "uygulama gerçekten sustu mu yoksa ben mi frenledim" sorusunu
     * buradan yanıtlar (`ReliableChannel._noteSendLimit`). Sayaç O(1) tutulur:
     * her pompa turunda akışları taramak, tam da sıcak yolda O(n) bir iş
     * olurdu.
     */
    this.pendingBytes = 0;

    /**
     * Karşı tarafla ortak yetenekler (FEATURES maskesi).
     *
     * Sıfır kalırsa hiçbir yeni denetim çerçevesi gönderilmez: eski bir eş
     * tanımadığı tipi protokol hatası sayıp tüneli kapatır.
     */
    this.features = 0;
    this.autoTuneWindows = limits.autoTuneWindows !== false;
    this.maxStreamWindow = Math.min(
      limits.maxStreamWindow || LIMITS.STREAM_WINDOW_MAX, LIMITS.STREAM_WINDOW_MAX,
    );
    this.maxConnectionWindow = Math.min(
      limits.maxConnectionWindow || LIMITS.CONNECTION_WINDOW_MAX, LIMITS.CONNECTION_WINDOW_MAX,
    );
    this._lastTuneAt = 0;
    this._channelBound = false;
    /** Alım penceresi tükendi mi — otomatik ayarın doğrudan büyüme kanıtı. */
    this._streamWindowStarved = false;
    this._connWindowStarved = false;
    this._lastBlockedAt = 0;
    /** GERÇEKTEN tüketilen (yerel sokete yazılan) bayt hızı — ayarın girdisi. */
    this.meterConsumed = new RateMeter(1000);

    this.meterIn = new RateMeter();
    this.meterOut = new RateMeter();
    this.counters = {
      streamsOpened: 0, streamsClosed: 0, resets: 0,
      controlIn: 0, controlOut: 0,
      datagramsIn: 0, datagramsOut: 0, datagramsDropped: 0,
      flowViolations: 0, sendFailures: 0, windowGrows: 0, windowBlocked: 0,
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

  /**
   * El sıkışmada uzlaşılan ortak yetenekler (`mine & theirs`).
   *
   * Bu maske kurulmadan hiçbir yeni denetim çerçevesi gönderilmez; gerekçe
   * constants.js FEATURES.
   */
  setFeatures(mask) {
    this.features = (Number(mask) || 0) >>> 0;
  }

  /**
   * Kanalı çoklayıcıya bağlar: "elimde şu kadar veri var" sorusunun cevabını
   * kanala verir.
   *
   * Kanal el sıkışma sırasında oluştuğu için yapıcıda hazır olmayabilir;
   * bağlama bu yüzden tembel yapılır ve bir kez yapılır.
   */
  _bindChannel() {
    if (this._channelBound) return this.socket.reliable || null;
    const ch = this.socket.reliable;
    if (!ch || typeof ch.setPendingSource !== 'function') return ch || null;
    ch.setPendingSource(() => this.pendingBytes);
    this._channelBound = true;
    return ch;
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
    this.pendingBytes -= stream.queuedBytes;
    stream.queuedBytes = 0;
    this._deactivate(stream);
    this.streams.delete(stream.id);
    // Kanalın o akış için tuttuğu sıralı teslim tamponunu da bırak; aksi hâlde
    // kapanan her akış `orderedBytes` tavanından kalıcı bir pay götürür ve
    // tavan yavaşça tükenir.
    const ch = this.socket.reliable;
    if (ch && typeof ch._dropOrderedState === 'function') ch._dropOrderedState(stream.id);
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

  /**
   * Akışı bandının sırasına sokar.
   *
   * YENİ AKIŞ, SIRANIN BAŞINA GİRER. Gerekçe: DRR aynı sınıftaki akışlar
   * arasında BANT GENİŞLİĞİNİ adil böler, ama yeni bir bağlantının ihtiyacı
   * bant genişliği değil, İLK TURU KAÇIRMAMAKTIR. Sıranın sonuna eklenen yeni
   * bir akış, önündeki her akışın 32 KiB'lik kuantumunu bekler; hat sıkışıkken
   * bu, bağlantının kurulmasının saniyelere yayılması demektir. Başa eklemek
   * bu bekleyişi kaldırır ve adaleti bozmaz: akış bir kuantum kullanır ve
   * `_rotate` ile sıranın sonuna gider — ayrıcalık ömür boyu BİR KEREdir.
   *
   * Yeniler kendi aralarında FIFO'dur: bir bağlantı seli, ilk gelenleri en
   * sona atmamalı.
   */
  _activate(stream) {
    if (stream.inActive || stream.closed) return;
    stream.inActive = true;
    const band = this.bands[stream.priority];
    // Bant boştan doluya geçiyorsa açlık sayacını ŞİMDİ başlat. Aksi hâlde
    // saatlerdir boş duran bir bant, ilk paketinde "açlıktan ölüyorum" diyip
    // üst bandın önüne geçerdi.
    if (band.length === 0) this.bandLastServed[stream.priority] = Date.now();

    if (band.length === 0 || !this._isFresh(stream)) { band.push(stream); return; }
    let i = 0;
    while (i < band.length && i < FRESH_SCAN_LIMIT && this._isFresh(band[i])) i++;
    band.splice(i, 0, stream);
  }

  _deactivate(stream) {
    if (!stream.inActive) return;
    stream.inActive = false;
    stream.creditedThisRound = false;
    stream.deficit = 0;
    const band = this.bands[stream.priority];
    const i = band.indexOf(stream);
    if (i >= 0) band.splice(i, 1);
  }

  /** Akışın sınıfını değiştirir (uygulama QoS'u panelden güncellenirse). */
  setStreamPriority(stream, qos) {
    const next = normalizePriority(qos);
    if (next === stream.priority) return;
    const wasActive = stream.inActive;
    if (wasActive) this._deactivate(stream);
    stream.priority = next;
    if (wasActive && (stream.queuedBytes > 0 || stream.finQueued)) this._activate(stream);
  }

  /** Bir akışın toplam kuyruk uzunluğu (tüm bantlar). */
  get activeStreamCount() {
    return this.bands[0].length + this.bands[1].length
      + this.bands[2].length + this.bands[3].length;
  }

  /**
   * Sıradaki bandı seçer: en yüksek öncelikli, BESLENEBİLİR ve boş olmayan
   * bant — ama altta açlıktan bekleyen bir bant varsa bir kereliğine ona sıra
   * verilir.
   *
   * "Beslenebilir" kontrolünün bant başına olması şart. Tek bir küresel fren
   * kullanılsaydı şu olurdu: hacimli aktarım kanal kuyruğunu izin verilen
   * seviyeye kadar doldurur, hemen ardından gelen bir oyun paketi ise
   * "kuyruk dolu" diye HİÇ verilmez — oysa kanalın kuyruğu da önceliklidir ve
   * o paketi verseydik en öne geçecekti. Sıralamayı bir katman aşağı taşıyıp
   * sonra üst katmanda frenlemek, kazanılan şeyi geri vermek olurdu.
   */
  _selectBand(now) {
    let best = -1;
    for (let b = 0; b < this.bands.length; b++) {
      if (this.bands[b].length === 0) continue;
      // Besleme sınırı bandın SIRADAKİ akışına göre değerlendirilir: yeni bir
      // akışın ilk segmenti, süren bir aktarımın doldurduğu kuyruk yüzünden
      // beklememeli (bkz. FRESH_QUEUE_FACTOR).
      if (!this._canFeedChannel(b, this.bands[b][0])) continue;
      if (best < 0) { best = b; continue; }
      if (now - this.bandLastServed[b] > STARVATION_GUARD_MS) return b;
    }
    return best;
  }

  /**
   * Bu akış ömrü boyunca hiç veri göndermedi mi?
   *
   * "Yeni bağlantı" ile "sessiz kalmış eski bağlantı" arasındaki ayrım tam
   * olarak burada. Ölçüt bilerek `bytesOut === 0`: akış BİR KEZ konuştuktan
   * sonra ayrıcalığını kalıcı olarak kaybeder. Ölçüt "son N ms'dir sessiz"
   * olsaydı, her yazımdan önce bekleyen bir akış ayrıcalığı sürekli geri
   * kazanır ve sıra bir daha hiç ilerlemezdi.
   */
  _isFresh(stream) {
    return stream !== undefined && stream.bytesOut === 0 && !stream.closed;
  }

  /**
   * Kanalın kuyruğunda bekletilmesine izin verilen bayt.
   *
   * Ölçü BAYT DEĞİL ZAMANDIR ve fark burada belirleyici. Sabit bir bayt bütçesi
   * (eski sürüm: tıkanıklık penceresinin iki katı, 4 MiB'e kadar) hızlı bir
   * hatta makul, yavaş bir hatta felakettir: 5 Mbit'te 4 MiB kuyruk, kuyruğa
   * yeni giren her baytın ALTI SANİYE beklemesi demektir. Zamana bağlanınca
   * hattın hızı değişse de kuyruğun ürettiği gecikme sabit kalır.
   *
   * TABAN BAYT SINIRI — neden zaman tek başına yetmiyor.
   *
   * Bütçe yalnızca zamandan türetilseydi, hız düştükçe bütçe de düşerdi ve bir
   * noktada BESLEME BİRİMİNİN ALTINA inerdi: 1 Mbit'lik bir hatta 20 ms yalnızca
   * ~2.5 KB'dir, oysa bir akışa tek seferde verilen segment 16 KB'dir. Bütçe
   * segmentten küçük olduğu anda hiçbir segment kuyruğa giremez; kuyruk boş
   * kalır, kuyruk boş olduğu için hiçbir şey ACK'lenmez, ACK gelmediği için de
   * bütçe hiç serbest kalmaz. Bu bir yavaşlama değil KİLİTLENMEDİR ve tam da
   * hattın en dar olduğu anda devreye girer.
   *
   * Bu yüzden taban BAYT cinsindendir ve besleme birimine bağlıdır: bir segment
   * artı bir MTU (bkz. QUEUE_FLOOR_MTUS). Taban devreye girdiğinde kuyruğun
   * ürettiği gecikme `targetQueueMs`'i aşar — bu bilinçli bir takastır:
   * ilerleyen ama biraz gecikmeli bir kuyruk, hiç ilerlemeyen bir kuyruktan
   * her koşulda iyidir. Gecikmeye duyarlı yük zaten bu kuyruğun ARKASINDA
   * beklemez: kanalın kendi kuyruğu da önceliklidir ve akış başlatan
   * çerçeveler fast-track ile öne geçer.
   */
  _queueAllowance() {
    const ch = this.socket.reliable;
    const floor = this._queueFloor();
    if (!ch) return floor;
    const rate = ch.pacingRate;
    if (!rate) {
      // Henüz hız tahmini yok (ilk turlar): pencere kadarıyla yetin.
      return Math.max(floor, Math.min(ch.congestionWindow || 0, this.maxOutstandingBytes));
    }
    const byTime = Math.floor((rate * this.targetQueueMs) / 1000);
    return Math.max(floor, Math.min(byTime, this.maxOutstandingBytes));
  }

  /** Kuyruk bütçesinin altına inemeyeceği bayt tabanı. */
  _queueFloor() {
    const ch = this.socket.reliable;
    const mtu = (ch && ch.opts && ch.opts.mtu) || ASSUMED_MTU;
    // Tavanı da aşmamalı: `maxOutstandingBytes` bellek sınırıdır ve taban onu
    // delemez (aksi hâlde taban, bellek tavanını anlamsız kılardı).
    return Math.min(this.maxOutstandingBytes, this.segmentBytes + QUEUE_FLOOR_MTUS * mtu);
  }

  /**
   * Bu sınıftan kanala daha fazla veri verilebilir mi?
   *
   * İki ayrı sınır var ve ikisi farklı şeyi koruyor:
   *   • kanal kuyruğu    → GECİKMEYİ sınırlar (baş-tıkanması)
   *   • outstandingBytes → BELLEĞİ sınırlar (ACK bekleyen toplam veri)
   *
   * Kuyruk sınırı SINIFA GÖRE ölçeklenir. Gerekçe: bu sınırın amacı, üst
   * katmanın sıralama kararının bayatlamasını engellemektir. Gerçek zamanlı
   * bir paket için o karar zaten "hemen git"tir ve kanalın kendi kuyruğu da
   * öncelikli olduğu için paket oraya girdiği anda en öne geçer. Onu üst
   * katmanda bekletmek, koruduğumuz şeyi bozardı.
   */
  _canFeedChannel(band = QOS.INTERACTIVE, head = undefined) {
    if (this.outstandingBytes >= this.maxOutstandingBytes) return false;
    const ch = this.socket.reliable;
    if (!ch) return this.outstandingBytes < this.segmentBytes * 8;

    let allowance = this._queueAllowance();
    if (band <= QOS.REALTIME) {
      // Yine de sınırsız değil: kendi içinde baş-tıkanması yapan bir gerçek
      // zamanlı akış da istemiyoruz, belleği de sınırsız bırakamayız.
      allowance *= REALTIME_QUEUE_FACTOR;
    } else if (this._isFresh(head)) {
      // Sıradaki akış henüz tek bayt göndermedi: ilk segmenti, aynı sınıftaki
      // süren bir aktarımın doldurduğu kuyruğun ARKASINDA beklememeli.
      allowance *= FRESH_QUEUE_FACTOR;
    }
    // Her iki ayrıcalık da sert bellek tavanının ALTINDA kalır: öncelik,
    // alıcı belleğini şişirme hakkı değildir.
    return ch.queuedBytes < Math.min(allowance, this.maxOutstandingBytes);
  }

  _pump() {
    if (this.pumping || this.closed) return;
    if (!this._channelBound) this._bindChannel();
    this.pumping = true;
    try { this._pumpLoop(); } finally { this.pumping = false; }
  }

  _pumpLoop() {
    let blocked = 0;
    let rateWaitMs = 0;
    let guard = 0;

    for (;;) {
      if (++guard > 10_000) {
        // Tek turda çok fazla iş: olay döngüsünü aç ve kaldığı yerden devam et.
        // Zamanlayıcı KURULMADAN çıkmak, kuyrukta veri varken pompayı yalnızca
        // bir sonraki yazıma/ACK'e bağlamak olurdu — ikisi de gelmeyebilir.
        if (rateWaitMs <= 0) rateWaitMs = 1;
        break;
      }

      const now = Date.now();
      const band = this._selectBand(now);
      if (band < 0) break;   // beslenebilir ve dolu bant yok
      const queue = this.bands[band];
      const stream = queue[0];

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

      const quantum = band === QOS.REALTIME ? REALTIME_QUANTUM : SCHED_QUANTUM;
      if (!stream.creditedThisRound) {
        stream.deficit += quantum;
        stream.creditedThisRound = true;
      }

      // Gerçek zamanlı bantta segment küçük tutulur: 300 baytlık bir oyun
      // paketini 16 KiB'lik bir bütçeyle göndermek, bütçeyi anlamsız kılar ve
      // aynı bandın diğer akışlarını gereksiz bekletir.
      const segment = band === QOS.REALTIME
        ? Math.min(this.segmentBytes, LIMITS.REALTIME_SEGMENT_BYTES)
        : this.segmentBytes;

      const allowance = Math.min(
        segment,
        stream.deficit,
        stream.queuedBytes,
        stream.sendWindow,
        this.connSendWindow,
      );

      if (allowance <= 0) {
        if (stream.sendWindow <= 0) {
          // Bu akışın penceresi kapalı: kredi gelene kadar sıradan çıkar.
          // Karşı tarafa da söylenir — pencere darboğazını YALNIZCA bu taraf
          // görebilir (gerekçe: frames.encodeWindowBlocked).
          this._noteWindowBlocked(now);
          this._deactivate(stream);
          blocked = 0;
          continue;
        }
        if (this.connSendWindow <= 0) { this._noteWindowBlocked(now); break; }
        // deficit tükendi: bandın sonuna.
        stream.creditedThisRound = false;
        this._rotate(queue);
        if (++blocked >= queue.length) break;
        continue;
      }

      const granted = this.egressBucket.takePartial(allowance);
      if (granted <= 0) {
        rateWaitMs = this.egressBucket.msUntil(1);
        break; // hız sınırı tünel genelinde: hiçbir akış ilerleyemez
      }

      blocked = 0;
      this.bandLastServed[band] = now;

      const payload = this._takeFromQueue(stream, granted);
      stream.sendWindow -= payload.length;
      this.connSendWindow -= payload.length;
      stream.deficit -= payload.length;
      stream.bytesOut += payload.length;

      this._sendOnStream(stream, frames.frameBytes(payload), payload.length);
      stream._maybeDrain();

      if (stream.deficit <= 0) {
        stream.creditedThisRound = false;
        this._rotate(queue);
      }
    }

    if (rateWaitMs > 0) this._armRateTimer(rateWaitMs);
  }

  _rotate(queue) {
    if (queue.length < 2) return;
    queue.push(queue.shift());
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
      this.pendingBytes -= n;
      return first;
    }
    if (first.length > n) {
      stream.queue[0] = first.subarray(n);
      stream.queuedBytes -= n;
      this.pendingBytes -= n;
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
    this.pendingBytes -= got;
    return parts.length === 1 ? parts[0] : Buffer.concat(parts, got);
  }

  // -------------------------------------------------------------------------
  // Gönderim
  // -------------------------------------------------------------------------

  /**
   * @param {boolean} [expedite] akış başlatan çerçeve: kendi bandının başına
   *   geçer (bandı atlamaz). Ayrıntı ve sıra güvenliği: channel.js
   *   `_enqueueMessage`.
   */
  _sendOnStream(stream, frame, accountedBytes, expedite = false) {
    if (this.closed) return;
    this.outstandingBytes += accountedBytes;
    this.meterOut.add(frame.length);

    let promise;
    try {
      promise = this.socket.send(frame, {
        streamId: stream.id, ordered: true, reliable: true, priority: stream.priority,
        expedite,
      });
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
   *
   * FAST-TRACK: bu çerçeve kendi bandının başına konur. Bir bağlantının
   * kurulması, aynı sınıftaki hacimli bir aktarımın kuyruk gecikmesini
   * ödememelidir — ödediğinde sonuç "yavaş açılan sayfa" değil, OPEN_TIMEOUT
   * dolduğu için DÜŞÜRÜLEN bağlantıdır.
   */
  sendOpen(stream, { appIdx, remoteAddress, remotePort }) {
    this._sendOnStream(stream, frames.frameOpen({ appIdx, remoteAddress, remotePort }), 0, true);
  }

  /**
   * Yerel hedefe bağlanıldı.
   *
   * Bu da fast-track'tir ve sebebi OPEN'dan bile keskin: karşı taraf bu
   * çerçeveyi `OPEN_TIMEOUT_MS` içinde görmezse akışı RESET'ler. Onay, ters
   * yöndeki aktarımın kuyruğunda beklerse, YEREL BAĞLANTI KURULMUŞ OLMASINA
   * RAĞMEN bağlantı düşürülür.
   */
  sendOpenAck(stream) {
    this._sendOnStream(stream, frames.frameOpenAck(), 0, true);
  }

  /**
   * Denetim mesajı — her zaman akış 0, sıralı ve EN YÜKSEK ÖNCELİKLİ.
   *
   * Öncelik burada bir konfor değil, doğruluk meselesi: CREDIT çerçeveleri
   * serbest bırakacakları verinin arkasında kuyruğa girerse akış denetimi
   * kilitlenir — gönderen kredi bekler, kredi ise gönderenin kuyruğunda sıra
   * bekler. PING/PONG'un gecikmesi ise RTT ölçümünü ve kalp atışını bozar.
   */
  sendControl(frame) {
    if (this.closed) return Promise.resolve();
    this.counters.controlOut++;
    this.meterOut.add(frame.length);
    try {
      const p = this.socket.send(frame, {
        streamId: STREAM.CONTROL, ordered: true, reliable: true, priority: QOS.CONTROL,
      });
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
        // PENCERE DARBOĞAZ SİNYALİ. Kalan alım penceresi bir segmentin altına
        // indiyse gönderen birazdan BİZİM yüzümüzden duracak demektir.
        //
        // Bu sinyal olmadan otomatik ayar kendi kuyruğunu yiyordu: pencere
        // hızı sınırlar → sınırlı hız, hızdan türetilen büyüme hedefini eşiğin
        // altında bırakır → pencere büyümez → hız sınırlı kalır. Ölçümde
        // 25 Mbit'lik bir hattın 17 Mbit'te asılı kalması buydu. Tüketim
        // hızından TÜRETİLEN bir hedef, o hızın kendisi pencereyle sınırlıyken
        // asla kurtarıcı olamaz; darboğazın kendisini gösteren doğrudan bir
        // kanıt gerekir.
        if (stream.recvWindow < this.segmentBytes) this._streamWindowStarved = true;
        if (this.connRecvWindow < this.segmentBytes) this._connWindowStarved = true;
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
        // Red de açılışın bir parçasıdır: karşı taraftaki bağlantı bu çerçeveyi
        // görene kadar bekler. Kuyruğa girmesi, reddi zaman aşımına çevirirdi.
        const p = this.socket.send(frames.frameRst(RST_CODE.RATE_LIMITED), {
          streamId, ordered: true, reliable: true, priority: QOS.CONTROL, expedite: true,
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
      case CTRL.WINDOW:
        this._applyPeerWindowUpdate(msg);
        return;
      case CTRL.WINDOW_BLOCKED:
        // Gönderen bizim penceremiz yüzünden durmuş: büyümenin DOĞRUDAN
        // kanıtı. Yalnızca BAYRAK kurulur; ayar kendi aralığında çalışır.
        //
        // Kısıtlamayı burada atlamak (ve her bildirimde büyütmek) ölçülmüş bir
        // hataydı: 250 ms'lik bir yolda gönderen açılış boyunca sürekli
        // bloklanır, bildirimler 200 ms'de bir gelir ve pencere birkaç saniyede
        // tavana (16 MiB) fırlar. Alım penceresi bir BELLEK TAAHHÜDÜDÜR;
        // ölçümden kopuk büyümesi, sığ tamponlu bir yolda devasa bir kayıp
        // fırtınasına dönüşür.
        this._streamWindowStarved = true;
        this._connWindowStarved = true;
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
    this.meterConsumed.add(bytes);

    const streamThreshold = this.localStreamWindow * LIMITS.CREDIT_THRESHOLD;
    const connThreshold = this.localConnectionWindow * LIMITS.CREDIT_THRESHOLD;

    if (stream.pendingCredit >= streamThreshold || this.connPendingCredit >= connThreshold) {
      this._flushCredits();
      return;
    }
    this._armCreditTimer();
  }

  // -------------------------------------------------------------------------
  // Pencere otomatik ayarı (BDP tabanlı)
  // -------------------------------------------------------------------------

  /**
   * Alım penceresini ölçülen bant genişliği-gecikme çarpımına göre büyütür.
   *
   * SORUN. Sabit bir alım penceresi, hattın kendisi kadar sert bir tavandır:
   *
   *     azami_hız = pencere / RTT
   *
   * 256 KiB'lik pencere 60 ms'de 34 Mbit, 120 ms'de 17 Mbit, 250 ms'lik bir
   * mobil/uydu yolunda 8 Mbit eder — hat 1 Gbit olsa bile. Üstelik zarar
   * yalnızca hız değil: pencere kapandığında çoklayıcı kanalı besleyemez,
   * kanalın kuyruğu boşalır ve BBR bunu "uygulamanın verisi bitti" sanar
   * (bkz. ReliableChannel._noteSendLimit). Yani sabit pencere, hem tavanı
   * koyar hem de tıkanıklık modelini kör eder.
   *
   * ÖLÇÜM. Girdi, karşı tarafın bant genişliği tahmini DEĞİL, BİZİM GERÇEKTEN
   * TÜKETTİĞİMİZ hızdır (`meterConsumed`: yerel sokete yazılmış baytlar).
   * Bunun iki sonucu var ve ikisi de bilinçli:
   *   • Ölçüm karşı tarafa güvenmez. Uzak uç "hattım 10 Gbit" diyerek bizde
   *     bellek ayırtamaz.
   *   • Yerel hedef yavaşsa pencere büyümez. Geri basınç aynen korunur:
   *     tüketemediğimiz veri için tampon taahhüt etmeyiz.
   *
   * FORMÜL.
   *
   *     hedef = 2 × tüketim_hızı × RTT
   *
   * Çarpan 2 nedir: kredi karşı tarafa bir tur sonra ulaşır. Pencere yalnızca
   * bir BDP olsaydı, kredi yoldayken gönderen durmak zorunda kalırdı — hat
   * her turda yarı boş kalırdı. İki BDP, "uçuştaki veri" ile "yoldaki krediyi"
   * aynı anda karşılar.
   *
   * YAKINSAMA. Pencere hızı sınırlıyorsa ölçülen hız `pencere / RTT` olur ve
   * hedef `2 × pencere` çıkar: pencere ikiye katlanır. Hız artık pencereyle
   * sınırlı olmadığında ölçüm sabitlenir ve hedef `2 × gerçek_hız × RTT`'de
   * durur. Yani üstel büyür, kendiliğinden durur.
   *
   * SINIRLAR. Pencere bir BELLEK TAAHHÜDÜDÜR. Akış başına tavan
   * `STREAM_WINDOW_MAX`, tünel geneli tavan `CONNECTION_WINDOW_MAX` — ikincisi
   * asıl garantidir: kaç akış olursa olsun bir tünelin tamponlayacağı alım
   * verisi onu aşamaz. Pencere yalnızca BÜYÜR; küçültmek, karşı tarafın zaten
   * kullanmakta olduğu bir taahhüdü geri almak olurdu ve akış denetimi
   * ihlaline (dolayısıyla akışın düşürülmesine) yol açardı.
   */
  _maybeTuneWindows(now) {
    if (!this.autoTuneWindows || this.closed) return;
    if ((this.features & FEATURES.AUTO_WINDOW) === 0) return;
    if (now - this._lastTuneAt < LIMITS.WINDOW_TUNE_INTERVAL_MS) return;
    this._lastTuneAt = now;

    // Sinyaller okunur okunmaz temizlenir: her ayar aralığı KENDİ kanıtına
    // bakmalı, geçmişteki bir tükenmenin kalıcı büyüme izni olmasına izin
    // verilmemeli.
    const streamStarved = this._streamWindowStarved;
    const connStarved = this._connWindowStarved;
    this._streamWindowStarved = false;
    this._connWindowStarved = false;

    const rttMs = this._tuningRttMs();
    if (!(rttMs > 0)) return;
    const ratePerSec = this.meterConsumed.sample(now);
    if (!(ratePerSec > 0) && !streamStarved && !connStarved) return;

    const bdp = (ratePerSec * rttMs) / 1000;
    let wantStream = clampWindow(
      Math.ceil(2 * bdp), LIMITS.STREAM_WINDOW, this.maxStreamWindow,
    );
    // Tünel geneli pencere birden çok akışı taşır ve akış başına tavandan
    // küçük olamaz — küçük olsaydı tek bir akış kendi penceresini asla
    // kullanamazdı.
    let wantConn = clampWindow(
      Math.max(Math.ceil(4 * bdp), wantStream),
      LIMITS.CONNECTION_WINDOW, this.maxConnectionWindow,
    );

    // Pencere GERÇEKTEN tükendiyse ölçüme değil kanıta uyulur ve pencere
    // ikiye katlanır — ama İKİ SINIRLA birlikte:
    //
    //   • Ayar aralığında (200 ms) EN FAZLA BİR katlama. Bildirim başına
    //     katlamak, 250 ms'lik bir yolda pencereyi saniyeler içinde tavana
    //     fırlatıyordu.
    //   • Katlama, ölçülmüş BDP'nin `STARVED_BDP_CAP` katını AŞAMAZ. Tükenme
    //     sinyali tahminin TAKILDIĞINI söyler, hattın sonsuz olduğunu değil.
    //     Bu tavan olmadan alım penceresi tıkanıklık penceresinden bağımsız
    //     büyür ve sığ tamponlu bir yolda kayıp fırtınası üretir.
    //
    // Üstel büyüme kendini durdurur: pencere yeterince büyüdüğü anda tükenme
    // sinyali gelmez ve hedef hız tabanlı formüle döner.
    if (streamStarved) {
      const ceiling = Math.max(Math.ceil(STARVED_BDP_CAP * bdp), LIMITS.STREAM_WINDOW);
      wantStream = clampWindow(
        Math.min(Math.max(wantStream, this.localStreamWindow * 2), ceiling),
        LIMITS.STREAM_WINDOW, this.maxStreamWindow,
      );
    }
    if (connStarved || wantConn < wantStream) {
      const ceiling = Math.max(Math.ceil(2 * STARVED_BDP_CAP * bdp), LIMITS.CONNECTION_WINDOW);
      wantConn = clampWindow(
        Math.min(
          Math.max(wantConn, wantStream, connStarved ? this.localConnectionWindow * 2 : 0),
          Math.max(ceiling, wantStream),
        ),
        LIMITS.CONNECTION_WINDOW, this.maxConnectionWindow,
      );
    }

    const growStream = wantStream >= this.localStreamWindow * LIMITS.WINDOW_GROW_FACTOR;
    const growConn = wantConn >= this.localConnectionWindow * LIMITS.WINDOW_GROW_FACTOR;
    if (!growStream && !growConn) return;

    const nextStream = growStream ? wantStream : this.localStreamWindow;
    const nextConn = growConn ? wantConn : this.localConnectionWindow;
    this._growLocalWindows(nextStream, nextConn);
  }

  /**
   * Karşı tarafın penceresi bizi durdurdu — bir kez bildir.
   *
   * Kısıtlama şart: pencere kapalıyken pompa saniyede yüzlerce kez bu yola
   * girer. Ayar aralığında tek bildirim, alıcının bir sonraki ayar turunda
   * kararını vermesi için yeterlidir; fazlası denetim düzlemini doldurur ve
   * tam da açmaya çalıştığı tıkanmayı büyütür.
   */
  _noteWindowBlocked(now) {
    if ((this.features & FEATURES.AUTO_WINDOW) === 0) return;
    if (now - this._lastBlockedAt < LIMITS.WINDOW_TUNE_INTERVAL_MS) return;
    this._lastBlockedAt = now;
    this.counters.windowBlocked++;
    this.sendControl(frames.encodeWindowBlocked());
  }

  /** Ayarın kullandığı RTT: saf ağ turu, kuyruk gecikmesi dahil değil. */
  _tuningRttMs() {
    const ch = this.socket.reliable;
    if (ch && ch.rttMs > 0) return ch.rttMs;
    if (this.rttMs > 0) return this.rttMs;
    return 0;
  }

  /**
   * Yerel pencereleri büyütür ve karşı tarafa bildirir.
   *
   * SIRA HAYATİ: önce KENDİ taahhüdümüzü büyütürüz, sonra çerçeveyi
   * göndeririz. Tersi olsaydı, gönderen bizim henüz ayırmadığımız pencereyi
   * kullanmaya başlar ve akış denetimi ihlali sayılıp akış düşürülürdü.
   */
  _growLocalWindows(nextStream, nextConn) {
    const streamDelta = nextStream - this.localStreamWindow;
    const connDelta = nextConn - this.localConnectionWindow;
    if (streamDelta <= 0 && connDelta <= 0) return;

    this.localStreamWindow = nextStream;
    this.localConnectionWindow = nextConn;

    if (streamDelta > 0) {
      for (const s of this.streams.values()) {
        if (!s.closed) s.recvWindow += streamDelta;
      }
    }
    if (connDelta > 0) this.connRecvWindow += connDelta;

    this.counters.windowGrows++;
    this.sendControl(frames.encodeWindow({
      streamWindow: this.localStreamWindow,
      connectionWindow: this.localConnectionWindow,
    }));
  }

  /**
   * Karşı taraf pencere tavanını büyüttü.
   *
   * Deltanın mevcut `sendWindow`a EKLENMESİ şart, tavanın kendisine
   * ATANMASI değil: akış o an penceresinin bir kısmını kullanmış olabilir ve
   * atamak, henüz ACK'lenmemiş baytları ikinci kez harcanabilir gösterirdi.
   */
  _applyPeerWindowUpdate({ streamWindow, connectionWindow }) {
    const nextStream = clampWindow(streamWindow, 0, LIMITS.STREAM_WINDOW_MAX);
    const nextConn = clampWindow(connectionWindow, 0, LIMITS.CONNECTION_WINDOW_MAX);

    // Yalnızca BÜYÜME kabul edilir. Küçültme, karşı tarafın zaten verdiği bir
    // taahhüdü geri alması demektir; uygulasaydık uçuştaki veri bir anda
    // "pencere ihlali" hâline gelirdi.
    const streamDelta = nextStream - this.peerStreamWindow;
    const connDelta = nextConn - this.peerConnectionWindow;

    if (streamDelta > 0) {
      this.peerStreamWindow = nextStream;
      for (const s of this.streams.values()) {
        if (!s.closed) {
          s.sendWindow += streamDelta;
          if (s.queuedBytes > 0 || s.finQueued) this._activate(s);
        }
      }
    }
    if (connDelta > 0) {
      this.peerConnectionWindow = nextConn;
      this.connSendWindow += connDelta;
    }
    if (streamDelta > 0 || connDelta > 0) this._pump();
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
    // Ayar burada tetiklenir: kredi boşaltımı zaten tüketimle orantılı ve
    // kısıtlanmış bir olaydır, ayrı bir zamanlayıcıya gerek yok.
    this._maybeTuneWindows(Date.now());

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
    if (!stream) return;

    // KARŞI TARAFA SÖYLENMELİ. Akışı yalnızca yerelde düşürmek, ölçülmüş bir
    // KİLİTLENMEYDİ: biz akışı yok ederiz, kredi üretmeyi bırakırız; gönderen
    // ise penceresi kapalı hâlde, gelmeyecek bir krediyi SONSUZA KADAR bekler.
    // Aktarım durur, hiçbir hata görünmez, hiçbir zamanlayıcı devreye girmez —
    // tünel "sessizce donmuş" olur. Tek yönlü yıkım her zaman bir askıda
    // kalma riskidir; sonlandırma iki tarafta da ilan edilmelidir.
    stream.queue.length = 0;
    this.pendingBytes -= stream.queuedBytes;
    stream.queuedBytes = 0;
    stream.writable = false;
    this._sendOnStream(stream, frames.frameRst(RST_CODE.FLOW_VIOLATION), 0, true);
    this._destroyStream(stream, RST_CODE.FLOW_VIOLATION, 'sıra atlaması');
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
      activeStreams: this.activeStreamCount,
      queuedByBand: this.bands.map((b) => b.length),
      channelQueuedBytes: this.socket.reliable ? this.socket.reliable.queuedBytes : 0,
      queueAllowanceBytes: this._queueAllowance(),
      outstandingBytes: this.outstandingBytes,
      /** Üst katmanın kanala vermediği veri — "app-limited" kararının girdisi. */
      pendingBytes: this.pendingBytes,
      /** Gönderimi durduran son sınır (none/drained/cwnd/pacing/tracking). */
      sendLimit: channel ? channel.sendLimit : null,
      streamWindow: this.localStreamWindow,
      peerStreamWindow: this.peerStreamWindow,
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
      /** Şekillendiricinin patlama payı ve onu belirleyen zamanlayıcı ölçümü.
       *  `timerLagMs` 10'un üzerindeyse makine kaba tikli (tipik: Windows) —
       *  patlama payı buna göre büyümüş olmalı, yoksa hat kullanılamıyordur. */
      pacingBurstBytes: channel ? (channel.pacingBurstBytes ?? null) : null,
      pacingBurstMs: channel ? (channel.pacingBurstMs ?? null) : null,
      timerLagMs: channel ? (channel.timerLagMs ?? null) : null,
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
    this.pendingBytes = 0;
    this.streams.clear();
    for (const band of this.bands) band.length = 0;
    this.emit('closed', err || null);
  }
}

/** Pencere değerini geçerli aralığa kırpar; geçersiz girdi tabana düşer. */
function clampWindow(v, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return min;
  return Math.min(Math.max(Math.floor(n), min), max);
}

/** QoS kodunu geçerli bir banda indirger; bilinmeyen değer etkileşimli olur. */
function normalizePriority(qos) {
  const n = Number(qos);
  if (!Number.isInteger(n) || n < QOS.CONTROL || n > QOS.BULK) return QOS.INTERACTIVE;
  // CONTROL bir uygulama sınıfı değildir: veri akışları onu talep edemez,
  // yoksa bir uygulama kendini kredi mesajlarının önüne koyabilirdi.
  return n === QOS.CONTROL ? QOS.INTERACTIVE : n;
}

module.exports = {
  Mux, TunnelStream, SCHED_QUANTUM, REALTIME_QUANTUM, STREAM_HIGH_WATER,
  STARVATION_GUARD_MS, REALTIME_QUEUE_FACTOR, FRESH_QUEUE_FACTOR,
  QUEUE_FLOOR_MTUS, normalizePriority, clampWindow,
};
