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
const { now: monotonicNow } = require('./clock.js');
const { LossRecovery, DEFAULT_CONGESTION_CONTROL } = require('./recovery.js');

const FRAME = Object.freeze({ RAW: 0x00, DATA: 0x01, ACK: 0x02, PING: 0x03, PONG: 0x04 });

/**
 * Gönderim kuyruğu öncelik bantları.
 *
 * Kanalın kuyruğu TEK bir FIFO olduğu sürece, üst katmanın (çoklayıcının) ne
 * kadar akıllı sıraladığı önemsizdir: adil sıralanmış segmentler buraya girip
 * geliş sırasına göre çıkar ve gecikmeye duyarlı küçük bir paket, önündeki
 * hacimli veri boşalana kadar bekler. Üst katmanın kararının hayatta kalması
 * için önceliğin BURAYA kadar inmesi gerekir.
 *
 * Sayı küçüldükçe öncelik artar. Çağıran (mux) kendi sınıflarını doğrudan bu
 * bantlara eşler.
 */
const PRIORITY_BANDS = 4;
const DEFAULT_PRIORITY = 2;
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
  /**
   * Tek bir mesajın azami boyutu ve TÜM yeniden birleştirmelerin toplam tavanı.
   *
   * Bunlar olmadan alıcı tarafın belleği tamamen GÖNDERENİN elindeydi: bir
   * DATA çerçevesi `count` alanında 65535 parça bildirebilir ve her parça MTU
   * kadar olabilir — tek mesajda ~78 MB, `maxReassembly` kadar eşzamanlı
   * mesajla gigabaytlar. Parça sayısını sınırlamak yetmez, gelen baytları da
   * saymak gerekir; ikisi ayrı ayrı aşılabilir.
   */
  maxMessageBytes: 16 * 1024 * 1024,
  maxReassemblyBytes: 64 * 1024 * 1024,
  /**
   * Sıralı modda bekletilecek mesaj SAYISI ve TOPLAM BAYTI.
   *
   * İkisi ayrı ayrı gerekli ve eskiden yalnızca ilki vardı — bu bir bellek
   * açığıydı: 128 mesaj sınırı, mesaj başına `maxMessageBytes` (16 MiB) ile
   * birleştiğinde tek bir akışta 2 GB'lık bir tampona izin veriyordu ve bunu
   * tetikleyen taraf UZAKTAKİ EŞTİ (sırayı bilerek bozup mesajları biriktirmek
   * yeterli). Reassembly tarafında aynı hata zaten kapatılmıştı; burada
   * kapalı değildi.
   *
   * Sayı sınırı neden yükseltildi: sınır aşıldığında kanal sırayı ZORLA atlar
   * ve o akıştaki veri bütünlüğü biter. Uçuştaki mesaj sayısı akış denetimi
   * penceresi ÷ segment kadardır; 128, 2 MiB'lik bir pencerede aşılır. Pencere
   * artık BDP'ye göre otomatik ayarlandığı için (tunnel/protocol/constants.js
   * STREAM_WINDOW_MAX = 16 MiB, segment 16 KiB → 1024 mesaj) sayaç ona göre
   * kurulur. Gerçek tavan artık bayt sınırıdır.
   */
  maxOrderedBuffer: 1024,
  maxOrderedBytes: 32 * 1024 * 1024,
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

/**
 * `expedite` ile kendi bandının BAŞINA alınabilecek azami parça sayısı.
 *
 * Fast-track, akış BAŞLATAN küçük çerçeveler içindir (OPEN/OPEN_ACK ve yeni
 * bir akışın reddi). Sınır olmasaydı çağıran, hacimli bir mesajı "acil"
 * işaretleyip bandın tamamını atlayabilirdi — yani bandın anlamını yok
 * ederdi. Dört parça ≈ 4 KB: her açılış çerçevesi buna rahatça sığar,
 * hiçbir veri bloğu sığmaz.
 */
const MAX_EXPEDITE_CHUNKS = 4;

/**
 * Gönderimin NEDEN durduğu. BBR'ın "uygulama sınırlı mıyım" kararı buna bakar;
 * gerekçe `_noteSendLimit`'te.
 */
const LIMIT = Object.freeze({
  /** Durmadı — kuyrukta iş var ve gönderilmeye devam ediyor. */
  NONE: 'none',
  /** Kuyruk boşaldı. Uygulama sınırı OLABİLİR — üst katmana sorulur. */
  DRAINED: 'drained',
  /** Tıkanıklık penceresi dolu: ACK bekleniyor. Ağ sınırı. */
  CWND: 'cwnd',
  /** Hız şekillendirici jeton bekliyor. Kendi politikamız. */
  PACING: 'pacing',
  /** İzlenen paket tavanı (bellek koruması). */
  TRACKING: 'tracking',
});

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
    // Öncelik bandı başına bir FIFO. Bant içinde sıra korunur (aynı akışın
    // parçaları karışmaz), bantlar arasında katı öncelik uygulanır.
    this.sendBands = Array.from({ length: PRIORITY_BANDS }, () => []);
    this.queuedCount = 0;
    this.queuedBytesCount = 0;
    // Kuyruk üyelik indeksi: anahtar -> yük boyutu.
    //
    // Boyutu burada tutmak şart; `chunks`tan okumak GÜVENİLİR DEĞİL. Bir parça
    // kuyruktayken ACK'lenebilir (kayıp sanılıp yeniden kuyruğa alınmış eski
    // bir gönderimi teyitleyen ACK) ve o anda `chunks`tan silinir. Boyut oradan
    // okunsaydı, sayaçtan hiç düşülmez ve kuyruk sonsuza kadar "dolu" görünürdü.
    this.queued = new Map();
    this.timer = null;
    this.timerAt = 0;
    this.pacingTimer = null;
    /** Son pompa turunda gönderimi durduran sınır (LIMIT). */
    this.sendLimit = LIMIT.NONE;
    /** Üst katmanın elinde tuttuğu bayt — `setPendingSource` ile kurulur. */
    this.pendingBytes = null;

    // --- alıcı durumu
    this.ackRanges = [];             // [[start,end], ...] artan, birleştirilmiş
    this.ackTimer = null;
    this.ackElicitingSinceAck = 0;
    this.largestReceived = -1;
    this.largestReceivedAt = 0;
    this.reassembly = new Map();     // "stream:msg" -> parça toplayıcı
    this.reassemblyBytes = 0;        // tüm yarım mesajların toplamı
    this.orderedState = new Map();   // streamId -> { next, buffer }
    this.orderedBytes = 0;           // sıralı tamponların TOPLAMI (bellek tavanı)
    this.delivered = new Set();      // "stream:msg" -> teslim edildi (yineleme eleme)

    this.stats = {
      sent: 0, resent: 0, acked: 0, received: 0, duplicates: 0,
      bytesSent: 0, bytesReceived: 0, giveUps: 0, probes: 0, lost: 0,
      unreliableSent: 0, oversized: 0, reassemblyDropped: 0,
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
    return {
      ...this.stats,
      ...this.recovery.snapshot(),
      queued: this.queuedCount,
      queuedByPriority: this.sendBands.map((b) => b.length),
      orderedBytes: this.orderedBytes,
      /** Gönderimi durduran son sınır — teşhisin başlangıç noktası. */
      sendLimit: this.sendLimit,
      upperPendingBytes: this.pendingBytes ? this.pendingBytes() : null,
    };
  }

  // ==========================================================================
  // Gönderme
  // ==========================================================================
  /** Kuyrukta bekleyen parça sayısı (tüm bantlar). */
  get queuedChunks() { return this.queuedCount; }

  /**
   * Kuyrukta bekleyen yük (bayt) — sayaçla tutulur, taranarak değil.
   *
   * Üst katman besleme derinliğini buna göre ayarlar ve bunu gönderilen HER
   * paket için sorar; kuyruğu her seferinde gezmek, tam da sıcak yolda O(n)
   * bir iş demek olurdu.
   */
  get queuedBytes() { return this.queuedBytesCount; }

  /**
   * Güvenilir mesaj gönderir. Tüm parçalar ACK'lenince çözülen Promise döner.
   * @param {Buffer} data
   * @param {{ordered?:boolean, streamId?:number, priority?:number, expedite?:boolean}} [opt]
   *   `priority` 0 = en yüksek. Verilmezse 2 (etkileşimli).
   *
   *   `expedite` — mesajı kendi bandının BAŞINA koyar (bandı ATLAMAZ).
   *   Yalnızca AKIŞ BAŞLATAN küçük çerçeveler içindir; gerekçesi ve neden
   *   sıralamayı bozmadığı `_enqueueMessage`'ta.
   */
  sendMessage(data, opt = {}) {
    if (this.closed) return Promise.reject(new Error('kanal kapalı'));
    const ordered = opt.ordered ?? this.defaultOrdered;
    const streamId = (opt.streamId ?? 0) & 0xffff;
    const priority = clampPriority(opt.priority);

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

    const keys = new Array(count);
    for (let i = 0; i < count; i++) {
      const chunkKey = `${msgKey}:${i}`;
      this.chunks.set(chunkKey, {
        key: chunkKey, msgKey, streamId, msgId, idx: i, count, ordered, priority,
        payload: data.subarray(i * payloadMax, Math.min((i + 1) * payloadMax, data.length)),
        attempts: 0,
      });
      keys[i] = chunkKey;
    }
    this._enqueueMessage(keys, priority, opt.expedite === true);

    this._pump();
    return promise;
  }

  /**
   * Bir mesajın parçalarını bandına yerleştirir.
   *
   * FAST-TRACK (`expedite`) — akış başlatan çerçevelerin varlık sebebi:
   *
   * Bandın kuyruğu FIFO'dur ve bu, aynı sınıftaki iki akış için doğrudur:
   * 16 KiB'lik segmentler hâlinde beslenen bir aktarımın parçaları bandın
   * içinde sırayla ilerler. Ama YENİ BİR AKIŞIN AÇILIŞ ÇERÇEVESİ o kuyruğun
   * sonuna girdiğinde, önündeki her şey boşalana kadar bekler — ve karşı taraf
   * o çerçeveyi görmeden yerel bağlantıyı hiç kurmaz. Sonuç, bir bağlantının
   * KURULMASININ hacimli bir aktarımın kuyruk gecikmesini yemesidir: aktarım
   * sürerken açılan sayfa "yavaş" değil, AÇILMAZ (OPEN_TIMEOUT_MS dolar ve
   * akış düşürülür).
   *
   * Bandı yükseltmek yanlış cevap olurdu: açılış çerçevesi kredi/kalp atışı
   * kadar kritik değildir ve CONTROL bandına girmesi, veri düzleminin denetim
   * düzlemini kirletmesi demek olurdu. Doğru cevap, KENDİ bandının başına
   * geçmek: gerçek zamanlı trafiğin önüne geçmez, yalnızca aynı sınıftaki
   * hacimli verinin arkasında beklemez.
   *
   * SIRALAMAYI NEDEN BOZMAZ? Kanalın sıra garantisi AKIŞ BAŞINADIR ve akış
   * başlatan çerçeve, tanımı gereği o akışın İLK mesajıdır (msgId=1) — kendi
   * akışında önüne geçebileceği bir şey yoktur. Farklı akışların çerçeveleri
   * arasında sıra zaten garanti edilmez (ve edilmemelidir). Alıcı tarafta
   * sıralı teslim msgId üzerinden yürüdüğü için, bir aktarımın parçalarıyla
   * araya giren açılış çerçevesi hiçbir şeyi karıştırmaz.
   *
   * @param {string[]} keys parça anahtarları (mesaj sırasında)
   */
  _enqueueMessage(keys, priority, expedite) {
    // Fast-track yalnızca KÜÇÜK mesajlar için: sınır, ayrıcalığın veri
    // taşımak için kullanılmasını engeller.
    if (expedite && keys.length <= MAX_EXPEDITE_CHUNKS) {
      // Ters sırada başa eklemek, parçaların bandın başında DOĞRU sırayla
      // dizilmesini sağlar.
      for (let i = keys.length - 1; i >= 0; i--) this._enqueue(keys[i], priority, true);
      return;
    }
    for (const key of keys) this._enqueue(key, priority, false);
  }

  /**
   * @param {boolean} front kurtarma için: kaybolan veri KENDİ bandının başına
   *   döner. Kuyruğun tepesine koymak, düşük öncelikli bir yeniden gönderimin
   *   gerçek zamanlı trafiğin önüne geçmesi demek olurdu.
   */
  _enqueue(chunkKey, priority, front) {
    const band = this.sendBands[clampPriority(priority)];
    if (front) band.unshift(chunkKey); else band.push(chunkKey);
    const chunk = this.chunks.get(chunkKey);
    const bytes = chunk ? chunk.payload.length : 0;
    this.queued.set(chunkKey, bytes);
    this.queuedCount++;
    this.queuedBytesCount += bytes;
  }

  /** Kuyruk sayaçlarını tek yerden düşür — üç ayrı çıkış yolu var. */
  _unqueue(chunkKey) {
    const bytes = this.queued.get(chunkKey);
    if (bytes === undefined) return;
    this.queued.delete(chunkKey);
    this.queuedCount--;
    this.queuedBytesCount -= bytes;
  }

  /**
   * Güvenilirlik istemeyen veri — kayıp olursa yeniden gönderilmez.
   *
   * BEKLEMEZ: gecikmeye duyarlı yükü hız şekillendiricide kuyruklamak, tam da
   * kaçınmak istediği şeyi yapar (geciken bir ses paketi, düşen bir ses
   * paketinden kötüdür). Ama şekillendiriciye MUHASEBE EDİLİR: bu baytlar da
   * hattan geçiyor. Edilmeseydi güvenilir taraf hattın tamamını boş sanıp
   * onun üstüne gönderir, toplam hız darboğazı aşar ve herkesin gecikmesi
   * artardı — yani oyun trafiğini korumak için yapılan şey oyunu bozardı.
   */
  sendUnreliable(data) {
    if (this.closed) throw new Error('kanal kapalı');
    const frame = Buffer.allocUnsafe(1 + data.length);
    frame[0] = FRAME.RAW;
    data.copy(frame, 1);
    this.stats.bytesSent += frame.length;
    this.stats.unreliableSent++;
    this.recovery.noteUnpacedSend(frame.length);
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
    const now = monotonicNow();
    this.sendLimit = LIMIT.NONE;

    for (;;) {
      const key = this._peek();
      if (key === null) { this.sendLimit = LIMIT.DRAINED; break; }
      const chunk = this.chunks.get(key);
      if (!chunk) { this._dequeue(); continue; }

      const size = DATA_HEADER_LEN + chunk.payload.length;
      if (!this.recovery.hasCongestionRoom(size)) { this.sendLimit = LIMIT.CWND; break; }
      if (this.recovery.sent.size >= this.opts.maxTrackedPackets) {
        this.sendLimit = LIMIT.TRACKING;
        break;
      }

      const wait = this.recovery.pacingDelay(size, now);
      if (wait > 0) { this.sendLimit = LIMIT.PACING; this._armPacingTimer(wait); break; }

      this._dequeue();
      // Turun damgası aşağı geçirilir: şekillendiricinin "izin var mı" ve
      // "gönderdim" hesapları AYNI ana bakmalı (bkz. `_transmit`).
      this._transmit(chunk, now);
    }

    this._noteSendLimit();
    this._rearmTimer();
  }

  /**
   * "Neden daha fazla gönderemedim" sorusunun cevabını BBR'a aktarır.
   *
   * ÖLÜM SARMALININ KAYNAĞI TAM OLARAK BU KARARDI.
   *
   * Eski davranış tek satırdı: kuyruk boşaldıysa `markAppLimited()`. O çağrı
   * BBR'a "uygulamanın gönderecek verisi kalmadı, bundan sonraki teslim hızı
   * örnekleri AĞI değil UYGULAMAYI ölçüyor" der. Doğru bir mekanizmadır —
   * ama kuyruğun boşalmasının tek sebebi uygulamanın susması DEĞİLDİR:
   *
   *   • Çoklayıcı kuyruğu bilerek kısa tutar (`targetQueueMs`). Kuyruk sürekli
   *     boşalır; üst katmanda megabaytlarca veri beklerken.
   *   • Akış denetimi penceresi kapanmış olabilir — karşı taraf yetişemiyordur.
   *   • Hız şekillendirici jeton bekliyordur.
   *
   * Üçünde de veri VARDIR. "Uygulama sınırlı" demek, BBR'ın şu üç davranışını
   * birden tetikler: başlangıç evresi tamamlanmaz (`fullBwCount` artmaz),
   * `inflight_hi` hiç kurulmaz, kayıp turları modelden dışlanır. Aktarım
   * saatlerce başlangıç evresinde asılı kalır; sonunda rastgele bir kayıp
   * serisi çıkışı zorladığında tavan, HİÇ ÖLÇÜLMEMİŞ bir kapasiteden türetilir
   * ve pencere çöker. Ölçümde 17 Mbit → 6 Mbit olarak görünen kilitlenme budur.
   *
   * Ayrım bu yüzden kaynağında yapılır: kuyruk boşaldığında ÜST KATMANA
   * sorulur. Elinde veri varsa bu bir uygulama sınırı değil, bizim kendi
   * politikamızın (kuyruk hedefi / pencere / şekillendirici) sonucudur ve
   * BBR'ın modelini dondurmaması gerekir.
   */
  _noteSendLimit() {
    if (this.sendLimit !== LIMIT.DRAINED) return;   // pencere/hız/tavan sınırı
    // Üst katman veri tutuyorsa "uygulama sınırlı" DEĞİLİZ.
    if (this.pendingBytes !== null && this.pendingBytes() > 0) return;
    this.recovery.markAppLimited();
  }

  /**
   * Üst katmanın (çoklayıcının) kanala VERMEDİĞİ ama elinde tuttuğu bayt
   * sayısını okuyan işlev.
   *
   * İşlev olarak alınır, sayı olarak değil: değer her pompa turunda ve akış
   * başına değişir; senkron tutmaya çalışmak iki sayacın kaçınılmaz olarak
   * ayrışması demek olurdu. Verilmezse davranış eskisiyle aynıdır.
   *
   * @param {(() => number)|null} fn
   */
  setPendingSource(fn) {
    this.pendingBytes = typeof fn === 'function' ? fn : null;
  }

  /**
   * Hız sınırı beklemesi.
   *
   * Uyanışta zamanlayıcının GERÇEKTE ne kadar uyuduğu ölçülüp şekillendiriciye
   * bildirilir. Ölçüm MONOTONİK saatle (`performance.now`) yapılır: `Date.now`
   * bir NTP düzeltmesinde geriye atlayabilir ve tek bir sıçrama, kova
   * kapasitesini saniyelerce yanlış boyutlandırırdı. Ölçümün ne işe yaradığı
   * ve olmadığında ne olduğu pacing.js'in başında.
   */
  _armPacingTimer(ms) {
    if (this.pacingTimer || this.closed) return;
    const delay = Math.max(1, Math.min(Math.ceil(ms), MAX_PACING_TIMER_MS));
    const armedAt = monotonicNow();
    this.pacingTimer = setTimeout(() => {
      this.pacingTimer = null;
      this.recovery.noteTimerWake(delay, monotonicNow() - armedAt);
      this._pump();
    }, delay);
    if (this.pacingTimer.unref) this.pacingTimer.unref();
  }

  /** Sıradaki parçanın anahtarı — en yüksek öncelikli boş olmayan bant. */
  _peek() {
    for (let b = 0; b < this.sendBands.length; b++) {
      if (this.sendBands[b].length) return this.sendBands[b][0];
    }
    return null;
  }

  _dequeue() {
    for (let b = 0; b < this.sendBands.length; b++) {
      if (!this.sendBands[b].length) continue;
      const key = this.sendBands[b].shift();
      this._unqueue(key);
      return key;
    }
    return undefined;
  }

  _removeFromQueue(predicate) {
    for (let b = 0; b < this.sendBands.length; b++) {
      const band = this.sendBands[b];
      const kept = [];
      for (const key of band) {
        if (predicate(key)) this._unqueue(key); else kept.push(key);
      }
      this.sendBands[b] = kept;
    }
  }

  /**
   * @param {number} [now] gönderim anı.
   *
   * Çağıranın damgasını AYNEN aşağı geçirmek önemli: hız şekillendirici hem
   * "gönderebilir miyim" sorusunda hem de "gönderdim" muhasebesinde jeton
   * doldurur. İkisi farklı damgalar kullanırsa kova aynı zaman aralığını iki
   * kez sayabilir ve şekillendirme hedeflenen hızın üstüne çıkar.
   */
  _transmit(chunk, now = monotonicNow()) {
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

    this.recovery.onPacketSent({
      pn, bytes: frame.length, ackEliciting: true, meta: chunk.key, now,
    });
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
    const delay = Math.max(1, at - monotonicNow());
    this.timer = setTimeout(() => { this.timer = null; this._onTimeout(); }, delay);
    if (this.timer.unref) this.timer.unref();
  }

  _clearTimer() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    this.timerAt = 0;
  }

  _onTimeout() {
    if (this.closed) return;
    const now = monotonicNow();
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
    while (sent < count && this.queuedCount > 0) {
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
    // numarasıyla gidecek. KENDİ BANDININ başına konur: kurtarma o bandın yeni
    // verisinden önceliklidir ama bandını ATLAMAZ. Kuyruğun tepesine koymak,
    // hacimli bir aktarımın yeniden gönderiminin gerçek zamanlı trafiğin önüne
    // geçmesi demek olurdu — düzeltmeye çalıştığımız şeyin tam olarak kendisi.
    for (const entry of lost) {
      const key = entry.meta;
      if (!key) continue;
      const chunk = this.chunks.get(key);
      if (!chunk) continue;                       // bu arada ACK'lenmiş
      if (this._giveUpIfExhausted(chunk)) continue;
      if (this.queued.has(key)) continue;         // zaten sırada
      this._enqueue(key, chunk.priority, true);
    }
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

    // Sıra önemli: ÖNCE kuyruktan çıkar, SONRA parçaları sil. Tersi olsaydı
    // kuyruk sayaçları silinmiş parçalara bakmaya çalışırdı.
    if (this.queued.size) this._removeFromQueue((k) => k.startsWith(prefix));
    for (const key of [...this.chunks.keys()]) {
      if (key.startsWith(prefix)) this.chunks.delete(key);
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
      // Bildirilen parça sayısı tek başına mesajın tavanını aşıyorsa, tek bir
      // bayt bile ayırmadan reddet: gönderen niyetini `count` alanında zaten
      // açık etmiştir.
      if (count * (this.opts.mtu - DATA_HEADER_LEN) > this.opts.maxMessageBytes) {
        this.stats.oversized++;
        this._softError(new Error(
          `mesaj çok büyük: ${count} parça bildirildi (tavan ${this.opts.maxMessageBytes} bayt)`,
        ));
        return;
      }
      if (this.reassembly.size >= this.opts.maxReassembly) this._dropOldestReassembly();
      m = { chunks: new Array(count), have: 0, count, ordered, bytes: 0 };
      this.reassembly.set(key, m);
    }
    if (m.chunks[idx] !== undefined) { this.stats.duplicates++; return; }

    // Toplam tavan: tek tek küçük ama birlikte büyük olan yarım mesajlar da
    // aynı belleği tüketir. Yer açmak için en eskisini düşürüyoruz — yarım
    // kalan mesaj zaten teslim edilemez.
    while (this.reassemblyBytes + payload.length > this.opts.maxReassemblyBytes
           && this.reassembly.size > 1) {
      this._dropOldestReassembly(key);
    }

    m.chunks[idx] = payload;
    m.have++;
    m.bytes += payload.length;
    this.reassemblyBytes += payload.length;

    if (m.bytes > this.opts.maxMessageBytes) {
      this.reassembly.delete(key);
      this.reassemblyBytes -= m.bytes;
      this.stats.oversized++;
      this._softError(new Error(`mesaj tavanı aşıldı: ${m.bytes} bayt`));
      return;
    }

    if (m.have === m.count) {
      this.reassembly.delete(key);
      this.reassemblyBytes -= m.bytes;
      this._markDelivered(key);
      this._deliver(streamId, msgId, Buffer.concat(m.chunks, m.bytes), m.ordered);
    }
  }

  /** En eski yarım mesajı düşürür. `except` verilirse o atlanır. */
  _dropOldestReassembly(except = null) {
    for (const [key, m] of this.reassembly) {
      if (key === except) continue;
      this.reassembly.delete(key);
      this.reassemblyBytes -= m.bytes;
      this.stats.reassemblyDropped++;
      return;
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
    if (!st.buffer.has(msgId)) this.orderedBytes += data.length;
    st.buffer.set(msgId, data);

    // İKİ TAVAN, İKİ FARKLI TEHDİT: sayı, sıranın hiç kapanmadığı durumu
    // (kalıcı kayıp) bağlar; bayt, karşı tarafın sırayı bilerek bozarak
    // belleğimizi doldurmasını bağlar. Biri diğerinin yerine geçemez.
    if (st.buffer.size > this.opts.maxOrderedBuffer
        || this.orderedBytes > this.opts.maxOrderedBytes) {
      // Sıra hiç kapanmıyorsa en küçük bekleyene atla. Bu, o akıştaki veri
      // bütünlüğünün SONUdur: üst katman akışı düşürmek zorunda kalır.
      const lowest = Math.min(...st.buffer.keys());
      st.next = lowest;
      this.emit('gap', { streamId, skippedTo: lowest });
    }
    while (st.buffer.has(st.next)) {
      const d = st.buffer.get(st.next);
      st.buffer.delete(st.next);
      this.orderedBytes -= d.length;
      this.emit('message', d, { streamId, msgId: st.next, ordered: true });
      st.next++;
    }
  }

  /** Bir akışın sıralı teslim tamponunu bırakır (akış kapandığında). */
  _dropOrderedState(streamId) {
    const st = this.orderedState.get(streamId);
    if (!st) return;
    for (const d of st.buffer.values()) this.orderedBytes -= d.length;
    this.orderedState.delete(streamId);
  }

  // ==========================================================================
  // ACK üretimi
  // ==========================================================================
  /** @returns {boolean} bu paket numarası ilk kez mi görüldü */
  _recordReceived(pn, ackEliciting) {
    const now = monotonicNow();
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
    // Telde giden TEK zaman alanı ve bir SÜRE (damga değil): saat tabanından
    // bağımsız. Monotonik saat kayan sayı döndüğü için tam sayıya yuvarlanır —
    // `writeUInt16BE` kesirli değer kabul etmez.
    const ackDelay = Math.round(
      Math.min(0xffff, Math.max(0, monotonicNow() - this.largestReceivedAt)),
    );

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

    const { acked, lost } = this.recovery.onAckReceived({ ranges, ackDelay, now: monotonicNow() });

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
    for (const band of this.sendBands) band.length = 0;
    this.chunks.clear();
    this.queuedCount = 0;
    this.queuedBytesCount = 0;
    this.queued.clear();
    this.reassembly.clear();
    this.reassemblyBytes = 0;
    this.orderedState.clear();
    this.orderedBytes = 0;
    this.delivered.clear();
    this.recovery.reset();
  }
}

/** Bant dışına taşan öncelikleri geçerli aralığa kırpar. */
function clampPriority(p) {
  const n = Number.isInteger(p) ? p : DEFAULT_PRIORITY;
  if (n < 0) return 0;
  if (n >= PRIORITY_BANDS) return PRIORITY_BANDS - 1;
  return n;
}

module.exports = {
  ReliableChannel, LossRecovery, FRAME,
  PRIORITY_BANDS, DEFAULT_PRIORITY, clampPriority,
  DATA_HEADER_LEN, ACK_HEADER_LEN, ACK_RANGE_LEN, PING_LEN, DEFAULTS,
  MAX_EXPEDITE_CHUNKS, MAX_PACING_TIMER_MS, LIMIT,
};
