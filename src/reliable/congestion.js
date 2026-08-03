'use strict';
// Tıkanıklık denetleyicileri — takılabilir (pluggable) motorlar.
//
// RFC 9002 kayıp tespiti (recovery.js) tıkanıklık denetiminden AYRI bir iştir:
// "hangi paket kayboldu" sorusuyla "ne kadar hızlı göndermeliyim" sorusunun
// cevabı aynı yerden gelmek zorunda değil. Bu dosya ikincisini üstlenir ve iki
// cevap sunar:
//
//   newreno  RFC 9002 §7 — kayıp odaklı. Kayıp = tıkanıklık varsayar.
//   bbr3     BBRv3 (draft-ietf-ccwg-bbr) — model odaklı. Yolun DARBOĞAZ BANT
//            GENİŞLİĞİNİ ve EN KÜÇÜK GİDİŞ-DÖNÜŞ SÜRESİNİ ölçer, gönderim
//            hızını doğrudan bu modelden türetir.
//
// Neden BBRv3 varsayılan?
//
//   NewReno (ve Reno/CUBIC ailesinin tamamı) kaybı tıkanıklık sinyali sayar.
//   Bu varsayım iki yaygın durumda yanlıştır ve ikisi de tam olarak bu projenin
//   çalıştığı ortamdır:
//
//   1. KAYIP TIKANIKLIKTAN GELMİYOR. Mobil/Wi-Fi/uydu hatlarında kayıp rastgele
//      bit hatasından doğar. Kayıp oranı %1 olan 100 Mbit'lik bir hatta Reno'nun
//      ulaşabileceği tavan (Mathis formülü) onlarca Mbit'in altındadır: hattın
//      kendisi boşken pencere sürekli yarılanır.
//   2. TAMPON ŞİŞMESİ (bufferbloat). Kayıp yalnızca darboğazdaki KUYRUK
//      TAŞTIĞINDA gelir. Kayıp odaklı denetleyici bu yüzden kuyruğu doldurmayı
//      hedefler; sonuç, hattı paylaşan her şeyin (SSH, oyun, ses) yüzlerce
//      milisaniyelik gecikme yemesi olur. BBR kuyruğu DOLDURMADAN darboğaz
//      hızında gönderir: aynı verimi, kuyruk gecikmesi olmadan.
//
//   Tünelin taşıdığı yükün karışık olması (toplu aktarım + etkileşimli oturum
//   aynı DTLS kanalında) ikinci maddeyi belirleyici yapıyor.
//
// BBRv3'ün v1/v2'den farkı ve neden v3:
//
//   v1 kaybı hiç dinlemiyordu; sığ tamponlu hatlarda aşırı kayıp üretiyor,
//   CUBIC'e karşı adaletsiz davranıyordu. v2 kayıp ve ECN'i modele "üst sınır"
//   (inflight_hi/bw_hi) olarak ekledi. v3 bunların üstüne daha hızlı yakınsayan
//   ProbeBW döngüsü, düzeltilmiş başlangıç çıkış ölçütü ve ACK yığılmasını
//   (aggregation) telafi eden extra_acked terimini koydu. Sonuncusu Wi-Fi ve
//   mobil ağlarda somut fark yaratır: ACK'ler yığın hâlinde geldiğinde v1
//   pencereyi küçük tutup hattı boş bırakıyordu.
//
// Denetleyici arayüzü (recovery.js bunu bekler):
//
//   onPacketSent(entry, ctx)   gönderim anı — round/örnekleme defteri
//   onAck(ctx)                 ACK işlendi — model güncellenir
//   onLoss(ctx)                kayıp ilan edildi
//   onPtoExpired(ctx)          sonda gönderildi (kayıp DEĞİL)
//   onPersistentCongestion()   ağ koptu — modeli sıfırla
//   cwnd                       bayt cinsinden gönderim penceresi
//   pacingRate                 bayt/s (Infinity = hız sınırı yok)
//   snapshot()                 teşhis

// ===========================================================================
// Kathleen Nichols'un pencereli maksimum/minimum süzgeci (Linux minmax.h).
//
// Üç örnek yeterlidir: en iyi değer, pencerenin ikinci çeyreğindeki en iyi ve
// son çeyrekteki en iyi. Böylece pencere kaydıkça tahmin, tüm geçmişi saklamaya
// gerek kalmadan yumuşakça düşer.
// ===========================================================================
class WindowedFilter {
  /**
   * @param {number} windowLength pencere uzunluğu (zaman birimi çağırana ait)
   * @param {1|-1} direction 1 = maksimum, -1 = minimum
   */
  constructor(windowLength, direction = 1) {
    this.window = windowLength;
    this.dir = direction;
    this.s = [{ t: 0, v: 0 }, { t: 0, v: 0 }, { t: 0, v: 0 }];
    this.initialized = false;
  }

  /** Yeni örnek eskisinden "daha iyi" mi (maks. için büyük, min. için küçük). */
  _better(a, b) { return this.dir > 0 ? a >= b : a <= b; }

  reset(t, v) {
    this.initialized = true;
    this.s[0] = { t, v };
    this.s[1] = { t, v };
    this.s[2] = { t, v };
    return v;
  }

  update(t, v) {
    if (!this.initialized) return this.reset(t, v);
    if (this._better(v, this.s[0].v) || (t - this.s[2].t) > this.window) {
      return this.reset(t, v);
    }
    if (this._better(v, this.s[1].v)) { this.s[1] = { t, v }; this.s[2] = { t, v }; }
    else if (this._better(v, this.s[2].v)) { this.s[2] = { t, v }; }
    return this._subwindowUpdate(t, v);
  }

  _subwindowUpdate(t, v) {
    const dt = t - this.s[0].t;
    if (dt > this.window) {
      // En eski örnek pencereden çıktı: hepsini bir kaydır.
      this.s[0] = this.s[1];
      this.s[1] = this.s[2];
      this.s[2] = { t, v };
      if ((t - this.s[0].t) > this.window) {
        this.s[0] = this.s[1];
        this.s[1] = this.s[2];
        this.s[2] = { t, v };
      }
    } else if (this.s[1].t === this.s[0].t && dt > this.window / 4) {
      this.s[1] = { t, v };
      this.s[2] = { t, v };
    } else if (this.s[2].t === this.s[1].t && dt > this.window / 2) {
      this.s[2] = { t, v };
    }
    return this.s[0].v;
  }

  get() { return this.initialized ? this.s[0].v : 0; }
}

// ===========================================================================
// Teslim hızı örnekleyicisi
// (draft-cheng-iccrg-delivery-rate-estimation)
//
// BBR'ın tamamı tek bir ölçüme dayanır: "son turda ağ SAHİDEN kaç bayt teslim
// etti". Bu, gönderilen bayt değildir (kaybolanı sayar), pencere de değildir
// (uçuşta bekleyeni sayar). Doğru ölçüm ACK'lerin kendisinden çıkar:
//
//   teslim_hızı = teslim_edilen_bayt / max(gönderim_aralığı, ack_aralığı)
//
// Paydadaki maksimum önemlidir: ACK'ler yığın hâlinde gelirse (Wi-Fi, LTE,
// ACK sıkıştıran ara katmanlar) ack_aralığı olduğundan küçük çıkar ve hız
// olduğundan büyük görünür; gönderim aralığı bu hatayı kapatır.
// ===========================================================================
class RateSampler {
  constructor() {
    this.delivered = 0;          // bağlantı ömründe teslim edilen bayt
    this.deliveredTime = 0;      // son teslim anı
    this.firstSentTime = 0;      // içinde bulunduğumuz "gönderim aralığının" başı
    this.appLimitedUntil = 0;    // 0 = sınır yok; aksi hâlde bu delivered'a kadar
    this.lostBytes = 0;
    this.sample = this._emptySample();
  }

  _emptySample() {
    return {
      deliveryRate: 0,     // bayt/ms
      delivered: 0,
      priorDelivered: 0,
      priorTime: 0,
      sendElapsed: 0,
      ackElapsed: 0,
      intervalMs: 0,
      isAppLimited: false,
      priorLost: 0,
      lost: 0,
      valid: false,
    };
  }

  /** Uygulama veri üretemediği için hattı boş bıraktık — örnekleri işaretle. */
  markAppLimited(bytesInFlight) {
    this.appLimitedUntil = Math.max(this.delivered + bytesInFlight, 1);
  }

  get isAppLimited() { return this.appLimitedUntil !== 0; }

  /** Gönderim anında paketin üzerine bağlantı durumunun fotoğrafı yazılır. */
  onPacketSent(entry, bytesInFlight, now) {
    if (bytesInFlight === 0) {
      // Hat boştu: yeni bir gönderim aralığı başlıyor.
      this.firstSentTime = now;
      this.deliveredTime = now;
    }
    entry.firstSentTime = this.firstSentTime;
    entry.deliveredTime = this.deliveredTime;
    entry.delivered = this.delivered;
    entry.deliveredLost = this.lostBytes;
    entry.isAppLimited = this.appLimitedUntil !== 0;
  }

  /** ACK turu başlarken çağrılır. */
  beginAck() { this.sample = this._emptySample(); }

  /** ACK'lenen her paket için. */
  onPacketAcked(entry, now) {
    this.delivered += entry.bytes;
    this.deliveredTime = now;

    // Örnek, ACK edilen paketler içindeki EN YENİ gönderimden alınır: en eski
    // paket, aradaki tüm gönderim aralığını kapsar ve hızı bulandırır.
    const s = this.sample;
    if (!s.valid || entry.delivered > s.priorDelivered) {
      s.valid = true;
      s.priorDelivered = entry.delivered;
      s.priorTime = entry.deliveredTime;
      s.priorLost = entry.deliveredLost;
      s.isAppLimited = entry.isAppLimited;
      s.sendElapsed = entry.sentTime - entry.firstSentTime;
      s.ackElapsed = this.deliveredTime - entry.deliveredTime;
      this.firstSentTime = entry.sentTime;
    }
  }

  noteLost(bytes) { this.lostBytes += bytes; }

  /**
   * ACK turunu kapatır ve örneği sonuçlandırır.
   * @param {number} minRttMs örnek bu süreden kısaysa güvenilmez sayılır
   */
  endAck(minRttMs) {
    const s = this.sample;
    // Uygulama sınırı, gerçekten o noktaya kadar teslim edildiğinde kalkar.
    if (this.appLimitedUntil !== 0 && this.delivered > this.appLimitedUntil) {
      this.appLimitedUntil = 0;
    }
    // `valid`, bu turda EN AZ BİR paketin ACK'lendiğini söyler. Zamanı
    // (priorTime) sıfıra karşı sınamak cazip ama yanlış: bağlantı ömrünün
    // sıfırıncı milisaniyesi geçerli bir zaman damgasıdır.
    if (!s.valid) return s;

    s.delivered = this.delivered - s.priorDelivered;
    s.lost = this.lostBytes - s.priorLost;
    s.intervalMs = Math.max(s.sendElapsed, s.ackElapsed);

    // min_rtt'den kısa aralıklar zamanlayıcı çözünürlüğünün gürültüsüdür;
    // bunlardan hız çıkarmak tahmini tavana fırlatır.
    if (s.intervalMs < Math.max(1, minRttMs)) { s.valid = false; return s; }
    s.deliveryRate = s.delivered / s.intervalMs;   // bayt/ms
    return s;
  }
}

// ===========================================================================
// NewReno — RFC 9002 §7
// ===========================================================================
const kLossReductionFactor = 0.5;       // RFC 9002 §7.3.2

function initialWindow(maxDatagramSize) {
  return Math.min(10 * maxDatagramSize, Math.max(14720, 2 * maxDatagramSize));
}
function minimumWindow(maxDatagramSize) {
  return 2 * maxDatagramSize;
}

class NewRenoController {
  constructor({ maxDatagramSize = 1200 } = {}) {
    this.name = 'newreno';
    this.maxDatagramSize = maxDatagramSize;
    this.cwnd = initialWindow(maxDatagramSize);
    this.ssthresh = Infinity;
    this.recoveryStartTime = 0;
    this.congestionEvents = 0;
    // NewReno hız şekillendirmez: pencere zaten patlamayı sınırlıyor.
    this.pacingRate = Infinity;
  }

  onPacketSent() { /* defter tutmaz */ }

  inRecovery(sentTime) { return sentTime <= this.recoveryStartTime; }

  onAck({ acked, now }) {
    for (const e of acked) {
      if (!e.inFlight) continue;
      // Kurtarma döneminde gönderilmiş paketler pencereyi büyütmez (§7.3.2).
      if (this.inRecovery(e.sentTime)) continue;
      if (this.cwnd < this.ssthresh) {
        this.cwnd += e.bytes;                                   // yavaş başlangıç
      } else {
        this.cwnd += Math.max(1,
          Math.floor(this.maxDatagramSize * e.bytes / this.cwnd)); // kaçınma
      }
    }
    void now;
  }

  /** Dönem başına bir kez pencereyi yarıya indirir. */
  congestionEvent(sentTime, now) {
    if (this.inRecovery(sentTime)) return;
    this.congestionEvents++;
    this.recoveryStartTime = now;
    this.ssthresh = Math.max(
      Math.floor(this.cwnd * kLossReductionFactor),
      minimumWindow(this.maxDatagramSize),
    );
    this.cwnd = this.ssthresh;
  }

  onLoss({ largestLost, now }) {
    if (!largestLost) return;
    this.congestionEvent(largestLost.sentTime, now);
  }

  onPersistentCongestion() {
    this.cwnd = minimumWindow(this.maxDatagramSize);
    this.recoveryStartTime = 0;   // yavaş başlangıca dön
    this.ssthresh = Infinity;
  }

  onPtoExpired() { /* PTO kayıp bildirimi değildir */ }

  snapshot() {
    return {
      cc: 'newreno',
      congestionWindow: this.cwnd,
      ssthresh: this.ssthresh === Infinity ? null : this.ssthresh,
      pacingRateBps: null,
      bandwidthBps: null,
      state: this.cwnd < this.ssthresh ? 'slow-start' : 'avoidance',
      congestionEvents: this.congestionEvents,
    };
  }
}

// ===========================================================================
// BBRv3
// ===========================================================================

/** Durum makinesi. ProbeBW dört evreli bir döngüdür. */
const BBR_STATE = Object.freeze({
  STARTUP: 'startup',
  DRAIN: 'drain',
  PROBE_BW_DOWN: 'probe-bw-down',
  PROBE_BW_CRUISE: 'probe-bw-cruise',
  PROBE_BW_REFILL: 'probe-bw-refill',
  PROBE_BW_UP: 'probe-bw-up',
  PROBE_RTT: 'probe-rtt',
});

const BBR_DEFAULTS = Object.freeze({
  /** 2/ln2 — her turda pencereyi ikiye katlamak için gereken en küçük kazanç. */
  startupPacingGain: 2.77,
  startupCwndGain: 2.0,
  /** 1/2.885 — başlangıçta biriken kuyruğu bir turda boşaltır. */
  drainPacingGain: 0.35,
  probeDownPacingGain: 0.9,
  probeCruisePacingGain: 1.0,
  probeRefillPacingGain: 1.0,
  probeUpPacingGain: 1.25,
  cwndGain: 2.0,
  probeRttCwndGain: 0.5,

  /** min_rtt bu kadar süre tazelenmezse ProbeRTT'ye girilir. */
  minRttWindowMs: 10_000,
  probeRttDurationMs: 200,
  probeRttIntervalMs: 5_000,

  /** Bir turdaki kayıp oranı bu eşiği aşarsa model üst sınırı düşürülür. */
  lossThresh: 0.02,
  /**
   * Kayıp oranı bu kadar bayt görülmeden HÜKÜM OLARAK kullanılmaz (paket
   * cinsinden ~8 paket).
   *
   * Bu eşik olmadan BBR, rastgele kayıplı hatlarda tam olarak kaçındığı
   * hataya düşer: 10 paketlik bir örnekte tek bir rastgele kayıp %10 oranı
   * gösterir, eşik aşılır, model tavanı düşürülür — ve bu her turda tekrarlanıp
   * hızı NewReno'nun altına indirir. Ölçüm turun tamamından, yeterli örnekle
   * alınmalı.
   */
  minLossSamplePackets: 8,
  /** Kayıpta inflight_hi/bw_hi'nin korunan oranı. */
  beta: 0.7,
  /** Kuyruğa dokunmamak için darboğaz penceresinden bırakılan pay. */
  headroom: 0.15,

  /** Başlangıç: 3 turda %25'ten az büyüme = hattın tavanı bulundu. */
  fullBwThresh: 1.25,
  fullBwCnt: 3,
  /** Başlangıç: bu kadar ardışık kayıplı tur da çıkış sebebidir. */
  fullLossCnt: 8,

  /**
   * Hedef hızın altında kalarak kuyruk oluşturmamak için bırakılan pay.
   *
   * Linux'ta %1'dir; burada %2. Sebep ölçüm çözünürlüğü: bu yığın zamanı
   * MİLİSANİYE cinsinden okur, çekirdek ise mikrosaniye. 40 ms'lik bir örnekleme
   * aralığında ±1 ms yuvarlama %2.5 hata demektir ve bant genişliği tahmini
   * PENCERELİ MAKSİMUM olduğu için bu hatanın sistematik olarak pozitif ucunu
   * seçer. %1'lik pay o gürültünün altında kalır; hedef hız darboğazın birkaç
   * binde üstüne çıkar ve fark kalıcı kuyruk olarak birikir.
   */
  pacingMargin: 0.02,
  /** ACK yığılması telafisi için pencere (tur). */
  extraAckedWinRounds: 5,
  /** Pencerenin asgari değeri (paket). */
  minPipeCwndPackets: 4,

  /** ProbeBW: yeni bant genişliği araması arasındaki bekleme. */
  bwProbeWaitMs: 2_000,
  bwProbeRandMs: 1_000,
  bwProbeBaseRounds: 2,
  bwProbeRandRounds: 2,
});

class Bbr3Controller {
  constructor(o = {}) {
    this.name = 'bbr3';
    this.cfg = { ...BBR_DEFAULTS, ...o.bbr };
    this.maxDatagramSize = o.maxDatagramSize || 1200;
    this.initialRtt = o.initialRtt || 333;

    // --- model
    /**
     * Darboğaz bant genişliği tahmini (bayt/ms).
     *
     * Süzgecin zaman ekseni TUR DEĞİL, ProbeBW ÇEVRİMİDİR (v3). Tur başına
     * kaydırmak, ProbeRTT'nin bilerek düşük tuttuğu birkaç turun tahmini
     * yere çakmasına ve saniyelerce toparlanamamasına yol açar — ProbeRTT'yi
     * %2'lik bir maliyetten %40'lık bir maliyete çevirirdi.
     */
    this.maxBwFilter = new WindowedFilter(2, 1);
    this.cycleCount = 0;
    this.maxBw = 0;
    this.bwLatest = 0;
    /** Kısa vadeli üst sınır — kayıp gördüğümüz turda düşürülür. */
    this.bwLo = Infinity;
    /** Uzun vadeli üst sınır — ProbeBW_UP'ta yukarı doğru yoklanır. */
    this.bwHi = Infinity;

    this.minRtt = Infinity;
    this.minRttStamp = 0;
    this.minRttExpired = false;
    this.probeRttMinDelay = Infinity;
    this.probeRttMinStamp = 0;

    this.inflightLatest = 0;
    this.inflightLo = Infinity;
    this.inflightHi = Infinity;

    /** ACK yığılması telafisi: beklenenden fazla ACK'lenen bayt. */
    this.extraAckedFilter = new WindowedFilter(this.cfg.extraAckedWinRounds, 1);
    this.extraAcked = 0;
    this.ackEpochStamp = 0;
    this.ackEpochAcked = 0;

    // --- tur sayacı (round trip)
    this.nextRoundDelivered = 0;
    this.roundStart = false;
    this.roundCount = 0;

    // --- durum
    this.state = BBR_STATE.STARTUP;
    this.pacingGain = this.cfg.startupPacingGain;
    this.cwndGain = this.cfg.startupCwndGain;
    this.filledPipe = false;
    this.fullBw = 0;
    this.fullBwCount = 0;
    this.lossRoundsInStartup = 0;
    this.lossRoundStart = false;
    this.lossRoundDelivered = 0;
    this.lossInRound = false;
    this.lossEventsInRound = 0;
    /** Tur içi ham sayaçlar — kayıp oranı BUNLARDAN çıkarılır. */
    this.roundAckedBytes = 0;
    this.roundLostBytes = 0;
    this.lossRateThisRound = 0;
    this.roundsSinceProbe = 0;
    this.probeWaitUntil = 0;
    this.cycleStamp = 0;
    this.bwProbeSamples = 0;
    this.inflightAtProbeStart = 0;

    // --- ProbeRTT
    this.probeRttDoneStamp = 0;
    this.probeRttRoundDone = false;
    this.idleRestart = false;
    this.priorState = BBR_STATE.STARTUP;
    this.priorCwnd = 0;

    // --- çıktı
    this.cwnd = initialWindow(this.maxDatagramSize);
    this.pacingRate = Infinity;   // ilk BW örneğine kadar hız sınırı yok

    this.congestionEvents = 0;
    this.probeRttCount = 0;
    this.startupExitReason = null;
  }

  // -------------------------------------------------------------------------
  // Yardımcılar
  // -------------------------------------------------------------------------
  get minPipeCwnd() { return this.cfg.minPipeCwndPackets * this.maxDatagramSize; }

  /** Modelin bant genişliği (bayt/ms) — kısa ve uzun vadeli sınırlarla budanmış. */
  get bw() { return Math.min(this.maxBw, this.bwLo, this.bwHi); }

  /** Bant genişliği-gecikme çarpımı: hattın "boruda" tutabileceği bayt. */
  bdp(gain = 1) {
    if (!Number.isFinite(this.minRtt) || this.bw <= 0) {
      return initialWindow(this.maxDatagramSize);
    }
    return Math.max(this.minPipeCwnd, Math.floor(this.bw * this.minRtt * gain));
  }

  /** Bir sonraki gönderimde hedeflenen uçuş miktarı. */
  targetInflight(gain = this.cwndGain) {
    return Math.min(this.bdp(gain) + this.extraAcked, this.inflightHi, this.inflightLo);
  }

  // -------------------------------------------------------------------------
  // Gönderim
  // -------------------------------------------------------------------------
  onPacketSent({ bytesInFlight, now }) {
    if (bytesInFlight === 0) {
      // Hat boşaldı: sonraki ACK'lerden alınacak ilk örnek "yeniden başlıyor"
      // demektir; ProbeRTT sayacını burada tazelemek gerekiyor.
      this.idleRestart = true;
      this.ackEpochStamp = now;
      this.ackEpochAcked = 0;
    }
  }

  // -------------------------------------------------------------------------
  // ACK — modelin tamamı burada güncellenir
  // -------------------------------------------------------------------------
  /**
   * @param {object} ctx
   * @param {object} ctx.rs          teslim hızı örneği (RateSampler.endAck)
   * @param {number} ctx.delivered   bağlantı ömrü teslim toplamı
   * @param {number} ctx.bytesInFlight ACK işlendikten SONRA uçuştaki bayt
   * @param {number} ctx.bytesLost   bu turda kaybedilen bayt
   * @param {number} ctx.minRtt      RFC 9002 min_rtt (ms)
   * @param {number} ctx.now
   */
  onAck(ctx) {
    const {
      rs, delivered, bytesInFlight, now,
    } = ctx;

    this._updateRound(delivered, rs);
    this._updateMinRtt(ctx);
    this._updateMaxBw(rs);
    this._updateAckAggregation(ctx);
    this._updateCongestionSignals(ctx);

    if (!this.filledPipe) this._checkStartupDone(ctx);
    this._checkDrain(bytesInFlight, now);
    this._updateProbeBwCycle(ctx);
    this._checkProbeRtt(ctx);

    this._advanceLatest(rs);
    this._setPacingRate();
    this._setCwnd(ctx);
  }

  // ---- tur sayacı ---------------------------------------------------------
  _updateRound(delivered, rs) {
    // Bir "tur" (round trip), turun başında gönderilmiş son paketin ACK'lendiği
    // andır. Zamanla değil TESLİM SAYACIYLA ölçmek, RTT dalgalansa bile tur
    // sınırlarını kaydırmaz.
    this.roundStart = rs.valid && rs.priorDelivered >= this.nextRoundDelivered;
    if (this.roundStart) {
      this.nextRoundDelivered = delivered;
      this.roundCount++;
      this.roundsSinceProbe++;
      // Hat boşalıp yeniden başlamıştı; bir tur tamamlandığına göre artık
      // normal akıştayız. Bayrak temizlenmezse ProbeRTT'ye bir daha hiç
      // girilmez.
      this.idleRestart = false;
    }
  }

  // ---- min_rtt ------------------------------------------------------------
  _updateMinRtt({ latestRtt, now }) {
    if (!(latestRtt > 0)) return;

    // v3: iki ayrı süzgeç. `probeRttMinDelay` kısa pencereli (ProbeRTT
    // zamanlaması için), `minRtt` uzun pencereli (modelin kendisi için).
    if (latestRtt < this.probeRttMinDelay || now - this.probeRttMinStamp > this.cfg.probeRttIntervalMs) {
      this.probeRttMinDelay = latestRtt;
      this.probeRttMinStamp = now;
    }
    // Bayatlama BİR KEZ hesaplanır ve bayrak olarak saklanır. Aşağıda damga
    // tazelendiği için, ProbeRTT kararında yeniden hesaplansaydı hep "taze"
    // çıkardı ve ProbeRTT'ye hiç girilmezdi.
    this.minRttExpired = now - this.minRttStamp > this.cfg.minRttWindowMs;

    // KESİN KÜÇÜK (`<`) olmalı, `<=` değil. Eşit örnekle damgayı tazelemek,
    // gecikmesi hiç değişmeyen kararlı bir hatta süzgecin ASLA bayatlamamasına
    // yol açar; o zaman yol boyunca kalıcı bir kuyruk oluşsa bile min_rtt bunu
    // fark edemez.
    if (latestRtt < this.minRtt || this.minRttExpired || this.minRtt === Infinity) {
      this.minRtt = this.minRttExpired
        ? Math.min(this.probeRttMinDelay, latestRtt)
        : Math.min(this.minRtt, latestRtt);
      this.minRttStamp = now;
    }
  }

  // ---- bant genişliği -----------------------------------------------------
  _updateMaxBw(rs) {
    if (!rs.valid || rs.deliveryRate <= 0) return;
    this.bwLatest = Math.max(this.bwLatest, rs.deliveryRate);

    // UYGULAMA SINIRLI örnek tahmini YÜKSELTMEZ ama düşürmesine de izin
    // verilmez: veri üretemediğimiz için yavaş görünen bir hat, yavaş bir hat
    // değildir. BBR'ın en sık yanlış uygulanan kuralı budur.
    if (rs.isAppLimited && rs.deliveryRate < this.maxBw) return;

    this.maxBw = this.maxBwFilter.update(this.cycleCount, rs.deliveryRate);
  }

  // ---- ACK yığılması (extra_acked) ---------------------------------------
  /**
   * Wi-Fi ve mobil ağlar ACK'leri biriktirip toplu gönderir. O anda pencere
   * yalnızca BDP kadarsa hat, ACK'ler gelene kadar boş kalır. v3 bu farkı
   * ölçüp pencereye ekler: "beklenen teslim" ile "gerçekleşen teslim" arasındaki
   * fazlanın 5 turluk pencereli maksimumu.
   */
  _updateAckAggregation({ ackedBytes = 0, now }) {
    if (this.bw <= 0 || ackedBytes <= 0) return;
    if (this.ackEpochStamp === 0) { this.ackEpochStamp = now; this.ackEpochAcked = 0; }

    // GERÇEKTEN yeni ACK'lenen bayt kullanılmalı — teslim hızı örneğinin
    // `delivered` alanı ardışık ACK'ler arasında ÖRTÜŞÜR (her örnek kendi
    // aralığının tamamını sayar). Onu biriktirmek toplamı katlayarak şişirir
    // ve pencereye eklenen "fazlalık" terimini anlamsız bir sayıya çevirir.
    const epochMs = Math.max(1, now - this.ackEpochStamp);
    const expected = this.bw * epochMs;
    this.ackEpochAcked += ackedBytes;

    if (this.ackEpochAcked <= expected) {
      // Yığılma yok: dönemi yeniden başlat.
      this.ackEpochStamp = now;
      this.ackEpochAcked = ackedBytes;
      return;
    }
    // Telafi payı BDP ile sınırlı: ACK yığılması pencereyi ikiye katlayabilir,
    // sınırsız büyütemez.
    const extra = Math.min(this.ackEpochAcked - expected, this.bdp(1));
    this.extraAcked = this.extraAckedFilter.update(this.roundCount, extra);
  }

  // ---- kayıp sinyalleri ---------------------------------------------------
  /**
   * Kayıp değerlendirmesi TUR BAŞINADIR, ACK başına değil.
   *
   * Tek bir ACK yığını birkaç paketi kapsar; oradaki kayıp oranı istatistiksel
   * gürültüdür. Kararı tur sonunda, yeterli örnekle vermek BBRv3'ün kayıp
   * duyarlılığını gerçek bir sinyale bağlar.
   */
  _updateCongestionSignals({ rs, ackedBytes = 0, bytesLost = 0, delivered }) {
    this.roundAckedBytes += ackedBytes;
    this.roundLostBytes += bytesLost;
    if (bytesLost > 0) { this.lossInRound = true; this.lossEventsInRound++; }

    this.lossRoundStart = rs.valid && rs.priorDelivered >= this.lossRoundDelivered;
    if (!this.lossRoundStart) { this.lossRateThisRound = 0; return; }
    this.lossRoundDelivered = delivered;

    const total = this.roundAckedBytes + this.roundLostBytes;
    const enough = total >= this.cfg.minLossSamplePackets * this.maxDatagramSize;
    this.lossRateThisRound = (enough && total > 0) ? this.roundLostBytes / total : 0;
    // Turun teslim ettiği bayt, o turda boruya SIĞAN miktarın ölçüsüdür.
    if (this.roundAckedBytes > 0) {
      this.inflightLatest = Math.max(this.roundAckedBytes, this.minPipeCwnd);
    }

    // Kayıp oranı eşiği aştıysa KISA VADELİ üst sınırlar (bw_lo/inflight_lo)
    // düşer. Uzun vadeli tavana (hi) burada dokunulmaz — o yalnızca yoklama
    // evresinde, bilerek yükseltilirken sınanır.
    if (this.lossRateThisRound > this.cfg.lossThresh) {
      this.congestionEvents++;
      // Alt sınır KENDİ önceki değerinden çarpımsal olarak iner ama GERÇEKTEN
      // BAŞARILMIŞ değerin altına asla düşmez. `latest * beta` yazmak — yani
      // az önce elde edilen hızın %70'ini tavan yapmak — her turda bir kademe
      // daha aşağı iner ve birkaç turda hattı kilitler.
      const bwBase = Number.isFinite(this.bwLo) ? this.bwLo : this.maxBw;
      this.bwLo = Math.max(this.bwLatest, bwBase * this.cfg.beta, this._minBw());

      const inflightBase = Number.isFinite(this.inflightLo)
        ? this.inflightLo
        : Math.max(this.bdp(1), this.inflightLatest);
      this.inflightLo = Math.max(
        this.inflightLatest,
        Math.floor(inflightBase * this.cfg.beta),
        this.minPipeCwnd,
      );
    } else if (!this.lossInRound) {
      // Temiz bir tur: kısa vadeli sınırları serbest bırak, model yeniden
      // yukarı yoklayabilsin.
      this.bwLo = Infinity;
      this.inflightLo = Infinity;
    }
    this.lossInRound = false;
    this.lossEventsInRound = 0;
    this.roundAckedBytes = 0;
    this.roundLostBytes = 0;
  }

  _minBw() { return this.maxDatagramSize / Math.max(this.minRtt, this.initialRtt); }

  _advanceLatest(rs) {
    if (!this.roundStart) return;
    this.bwLatest = rs.valid ? rs.deliveryRate : this.bwLatest;
    this.inflightLatest = rs.valid ? rs.delivered : this.inflightLatest;
  }

  // ---- başlangıç ----------------------------------------------------------
  /**
   * Başlangıçtan çıkış ölçütü ikilidir (v3):
   *   • bant genişliği 3 turda %25'ten az büyüdü → boru doldu
   *   • ya da 8 ardışık turda kayıp görüldü → sığ tamponlu hat, kuyruğu
   *     doldurmadan çık
   */
  _checkStartupDone(ctx) {
    if (this.state !== BBR_STATE.STARTUP) return;

    // Kayıplı turları say: sığ tamponlu bir hatta bant genişliği daha
    // düzleşmeden kuyruk taşar. O noktada büyümeye devam etmek, veri değil
    // yalnızca kayıp üretir.
    if (this.lossRoundStart && this.lossRateThisRound > this.cfg.lossThresh) {
      this.lossRoundsInStartup++;
    }
    if (!this.roundStart) return;

    if (this.maxBw >= this.fullBw * this.cfg.fullBwThresh) {
      this.fullBw = this.maxBw;
      this.fullBwCount = 0;
    } else if (!ctx.rs.isAppLimited) {
      // Uygulama sınırlı turlar sayılmaz: veri veremediğimiz için büyümeyen
      // bant genişliği, hattın tavanı değildir.
      this.fullBwCount++;
    }

    if (this.fullBwCount >= this.cfg.fullBwCnt) {
      this.filledPipe = true;
      this.startupExitReason = 'bandwidth-plateau';
    } else if (this.lossRoundsInStartup >= this.cfg.fullLossCnt) {
      this.filledPipe = true;
      this.startupExitReason = 'loss';
      this.inflightHi = Math.max(this.inflightLatest, this.minPipeCwnd);
    }

    if (!this.filledPipe) return;
    this._enterDrain();
  }

  _enterDrain() {
    this.state = BBR_STATE.DRAIN;
    this.pacingGain = this.cfg.drainPacingGain;
    this.cwndGain = this.cfg.startupCwndGain;
    // Başlangıçta uçuşa çıkan fazlalık, hattın gerçek kapasitesinin üst
    // sınırıdır: modelin uzun vadeli tavanını buradan kur.
    if (this.inflightHi === Infinity) this.inflightHi = Math.max(this.cwnd, this.bdp(1));
  }

  _checkDrain(bytesInFlight, now) {
    if (this.state !== BBR_STATE.DRAIN) return;
    // Kuyruk boşaldı (uçuş ≤ BDP) → sabit hızda seyre geç.
    if (bytesInFlight > this.bdp(1)) return;
    this._enterProbeBwDown(now);
  }

  // ---- ProbeBW döngüsü ----------------------------------------------------
  _enterProbeBwDown(now) {
    // Yeni çevrim: bant genişliği süzgecinin penceresi bir kademe kayar.
    this.cycleCount++;
    this.state = BBR_STATE.PROBE_BW_DOWN;
    this.pacingGain = this.cfg.probeDownPacingGain;
    this.cwndGain = this.cfg.cwndGain;
    this.cycleStamp = now;
    this.bwProbeSamples = 0;
    this._pickProbeWait(now);
  }

  _pickProbeWait(now) {
    // Rastgelelik şart: sabit bir periyot, aynı darboğazı paylaşan iki akışın
    // sonsuza kadar aynı fazda yoklama yapmasına ve birbirini görmemesine yol
    // açar (faz kilitlenmesi).
    this.probeWaitUntil = now + this.cfg.bwProbeWaitMs + Math.random() * this.cfg.bwProbeRandMs;
    this.roundsSinceProbe = 0;
    this.probeRounds = this.cfg.bwProbeBaseRounds
      + Math.floor(Math.random() * (this.cfg.bwProbeRandRounds + 1));
  }

  _updateProbeBwCycle(ctx) {
    const { bytesInFlight, now } = ctx;
    switch (this.state) {
      case BBR_STATE.PROBE_BW_DOWN: {
        // İNİŞ EVRESİNİN TEK İŞİ KUYRUĞU BOŞALTMAK.
        //
        // İki koşul birden aranır ve ikincisi hayatidir:
        //   • uçuş, tavanın pay bırakılmış seviyesinin altında
        //   • uçuş ≤ BDP — yani darboğazda BEKLEYEN veri kalmadı
        //
        // Yalnızca birinciye bakmak, her çevrimde bir BDP'lik kalıcı kuyruğun
        // hiç boşaltılmadan taşınması demektir: BBR'ın "kuyruk oluşturmam"
        // sözü tam olarak burada tutulur ya da tutulmaz.
        const drained = bytesInFlight <= this._inflightWithHeadroom()
          && bytesInFlight <= this.bdp(1);
        // Model yanlışsa (BDP olduğundan küçük tahmin edilmişse) iniş evresi
        // sonsuza kadar sürebilirdi; zaman sınırı bunu bağlar.
        const tooLong = now - this.cycleStamp > Math.max(8 * this.minRtt, 100);
        if (drained || tooLong) {
          this.state = BBR_STATE.PROBE_BW_CRUISE;
          this.pacingGain = this.cfg.probeCruisePacingGain;
          this.cycleStamp = now;
        }
        return;
      }

      case BBR_STATE.PROBE_BW_CRUISE:
        if (now >= this.probeWaitUntil && this.roundsSinceProbe >= this.probeRounds) {
          this.state = BBR_STATE.PROBE_BW_REFILL;
          this.pacingGain = this.cfg.probeRefillPacingGain;
          this.cycleStamp = now;
          // Yoklamadan önce kısa vadeli sınırları kaldır: yoklamanın amacı
          // zaten bunların hâlâ geçerli olup olmadığını sınamak.
          this.bwLo = Infinity;
          this.inflightLo = Infinity;
          this.bwProbeSamples = 0;
        }
        return;

      case BBR_STATE.PROBE_BW_REFILL:
        // Boruyu bir tur boyunca hedef hızda doldur, sonra yukarı yokla.
        if (this.roundStart) {
          this.state = BBR_STATE.PROBE_BW_UP;
          this.pacingGain = this.cfg.probeUpPacingGain;
          this.cycleStamp = now;
          this.inflightAtProbeStart = bytesInFlight;
          this.bwProbeSamples = 1;
        }
        return;

      case BBR_STATE.PROBE_BW_UP: {
        // Yoklama, ya kayıp/aşırı uçuş görülünce ya da bir tur dolunca biter.
        if (this._isInflightTooHigh()) {
          // Tavan, BAŞARILMIŞ uçuş miktarının altına indirilmez. Yoklama
          // sırasında görülen kayıp "bu seviyeye çıkma" der, "az önce
          // taşıdığın kadarını da taşıyamazsın" demez.
          this.inflightHi = Math.max(
            this.inflightLatest,
            Math.floor(this.bdp(1) * this.cfg.beta),
            this.minPipeCwnd,
          );
          this._enterProbeBwDown(now);
          return;
        }
        if (this.roundStart) {
          // Bir tur temiz geçti: tavanı yukarı taşı ve seyre dön.
          this.inflightHi = Math.max(this.inflightHi === Infinity ? 0 : this.inflightHi,
                                     bytesInFlight);
          this._enterProbeBwDown(now);
        }
        return;
      }

      default:
    }
  }

  _inflightWithHeadroom() {
    if (this.inflightHi === Infinity) return this.bdp(1);
    return Math.max(
      Math.floor(this.inflightHi * (1 - this.cfg.headroom)),
      this.minPipeCwnd,
    );
  }

  /**
   * Yoklama fazla mı ileri gitti? Ölçüt, tur sonunda hesaplanmış kayıp
   * oranıdır (_updateCongestionSignals); ACK başına bakmak, rastgele kayıplı
   * hatlarda yoklamayı hiç tamamlanamaz hâle getirirdi.
   */
  _isInflightTooHigh() {
    return this.lossRoundStart && this.lossRateThisRound > this.cfg.lossThresh;
  }

  // ---- ProbeRTT -----------------------------------------------------------
  /**
   * min_rtt yalnızca hat BOŞKEN ölçülebilir. 10 saniyedir tazelenmediyse
   * pencereyi kısa bir süre (200 ms) yarı BDP'ye indirip gerçek gecikmeyi
   * ölçeriz. Bu, BBR'ın kuyruk oluşturmama sözünün bedelini ödediği yerdir:
   * saniyede %2'den az verim kaybı karşılığında model doğru kalır.
   */
  _checkProbeRtt(ctx) {
    const { now, bytesInFlight } = ctx;

    if (this.state !== BBR_STATE.PROBE_RTT
        && this.filledPipe
        && this.minRttExpired
        && !this.idleRestart) {
      this.priorState = this.state;
      this.priorCwnd = this.cwnd;
      this.state = BBR_STATE.PROBE_RTT;
      this.pacingGain = 1.0;
      this.probeRttDoneStamp = 0;
      this.probeRttRoundDone = false;
      this.probeRttCount++;
      return;
    }

    if (this.state !== BBR_STATE.PROBE_RTT) return;

    const target = Math.max(this.bdp(this.cfg.probeRttCwndGain), this.minPipeCwnd);
    if (this.probeRttDoneStamp === 0 && bytesInFlight <= target) {
      this.probeRttDoneStamp = now + this.cfg.probeRttDurationMs;
      this.probeRttRoundDone = false;
      this.nextRoundDelivered = ctx.delivered;
      return;
    }
    if (this.probeRttDoneStamp === 0) return;

    if (this.roundStart) this.probeRttRoundDone = true;
    if (!this.probeRttRoundDone || now < this.probeRttDoneStamp) return;

    // Ölçüm bitti: min_rtt tazelendi, eski duruma dön.
    this.minRttStamp = now;
    this.minRtt = Math.min(this.minRtt, this.probeRttMinDelay);
    if (this.filledPipe) this._enterProbeBwDown(now);
    else { this.state = BBR_STATE.STARTUP; this.pacingGain = this.cfg.startupPacingGain; }
    this.cwnd = Math.max(this.cwnd, this.priorCwnd);
  }

  // ---- çıktı: hız ve pencere ---------------------------------------------
  _setPacingRate() {
    if (this.bw <= 0) { this.pacingRate = Infinity; return; }
    // bayt/ms → bayt/s; %1 pay, hedefin hafif altında kalıp kuyruk
    // oluşturmamak için.
    const rate = this.bw * 1000 * this.pacingGain * (1 - this.cfg.pacingMargin);
    // Başlangıçta hız asla DÜŞMEZ: ilk turlarda tahmin gürültülüdür ve
    // düşürmek büyümeyi durdurur.
    if (this.state === BBR_STATE.STARTUP && Number.isFinite(this.pacingRate)) {
      this.pacingRate = Math.max(this.pacingRate, rate);
      return;
    }
    this.pacingRate = Math.max(rate, this.maxDatagramSize * 4);
  }

  /**
   * Pencere BBR'da bir HEDEF değil TAVANDIR: gönderim hızını pacer belirler,
   * pencere yalnızca ACK saati bozulduğunda (ACK yığılması, kayıp) uçuşun
   * sınırsız büyümesini engeller. Bu yüzden ACK'lenen kadar büyür ve hedefte
   * kırpılır — hedefe sıçramaz.
   */
  _setCwnd({ ackedBytes = 0 }) {
    const floor = this.minPipeCwnd;

    if (this.state === BBR_STATE.PROBE_RTT) {
      // Ölçüm için bilerek kısıyoruz; büyütme yok.
      this.cwnd = Math.max(Math.min(this.cwnd, this.bdp(this.cfg.probeRttCwndGain)), floor);
      return;
    }

    if (!this.filledPipe) {
      // Başlangıç: hedef, kazançla ölçeklenmiş BDP. Hedefin ALTINDAYKEN
      // ACK'lenen kadar büyür; üstündeyse olduğu yerde kalır (küçültmek,
      // henüz öğrenilmemiş bir tavana göre karar vermek olurdu).
      const target = Math.max(
        this.bdp(this.cwndGain) + this.extraAcked,
        initialWindow(this.maxDatagramSize),
      );
      if (this.cwnd < target) this.cwnd = Math.min(this.cwnd + ackedBytes, target);
      this.cwnd = Math.max(Math.floor(this.cwnd), floor);
      return;
    }

    let target = this.targetInflight();
    // Pay YALNIZCA iniş evresinde uygulanır: amacı kuyruğu boşaltmak. Seyir
    // evresinde de uygulamak, tavanın %15 altında kalıcı olarak gezinmek —
    // yani hattın bir kısmını her zaman boş bırakmak — olurdu.
    if (this.state === BBR_STATE.PROBE_BW_DOWN) {
      target = Math.min(target, this._inflightWithHeadroom());
    }
    this.cwnd = Math.max(Math.floor(Math.min(this.cwnd + ackedBytes, target)), floor);
  }

  // ---- kayıp / PTO --------------------------------------------------------
  onLoss({ bytesLost }) {
    // Kaybın kendisi burada pencere küçültmez: BBR'ın kayıp tepkisi TUR
    // BAŞINA, oran üzerinden verilir (_updateCongestionSignals). Anlık tepki,
    // rastgele bit hatası olan hatlarda tam olarak NewReno'nun hatasını
    // tekrarlamak olurdu.
    void bytesLost;
  }

  onPtoExpired() { /* sonda kayıp bildirimi değildir */ }

  onPersistentCongestion() {
    // Ağ gerçekten koptu: model artık geçmişin fotoğrafı. Sıfırdan öğren.
    this.maxBwFilter = new WindowedFilter(2, 1);
    this.maxBw = 0;
    this.bwLatest = 0;
    this.bwLo = Infinity;
    this.bwHi = Infinity;
    this.inflightLo = Infinity;
    this.inflightHi = Infinity;
    this.extraAcked = 0;
    this.filledPipe = false;
    this.fullBw = 0;
    this.fullBwCount = 0;
    this.lossRoundsInStartup = 0;
    this.state = BBR_STATE.STARTUP;
    this.pacingGain = this.cfg.startupPacingGain;
    this.cwndGain = this.cfg.startupCwndGain;
    this.cwnd = this.minPipeCwnd;
    this.pacingRate = Infinity;
  }

  snapshot() {
    const bwBps = this.bw > 0 ? Math.round(this.bw * 1000) : null;
    return {
      cc: 'bbr3',
      congestionWindow: this.cwnd,
      ssthresh: null,
      state: this.state,
      pacingRateBps: Number.isFinite(this.pacingRate) ? Math.round(this.pacingRate) : null,
      bandwidthBps: bwBps,
      pacingGain: +this.pacingGain.toFixed(2),
      cwndGain: +this.cwndGain.toFixed(2),
      bdp: this.bw > 0 && Number.isFinite(this.minRtt) ? Math.round(this.bw * this.minRtt) : null,
      extraAcked: Math.round(this.extraAcked),
      inflightHi: Number.isFinite(this.inflightHi) ? Math.round(this.inflightHi) : null,
      inflightLo: Number.isFinite(this.inflightLo) ? Math.round(this.inflightLo) : null,
      filledPipe: this.filledPipe,
      startupExit: this.startupExitReason,
      rounds: this.roundCount,
      probeRttCount: this.probeRttCount,
      congestionEvents: this.congestionEvents,
    };
  }
}

// ===========================================================================
const CONTROLLERS = Object.freeze({
  newreno: NewRenoController,
  reno: NewRenoController,
  bbr: Bbr3Controller,
  bbr3: Bbr3Controller,
  bbrv3: Bbr3Controller,
});

/**
 * @param {string} name 'bbr3' | 'newreno'
 * @param {object} opts { maxDatagramSize, initialRtt, bbr }
 */
function createCongestionController(name, opts = {}) {
  const key = String(name || 'bbr3').toLowerCase();
  const Ctor = CONTROLLERS[key];
  if (!Ctor) {
    throw new Error(
      `bilinmeyen tıkanıklık denetleyicisi: '${name}' — `
      + `desteklenenler: ${Object.keys(CONTROLLERS).join(', ')}`,
    );
  }
  return new Ctor(opts);
}

module.exports = {
  createCongestionController,
  NewRenoController,
  Bbr3Controller,
  RateSampler,
  WindowedFilter,
  BBR_STATE,
  BBR_DEFAULTS,
  initialWindow,
  minimumWindow,
  kLossReductionFactor,
};
