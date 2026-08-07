'use strict';
// Kayıp tespiti ve tıkanıklık denetimi — RFC 9002 (QUIC Loss Detection and
// Congestion Control) uyarlaması + BBRv3 tıkanıklık modeli.
//
// Neden RFC 9002? "Kaybolan paketi yeniden gönder" tek başına bir kurtarma
// stratejisi DEĞİLDİR. Ağır kayıp altında (%50 gibi) naif bir zamanlayıcı
// şu üç tuzağa düşer:
//
//   1. TEK PAKET KURTARMA — zaman aşımında yalnızca en eski paketi göndermek,
//      N kayıp paketi kurtarmak için N tur bekletir. RFC 9002 §6.1 bunun
//      yerine ACK bilgisinden TÜM kayıpları aynı anda çıkarır.
//   2. KÖR ÜSTEL GERİ ÇEKİLME — her zaman aşımında RTO'yu ikiye katlamak,
//      kayıp tıkanıklıktan değil hattan geliyorsa kurtarmayı durdurur.
//      RFC 9002 §6.2 bunu PTO ile ayırır: PTO yalnızca "sonda" (probe)
//      gönderir, kayıp İLAN ETMEZ ve tıkanıklık penceresini küçültmez.
//   3. AÇIK DÖNGÜ GÖNDERİM — sabit `maxInFlight` ne ağın kapasitesini
//      kullanır ne de tıkanıklığa tepki verir.
//
// Bu modül DÖRT kavramı ayrı tutar:
//   • RTT tahmini      §5   — smoothed_rtt / rttvar / min_rtt, ack_delay düşülür
//   • Kayıp tespiti    §6   — paket eşiği (3) + zaman eşiği (9/8 × RTT) + PTO
//   • Tıkanıklık       §7   — TAKILABİLİR: BBRv3 (varsayılan) ya da NewReno
//   • Hız şekillendirme      pacer — pencereyi zamana yayar (BBR için zorunlu)
//
// Tıkanıklık denetiminin ayrı bir dosyada (congestion.js) ve takılabilir
// olmasının sebebi: kayıp tespiti bir PROTOKOL kuralıdır, tıkanıklık denetimi
// bir POLİTİKADIR. İkisini aynı sınıfta birleştirmek, politikayı değiştirmek
// isteyen herkesi protokole dokunmaya zorlar.
//
// QUIC'ten devralınan can alıcı tasarım kuralı: YENİDEN GÖNDERİLEN VERİ YENİ
// BİR PAKET NUMARASI ALIR. Böylece her ACK tek bir gönderime karşılık gelir ve
// RTT örneği belirsizliğe düşmez (Karn algoritmasına gerek kalmaz).

const {
  createCongestionController, RateSampler,
  initialWindow, minimumWindow, kLossReductionFactor,
} = require('./congestion.js');
const { Pacer } = require('./pacing.js');
const { now: monotonicNow } = require('./clock.js');

const kPacketThreshold = 3;             // RFC 9002 §6.1.1
const kTimeThreshold = 9 / 8;           // RFC 9002 §6.1.2
const kGranularity = 1;                 // ms — zamanlayıcı çözünürlüğü
const kInitialRtt = 333;                // ms — RFC 9002 §6.2.2
const kPersistentCongestionThreshold = 3; // RFC 9002 §7.6

/** Varsayılan tıkanıklık denetleyicisi. Gerekçesi congestion.js başında. */
const DEFAULT_CONGESTION_CONTROL = 'bbr3';

class LossRecovery {
  /**
   * @param {object} o
   * @param {number} [o.maxDatagramSize]  tıkanıklık penceresi bayt biriminde
   * @param {number} [o.maxAckDelay]      karşı tarafın bildirdiği azami ACK gecikmesi
   * @param {number} [o.initialRtt]
   * @param {number} [o.minPto]           PTO alt sınırı (test/LAN için)
   * @param {number} [o.maxPto]           PTO üst sınırı
   * @param {'bbr3'|'newreno'} [o.congestionControl]
   * @param {boolean} [o.pacing]          BBR ile varsayılan açık
   * @param {object} [o.bbr]              BBR ince ayarları (congestion.js)
   */
  constructor({
    maxDatagramSize = 1200, maxAckDelay = 25, initialRtt = kInitialRtt,
    minPto = 2 * kGranularity, maxPto = 8_000,
    congestionControl = DEFAULT_CONGESTION_CONTROL, pacing, bbr,
  } = {}) {
    this.maxDatagramSize = maxDatagramSize;
    this.maxAckDelay = maxAckDelay;
    this.minPto = minPto;
    this.maxPto = maxPto;

    // --- RTT (RFC 9002 §5)
    this.latestRtt = 0;
    this.minRtt = Infinity;
    this.smoothedRtt = initialRtt;
    this.rttvar = initialRtt / 2;
    this.hasRttSample = false;
    this.firstRttSampleTime = 0;

    // --- kayıp tespiti (§6)
    this.sent = new Map();          // pn -> { bytes, sentTime, ackEliciting, inFlight, meta }
    this.largestAckedPacket = -1;
    this.timeOfLastAckElicitingPacket = 0;
    this.lossTime = 0;              // 0 = ayarlanmamış
    this.ptoCount = 0;

    // --- tıkanıklık (§7) — takılabilir
    this.cc = createCongestionController(congestionControl, {
      maxDatagramSize, initialRtt, bbr,
    });
    this.bytesInFlight = 0;

    // --- hız şekillendirme
    // NewReno pacer istemiyorsa kapalı kalır: pencere zaten patlamayı
    // sınırlıyor ve NewReno'nun ölçtüğü bir hedef hız yok.
    const wantPacing = pacing === undefined ? this.cc.name === 'bbr3' : !!pacing;
    this.pacer = wantPacing ? new Pacer({ maxDatagramSize }) : null;
    this.rateSampler = new RateSampler();

    this.stats = {
      packetsSent: 0, packetsAcked: 0, packetsLost: 0, probesSent: 0,
      congestionEvents: 0, persistentCongestion: 0, spuriousLoss: 0,
      bytesLost: 0, unpacedBytes: 0,
    };
  }

  // ==========================================================================
  // Pencere — denetleyiciye vekâlet
  // ==========================================================================
  get congestionWindow() { return this.cc.cwnd; }
  set congestionWindow(v) { this.cc.cwnd = v; }

  /** NewReno'da eşik, BBR'da null (kavram yok). */
  get ssthresh() { return this.cc.ssthresh === undefined ? Infinity : this.cc.ssthresh; }
  set ssthresh(v) { this.cc.ssthresh = v; }

  get congestionControl() { return this.cc.name; }

  /** Hedef gönderim hızı (bayt/s) — şekillendirme kapalıysa null. */
  get pacingRate() {
    return this.pacer && this.pacer.enabled ? this.pacer.rate : null;
  }

  // ==========================================================================
  // Gönderim
  // ==========================================================================
  /**
   * @param {object} o
   * @param {number} o.pn            paket numarası (monoton artan)
   * @param {number} o.bytes
   * @param {boolean} [o.ackEliciting] ACK bekleyen bir paket mi (ACK çerçeveleri hariç her şey)
   * @param {*} [o.meta]             çağıranın kayıt tuttuğu veri (hangi parça?)
   */
  onPacketSent({ pn, bytes, ackEliciting = true, meta = null, now = monotonicNow() }) {
    const entry = { pn, bytes, sentTime: now, ackEliciting, inFlight: ackEliciting, meta };

    // Teslim hızı örneklemesi paketin ÜZERİNE yazılır: ACK geldiğinde o anki
    // bağlantı durumuyla karşılaştırılıp gerçek teslim hızı çıkarılır.
    this.rateSampler.onPacketSent(entry, this.bytesInFlight, now);
    this.cc.onPacketSent({ entry, bytesInFlight: this.bytesInFlight, now });

    this.sent.set(pn, entry);
    this.stats.packetsSent++;
    if (entry.inFlight) {
      this.bytesInFlight += bytes;
      this.timeOfLastAckElicitingPacket = now;
    }
    if (this.pacer) this.pacer.onSent(bytes, now);
    return entry;
  }

  /** Tıkanıklık penceresinde kalan yer (bayt). Negatif olabilir. */
  available() { return this.cc.cwnd - this.bytesInFlight; }

  /** Pencere bu boyutta bir pakete yer veriyor mu (hız şekillendirme HARİÇ). */
  hasCongestionRoom(bytes) {
    // Pencere tamamen doluyken bile en az bir paket akmalı; aksi hâlde
    // ilk kayıp sonrası bağlantı kalıcı olarak kilitlenebilir.
    return this.bytesInFlight === 0 || this.bytesInFlight + bytes <= this.cc.cwnd;
  }

  /** Bu boyutta bir paket şu an gönderilebilir mi (pencere + hız). */
  canSend(bytes, now = monotonicNow()) {
    if (!this.hasCongestionRoom(bytes)) return false;
    if (!this.pacer) return true;
    return this.pacer.canSend(bytes, now);
  }

  /**
   * Hız şekillendiricinin izin vermesine kalan süre (ms).
   * @returns {number} 0 = şimdi gönderilebilir
   */
  pacingDelay(bytes, now = monotonicNow()) {
    if (!this.pacer) return 0;
    return this.pacer.delayUntilSend(bytes, now);
  }

  /**
   * Hız şekillendiriciyi BEKLETMEDEN geçen bir gönderim (güvenilir olmayan
   * datagram, gecikmeye duyarlı yük).
   *
   * Beklemez ama sayılır: o baytlar da darboğazdan geçiyor. Sayılmasaydı
   * güvenilir taraf hattı olduğundan boş sanıp üstüne gönderir ve toplam hız
   * darboğazı aşardı — gerçek zamanlı trafiği korumak için eklenen ayrıcalık,
   * herkesin gecikmesini artırarak tam tersini yapardı.
   */
  noteUnpacedSend(bytes, now = monotonicNow()) {
    this.stats.unpacedBytes += bytes;
    if (this.pacer) this.pacer.onSent(bytes, now);
  }

  /**
   * Hız şekillendirme zamanlayıcısı uyandı: İSTENEN ve GERÇEKLEŞEN gecikme.
   *
   * Şekillendiricinin jeton kovası, iki uyanma arasında biriken hakkın
   * tavanıdır. Tavanı sabit (≈1 ms) varsaymak, `setTimeout(1)`'in gerçekten
   * 1 ms sürdüğünü varsaymaktır; Windows'ta bu süre ~15.6 ms'dir ve aradaki
   * fark doğrudan verim kaybına dönüşür (gerekçe ve aritmetik: pacing.js).
   * Burada ölçümü şekillendiriciye geri veriyoruz ki kova o makinenin gerçek
   * uyanma aralığına göre boyutlansın.
   *
   * @param {number} requestedMs istenen gecikme
   * @param {number} actualMs    monotonik saatle ölçülen gerçek gecikme
   */
  noteTimerWake(requestedMs, actualMs, now = monotonicNow()) {
    if (this.pacer) this.pacer.observeTimerWake(requestedMs, actualMs, now);
  }

  /**
   * Gönderecek veri kalmadı: bundan sonraki teslim hızı örnekleri AĞIN değil
   * UYGULAMANIN sınırını ölçer. İşaretlenmezse BBR, boş kalan hattı yavaş bir
   * hat sanır ve hızı kalıcı olarak düşürür.
   */
  markAppLimited() {
    this.rateSampler.markAppLimited(this.bytesInFlight);
  }

  get isAppLimited() { return this.rateSampler.isAppLimited; }

  // ==========================================================================
  // ACK işleme — RFC 9002 §5.1, §6.1
  // ==========================================================================
  /**
   * @param {object} o
   * @param {Array<[number,number]>} o.ranges  ACK'lenen kapalı aralıklar
   * @param {number} [o.ackDelay]              gönderenin bildirdiği gecikme (ms)
   * @returns {{acked: object[], lost: object[]}}
   */
  onAckReceived({ ranges, ackDelay = 0, now = monotonicNow() }) {
    const acked = [];
    let largestNewlyAcked = -1;
    let largestNewlyAckedEntry = null;

    for (const [start, end] of ranges) {
      // Aralık genişliği çok büyük olabilir; gönderilenler kümesi küçüktür.
      if (end - start > this.sent.size) {
        for (const [pn, entry] of this.sent) {
          if (pn >= start && pn <= end) { acked.push(entry); this.sent.delete(pn); }
        }
      } else {
        for (let pn = start; pn <= end; pn++) {
          const entry = this.sent.get(pn);
          if (!entry) continue;
          acked.push(entry);
          this.sent.delete(pn);
        }
      }
    }
    if (acked.length === 0) return { acked, lost: [] };

    for (const e of acked) {
      if (e.pn > largestNewlyAcked) { largestNewlyAcked = e.pn; largestNewlyAckedEntry = e; }
    }
    if (largestNewlyAcked > this.largestAckedPacket) this.largestAckedPacket = largestNewlyAcked;

    // RTT örneği YALNIZCA en büyük yeni ACK'lenen paketten alınır (§5.1) ve
    // yalnızca o paket ACK bekleyen bir paketse.
    if (largestNewlyAckedEntry && largestNewlyAckedEntry.ackEliciting) {
      this._updateRtt(now - largestNewlyAckedEntry.sentTime, ackDelay, now);
    }

    // --- teslim hızı örneği: ACK'lenen paketler sırayla işlenir
    this.rateSampler.beginAck();
    let ackedBytes = 0;
    for (const e of acked) {
      if (e.inFlight) this.bytesInFlight -= e.bytes;
      ackedBytes += e.bytes;
      this.rateSampler.onPacketAcked(e, now);
    }
    this.stats.packetsAcked += acked.length;

    // Kayıp tespiti ACK'ten SONRA yapılır: ACK bilgisi olmadan hangi paketin
    // geride kaldığı bilinemez.
    const lost = this._detectAndRemoveLostPackets(now);
    let bytesLost = 0;
    if (lost.length) bytesLost = this._accountLoss(lost);

    const rs = this.rateSampler.endAck(this.hasRttSample ? this.minRtt : 0);

    const ctx = {
      acked,
      lost,
      rs,
      ackedBytes,
      delivered: this.rateSampler.delivered,
      bytesInFlight: this.bytesInFlight,
      bytesLost,
      packetsLost: lost.length,
      minRtt: this.hasRttSample ? this.minRtt : this.smoothedRtt,
      latestRtt: this.latestRtt,
      smoothedRtt: this.smoothedRtt,
      now,
    };

    this.cc.onAck(ctx);
    if (lost.length) this._applyLoss(lost, ctx);
    this._syncPacer();

    // İlerleme oldu → PTO geri çekilmesi sıfırlanır (§6.2.1).
    this.ptoCount = 0;
    return { acked, lost };
  }

  _updateRtt(rttSample, ackDelay, now) {
    this.latestRtt = Math.max(rttSample, kGranularity);

    if (!this.hasRttSample) {
      this.minRtt = this.latestRtt;
      this.smoothedRtt = this.latestRtt;
      this.rttvar = this.latestRtt / 2;
      this.hasRttSample = true;
      this.firstRttSampleTime = now;
      return;
    }

    this.minRtt = Math.min(this.minRtt, this.latestRtt);

    // ack_delay yalnızca gerçekten bekleme olduğunda düşülür; aksi hâlde
    // RTT olduğundan küçük tahmin edilir ve zamanlayıcılar erken tetiklenir.
    const delay = Math.min(ackDelay, this.maxAckDelay);
    let adjusted = this.latestRtt;
    if (this.latestRtt >= this.minRtt + delay) adjusted = this.latestRtt - delay;

    this.rttvar = 0.75 * this.rttvar + 0.25 * Math.abs(this.smoothedRtt - adjusted);
    this.smoothedRtt = 0.875 * this.smoothedRtt + 0.125 * adjusted;
  }

  /** Denetleyicinin hedef hızını şekillendiriciye aktarır. */
  _syncPacer() {
    if (!this.pacer) return;
    this.pacer.setRate(this.cc.pacingRate);
  }

  // ==========================================================================
  // Kayıp tespiti — RFC 9002 §6.1
  // ==========================================================================
  _detectAndRemoveLostPackets(now) {
    this.lossTime = 0;
    const lossDelay = Math.max(
      kTimeThreshold * Math.max(this.latestRtt, this.smoothedRtt),
      kGranularity,
    );
    const lostSendTime = now - lossDelay;
    const lost = [];

    for (const [pn, entry] of this.sent) {
      if (pn > this.largestAckedPacket) continue;   // henüz "geride kalmış" sayılmaz

      // İki ölçüt: zaman eşiği VEYA paket eşiği (§6.1.1, §6.1.2)
      if (entry.sentTime <= lostSendTime ||
          this.largestAckedPacket - pn >= kPacketThreshold) {
        this.sent.delete(pn);
        lost.push(entry);
      } else {
        // Henüz kayıp değil — zamanlayıcıyı en erken aday için kur.
        const t = entry.sentTime + lossDelay;
        this.lossTime = this.lossTime === 0 ? t : Math.min(this.lossTime, t);
      }
    }
    return lost;
  }

  // ==========================================================================
  // Zamanlayıcı — RFC 9002 §6.2
  // ==========================================================================
  /** Bir sonraki kayıp-tespiti zamanı (epoch ms) ya da null. */
  getLossDetectionTime() {
    if (this.lossTime !== 0) return this.lossTime;
    if (!this._hasAckElicitingInFlight()) return null;
    return this.timeOfLastAckElicitingPacket + this.currentPto();
  }

  /** PTO = smoothed_rtt + max(4·rttvar, granularity) + max_ack_delay, 2^pto_count katıyla. */
  currentPto() {
    const base = this.smoothedRtt + Math.max(4 * this.rttvar, kGranularity) + this.maxAckDelay;
    const backed = base * (2 ** this.ptoCount);
    return Math.min(this.maxPto, Math.max(this.minPto, Math.round(backed)));
  }

  _hasAckElicitingInFlight() {
    for (const e of this.sent.values()) if (e.inFlight) return true;
    return false;
  }

  /**
   * Zamanlayıcı doldu.
   * @returns {{lost: object[], probes: number}}
   *   `lost` boş ve `probes > 0` ise bu bir PTO'dur: kayıp İLAN EDİLMEZ,
   *   yalnızca ACK üretmek için sonda paketleri gönderilir (§6.2.4).
   */
  onLossDetectionTimeout(now = monotonicNow()) {
    if (this.lossTime !== 0 && this.lossTime <= now) {
      const lost = this._detectAndRemoveLostPackets(now);
      if (lost.length) {
        const bytesLost = this._accountLoss(lost);
        this._applyLoss(lost, {
          lost, bytesLost, packetsLost: lost.length, bytesInFlight: this.bytesInFlight, now,
        });
        this._syncPacer();
      }
      return { lost, probes: 0 };
    }
    if (!this._hasAckElicitingInFlight()) return { lost: [], probes: 0 };

    // PTO: ağın hâlâ ayakta olup olmadığını anlamak için iki sonda gönder.
    // Bu bir kayıp bildirimi DEĞİLDİR — pencere küçültülmez.
    this.ptoCount++;
    this.stats.probesSent += 2;
    this.cc.onPtoExpired({ now });
    return { lost: [], probes: 2 };
  }

  // ==========================================================================
  // Kayıp muhasebesi
  // ==========================================================================
  /** Uçuş defterini düşer, sayaçları günceller. @returns {number} kayıp bayt */
  _accountLoss(lost) {
    this.stats.packetsLost += lost.length;
    let bytesLost = 0;
    for (const e of lost) {
      if (!e.inFlight) continue;
      this.bytesInFlight -= e.bytes;
      bytesLost += e.bytes;
    }
    this.stats.bytesLost += bytesLost;
    this.rateSampler.noteLost(bytesLost);
    return bytesLost;
  }

  /** Denetleyiciye kaybı bildirir ve kalıcı tıkanıklığı denetler. */
  _applyLoss(lost, ctx) {
    let largestLost = null;
    for (const e of lost) {
      if (!e.inFlight) continue;
      if (!largestLost || e.sentTime > largestLost.sentTime) largestLost = e;
    }
    if (!largestLost) return;

    this.cc.onLoss({ ...ctx, largestLost });
    this.stats.congestionEvents = this.cc.congestionEvents || this.stats.congestionEvents;

    if (this._inPersistentCongestion(lost)) {
      this.stats.persistentCongestion++;
      this.cc.onPersistentCongestion({ now: ctx.now });
      if (this.pacer) this.pacer.reset();
    }
  }

  /**
   * Kalıcı tıkanıklık (§7.6): art arda kaybedilen ACK bekleyen paketler,
   * birkaç PTO süresinden uzun bir aralığı kaplıyorsa ağ gerçekten kopmuştur;
   * model sıfırlanır.
   */
  _inPersistentCongestion(lost) {
    if (!this.hasRttSample) return false;
    const elicit = lost.filter((e) => e.ackEliciting && e.sentTime > this.firstRttSampleTime);
    if (elicit.length < 2) return false;
    let min = Infinity;
    let max = -Infinity;
    for (const e of elicit) {
      if (e.sentTime < min) min = e.sentTime;
      if (e.sentTime > max) max = e.sentTime;
    }
    const ptoBase = this.smoothedRtt + Math.max(4 * this.rttvar, kGranularity) + this.maxAckDelay;
    // (2^0 + 2^1 + 2^2) = 7 katsayısı, kPersistentCongestionThreshold=3 için
    // ardışık PTO geri çekilmelerinin toplamıdır.
    const duration = ptoBase * ((2 ** kPersistentCongestionThreshold) - 1);
    return (max - min) > duration;
  }

  /** İzlenmeyi bırakan tüm paketleri temizler (kanal kapanışı). */
  reset() {
    this.sent.clear();
    this.bytesInFlight = 0;
    this.lossTime = 0;
    this.ptoCount = 0;
    if (this.pacer) this.pacer.reset();
  }

  snapshot() {
    return {
      smoothedRtt: Math.round(this.smoothedRtt),
      rttvar: Math.round(this.rttvar),
      minRtt: this.minRtt === Infinity ? null : Math.round(this.minRtt),
      latestRtt: Math.round(this.latestRtt),
      pto: this.currentPto(),
      ptoCount: this.ptoCount,
      bytesInFlight: this.bytesInFlight,
      inFlightPackets: this.sent.size,
      appLimited: this.rateSampler.isAppLimited,
      deliveredBytes: this.rateSampler.delivered,
      ...this.stats,
      ...this.cc.snapshot(),
      ...(this.pacer ? this.pacer.snapshot() : { pacingEnabled: false }),
    };
  }
}

module.exports = {
  LossRecovery,
  kPacketThreshold, kTimeThreshold, kGranularity, kInitialRtt,
  kLossReductionFactor, kPersistentCongestionThreshold,
  DEFAULT_CONGESTION_CONTROL,
  initialWindow, minimumWindow,
};
