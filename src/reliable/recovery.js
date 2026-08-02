'use strict';
// Kayıp tespiti ve tıkanıklık denetimi — RFC 9002 (QUIC Loss Detection and
// Congestion Control) uyarlaması.
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
//      kullanır ne de tıkanıklığa tepki verir. RFC 9002 §7 (NewReno)
//      pencereyi ACK'lerle büyütür, kayıpta yarıya indirir.
//
// Bu modül üç kavramı ayrı tutar (RFC 9002'nin kendi ayrımı):
//   • RTT tahmini      §5  — smoothed_rtt / rttvar / min_rtt, ack_delay düşülür
//   • Kayıp tespiti    §6  — paket eşiği (3) + zaman eşiği (9/8 × RTT) + PTO
//   • Tıkanıklık       §7  — NewReno: yavaş başlangıç, kurtarma, kalıcı tıkanıklık
//
// QUIC'ten devralınan can alıcı tasarım kuralı: YENİDEN GÖNDERİLEN VERİ YENİ
// BİR PAKET NUMARASI ALIR. Böylece her ACK tek bir gönderime karşılık gelir ve
// RTT örneği belirsizliğe düşmez (Karn algoritmasına gerek kalmaz).

const kPacketThreshold = 3;             // RFC 9002 §6.1.1
const kTimeThreshold = 9 / 8;           // RFC 9002 §6.1.2
const kGranularity = 1;                 // ms — zamanlayıcı çözünürlüğü
const kInitialRtt = 333;                // ms — RFC 9002 §6.2.2
const kLossReductionFactor = 0.5;       // RFC 9002 §7.3.2
const kPersistentCongestionThreshold = 3; // RFC 9002 §7.6

class LossRecovery {
  /**
   * @param {object} o
   * @param {number} [o.maxDatagramSize]  tıkanıklık penceresi bayt biriminde
   * @param {number} [o.maxAckDelay]      karşı tarafın bildirdiği azami ACK gecikmesi
   * @param {number} [o.initialRtt]
   * @param {number} [o.minPto]           PTO alt sınırı (test/LAN için)
   * @param {number} [o.maxPto]           PTO üst sınırı
   */
  constructor({
    maxDatagramSize = 1200, maxAckDelay = 25, initialRtt = kInitialRtt,
    minPto = 2 * kGranularity, maxPto = 8_000,
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

    // --- tıkanıklık (§7, NewReno)
    this.congestionWindow = initialWindow(maxDatagramSize);
    this.bytesInFlight = 0;
    this.ssthresh = Infinity;
    this.congestionRecoveryStartTime = 0;

    this.stats = {
      packetsSent: 0, packetsAcked: 0, packetsLost: 0, probesSent: 0,
      congestionEvents: 0, persistentCongestion: 0, spuriousLoss: 0,
    };
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
  onPacketSent({ pn, bytes, ackEliciting = true, meta = null, now = Date.now() }) {
    const entry = { pn, bytes, sentTime: now, ackEliciting, inFlight: ackEliciting, meta };
    this.sent.set(pn, entry);
    this.stats.packetsSent++;
    if (entry.inFlight) {
      this.bytesInFlight += bytes;
      this.timeOfLastAckElicitingPacket = now;
    }
    return entry;
  }

  /** Tıkanıklık penceresinde kalan yer (bayt). Negatif olabilir. */
  available() { return this.congestionWindow - this.bytesInFlight; }

  /** Bu boyutta bir paket şu an gönderilebilir mi? */
  canSend(bytes) {
    // Pencere tamamen doluyken bile en az bir paket akmalı; aksi hâlde
    // ilk kayıp sonrası bağlantı kalıcı olarak kilitlenebilir.
    return this.bytesInFlight === 0 || this.bytesInFlight + bytes <= this.congestionWindow;
  }

  // ==========================================================================
  // ACK işleme — RFC 9002 §5.1, §6.1
  // ==========================================================================
  /**
   * @param {object} o
   * @param {Array<[number,number]>} o.ranges  ACK'lenen kapalı aralıklar
   * @param {number} [o.ackDelay]              gönderenin bildirdiği gecikme (ms)
   * @returns {{acked: object[], lost: object[]}}
   */
  onAckReceived({ ranges, ackDelay = 0, now = Date.now() }) {
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

    for (const e of acked) if (e.inFlight) this.bytesInFlight -= e.bytes;
    this.stats.packetsAcked += acked.length;
    this._onPacketsAcked(acked, now);

    const lost = this._detectAndRemoveLostPackets(now);
    if (lost.length) this._onPacketsLost(lost, now);

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
  onLossDetectionTimeout(now = Date.now()) {
    if (this.lossTime !== 0 && this.lossTime <= now) {
      const lost = this._detectAndRemoveLostPackets(now);
      if (lost.length) this._onPacketsLost(lost, now);
      return { lost, probes: 0 };
    }
    if (!this._hasAckElicitingInFlight()) return { lost: [], probes: 0 };

    // PTO: ağın hâlâ ayakta olup olmadığını anlamak için iki sonda gönder.
    // Bu bir kayıp bildirimi DEĞİLDİR — pencere küçültülmez.
    this.ptoCount++;
    this.stats.probesSent += 2;
    return { lost: [], probes: 2 };
  }

  // ==========================================================================
  // Tıkanıklık denetimi — RFC 9002 §7 (NewReno)
  // ==========================================================================
  _inCongestionRecovery(sentTime) {
    return sentTime <= this.congestionRecoveryStartTime;
  }

  _onPacketsAcked(acked, now) {
    for (const e of acked) {
      if (!e.inFlight) continue;
      // Kurtarma döneminde gönderilmiş paketler pencereyi büyütmez (§7.3.2).
      if (this._inCongestionRecovery(e.sentTime)) continue;
      if (this.congestionWindow < this.ssthresh) {
        this.congestionWindow += e.bytes;                     // yavaş başlangıç
      } else {
        this.congestionWindow += Math.max(1,
          Math.floor(this.maxDatagramSize * e.bytes / this.congestionWindow)); // tıkanıklıktan kaçınma
      }
    }
  }

  _onCongestionEvent(sentTime, now) {
    if (this._inCongestionRecovery(sentTime)) return;   // dönem başına bir kez
    this.stats.congestionEvents++;
    this.congestionRecoveryStartTime = now;
    this.ssthresh = Math.max(
      Math.floor(this.congestionWindow * kLossReductionFactor),
      minimumWindow(this.maxDatagramSize),
    );
    this.congestionWindow = this.ssthresh;
  }

  _onPacketsLost(lost, now) {
    this.stats.packetsLost += lost.length;
    let largestLost = null;
    for (const e of lost) {
      if (!e.inFlight) continue;
      this.bytesInFlight -= e.bytes;
      if (!largestLost || e.sentTime > largestLost.sentTime) largestLost = e;
    }
    if (!largestLost) return;

    this._onCongestionEvent(largestLost.sentTime, now);

    if (this._inPersistentCongestion(lost)) {
      this.stats.persistentCongestion++;
      this.congestionWindow = minimumWindow(this.maxDatagramSize);
      this.congestionRecoveryStartTime = 0;   // yavaş başlangıca dön
      this.ssthresh = Infinity;
    }
  }

  /**
   * Kalıcı tıkanıklık (§7.6): art arda kaybedilen ACK bekleyen paketler,
   * birkaç PTO süresinden uzun bir aralığı kaplıyorsa ağ gerçekten kopmuştur;
   * pencere asgari değere düşürülür.
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
  }

  snapshot() {
    return {
      smoothedRtt: Math.round(this.smoothedRtt),
      rttvar: Math.round(this.rttvar),
      minRtt: this.minRtt === Infinity ? null : Math.round(this.minRtt),
      latestRtt: Math.round(this.latestRtt),
      pto: this.currentPto(),
      ptoCount: this.ptoCount,
      congestionWindow: this.congestionWindow,
      bytesInFlight: this.bytesInFlight,
      ssthresh: this.ssthresh === Infinity ? null : this.ssthresh,
      inFlightPackets: this.sent.size,
      ...this.stats,
    };
  }
}

// RFC 9002 §7.2
function initialWindow(maxDatagramSize) {
  return Math.min(10 * maxDatagramSize, Math.max(14720, 2 * maxDatagramSize));
}
function minimumWindow(maxDatagramSize) {
  return 2 * maxDatagramSize;
}

module.exports = {
  LossRecovery,
  kPacketThreshold, kTimeThreshold, kGranularity, kInitialRtt,
  kLossReductionFactor, kPersistentCongestionThreshold,
  initialWindow, minimumWindow,
};
