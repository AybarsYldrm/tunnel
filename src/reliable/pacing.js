'use strict';
// Hız şekillendirici (pacer) — BBR'ın ikinci yarısı.
//
// Tıkanıklık penceresi "aynı anda ne kadar veri uçuşta olabilir" sorusunu
// yanıtlar; hattın kapasitesini AŞMAYAN bir pencere bile veriyi tek seferde
// salarsa darboğazda anlık bir kuyruk oluşur. Pencere hacim, pacer ZAMANDIR:
// aynı baytları RTT'ye yayarak gönderir.
//
// BBR için isteğe bağlı değil, zorunlu: modelin ölçtüğü şey darboğaz hızıdır
// ve o hızda göndermenin tek yolu paketleri zamanda ayırmaktır. Pacer olmadan
// BBR, NewReno'dan daha kötü davranır — pencereyi büyük tutar ve patlamalarla
// kuyruk üretir.
//
// Uygulama bir jeton kovasıdır ve iki ayrıntısı önemlidir:
//
//   • PATLAMA PAYI (burst). Her paketi ayrı bir zamanlayıcıyla göndermek,
//     Node'un zamanlayıcı çözünürlüğünde (≈1 ms) 1200 baytlık paketlerle
//     ~9.6 Mbit'lik bir tavan demektir. Küçük bir patlamaya izin vermek
//     (varsayılan ~1 ms'lik veri, en az 2 paket) bu tavanı kaldırır ve
//     darboğazdaki kuyruğa ölçülebilir bir katkı yapmaz.
//   • SINIRSIZ BAŞLANGIÇ. Bant genişliği örneği oluşana kadar hız sınırı
//     YOKTUR. İlk turu yapay olarak yavaşlatmak, RTT tahmini de yokken
//     tamamen tahmine dayalı bir gecikme eklemek olurdu.

const DEFAULTS = Object.freeze({
  /** Kovanın taşıyabileceği azami süre — bu kadar veri patlama hâlinde çıkabilir. */
  burstMs: 1,
  /** Patlamanın alt ve üst sınırı (paket). */
  minBurstPackets: 2,
  maxBurstPackets: 16,
});

class Pacer {
  /**
   * @param {object} o
   * @param {number} o.maxDatagramSize
   * @param {number} [o.burstMs]
   */
  constructor({ maxDatagramSize = 1200, ...o } = {}) {
    this.opt = { ...DEFAULTS, ...o };
    this.maxDatagramSize = maxDatagramSize;
    /** bayt/s — Infinity: şekillendirme kapalı. */
    this.rate = Infinity;
    this.tokens = this._burstBytes();
    // null = henüz hiç doldurulmadı. 0 KULLANILAMAZ: sıfır geçerli bir zaman
    // damgasıdır ve nöbetçi değer olarak kullanılırsa kova hiç dolmaz.
    this.lastFill = null;
    this.sentPaced = 0;
    this.delayedTimes = 0;
  }

  get enabled() { return Number.isFinite(this.rate) && this.rate > 0; }

  _burstBytes() {
    const min = this.opt.minBurstPackets * this.maxDatagramSize;
    if (!this.enabled) return min;
    const max = this.opt.maxBurstPackets * this.maxDatagramSize;
    return Math.min(max, Math.max(min, Math.floor((this.rate * this.opt.burstMs) / 1000)));
  }

  /** @param {number} bytesPerSec Infinity ⇒ şekillendirme yok */
  setRate(bytesPerSec) {
    const next = Number.isFinite(bytesPerSec) && bytesPerSec > 0 ? bytesPerSec : Infinity;
    if (next === this.rate) return;
    this.rate = next;
    // Kovayı yeni patlama payına kırp; hız düştüğünde eski jetonlarla büyük
    // bir patlama yapmak, tam da engellemek istediğimiz şey.
    this.tokens = Math.min(this.tokens, this._burstBytes());
  }

  _refill(now) {
    if (!this.enabled) { this.tokens = this._burstBytes(); this.lastFill = now; return; }
    if (this.lastFill === null) { this.lastFill = now; return; }
    const dt = now - this.lastFill;
    if (dt <= 0) return;
    this.lastFill = now;
    this.tokens = Math.min(this._burstBytes(), this.tokens + (this.rate * dt) / 1000);
  }

  /** Bu boyutta bir paket ŞU AN gönderilebilir mi. */
  canSend(bytes, now) {
    if (!this.enabled) return true;
    this._refill(now);
    // Kova, tek bir paketten küçük bir patlama payıyla yapılandırılmış olsa
    // bile en az bir paket akmalı; aksi hâlde kanal kalıcı olarak kilitlenir.
    return this.tokens >= Math.min(bytes, this._burstBytes());
  }

  /** Gönderilebilene kadar geçecek süre (ms). 0 = şimdi. */
  delayUntilSend(bytes, now) {
    if (!this.enabled) return 0;
    this._refill(now);
    const need = Math.min(bytes, this._burstBytes()) - this.tokens;
    if (need <= 0) return 0;
    this.delayedTimes++;
    return Math.max(1, Math.ceil((need * 1000) / this.rate));
  }

  onSent(bytes, now) {
    if (!this.enabled) return;
    this._refill(now);
    this.tokens -= bytes;
    this.sentPaced += bytes;
  }

  reset() {
    this.tokens = this._burstBytes();
    this.lastFill = null;
  }

  snapshot() {
    return {
      pacingEnabled: this.enabled,
      pacingRateBps: this.enabled ? Math.round(this.rate) : null,
      pacingBurstBytes: this._burstBytes(),
      pacingDelays: this.delayedTimes,
    };
  }
}

module.exports = { Pacer, PACER_DEFAULTS: DEFAULTS };
