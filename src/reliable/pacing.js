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
// Uygulama bir jeton kovasıdır ve ÜÇ ayrıntısı önemlidir:
//
//   • PATLAMA PAYI (burst). Her paketi ayrı bir zamanlayıcıyla göndermek,
//     Node'un zamanlayıcı çözünürlüğünde (≈1 ms) 1200 baytlık paketlerle
//     ~9.6 Mbit'lik bir tavan demektir. Küçük bir patlamaya izin vermek
//     (varsayılan ~1 ms'lik veri, en az 2 paket) bu tavanı kaldırır ve
//     darboğazdaki kuyruğa ölçülebilir bir katkı yapmaz.
//   • SINIRSIZ BAŞLANGIÇ. Bant genişliği örneği oluşana kadar hız sınırı
//     YOKTUR. İlk turu yapay olarak yavaşlatmak, RTT tahmini de yokken
//     tamamen tahmine dayalı bir gecikme eklemek olurdu.
//   • ZAMANLAYICI ÇÖZÜNÜRLÜĞÜ. Aşağıdaki bölümün tamamı bunun içindir.
//
// ---------------------------------------------------------------------------
// ZAMANLAYICI ÇÖZÜNÜRLÜĞÜ — "1 ms'lik kova" varsayımının maliyeti
// ---------------------------------------------------------------------------
//
// Kovanın kapasitesi, iki uyanma arasında biriken jetonların TAVANIDIR. Sabit
// 1 ms'ye kilitlemek şu sessiz varsayımı yapar: "setTimeout(1) gerçekten 1 ms
// sonra çalışır". Bu varsayım hiçbir işletim sisteminde tam doğru değildir ve
// bazılarında hiç doğru değildir:
//
//     Linux (varsayılan)      ~1.0 – 1.5 ms
//     macOS                   ~1.0 – 2.0 ms
//     Windows (varsayılan)    ~15.6 ms   ← sistem saati tik aralığı
//     Yük altında / VM        onlarca ms (olay döngüsü sıkışması, GC, konak)
//
// Zamanlayıcı 15.6 ms sonra uyandığında kova hâlâ yalnızca 1 ms'lik veri
// tutabiliyorsa, o turda çıkabilecek azami veri 1 ms'lik veridir; aradaki
// 14.6 ms'lik hak SESSİZCE ÇÖPE GİDER. Sonuç bir hata mesajı değil, aritmetik
// bir tavandır:
//
//     gerçek hız  ≈  hedef_hız × (kova_süresi / uyanma_aralığı)
//     25 Mbit     ×  (1 ms / 15.6 ms)  ≈  1.6 Mbit
//
// Yani hattın kendisi boşken, kayıp da yokken, BBR modeli 25 Mbit derken
// gerçekte ~1.6 Mbit akar — üstelik BBR bunu "hattın hızı bu" diye öğrenmez,
// çünkü örnekler uygulama sınırlı (app-limited) işaretlidir. Arıza, hız
// düşüklüğü olarak değil "tünel bazen yavaş" olarak görünür.
//
// ÇÖZÜM: kovanın kapasitesini sabit varsaymak yerine ÖLÇMEK.
//
// Şekillendirici her uyandığında çağıran, "şu kadar istemiştim, şu kadar
// uyudum" bilgisini `observeTimerWake()` ile geri bildirir. Aradaki fark
// (overshoot) zamanlayıcının gerçek çözünürlüğüdür ve kova kapasitesi buna
// göre büyür: kova artık "1 ms'lik veri" değil "BİR UYANMA ARALIĞI kadar
// veri" tutar. Windows'ta 15.6 ms, Linux'ta 1.2 ms — ikisinde de hattın
// tamamı kullanılır.
//
// Bu bir "patlamaya izin verme" tavizi DEĞİL, ölçüm hatasının düzeltilmesidir:
// zaten o kadar uyuyorduk, yalnızca hak edilen jetonları atıyorduk. Yine de
// üç sınır korunur:
//
//   1. `maxBurstMs` — telafi edilecek gecikmenin tavanı (varsayılan 25 ms).
//      Olay döngüsünü kilitleyen tek seferlik bir iş (senkron kripto, GC,
//      sanal makine duraklaması) yüzünden 400 ms uyunursa, 400 ms'lik veri
//      tek seferde salınmaz.
//   2. `maxBurstBytes` — mutlak bayt tavanı. Çok hızlı hatlarda (≥ 400 Mbit)
//      25 ms'lik verinin işletim sistemi gönderim tamponunu taşırmasını
//      engeller.
//   3. Tıkanıklık penceresi. Pacer yalnızca ZAMANI yönetir; her paket ayrıca
//      `hasCongestionRoom()` denetiminden geçer, dolayısıyla patlama hiçbir
//      koşulda cwnd'yi aşamaz. Bufferbloat sınırı BBR'ın kendi modelinde
//      (cwnd ≈ 2×BDP) durur ve bu değişiklik ona dokunmaz.
//
// Gözlenen gecikme PENCERELİ MAKSİMUM ile tutulur (Nichols süzgeci, aynı
// yapı bant genişliği tahmininde de kullanılıyor). Ortalama YANLIŞ olurdu:
// kovanın EN KÖTÜ uyanma aralığını karşılaması gerekir, tipik olanı değil —
// aksi hâlde her kaçırılan tik kalıcı bir verim kaybına dönüşür. Pencere
// (varsayılan 5 s) geçici bir takılmanın kalıcılaşmasını engeller.

const { WindowedFilter } = require('./congestion.js');
const { now: monotonicNow } = require('./clock.js');

const DEFAULTS = Object.freeze({
  /** Zamanlayıcı hassasken kovanın taşıyabileceği süre. */
  burstMs: 1,
  /** Patlamanın alt ve üst sınırı (paket) — HASSAS zamanlayıcı durumunda. */
  minBurstPackets: 2,
  maxBurstPackets: 16,
  /**
   * Telafi edilecek zamanlayıcı gecikmesinin tavanı (ms).
   *
   * 25 ms neden? Windows'un 15.6 ms'lik tikini artı gecikme oynamasını (jitter)
   * kapsayacak kadar büyük; tek seferlik bir olay döngüsü kilitlenmesini
   * saniyelik bir patlamaya çevirmeyecek kadar küçük.
   */
  maxBurstMs: 25,
  /** Gözlenen gecikmenin geçerli kalacağı pencere (ms). */
  lagWindowMs: 5_000,
  /** Patlamanın mutlak tavanı — çok hızlı hatlarda güvenlik valfi. */
  maxBurstBytes: 1024 * 1024,
});

/**
 * Bu kadar geriye giden bir zaman damgası SAAT SIÇRAMASI sayılır.
 *
 * Eşiğin altındaki negatif farklar çağıranın damga yaşından doğar (bkz.
 * `_refill`) ve yok sayılmalıdır; üstündekiler gerçek bir saat düzeltmesidir
 * ve kova onlara takılıp kalmamalıdır.
 */
const CLOCK_JUMP_MS = 1000;

class Pacer {
  /**
   * @param {object} o
   * @param {number} o.maxDatagramSize
   * @param {number} [o.burstMs]
   * @param {number} [o.maxBurstMs]
   * @param {number} [o.maxBurstBytes]
   * @param {number} [o.lagWindowMs]
   */
  constructor({ maxDatagramSize = 1200, ...o } = {}) {
    this.opt = { ...DEFAULTS };
    for (const [k, v] of Object.entries(o)) if (v !== undefined) this.opt[k] = v;
    this.maxDatagramSize = maxDatagramSize;
    /** bayt/s — Infinity: şekillendirme kapalı. */
    this.rate = Infinity;

    // --- zamanlayıcı çözünürlüğü ölçümü
    /** Gözlenen uyanma gecikmesi (ms) — pencereli MAKSİMUM. */
    this.timerLagMs = 0;
    this._lagFilter = new WindowedFilter(this.opt.lagWindowMs, 1);
    this.lagSamples = 0;
    /** Bağlantı ömrü boyunca görülen en kötü gecikme — yalnızca teşhis için. */
    this.worstLagMs = 0;

    this.tokens = this._burstBytes();
    // null = henüz hiç doldurulmadı. 0 KULLANILAMAZ: sıfır geçerli bir zaman
    // damgasıdır ve nöbetçi değer olarak kullanılırsa kova hiç dolmaz.
    this.lastFill = null;
    this.sentPaced = 0;
    this.delayedTimes = 0;
  }

  get enabled() { return Number.isFinite(this.rate) && this.rate > 0; }

  /**
   * Kovanın kapsadığı süre (ms) — bir uyanma aralığı.
   *
   * Gecikme hiç ölçülmemişse (ya da gerçekten sıfırsa) yapılandırılan
   * `burstMs` aynen geçerlidir; bu, ölçüm eklenmeden önceki davranışın
   * BİREBİR aynısıdır. Ölçüm oluştukça pencere gerçek uyanma aralığına
   * yaklaşır.
   */
  get burstWindowMs() {
    if (!(this.timerLagMs > 0)) return this.opt.burstMs;
    return Math.min(this.opt.burstMs + this.timerLagMs, this.opt.maxBurstMs);
  }

  _burstBytes() {
    const min = this.opt.minBurstPackets * this.maxDatagramSize;
    if (!this.enabled) return min;

    // 1) Hassas zamanlayıcı varsayımıyla ideal patlama: 1 ms'lik veri, paket
    //    tavanıyla kırpılmış. Hızlı hatlarda tavan bilinçlidir — 1 ms'lik veri
    //    yüzlerce kilobayt olabilir ve bunu tek seferde salmanın kimseye
    //    faydası yoktur.
    const ideal = Math.min(
      this.opt.maxBurstPackets * this.maxDatagramSize,
      Math.floor((this.rate * this.opt.burstMs) / 1000),
    );

    // 2) Zamanlayıcı telafisi: gerçekte uyunan süre kadarlık veri. Buraya
    //    PAKET TAVANI UYGULANMAZ — uygulamak, düzeltmeye çalıştığımız hatanın
    //    ta kendisi olurdu: kova bir uyanma aralığını karşılayamazsa hattın
    //    geri kalanı kullanılamaz.
    const compensated = this.timerLagMs > 0
      ? Math.floor((this.rate * this.burstWindowMs) / 1000)
      : 0;

    const want = Math.max(ideal, compensated);
    return Math.max(min, Math.min(want, this.opt.maxBurstBytes));
  }

  /**
   * Zamanlayıcının GERÇEKTE ne kadar uyuduğunu bildirir.
   *
   * Çağıran (kanalın hız zamanlayıcısı) `setTimeout(delay)` kurar ve uyandığında
   * geçen süreyi MONOTONİK bir saatle ölçüp buraya verir. Aradaki fark, o
   * makinedeki gerçek zamanlayıcı çözünürlüğüdür.
   *
   * @param {number} requestedMs istenen gecikme
   * @param {number} actualMs    ölçülen gerçek gecikme (monotonik)
   * @param {number} [now]       pencere ekseni (epoch ms)
   */
  observeTimerWake(requestedMs, actualMs, now = monotonicNow()) {
    if (!Number.isFinite(requestedMs) || !Number.isFinite(actualMs)) return;

    // Erken uyanma (negatif fark) bir bilgi taşımaz: 0 sayılır ama YİNE DE
    // süzgece verilir, yoksa pencereli maksimum bir daha hiç düşmez.
    const overshoot = actualMs - requestedMs;
    const sample = Math.min(Math.max(overshoot, 0), this.opt.maxBurstMs);

    this.lagSamples++;
    if (sample > this.worstLagMs) this.worstLagMs = sample;
    this.timerLagMs = this._lagFilter.update(now, sample);
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
    if (dt <= 0) {
      // KÜÇÜK NEGATİF FARKLAR SAAT HATASI DEĞİLDİR ve damga geri sarılarak
      // "düzeltilemez". Gönderim yolunda iki damga dolaşır: pompa döngüsü
      // turun BAŞINDA aldığı damgayı kullanır, gönderim muhasebesi ise taze
      // bir damga alır. Döngü bir milisaniyeyi aşınca ikincisi birincinin
      // önüne geçer ve sonraki dolum çağrısı geriye bakar. Damgayı o anda
      // geri sarmak, AYNI ARALIK İÇİN İKİNCİ KEZ jeton vermek olur —
      // döngü ne kadar uzunsa hız o kadar aşılır, yani şekillendirme
      // sessizce devre dışı kalır.
      //
      // Yalnızca GERÇEK bir saat sıçraması (NTP düzeltmesi, sanal makinenin
      // geri alınması) damgayı yeniden kurar; aksi hâlde kova bir daha hiç
      // dolmazdı.
      if (dt < -CLOCK_JUMP_MS) this.lastFill = now;
      return;
    }
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
    // Gözlenen zamanlayıcı gecikmesi BİLEREK korunur: o, bağlantının değil
    // ÜZERİNDE ÇALIŞILAN MAKİNENİN özelliğidir. Her yeniden bağlanmada
    // sıfırlamak, her seferinde aynı dersi yeniden öğrenmek olurdu.
  }

  snapshot() {
    return {
      pacingEnabled: this.enabled,
      pacingRateBps: this.enabled ? Math.round(this.rate) : null,
      pacingBurstBytes: this._burstBytes(),
      pacingBurstMs: +this.burstWindowMs.toFixed(2),
      pacingDelays: this.delayedTimes,
      /** Ölçülen zamanlayıcı çözünürlüğü — 15+ ise makine kaba tikli. */
      timerLagMs: +this.timerLagMs.toFixed(2),
      timerLagSamples: this.lagSamples,
      timerLagWorstMs: +this.worstLagMs.toFixed(2),
    };
  }
}

module.exports = { Pacer, PACER_DEFAULTS: DEFAULTS };
