'use strict';
// Hız şekillendirme ve sayaçlar.
//
// İki ayrı ihtiyaç var ve ikisini tek mekanizmayla çözmek yanlış olurdu:
//
//   TokenBucket   — "bu uygulama saniyede en fazla şu kadar bayt geçirsin".
//                   Bir ÜST SINIR. Kısa patlamalara izin verir (kova dolusu
//                   kadar), sürekli hızı kesin tutar.
//   RateMeter     — "şu an ne kadar akıyor". Bir ÖLÇÜM. Yönetim panelindeki
//                   bant genişliği göstergesi buradan beslenir.
//
// Kovanın kapasitesi neden ayrı bir parametre? Kapasite = hız yapılsaydı
// (yaygın hata) her paket için tam bir saniyelik jeton birikmesi gerekirdi ve
// küçük ama sık istekler, ortalama hızın çok altında kalmalarına rağmen
// sürekli bekletilirdi. Kapasite bir "patlama bütçesi"dir: kullanılmayan
// kapasitenin sınırlı bir kısmını biriktirmeye izin verir.

/**
 * Kovanın taşıyabileceği ASGARİ süre (ms) — zamanlayıcı çözünürlüğü payı.
 *
 * Kova kapasitesi, iki uyanma arasında biriken hakkın tavanıdır. Kapasite bir
 * uyanma aralığından küçükse, aradaki fark her turda sessizce çöpe gider ve
 * şekillendirici hedeflenen hızın ALTINDA bir tavan uygular:
 *
 *     gerçek hız ≈ hedef × (kapasite_süresi / uyanma_aralığı)
 *
 * Node'un zamanlayıcısı Windows'ta ~15.6 ms, yük altında daha da kaba
 * çalışır (ayrıntı: src/reliable/pacing.js). 25 ms'lik taban, o tikin
 * tamamını ve bir miktar oynamayı karşılar; yönetim panelinden konan bir
 * sınırın, işletim sisteminin saat tikine bağlı olarak kendi kendini
 * daraltmasını engeller.
 */
const MIN_BUCKET_MS = 25;

class TokenBucket {
  /**
   * @param {object} o
   * @param {number} o.ratePerSec saniyede eklenen jeton (bayt/sn)
   * @param {number} [o.burst] kova kapasitesi; verilmezse 250 ms'lik hız
   */
  constructor({ ratePerSec, burst }) {
    this.ratePerSec = Math.max(0, ratePerSec || 0);
    this.capacity = this._capacityFor(burst);
    this.tokens = this.capacity;
    this.last = Date.now();
  }

  get unlimited() { return this.ratePerSec <= 0; }

  /** İstenen patlama payını zamanlayıcı tabanıyla birlikte değerlendirir. */
  _capacityFor(burst) {
    const asked = burst || Math.ceil(this.ratePerSec / 4) || 1;
    const timerFloor = Math.ceil((this.ratePerSec * MIN_BUCKET_MS) / 1000);
    return Math.max(1, asked, timerFloor);
  }

  setRate(ratePerSec, burst) {
    this._refill(Date.now());
    this.ratePerSec = Math.max(0, ratePerSec || 0);
    this.capacity = this._capacityFor(burst);
    if (this.tokens > this.capacity) this.tokens = this.capacity;
  }

  _refill(now) {
    const elapsed = now - this.last;
    if (elapsed <= 0) {
      // Saat GERİYE gitti (NTP düzeltmesi, sanal makine duraklaması). Damgayı
      // güncellemeden dönmek, kovanın bir daha ASLA dolmaması demekti:
      // sonraki her ölçüm de negatif çıkar ve tüm hız şekillendirme kalıcı
      // olarak kilitlenirdi. Sıçramayı yutup şimdiye sabitliyoruz.
      if (elapsed < 0) this.last = now;
      return;
    }
    this.last = now;
    if (this.unlimited) { this.tokens = this.capacity; return; }
    this.tokens = Math.min(this.capacity, this.tokens + (elapsed / 1000) * this.ratePerSec);
  }

  /** İstenen kadarını alabilirse alır; alamazsa HİÇ almaz ve 0 döner. */
  take(n, now = Date.now()) {
    if (this.unlimited) return n;
    this._refill(now);
    if (this.tokens >= n) { this.tokens -= n; return n; }
    return 0;
  }

  /**
   * En fazla `n` kadar, elde ne varsa onu alır.
   *
   * Akış şekillendirmede doğru davranış budur: 16 KiB'lik bir segment için
   * jeton yetmiyorsa 6 KiB gönderip kalanını sonraki tura bırakmak, tüm
   * segmenti bekletmekten hem daha akıcı hem de gecikme açısından daha iyidir.
   */
  takePartial(n, now = Date.now()) {
    if (this.unlimited) return n;
    this._refill(now);
    const granted = Math.min(n, Math.floor(this.tokens));
    if (granted > 0) this.tokens -= granted;
    return granted;
  }

  /** `n` jetonun birikmesi için gereken süre (ms). */
  msUntil(n, now = Date.now()) {
    if (this.unlimited) return 0;
    this._refill(now);
    if (this.tokens >= n) return 0;
    return Math.ceil(((n - this.tokens) / this.ratePerSec) * 1000);
  }
}

/**
 * Üstel ağırlıklı hareketli ortalama ile anlık hız + toplam sayaç.
 *
 * Sabit pencereli sayaç (her saniye sıfırla) yerine EWMA: sabit pencere,
 * pencerenin başında ve sonunda aynı trafiği çok farklı gösterir ve panelde
 * sürekli zıplayan bir grafik üretir.
 */
class RateMeter {
  /** @param {number} halfLifeMs ağırlığın yarıya düştüğü süre */
  constructor(halfLifeMs = 2000) {
    this.halfLifeMs = halfLifeMs;
    this.total = 0;
    this.rate = 0;
    this.last = Date.now();
    this.pending = 0;
  }

  add(bytes) {
    this.total += bytes;
    this.pending += bytes;
  }

  /** @returns {number} bayt/sn */
  sample(now = Date.now()) {
    const elapsed = now - this.last;
    // Saat geriye gittiyse pencereyi yeniden başlat — aksi hâlde ölçer bir
    // daha hiç güncellenmez ve panel donmuş bir hız gösterir.
    if (elapsed < 0) { this.last = now; return this.rate; }
    if (elapsed < 50) return this.rate;
    this.last = now;
    const instant = (this.pending * 1000) / elapsed;
    this.pending = 0;
    const alpha = 1 - Math.exp(-elapsed / this.halfLifeMs);
    this.rate += alpha * (instant - this.rate);
    if (this.rate < 1) this.rate = instant > 0 ? this.rate : 0;
    return this.rate;
  }
}

/**
 * Anahtar başına kayan pencereli sayaç — kaynak IP'ye göre bağlantı/paket
 * hızı sınırlamak için. Sürekli büyümemesi için süpürülür.
 */
class KeyedCounter {
  constructor({ windowMs = 1000, max = 100, maxKeys = 20_000 } = {}) {
    this.windowMs = windowMs;
    this.max = max;
    this.maxKeys = maxKeys;
    this.map = new Map();
  }

  /** @returns {boolean} sınır AŞILMADIYSA true */
  allow(key, now = Date.now(), cost = 1) {
    let e = this.map.get(key);
    if (!e || now - e.start >= this.windowMs) {
      if (!e && this.map.size >= this.maxKeys) this._evict();
      e = { start: now, count: 0 };
      this.map.set(key, e);
    }
    if (e.count + cost > this.max) { e.count += cost; return false; }
    e.count += cost;
    return true;
  }

  count(key) { return this.map.get(key)?.count || 0; }

  _evict() {
    // En eski çeyreği at. Tam LRU tutmak, bu sayaçların değerinden pahalı bir
    // veri yapısı gerektirirdi; sınır zaten kaba bir sezgisel.
    const drop = Math.max(1, Math.floor(this.maxKeys / 4));
    let n = 0;
    for (const k of this.map.keys()) { this.map.delete(k); if (++n >= drop) break; }
  }

  sweep(now = Date.now()) {
    for (const [k, e] of this.map) {
      if (now - e.start >= this.windowMs * 2) this.map.delete(k);
    }
  }
}

module.exports = { TokenBucket, RateMeter, KeyedCounter, MIN_BUCKET_MS };
