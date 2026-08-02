'use strict';
// Genel port havuzu.
//
// Bir tünel bağlandığında dış dünyada bir port açılır, tünel gidince kapanır.
// Port RASTGELE seçilir, sıradaki boş port değil: sıralı dağıtım, ilk kez
// bağlanan bir istemcinin hangi portu alacağını dışarıdan tahmin edilebilir
// kılar ve tarama yapan birine "20000'den başla, hepsi dolu" kolaylığı verir.
//
// LINGER: tünel koptuğunda port hemen serbest bırakılmaz. Bir kopma çoğu zaman
// geçicidir (mobil ağ, kısa kesinti) ve istemci saniyeler içinde geri gelir.
// Portu hemen bırakmak, o aralıkta başka bir istemcinin onu kapmasına ve geri
// dönen istemcinin farklı bir adresle açılmasına yol açardı — dışarıdaki her
// yapılandırma (DNS kaydı, güvenlik duvarı kuralı, istemci ayarı) bozulurdu.

const crypto = require('node:crypto');

const { PROTO_NAME, TIMING } = require('../protocol/constants.js');

class PortAllocator {
  /**
   * @param {object} o
   * @param {number} o.min havuzun alt sınırı (dahil)
   * @param {number} o.max havuzun üst sınırı (dahil)
   * @param {number[]} [o.exclude] havuzdan çıkarılacak portlar
   * @param {number} [o.lingerMs]
   */
  constructor({
    min = 20000, max = 30000, exclude = [], lingerMs = TIMING.PORT_LINGER_MS, log,
  }) {
    if (min < 1 || max > 65535 || min > max) throw new Error(`geçersiz port havuzu: ${min}-${max}`);
    this.min = min;
    this.max = max;
    this.lingerMs = lingerMs;
    this.log = log;
    this.excluded = new Set(exclude);

    /** `${proto}:${port}` -> { holder, appId, tunnelId, state, until } */
    this.reservations = new Map();
    /** Bağlanamadığı görülen portlar (dışarıda başka bir süreç dinliyor). */
    this.unusable = new Set();

    this._sweepTimer = setInterval(() => this.sweep(), 5000);
    if (this._sweepTimer.unref) this._sweepTimer.unref();
  }

  get size() { return this.max - this.min + 1; }

  _key(proto, port) { return `${proto}:${port}`; }

  isAvailable(proto, port, holder) {
    if (port < this.min || port > this.max) return false;
    if (this.excluded.has(port)) return false;
    if (this.unusable.has(this._key(proto, port))) return false;
    const r = this.reservations.get(this._key(proto, port));
    if (!r) return true;
    // Linger'daki port, ONU BIRAKAN sahibe geri verilebilir; başkasına verilmez.
    return r.state === 'linger' && r.holder === holder;
  }

  /**
   * Havuzdan rastgele, rezerve edilmemiş bir port seçer.
   *
   * Önce K kez rastgele dener (havuz seyrekken bu O(1)'dir), dolmaya
   * yaklaşınca kalanların listesini çıkarıp aralarından rastgele seçer —
   * yalnızca rastgele deneme yapsaydı havuz %95 doluyken beklenen deneme
   * sayısı 20'ye çıkardı ve dolduğunda hiç bitmezdi.
   */
  pick(proto, { preferred = 0, holder = null } = {}) {
    if (preferred && this.isAvailable(proto, preferred, holder)) return preferred;

    for (let i = 0; i < 24; i++) {
      const port = this.min + crypto.randomInt(this.size);
      if (this.isAvailable(proto, port, holder)) return port;
    }
    const free = [];
    for (let port = this.min; port <= this.max; port++) {
      if (this.isAvailable(proto, port, holder)) free.push(port);
    }
    if (free.length === 0) return 0;
    return free[crypto.randomInt(free.length)];
  }

  /**
   * Portu belirli bir sahibe bağlar.
   * @returns {boolean} başarılıysa true
   */
  reserve(proto, port, { holder, appId = null, tunnelId = null, sticky = false }) {
    if (!this.isAvailable(proto, port, holder)) return false;
    this.reservations.set(this._key(proto, port), {
      proto, port, holder, appId, tunnelId, sticky, state: 'active', since: Date.now(), until: 0,
    });
    return true;
  }

  /**
   * Rezervasyonu linger durumuna alır. `immediate` ile hemen serbest bırakılır
   * (uygulama silindiğinde: dönecek bir istemci yok).
   */
  release(proto, port, { immediate = false } = {}) {
    const key = this._key(proto, port);
    const r = this.reservations.get(key);
    if (!r) return;
    if (immediate || this.lingerMs <= 0) { this.reservations.delete(key); return; }
    r.state = 'linger';
    r.until = Date.now() + this.lingerMs;
  }

  /** Bir sahibin tüm portlarını linger'a alır (tünel koptuğunda). */
  releaseHolder(holder, opts) {
    for (const r of this.reservations.values()) {
      if (r.holder === holder && r.state === 'active') this.release(r.proto, r.port, opts);
    }
  }

  /**
   * Bir sahibin (ve varsa uygulamanın) elindeki ya da linger'daki portu bulur.
   * Yeniden bağlanan bir istemciye AYNI portu geri verebilmenin yolu budur.
   */
  findByHolder(proto, holder, appId = null) {
    for (const r of this.reservations.values()) {
      if (r.proto !== proto || r.holder !== holder) continue;
      if (appId && r.appId !== appId) continue;
      return r.port;
    }
    return 0;
  }

  /** Linger'daki bir portu aynı sahip için geri diriltir. */
  reclaim(proto, port, holder) {
    const r = this.reservations.get(this._key(proto, port));
    if (!r || r.holder !== holder) return false;
    r.state = 'active';
    r.until = 0;
    return true;
  }

  /** Sistemde başka bir süreç dinliyor — havuzdan kalıcı olarak çıkar. */
  markUnusable(proto, port) {
    this.unusable.add(this._key(proto, port));
    this.reservations.delete(this._key(proto, port));
    this.log?.warn('port bağlanamadı, havuzdan çıkarıldı', { proto: PROTO_NAME[proto] || proto, port });
  }

  sweep(now = Date.now()) {
    for (const [key, r] of this.reservations) {
      if (r.state === 'linger' && r.until <= now) this.reservations.delete(key);
    }
  }

  stats() {
    let active = 0;
    let linger = 0;
    for (const r of this.reservations.values()) {
      if (r.state === 'active') active++; else linger++;
    }
    return {
      poolMin: this.min,
      poolMax: this.max,
      poolSize: this.size,
      active,
      linger,
      unusable: this.unusable.size,
      free: this.size - active - linger - this.unusable.size,
    };
  }

  list() {
    return [...this.reservations.values()].map((r) => ({
      proto: PROTO_NAME[r.proto] || String(r.proto),
      port: r.port,
      appId: r.appId,
      tunnelId: r.tunnelId,
      state: r.state,
      sticky: r.sticky,
      since: r.since,
      until: r.until || null,
    }));
  }

  stop() {
    if (this._sweepTimer) clearInterval(this._sweepTimer);
    this._sweepTimer = null;
  }
}

module.exports = { PortAllocator };
