'use strict';
// Per-peer token bucket rate limiter — Phase 4 DoS koruması.
//
// Handshake maliyetleri (cookie mint, ECDHE, signature verify) pahalı işlemlerdir;
// tek bir IP'nin saniyede binlerce CH göndererek CPU'yu doldurmasını engellemek için
// peer adresi başına token bucket kullanıyoruz.

class RateLimiter {
  constructor({ capacity = 20, refillPerSec = 10, ttlMs = 120_000 } = {}) {
    this.capacity = capacity;
    this.refill = refillPerSec;
    this.ttlMs = ttlMs;
    this.buckets = new Map(); // key → { tokens, lastTs }
  }

  // Return true if request allowed, false if rate-limited.
  allow(key, now = Date.now()) {
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.capacity, lastTs: now };
      this.buckets.set(key, b);
    }
    const elapsed = (now - b.lastTs) / 1000;
    b.tokens = Math.min(this.capacity, b.tokens + elapsed * this.refill);
    b.lastTs = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  // Periyodik temizlik
  sweep(now = Date.now()) {
    for (const [k, b] of this.buckets) {
      if (now - b.lastTs > this.ttlMs) this.buckets.delete(k);
    }
  }
}

module.exports = { RateLimiter };
