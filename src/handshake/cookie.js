'use strict';
// DTLS Stateless Cookie — RFC 9147 §5.1.
//
// DTLS sunucusu ilk ClientHello'ya HelloRetryRequest + cookie ile cevap vererek
// istemcinin IP adresinin spoofed olmadığını doğrular (return-routability).
// Cookie "state" tutulmadan üretilir: HMAC(secret, bind_data).
//
// bind_data şunları içermeli:
//   - istemci address:port  (spoof'u zorlaştırır)
//   - ClientHello'nun transcript hash'i (session binding; farklı bir CH ile cookie yeniden kullanılamaz)
//   - zaman damgası  (TTL / tekrar saldırı kapatma)
//
// Secret server başlangıcında random üretilir, periyodik olarak rotate edilebilir.

const crypto = require('node:crypto');

const DEFAULT_TTL_MS = 60_000; // 60 sn — ikinci CH bu süre içinde gelmezse invalid

class CookieMinter {
  constructor({ secret = null, ttlMs = DEFAULT_TTL_MS } = {}) {
    this.secret = secret || crypto.randomBytes(32);
    this.ttlMs = ttlMs;
  }

  // peer = { address, port }, chHashLike = Buffer (transcript hash of ClientHello1)
  mint(peer, chHashLike, now = Date.now()) {
    const payload = buildBindData(peer, chHashLike, now);
    const mac = hmac(this.secret, payload);
    // Cookie wire format: timestamp(8 BE) || mac(32)
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(now), 0);
    return Buffer.concat([ts, mac]);
  }

  // Dönen { ok, reason } — ok=true ise kabul
  verify(cookie, peer, chHashLike, now = Date.now()) {
    if (!Buffer.isBuffer(cookie) || cookie.length !== 8 + 32) {
      return { ok: false, reason: 'invalid cookie length' };
    }
    const issuedAt = Number(cookie.readBigUInt64BE(0));
    if (now - issuedAt > this.ttlMs) return { ok: false, reason: 'expired' };
    if (issuedAt > now + 5_000)      return { ok: false, reason: 'future-dated' };

    const payload = buildBindData(peer, chHashLike, issuedAt);
    const expected = hmac(this.secret, payload);
    const got = cookie.slice(8);
    if (!crypto.timingSafeEqual(expected, got)) return { ok: false, reason: 'mac mismatch' };

    return { ok: true, issuedAt };
  }
}

function buildBindData(peer, chHashLike, timestamp) {
  if (!chHashLike) chHashLike = Buffer.alloc(0);

  const addr = Buffer.from(String(peer.address), 'ascii');
  const port = Buffer.alloc(2);
  port.writeUInt16BE(peer.port & 0xffff, 0);
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(timestamp), 0);

  // uzunluk-önekli alanlar ki canonical olsun
  function lp(b) {
    const l = Buffer.alloc(2);
    l.writeUInt16BE(b.length, 0);
    return Buffer.concat([l, b]);
  }
  return Buffer.concat([lp(addr), port, ts, lp(chHashLike)]);
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

module.exports = {
  CookieMinter,
  DEFAULT_TTL_MS,
};
