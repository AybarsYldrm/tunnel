'use strict';
// Sabit genişlikli, big-endian, uzunluk önekli ilkel okuyucu/yazıcı.
//
// Neden JSON değil? Denetim mesajlarının çoğu sıcak yolda: her yeni genel
// bağlantı bir OPEN, her pencere yenilemesi bir CREDIT üretir. `JSON.stringify`
// + `JSON.parse` bu boyutta bir mesaj için baytların kendisinden pahalıdır ve
// her çağrıda çöp üretir. Sabit yerleşimli bir kodlama, aynı bilgiyi ayırma
// yapmadan ve dalsız okur.
//
// JSON yine de var — ama YALNIZCA seyrek ve yapısı değişken olanlarda
// (APP_SYNC, STATS, CONFIG). Orada okunabilirlik ve ileri uyumluluk, birkaç
// mikrosaniyeden değerli.

class Writer {
  constructor(size = 256) {
    this.buf = Buffer.allocUnsafe(size);
    this.off = 0;
  }

  _need(n) {
    if (this.off + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.off + n) size *= 2;
    const next = Buffer.allocUnsafe(size);
    this.buf.copy(next, 0, 0, this.off);
    this.buf = next;
  }

  u8(v) { this._need(1); this.buf.writeUInt8(v & 0xff, this.off); this.off += 1; return this; }
  u16(v) { this._need(2); this.buf.writeUInt16BE(v & 0xffff, this.off); this.off += 2; return this; }
  u32(v) { this._need(4); this.buf.writeUInt32BE(v >>> 0, this.off); this.off += 4; return this; }

  /** 48 bit — zaman damgaları ve sayaçlar için. Number.MAX_SAFE_INTEGER altında
   *  kaldığı sürece BigInt'e gerek yok; epoch-ms 2^48'e 8000 yılında ulaşır. */
  u48(v) { this._need(6); this.buf.writeUIntBE(Math.max(0, Math.min(v, 0xffffffffffff)), this.off, 6); this.off += 6; return this; }

  bytes(b) {
    if (!b || b.length === 0) return this;
    this._need(b.length);
    b.copy(this.buf, this.off);
    this.off += b.length;
    return this;
  }

  /** u8 uzunluklu dize (≤255 bayt). Uzunsa KESİLİR — bir ad alanının taşması
   *  yüzünden bağlantı düşürmek, gerçekte hep kötü bir takas oldu. */
  str8(s) {
    const b = Buffer.from(String(s ?? ''), 'utf8').subarray(0, 255);
    return this.u8(b.length).bytes(b);
  }

  str16(s) {
    const b = Buffer.from(String(s ?? ''), 'utf8').subarray(0, 0xffff);
    return this.u16(b.length).bytes(b);
  }

  blob32(b) {
    const buf = Buffer.isBuffer(b) ? b : Buffer.from(b || '');
    return this.u32(buf.length).bytes(buf);
  }

  done() { return this.buf.subarray(0, this.off); }
}

class ProtocolError extends Error {
  constructor(message) { super(message); this.name = 'ProtocolError'; }
}

class Reader {
  constructor(buf, off = 0) {
    this.buf = buf;
    this.off = off;
  }

  get remaining() { return this.buf.length - this.off; }

  _take(n) {
    if (this.off + n > this.buf.length) {
      throw new ProtocolError(`çerçeve kısa: ${n} bayt gerekiyordu, ${this.remaining} kaldı`);
    }
    const at = this.off;
    this.off += n;
    return at;
  }

  u8() { return this.buf.readUInt8(this._take(1)); }
  u16() { return this.buf.readUInt16BE(this._take(2)); }
  u32() { return this.buf.readUInt32BE(this._take(4)); }
  u48() { return this.buf.readUIntBE(this._take(6), 6); }

  /** Kopyasız dilim. Çağıran onu SAKLAYACAKSA kopyalamalı: alttaki tampon
   *  kanaldan gelir ve ömrü bu çağrıya bağlıdır. */
  slice(n) { return this.buf.subarray(this._take(n), this.off); }

  str8() { return this.slice(this.u8()).toString('utf8'); }
  str16() { return this.slice(this.u16()).toString('utf8'); }
  blob32() { return this.slice(this.u32()); }

  /** Geri kalan her şey. */
  rest() { const r = this.buf.subarray(this.off); this.off = this.buf.length; return r; }
}

// ---------------------------------------------------------------------------
// IP adresleri
// ---------------------------------------------------------------------------
// Adresi metin olarak taşımak 15-45 bayt eder ve her okumada bir ayrıştırma
// gerektirir; ikili biçim 4 ya da 16 bayttır ve doğrudan karşılaştırılabilir.

const ADDR = Object.freeze({ V4: 4, V6: 6 });

function encodeIp(w, address) {
  const raw = ipToBuffer(address);
  if (!raw) { w.u8(ADDR.V4).bytes(Buffer.alloc(4)); return; }
  w.u8(raw.length === 4 ? ADDR.V4 : ADDR.V6).bytes(raw);
}

function decodeIp(r) {
  const type = r.u8();
  if (type === ADDR.V4) return bufferToIp(r.slice(4));
  if (type === ADDR.V6) return bufferToIp(r.slice(16));
  throw new ProtocolError(`bilinmeyen adres tipi: ${type}`);
}

function ipToBuffer(address) {
  if (typeof address !== 'string' || address.length === 0) return null;
  // IPv4-eşlenmiş IPv6 (::ffff:1.2.3.4) — Node bir IPv6 soketinde IPv4
  // eşlerini bu biçimde verir. Dört bayt olarak taşımak, karşı tarafın
  // aynı adresi iki farklı dizeyle görmesini engeller.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  const value = mapped ? mapped[1] : address;

  if (value.includes('.') && !value.includes(':')) {
    const parts = value.split('.');
    if (parts.length !== 4) return null;
    const out = Buffer.allocUnsafe(4);
    for (let i = 0; i < 4; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      out[i] = n;
    }
    return out;
  }
  if (!value.includes(':')) return null;
  return ipv6ToBuffer(value);
}

function ipv6ToBuffer(value) {
  const zone = value.indexOf('%');
  const text = zone >= 0 ? value.slice(0, zone) : value;
  const halves = text.split('::');
  if (halves.length > 2) return null;

  const expand = (part) => (part ? part.split(':').filter((s) => s !== '') : []);
  const head = expand(halves[0]);
  const tail = halves.length === 2 ? expand(halves[1]) : [];

  const groups = [];
  const pushGroup = (g) => {
    // Son grup IPv4 gösterimi olabilir: ::ffff:192.0.2.1
    if (g.includes('.')) {
      const v4 = ipToBuffer(g);
      if (!v4) throw new ProtocolError(`geçersiz IPv6: ${value}`);
      groups.push(v4.readUInt16BE(0), v4.readUInt16BE(2));
      return;
    }
    const n = parseInt(g, 16);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new ProtocolError(`geçersiz IPv6: ${value}`);
    groups.push(n);
  };

  try {
    head.forEach(pushGroup);
    const headLen = groups.length;
    const tailGroups = [];
    const save = groups.length;
    tail.forEach(pushGroup);
    for (let i = save; i < groups.length; i++) tailGroups.push(groups[i]);
    groups.length = headLen;

    if (halves.length === 2) {
      const fill = 8 - headLen - tailGroups.length;
      if (fill < 0) return null;
      for (let i = 0; i < fill; i++) groups.push(0);
    }
    groups.push(...tailGroups);
  } catch { return null; }

  if (groups.length !== 8) return null;
  const out = Buffer.allocUnsafe(16);
  for (let i = 0; i < 8; i++) out.writeUInt16BE(groups[i], i * 2);
  return out;
}

function bufferToIp(raw) {
  if (raw.length === 4) return `${raw[0]}.${raw[1]}.${raw[2]}.${raw[3]}`;
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(raw.readUInt16BE(i));

  // En uzun sıfır dizisini :: ile kısalt (RFC 5952). Kısaltmamak da geçerli
  // olurdu ama aynı adresin iki farklı dizeyle loglanmasına yol açardı ve
  // "bu IP'yi daha önce gördük mü" sorusu dize karşılaştırmasıyla yanıtlanıyor.
  let bestStart = -1; let bestLen = 0; let curStart = -1; let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart < 0) { curStart = i; curLen = 0; }
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':');

  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':');
  return `${head}::${tail}`;
}

module.exports = {
  Writer, Reader, ProtocolError,
  encodeIp, decodeIp, ipToBuffer, bufferToIp,
  ADDR,
};
