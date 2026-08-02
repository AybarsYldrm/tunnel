'use strict';
// Minimal DER (X.690) okuyucu/yazıcı.
//
// Neden kendi kodumuz? Bu paket sıfır bağımlılıklıdır ve `node:crypto`
// X509Certificate sınıfı yalnızca sertifikaları çözer — OCSP yanıtları
// (RFC 6960) ve CRL'ler (RFC 5280) için ASN.1 seviyesinde okuma/yazma
// gerekir. Buradaki kod SADECE bu iki yapı + X.509 uzantıları için gereken
// kadarını kapsar.
//
// GÜVENLİK NOTU: bu ayrıştırıcı ağdan gelen veriyi işler. Her okuma sınır
// kontrollüdür, belirsiz uzunluk (indefinite length) reddedilir ve
// özyineleme derinliği sınırlıdır — bozuk bir OCSP yanıtı süreci
// düşüremez, yalnızca `Error` fırlatır.

const TAG = Object.freeze({
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  ENUMERATED: 0x0a,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
});

const MAX_DEPTH = 32;

// ============================================================================
// Okuma
// ============================================================================
/**
 * `off` konumundaki tek TLV düğümünü okur.
 * @returns {{tag:number, headerLen:number, len:number, totalLen:number,
 *            contentOff:number, content:Buffer}}
 */
function readTLV(buf, off = 0) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('DER: Buffer bekleniyor');
  if (off < 0 || off + 2 > buf.length) throw new Error('DER: beklenmeyen veri sonu');

  const tag = buf[off];
  // Yüksek etiket numaraları (0x1f) X.509/OCSP/CRL'de kullanılmaz.
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: çok baytlı etiket desteklenmiyor');

  let p = off + 1;
  let len = buf[p++];
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    if (nBytes === 0) throw new Error('DER: belirsiz uzunluk (BER) reddedildi');
    if (nBytes > 4) throw new Error('DER: uzunluk alanı çok geniş');
    if (p + nBytes > buf.length) throw new Error('DER: uzunluk alanı kesik');
    len = 0;
    for (let i = 0; i < nBytes; i++) len = len * 256 + buf[p++];
  }
  const contentOff = p;
  if (contentOff + len > buf.length) throw new Error('DER: içerik kesik');
  return {
    tag,
    headerLen: contentOff - off,
    len,
    totalLen: (contentOff - off) + len,
    contentOff,
    content: buf.subarray(contentOff, contentOff + len),
  };
}

/** Bir yapıcı (constructed) düğümün içeriğindeki üst seviye TLV'leri döner. */
function readChildren(content, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('DER: özyineleme sınırı aşıldı');
  const out = [];
  let off = 0;
  while (off < content.length) {
    const node = readTLV(content, off);
    out.push(node);
    off += node.totalLen;
  }
  return out;
}

/** Belirli bir etiket bekler; uymazsa hata verir. */
function expect(node, tag, what = 'düğüm') {
  if (!node || node.tag !== tag) {
    throw new Error(`DER: ${what} için 0x${tag.toString(16)} bekleniyordu, ` +
                    `0x${(node ? node.tag : -1).toString(16)} geldi`);
  }
  return node;
}

/** İşaretsiz INTEGER içeriğini normalize eder (baştaki 0x00 dolgusu atılır). */
function unsignedInt(content) {
  let i = 0;
  while (i < content.length - 1 && content[i] === 0x00) i++;
  return content.subarray(i);
}

/** INTEGER içeriğini BigInt'e çevirir (işaretsiz). */
function intToBigInt(content) {
  let v = 0n;
  for (const b of content) v = (v << 8n) | BigInt(b);
  return v;
}

/** BIT STRING içeriğinden dolgu baytını atarak ham bitleri döner. */
function bitStringBytes(content) {
  if (content.length === 0) throw new Error('DER: boş BIT STRING');
  const unused = content[0];
  if (unused > 7) throw new Error('DER: geçersiz BIT STRING dolgusu');
  return content.subarray(1);
}

/**
 * OBJECT IDENTIFIER içeriğini noktalı-ondalık gösterime çevirir.
 *
 * DİKKAT: ilk iki bileşen TEK bir alt-tanımlayıcıya sıkıştırılır
 * (40·X + Y, X∈{0,1,2}) ve bu değer TEK BAYTA SIĞMAK ZORUNDA DEĞİLDİR —
 * ör. 2.999.1'in ilk alt-tanımlayıcısı 1079'dur ve iki bayta yayılır.
 * Bu yüzden ilk bileşen de base-128 olarak okunmalı, sonra ayrıştırılmalıdır.
 * Tek bayt varsayan bir çözücü böyle OID'leri SESSİZCE yanlış çözer — bir EKU
 * kontrolünde bu, anahtar amacını yanlış tanımak demektir.
 */
function oidToString(content) {
  if (content.length === 0) throw new Error('DER: boş OID');

  const subids = [];
  let value = 0n;
  let started = false;
  for (let i = 0; i < content.length; i++) {
    const b = content[i];
    if (!started && b === 0x80) throw new Error('DER: OID alt-tanımlayıcısında sıfır dolgusu');
    value = (value << 7n) | BigInt(b & 0x7f);
    started = true;
    if ((b & 0x80) === 0) { subids.push(value); value = 0n; started = false; }
  }
  if (started) throw new Error('DER: OID son bileşeni tamamlanmamış');

  const first = subids[0];
  const parts = first < 40n ? [0n, first]
              : first < 80n ? [1n, first - 40n]
              : [2n, first - 80n];
  return [...parts, ...subids.slice(1)].map((v) => v.toString()).join('.');
}

/** Noktalı-ondalık OID'i DER içeriğine kodlar. */
function oidToDer(dotted) {
  const parts = String(dotted).split('.').map((p) => {
    if (!/^\d+$/.test(p)) throw new Error(`DER: geçersiz OID bileşeni '${p}'`);
    return BigInt(p);
  });
  if (parts.length < 2) throw new Error('DER: OID en az iki bileşen içermeli');
  if (parts[0] > 2n) throw new Error('DER: OID kök bileşeni 0, 1 veya 2 olmalı');
  if (parts[0] < 2n && parts[1] > 39n) {
    throw new Error('DER: 0.x / 1.x köklerinde ikinci bileşen 39\'u aşamaz');
  }

  const bytes = [];
  const push = (v) => {
    const chunk = [Number(v & 0x7fn)];
    v >>= 7n;
    while (v > 0n) { chunk.unshift(Number((v & 0x7fn) | 0x80n)); v >>= 7n; }
    bytes.push(...chunk);
  };
  push(parts[0] * 40n + parts[1]);
  for (let i = 2; i < parts.length; i++) push(parts[i]);
  return Buffer.from(bytes);
}

/** UTCTime / GeneralizedTime → epoch ms. */
function timeToMs(node) {
  const s = node.content.toString('ascii');
  let y; let rest;
  if (node.tag === TAG.UTC_TIME) {
    if (s.length < 11) throw new Error('DER: kısa UTCTime');
    const yy = Number(s.slice(0, 2));
    y = yy >= 50 ? 1900 + yy : 2000 + yy;   // RFC 5280 §4.1.2.5.1
    rest = s.slice(2);
  } else if (node.tag === TAG.GENERALIZED_TIME) {
    if (s.length < 13) throw new Error('DER: kısa GeneralizedTime');
    y = Number(s.slice(0, 4));
    rest = s.slice(4);
  } else {
    throw new Error(`DER: zaman değeri değil (0x${node.tag.toString(16)})`);
  }
  const mo = Number(rest.slice(0, 2));
  const d = Number(rest.slice(2, 4));
  const h = Number(rest.slice(4, 6));
  const mi = Number(rest.slice(6, 8));
  const se = rest.length >= 10 && /^\d\d/.test(rest.slice(8, 10)) ? Number(rest.slice(8, 10)) : 0;
  const ms = Date.UTC(y, mo - 1, d, h, mi, se);
  if (!Number.isFinite(ms)) throw new Error('DER: çözümlenemeyen zaman');
  return ms;
}

// ============================================================================
// Yazma
// ============================================================================
function encodeLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let v = len;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  const c = content && content.length ? content : Buffer.alloc(0);
  return Buffer.concat([Buffer.from([tag]), encodeLen(c.length), c]);
}

const seq = (...parts) => tlv(TAG.SEQUENCE, Buffer.concat(parts.filter(Boolean)));
const set = (...parts) => tlv(TAG.SET, Buffer.concat(parts.filter(Boolean)));
const octetString = (buf) => tlv(TAG.OCTET_STRING, buf);
const nullValue = () => tlv(TAG.NULL, Buffer.alloc(0));
const oid = (dotted) => tlv(TAG.OID, oidToDer(dotted));
const enumerated = (v) => tlv(TAG.ENUMERATED, Buffer.from([v & 0xff]));
const boolean = (v) => tlv(TAG.BOOLEAN, Buffer.from([v ? 0xff : 0x00]));
/** [n] EXPLICIT (constructed) */
const ctx = (n, content) => tlv(0xa0 | n, content);
/** [n] IMPLICIT (primitive) */
const ctxPrimitive = (n, content) => tlv(0x80 | n, content);

function bitString(bytes, unusedBits = 0) {
  return tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([unusedBits]), bytes]));
}

/** Ham (işaretsiz, big-endian) bayt dizisini DER INTEGER'a kodlar. */
function integerFromBytes(bytes) {
  let b = unsignedInt(Buffer.from(bytes));
  if (b.length === 0) b = Buffer.from([0x00]);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return tlv(TAG.INTEGER, b);
}

function generalizedTime(dateOrMs) {
  const d = dateOrMs instanceof Date ? dateOrMs : new Date(dateOrMs);
  const p = (n) => String(n).padStart(2, '0');
  const s = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
            `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(TAG.GENERALIZED_TIME, Buffer.from(s, 'ascii'));
}

module.exports = {
  TAG,
  // okuma
  readTLV, readChildren, expect, unsignedInt, intToBigInt, bitStringBytes,
  oidToString, timeToMs,
  // yazma
  tlv, seq, set, octetString, nullValue, oid, oidToDer, enumerated, boolean,
  ctx, ctxPrimitive, bitString, integerFromBytes, generalizedTime, encodeLen,
};
