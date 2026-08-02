'use strict';
// AEAD kayıt koruması ilkelleri — RFC 8446 §5.2/§5.3, RFC 9147 §4.2.
//
// Bu modül hot path'tedir: her kayıt için çağrılır. Bu yüzden BigInt kullanmaz,
// gereksiz Buffer kopyası çıkarmaz ve tüm tahsisleri tek seferde yapar.

const crypto = require('node:crypto');

/**
 * TLS 1.3 / DTLS 1.3 per-record nonce:
 *   64-bit sequence number, sola sıfırla doldurulup write_iv ile XOR'lanır.
 * @param {Buffer} writeIv  statik IV (12 bayt)
 * @param {number|bigint} recordSeq
 */
function buildAeadNonce(writeIv, recordSeq) {
  const seq = typeof recordSeq === 'bigint' ? Number(recordSeq) : recordSeq;
  const nonce = Buffer.from(writeIv);
  const off = nonce.length - 8;
  const hi = Math.floor(seq / 0x100000000);
  const lo = seq >>> 0;
  nonce[off]     ^= (hi >>> 24) & 0xff;
  nonce[off + 1] ^= (hi >>> 16) & 0xff;
  nonce[off + 2] ^= (hi >>> 8)  & 0xff;
  nonce[off + 3] ^=  hi         & 0xff;
  nonce[off + 4] ^= (lo >>> 24) & 0xff;
  nonce[off + 5] ^= (lo >>> 16) & 0xff;
  nonce[off + 6] ^= (lo >>> 8)  & 0xff;
  nonce[off + 7] ^=  lo         & 0xff;
  return nonce;
}

/**
 * TLSInnerPlaintext (RFC 8446 §5.2): content || content_type || zeros(padding)
 */
function buildInnerPlaintext(contentType, content, paddingLen = 0) {
  const out = Buffer.allocUnsafe(content.length + 1 + paddingLen);
  content.copy(out, 0);
  out[content.length] = contentType;
  if (paddingLen > 0) out.fill(0, content.length + 1);
  return out;
}

/**
 * Sondaki sıfır dolgusu atılır; ilk sıfır olmayan bayt gerçek content_type'tır.
 */
function parseInnerPlaintext(inner) {
  let i = inner.length - 1;
  while (i >= 0 && inner[i] === 0) i--;
  if (i < 0) throw new Error('inner plaintext tamamen sıfır — geçersiz kayıt');
  return { contentType: inner[i], content: inner.subarray(0, i) };
}

function aeadSeal({ aead, key, nonce, aad, plaintext, tagLen = 16 }) {
  const cipher = crypto.createCipheriv(aead, key, nonce, { authTagLength: tagLen });
  if (aad && aad.length > 0) cipher.setAAD(aad);
  const head = cipher.update(plaintext);
  const tail = cipher.final();
  const tag = cipher.getAuthTag();
  return tail.length === 0
    ? Buffer.concat([head, tag], head.length + tag.length)
    : Buffer.concat([head, tail, tag]);
}

function aeadOpen({ aead, key, nonce, aad, ciphertextWithTag, tagLen = 16 }) {
  if (ciphertextWithTag.length < tagLen) throw new Error('ciphertext tag boyundan kısa');
  const splitAt = ciphertextWithTag.length - tagLen;
  const ct  = ciphertextWithTag.subarray(0, splitAt);
  const tag = ciphertextWithTag.subarray(splitAt);

  const decipher = crypto.createDecipheriv(aead, key, nonce, { authTagLength: tagLen });
  if (aad && aad.length > 0) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    const head = decipher.update(ct);
    const tail = decipher.final();
    return tail.length === 0 ? head : Buffer.concat([head, tail]);
  } catch (e) {
    // Mesaj sabit tutulur: hangi aşamada başarısız olduğunu sızdırmak yan kanal açar.
    throw new Error('AEAD authentication failed');
  }
}

/**
 * DTLS 1.3 sequence-number maskesi — RFC 9147 §4.2.3.
 * Ciphertext'in ilk 16 baytı örnek olarak alınır.
 */
function snMask(snCipher, snKey, ciphertext) {
  if (snCipher === 'aes-128-ecb' || snCipher === 'aes-256-ecb') {
    let block = ciphertext.subarray(0, 16);
    if (block.length < 16) {
      const padded = Buffer.alloc(16, 0);
      block.copy(padded);
      block = padded;
    }
    const c = crypto.createCipheriv(snCipher, snKey, '');
    c.setAutoPadding(false);
    return c.update(block);
  }
  if (snCipher === 'chacha20') {
    // İlk 4 bayt counter, sonraki 12 bayt nonce.
    let iv = ciphertext.subarray(0, 16);
    if (iv.length < 16) {
      const padded = Buffer.alloc(16, 0);
      iv.copy(padded);
      iv = padded;
    }
    const c = crypto.createCipheriv('chacha20', snKey, iv);
    return c.update(ZERO16);
  }
  throw new Error(`bilinmeyen sn cipher: ${snCipher}`);
}
const ZERO16 = Buffer.alloc(16, 0);

/**
 * Kısaltılmış sequence number'dan tam değeri kurar (RFC 9147 §4.2.2 Ek A).
 * En yakın aday seçilir.
 */
function reconstructSeq(lastKnownFullSeq, truncated, snBits) {
  const window = snBits === 16 ? 0x10000 : 0x100;
  const mask = window - 1;
  const low = truncated & mask;
  const lastHigh = lastKnownFullSeq - (lastKnownFullSeq & mask);

  let best = -1;
  let bestDist = Infinity;
  for (let k = -1; k <= 1; k++) {
    const cand = lastHigh + k * window + low;
    if (cand < 0) continue;
    const d = Math.abs(cand - lastKnownFullSeq);
    if (d < bestDist) { best = cand; bestDist = d; }
  }
  return best < 0 ? low : best;
}

module.exports = {
  buildAeadNonce, buildInnerPlaintext, parseInnerPlaintext,
  aeadSeal, aeadOpen, snMask, reconstructSeq,
};
