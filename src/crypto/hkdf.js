'use strict';

const crypto = require('node:crypto');

// RFC 9147 §5.9: TLS 1.3 "tls13 " (trailing space) kullanır; DTLS 1.3 SHALL
// "dtls13" (trailing space YOK) kullanır — key separation için. İkisi de
// 6 byte (DTLS 1 harf uzun olduğu için boşluk feda edilmiş), ama byte'lar
// farklı, dolayısıyla türetilen TÜM key material farklı. Bu iki prefix asla
// birbirinin yerine geçmez.
const TLS13_LABEL_PREFIX_BUF  = Buffer.from('tls13 ', 'ascii');
const DTLS13_LABEL_PREFIX_BUF = Buffer.from('dtls13', 'ascii');
// Bu modül bir DTLS 1.3 stack'i olduğu için varsayılan prefix "dtls13" olmalı.
const LABEL_PREFIX = DTLS13_LABEL_PREFIX_BUF;

function hkdfExtract(hash, salt, ikm) {
  const saltBuf = (salt && salt.length > 0) ? salt : Buffer.alloc(hashLen(hash), 0);
  return crypto.createHmac(hash, saltBuf).update(ikm).digest();
}

function hkdfExpand(hash, prk, info, length) {
  const hLen = hashLen(hash);
  if (length > 255 * hLen) throw new RangeError(`HKDF-Expand length too large (${length} > ${255 * hLen})`);
  
  const out = Buffer.alloc(length);
  let T = Buffer.alloc(0);
  let written = 0;
  let counter = 1;
  
  while (written < length) {
    const h = crypto.createHmac(hash, prk);
    h.update(T);
    h.update(info);
    h.update(Buffer.from([counter]));
    T = h.digest();
    
    const take = Math.min(hLen, length - written);
    T.copy(out, written, 0, take);
    written += take;
    counter += 1;
  }
  return out;
}

// Varsayılan prefix LABEL_PREFIX yapıldı
function buildHkdfLabel(length, label, context, prefix = LABEL_PREFIX) {
  const labelBuf = typeof label === 'string' ? Buffer.from(label, 'ascii') : label;
  const ctxBuf   = context ? (Buffer.isBuffer(context) ? context : Buffer.from(context)) : Buffer.alloc(0);
  const fullLabel = Buffer.concat([prefix, labelBuf]);
  
  if (fullLabel.length < 7 || fullLabel.length > 255) {
    throw new RangeError(`HkdfLabel.label length out of range: ${fullLabel.length}`);
  }
  if (ctxBuf.length > 255) {
    throw new RangeError(`HkdfLabel.context length > 255: ${ctxBuf.length}`);
  }
  
  const out = Buffer.alloc(2 + 1 + fullLabel.length + 1 + ctxBuf.length);
  let o = 0;
  out.writeUInt16BE(length, o); o += 2;
  out.writeUInt8(fullLabel.length, o); o += 1;
  fullLabel.copy(out, o); o += fullLabel.length;
  out.writeUInt8(ctxBuf.length, o); o += 1;
  ctxBuf.copy(out, o);
  
  return out;
}

function hkdfExpandLabel(hash, secret, label, context, length, prefix = LABEL_PREFIX) {
  const info = buildHkdfLabel(length, label, context, prefix);
  return hkdfExpand(hash, secret, info, length);
}

// Derive-Secret ARTIK KESİNLİKLE "dtls13" KULLANIYOR!
function deriveSecret(hash, secret, label, messagesHash, prefix = LABEL_PREFIX) {
  const hLen = hashLen(hash);
  const ctx = messagesHash ?? hashEmpty(hash);
  if (ctx.length !== hLen) {
    throw new Error(`Derive-Secret: context length ${ctx.length} != Hash.length ${hLen}`);
  }
  return hkdfExpandLabel(hash, secret, label, ctx, hLen, prefix);
}

function hashLen(name) {
  switch (name.toLowerCase()) {
    case 'sha256': return 32;
    case 'sha384': return 48;
    case 'sha512': return 64;
    default: throw new Error(`unknown hash: ${name}`);
  }
}

function hashEmpty(name) {
  return crypto.createHash(name).digest();
}

function transcriptHash(name, ...chunks) {
  const h = crypto.createHash(name);
  for (const c of chunks) h.update(c);
  return h.digest();
}

module.exports = {
  hkdfExtract,
  hkdfExpand,
  hkdfExpandLabel,
  deriveSecret,
  buildHkdfLabel,
  hashLen,
  hashEmpty,
  transcriptHash,
  TLS13_LABEL_PREFIX: TLS13_LABEL_PREFIX_BUF,
  DTLS13_LABEL_PREFIX: DTLS13_LABEL_PREFIX_BUF,
};