'use strict';
// Handshake mesajları — HER İKİ DTLS SÜRÜMÜ İÇİN TEK DOSYA.
//
//   BÖLÜM 1: DTLS 1.3 — RFC 8446 §4.3.1, §4.4.2-4
//   BÖLÜM 2: DTLS 1.2 — RFC 6347 §4.2.1, RFC 5246 §7.4, RFC 8422 (ECDHE)
//   BÖLÜM 3: Ortak imza katmanı — SignatureScheme kodlaması iki sürümde AYNIDIR
//
// Üçüncü bölüm bu birleştirmenin asıl gerekçesidir: TLS 1.3'ün
// CertificateVerify'ı, TLS 1.2'nin `SignatureAndHashAlgorithm` u16
// kodlamasını aynen kullanır (0x0403 = ecdsa_secp256r1_sha256 her ikisinde de
// geçerlidir). Ayrı dosyalarda dururken 1.3 modülü 1.2 modülünden `sign12`
// import etmek zorundaydı — yani bağımlılık yönü sürüm numaralarıyla ters
// düşüyordu. Tek dosyada ortak katman aşağıda, iki sürüm de onun üstünde durur.

const crypto = require('node:crypto');
const { VERSION, SIG_SCHEME, CLIENT_CERT_TYPE, NAMES } = require('../constants.js');
const { encodeExtensions, decodeExtensions } = require('./extensions.js');

const readU24 = (b, o) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];
function writeU24(b, v, o) { b[o] = (v >> 16) & 0xff; b[o + 1] = (v >> 8) & 0xff; b[o + 2] = v & 0xff; }

// ============================================================================
// BÖLÜM 1 — DTLS 1.3 mesajları
// ============================================================================
// ===== EncryptedExtensions (§4.3.1) =====
function buildEncryptedExtensions(extList = []) { return encodeExtensions(extList); }
function parseEncryptedExtensions(body) {
  return { extensions: decodeExtensions(body, 0).extensions };
}

// ===== Certificate (§4.4.2) =====
//   opaque certificate_request_context<0..2^8-1>;  (server: empty)
//   CertificateEntry certificate_list<0..2^24-1>;
//     opaque cert_data<1..2^24-1>;
//     Extension extensions<0..2^16-1>;  (leaf'te boş olabilir)
//
// `context`: sunucu Certificate'inde DAİMA boş; istemci Certificate'inde
// CertificateRequest.certificate_request_context aynen yansıtılmalıdır (§4.4.2).
//
// `entryExtensions`: CertificateEntry başına uzantı listesi. TLS 1.3'te OCSP
// zımbalama (stapling) buradan taşınır — RFC 8446 §4.4.2.1: status_request
// uzantısı LEAF girdisine iliştirilir, ayrı bir CertificateStatus mesajı yoktur
// (bu TLS 1.2'ye özgüdür).
function buildCertificate({ certChainDER, context = null, entryExtensions = null }) {
  const ctx = context || Buffer.alloc(0);
  const extBufs = certChainDER.map((_, i) => {
    const list = entryExtensions && entryExtensions[i];
    return list && list.length ? encodeExtensions(list) : Buffer.from([0x00, 0x00]);
  });

  let certListLength = 0;
  for (let i = 0; i < certChainDER.length; i++) {
    certListLength += 3 + certChainDER[i].length + extBufs[i].length;
  }

  const buf = Buffer.allocUnsafe(1 + ctx.length + 3 + certListLength);
  let o = 0;
  buf.writeUInt8(ctx.length, o); o += 1;
  if (ctx.length) { ctx.copy(buf, o); o += ctx.length; }
  buf.writeUIntBE(certListLength, o, 3); o += 3;

  for (let i = 0; i < certChainDER.length; i++) {
    const cert = certChainDER[i];
    buf.writeUIntBE(cert.length, o, 3); o += 3;
    cert.copy(buf, o); o += cert.length;
    extBufs[i].copy(buf, o); o += extBufs[i].length;
  }
  return buf;
}

function parseCertificate(body) {
  if (body.length < 4) throw new Error('Certificate truncated');
  let o = 0;
  const ctxLen = body.readUInt8(o); o += 1;
  if (o + ctxLen + 3 > body.length) throw new Error('Certificate context truncated');
  const context = body.subarray(o, o + ctxLen); o += ctxLen;
  const listLen = readU24(body, o); o += 3;
  const end = o + listLen;
  if (end > body.length) throw new Error('Certificate list truncated');

  const entries = [];
  while (o + 3 <= end) {
    const cLen = readU24(body, o); o += 3;
    if (o + cLen + 2 > end) throw new Error('Certificate entry truncated');
    const cert = body.subarray(o, o + cLen); o += cLen;
    const eLen = body.readUInt16BE(o); o += 2;
    if (o + eLen > end) throw new Error('Certificate entry extensions truncated');
    const extData = body.subarray(o, o + eLen); o += eLen;
    // Uzantı bloğu, dış katmanda uzunluk öneki OLMADAN gelir; decodeExtensions
    // ise önekli bekler — bu yüzden burada elle çözülür.
    const extensions = [];
    let p = 0;
    while (p + 4 <= extData.length) {
      const type = extData.readUInt16BE(p);
      const dLen = extData.readUInt16BE(p + 2);
      if (p + 4 + dLen > extData.length) throw new Error('CertificateEntry extension truncated');
      extensions.push({ type, data: extData.subarray(p + 4, p + 4 + dLen) });
      p += 4 + dLen;
    }
    entries.push({ cert, extData, extensions });
  }
  return { context, entries };
}

// ===== CertificateVerify (§4.4.3) =====
// Imza girdisi:
//   64 * 0x20  ||  "TLS 1.3, server CertificateVerify"  ||  0x00  ||  transcript_hash
// veya "client CertificateVerify" (mutual auth).
const CV_SERVER_CONTEXT = Buffer.concat([
  Buffer.alloc(64, 0x20),
  Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
  Buffer.from([0x00]),
]);
const CV_CLIENT_CONTEXT = Buffer.concat([
  Buffer.alloc(64, 0x20),
  Buffer.from('TLS 1.3, client CertificateVerify', 'ascii'),
  Buffer.from([0x00]),
]);

function certVerifyInput(role, transcriptHash) {
  const prefix = role === 'server' ? CV_SERVER_CONTEXT : CV_CLIENT_CONTEXT;
  return Buffer.concat([prefix, transcriptHash]);
}

// TLS 1.3'te RSA imzaları DAİMA PSS'tir (RFC 8446 §4.2.3); PKCS#1 v1.5 şemaları
// yalnızca sertifika imzalarında görülebilir, CertificateVerify'da kullanılamaz.
function signCertVerify({ role, privateKey, sigScheme, transcriptHash }) {
  const input = certVerifyInput(role, transcriptHash);
  const sig = sign12(sigScheme, privateKey, input);
  const out = Buffer.allocUnsafe(4 + sig.length);
  out.writeUInt16BE(sigScheme, 0);
  out.writeUInt16BE(sig.length, 2);
  sig.copy(out, 4);
  return out;
}
function parseCertVerify(body) {
  if (body.length < 4) throw new Error('CertificateVerify truncated');
  const sigScheme = body.readUInt16BE(0);
  const sigLen = body.readUInt16BE(2);
  if (4 + sigLen > body.length) throw new Error('CertificateVerify signature truncated');
  return { sigScheme, signature: body.subarray(4, 4 + sigLen) };
}
function verifyCertVerify({ role, publicKey, sigScheme, signature, transcriptHash }) {
  if (TLS13_FORBIDDEN_SIG.has(sigScheme)) {
    throw new Error(`TLS 1.3 CertificateVerify'da yasak imza şeması: 0x${sigScheme.toString(16)}`);
  }
  const input = certVerifyInput(role, transcriptHash);
  return verify12(sigScheme, publicKey, input, signature);
}
const TLS13_FORBIDDEN_SIG = new Set([
  SIG_SCHEME.RSA_PKCS1_SHA256, SIG_SCHEME.RSA_PKCS1_SHA384, SIG_SCHEME.RSA_PKCS1_SHA512,
]);

// ===== CertificateRequest (TLS 1.3, §4.3.2) =====
//   opaque certificate_request_context<0..2^8-1>;
//   Extension extensions<2..2^16-1>;
function buildCertificateRequest({ context = Buffer.alloc(0), extensions }) {
  const extBuf = encodeExtensions(extensions);
  const out = Buffer.allocUnsafe(1 + context.length + extBuf.length);
  out.writeUInt8(context.length, 0);
  context.copy(out, 1);
  extBuf.copy(out, 1 + context.length);
  return out;
}

function parseCertificateRequest(body) {
  const ctxLen = body.readUInt8(0);
  const context = body.subarray(1, 1 + ctxLen);
  const { extensions } = decodeExtensions(body, 1 + ctxLen);
  return { context, extensions };
}

/** Anahtar tipine uygun TLS 1.3 imza şemasını seç (karşı tarafın listesine göre). */
function chooseSigScheme13(keyType, peerSupported) {
  const prefs = {
    ec:      [SIG_SCHEME.ECDSA_SECP256R1_SHA256, SIG_SCHEME.ECDSA_SECP384R1_SHA384,
              SIG_SCHEME.ECDSA_SECP521R1_SHA512],
    rsa:     [SIG_SCHEME.RSA_PSS_RSAE_SHA256, SIG_SCHEME.RSA_PSS_RSAE_SHA384,
              SIG_SCHEME.RSA_PSS_RSAE_SHA512],
    ed25519: [SIG_SCHEME.ED25519],
    ed448:   [SIG_SCHEME.ED448],
  }[keyType];
  if (!prefs) throw new Error(`desteklenmeyen anahtar tipi: ${keyType}`);
  if (!peerSupported || peerSupported.length === 0) return prefs[0];
  const set = new Set(peerSupported);
  for (const s of prefs) if (set.has(s)) return s;
  return prefs[0];
}

// ===== Finished (§4.4.4) =====
// verify_data = HMAC(finished_key, Transcript-Hash up to but NOT including Finished)
function buildFinished({ hash, finishedKey, transcriptHash }) {
  return crypto.createHmac(hash, finishedKey).update(transcriptHash).digest();
}
function verifyFinished({ hash, finishedKey, transcriptHash, received }) {
  const expected = buildFinished({ hash, finishedKey, transcriptHash });
  if (expected.length !== received.length) return false;
  return crypto.timingSafeEqual(expected, received);
}

// ============================================================================
// BÖLÜM 2 — DTLS 1.2 mesajları
// ============================================================================
// TLS 1.3'te olmayan/farklı olan her şey burada: HelloVerifyRequest,
// ServerKeyExchange, ServerHelloDone, ClientKeyExchange, Certificate (1.2
// biçimi — context ve per-cert extension YOK), CertificateRequest (1.2),
// CertificateVerify (1.2), CertificateStatus (OCSP zımbalama, RFC 6066 §8).

// ===== HelloVerifyRequest — RFC 6347 §4.2.1 =====
// RFC 6347: server_version alanı DTLS 1.0 (0xfeff) olmalıdır (tarihsel uyumluluk).
function buildHelloVerifyRequest(cookie, serverVersion = VERSION.DTLS_1_0) {
  if (cookie.length > 255) throw new RangeError('HVR cookie > 255');
  const out = Buffer.allocUnsafe(3 + cookie.length);
  out.writeUInt16BE(serverVersion, 0);
  out.writeUInt8(cookie.length, 2);
  cookie.copy(out, 3);
  return out;
}

function parseHelloVerifyRequest(body) {
  if (body.length < 3) throw new Error('HelloVerifyRequest truncated');
  const serverVersion = body.readUInt16BE(0);
  const len = body.readUInt8(2);
  if (3 + len > body.length) throw new Error('HVR cookie truncated');
  return { serverVersion, cookie: body.subarray(3, 3 + len) };
}

// ===== Certificate (TLS 1.2, §7.4.2) =====
//   ASN.1Cert certificate_list<0..2^24-1>;   (her biri opaque<1..2^24-1>)
function buildCertificate12(certChainDER) {
  let listLen = 0;
  for (const c of certChainDER) listLen += 3 + c.length;
  const out = Buffer.allocUnsafe(3 + listLen);
  writeU24(out, listLen, 0);
  let o = 3;
  for (const c of certChainDER) {
    writeU24(out, c.length, o); o += 3;
    c.copy(out, o); o += c.length;
  }
  return out;
}

function parseCertificate12(body) {
  if (body.length < 3) throw new Error('Certificate truncated');
  const listLen = readU24(body, 0);
  const end = 3 + listLen;
  if (end > body.length) throw new Error('Certificate list truncated');
  const entries = [];
  let o = 3;
  while (o + 3 <= end) {
    const len = readU24(body, o); o += 3;
    if (o + len > end) throw new Error('Certificate entry truncated');
    entries.push({ cert: body.subarray(o, o + len) }); o += len;
  }
  return { entries };
}

// ===== ServerKeyExchange (ECDHE) — RFC 8422 §5.4 =====
//   ECParameters: curve_type(1) = named_curve(3), namedcurve(2)
//   ECPoint public: opaque point<1..2^8-1>
//   signed_params: SignatureAndHashAlgorithm(2) + opaque signature<0..2^16-1>
//   İmza girdisi: client_random || server_random || ServerECDHParams
const CURVE_TYPE_NAMED = 3;

function serverEcdhParams(group, publicRaw) {
  const out = Buffer.allocUnsafe(4 + publicRaw.length);
  out.writeUInt8(CURVE_TYPE_NAMED, 0);
  out.writeUInt16BE(group, 1);
  out.writeUInt8(publicRaw.length, 3);
  publicRaw.copy(out, 4);
  return out;
}

function buildServerKeyExchange({ group, publicRaw, sigScheme, privateKey, clientRandom, serverRandom }) {
  const params = serverEcdhParams(group, publicRaw);
  const signed = Buffer.concat([clientRandom, serverRandom, params]);
  const signature = sign12(sigScheme, privateKey, signed);
  const out = Buffer.allocUnsafe(params.length + 4 + signature.length);
  params.copy(out, 0);
  out.writeUInt16BE(sigScheme, params.length);
  out.writeUInt16BE(signature.length, params.length + 2);
  signature.copy(out, params.length + 4);
  return out;
}

function parseServerKeyExchange(body) {
  if (body.length < 4) throw new Error('ServerKeyExchange truncated');
  const curveType = body.readUInt8(0);
  if (curveType !== CURVE_TYPE_NAMED) throw new Error(`desteklenmeyen curve_type: ${curveType}`);
  const group = body.readUInt16BE(1);
  const pubLen = body.readUInt8(3);
  if (4 + pubLen + 4 > body.length) throw new Error('ServerKeyExchange truncated (pub)');
  const publicRaw = body.subarray(4, 4 + pubLen);
  const params = body.subarray(0, 4 + pubLen);
  let o = 4 + pubLen;
  const sigScheme = body.readUInt16BE(o); o += 2;
  const sigLen = body.readUInt16BE(o); o += 2;
  if (o + sigLen > body.length) throw new Error('ServerKeyExchange truncated (sig)');
  const signature = body.subarray(o, o + sigLen);
  return { group, publicRaw, params, sigScheme, signature };
}

function verifyServerKeyExchange({ publicKey, clientRandom, serverRandom, params, sigScheme, signature }) {
  const signed = Buffer.concat([clientRandom, serverRandom, params]);
  return verify12(sigScheme, publicKey, signed, signature);
}

// ===== ClientKeyExchange (ECDHE) — RFC 8422 §5.7 =====
function buildClientKeyExchange(publicRaw) {
  const out = Buffer.allocUnsafe(1 + publicRaw.length);
  out.writeUInt8(publicRaw.length, 0);
  publicRaw.copy(out, 1);
  return out;
}

function parseClientKeyExchange(body) {
  if (body.length < 1) throw new Error('ClientKeyExchange truncated');
  const len = body.readUInt8(0);
  if (1 + len > body.length) throw new Error('ClientKeyExchange point truncated');
  return { publicRaw: body.subarray(1, 1 + len) };
}

// ===== ServerHelloDone =====
const SERVER_HELLO_DONE_BODY = Buffer.alloc(0);

// ===== CertificateRequest (TLS 1.2, §7.4.4) =====
function buildCertificateRequest12({ certTypes, sigSchemes, certificateAuthorities = [] }) {
  let caLen = 0;
  for (const dn of certificateAuthorities) caLen += 2 + dn.length;
  const out = Buffer.allocUnsafe(1 + certTypes.length + 2 + sigSchemes.length * 2 + 2 + caLen);
  let o = 0;
  out.writeUInt8(certTypes.length, o); o += 1;
  for (const t of certTypes) { out.writeUInt8(t, o); o += 1; }
  out.writeUInt16BE(sigSchemes.length * 2, o); o += 2;
  for (const s of sigSchemes) { out.writeUInt16BE(s, o); o += 2; }
  out.writeUInt16BE(caLen, o); o += 2;
  for (const dn of certificateAuthorities) {
    out.writeUInt16BE(dn.length, o); o += 2;
    dn.copy(out, o); o += dn.length;
  }
  return out;
}

function parseCertificateRequest12(body) {
  let o = 0;
  const typeCount = body.readUInt8(o); o += 1;
  const certTypes = [];
  for (let i = 0; i < typeCount; i++) certTypes.push(body.readUInt8(o + i));
  o += typeCount;
  const sigLen = body.readUInt16BE(o); o += 2;
  const sigSchemes = [];
  for (let i = 0; i < sigLen; i += 2) sigSchemes.push(body.readUInt16BE(o + i));
  o += sigLen;
  const caLen = o + 2 <= body.length ? body.readUInt16BE(o) : 0;
  return { certTypes, sigSchemes, caLength: caLen };
}

// ===== CertificateVerify (TLS 1.2, §7.4.8) =====
// digitally-signed struct { handshake_messages }
// TLS 1.3'ten farkı: sabit context prefix'i YOK; ham handshake baytları imzalanır.
function buildCertificateVerify12({ sigScheme, privateKey, handshakeMessages }) {
  const signature = sign12(sigScheme, privateKey, handshakeMessages);
  const out = Buffer.allocUnsafe(4 + signature.length);
  out.writeUInt16BE(sigScheme, 0);
  out.writeUInt16BE(signature.length, 2);
  signature.copy(out, 4);
  return out;
}

function parseCertificateVerify12(body) {
  const sigScheme = body.readUInt16BE(0);
  const sigLen = body.readUInt16BE(2);
  return { sigScheme, signature: body.subarray(4, 4 + sigLen) };
}

function verifyCertificateVerify12({ publicKey, sigScheme, signature, handshakeMessages }) {
  return verify12(sigScheme, publicKey, handshakeMessages, signature);
}

// ===== CertificateStatus (TLS 1.2, RFC 6066 §8) =====
//   struct { CertificateStatusType status_type; select { case ocsp:
//            opaque OCSPResponse<1..2^24-1>; } } CertificateStatus;
// TLS 1.3'te bu mesaj YOKTUR — zımbalanmış yanıt CertificateEntry uzantısına
// taşınmıştır (bkz. buildCertificate).
const STATUS_TYPE_OCSP = 1;

function buildCertificateStatus(ocspResponseDer) {
  const out = Buffer.allocUnsafe(4 + ocspResponseDer.length);
  out.writeUInt8(STATUS_TYPE_OCSP, 0);
  writeU24(out, ocspResponseDer.length, 1);
  ocspResponseDer.copy(out, 4);
  return out;
}

function parseCertificateStatus(body) {
  if (body.length < 4) throw new Error('CertificateStatus truncated');
  const statusType = body.readUInt8(0);
  const len = readU24(body, 1);
  if (4 + len > body.length) throw new Error('CertificateStatus response truncated');
  return { statusType, response: body.subarray(4, 4 + len) };
}

// ============================================================================
// BÖLÜM 3 — Ortak imza katmanı
// ============================================================================
// SIG_SCHEME'in u16 kodlaması TLS 1.2'nin (hash, signature) çiftiyle birebir aynıdır:
//   0x0401 = (sha256, rsa)  0x0403 = (sha256, ecdsa)  0x0503 = (sha384, ecdsa) ...
// Bu yüzden imzalama/doğrulama iki sürümde TEK uygulamadır; farklılık yalnızca
// İMZALANAN GİRDİDEDİR (1.3'te sabit context prefix'i, 1.2'de ham baytlar).
const HASH_BY_CODE = { 2: 'sha1', 3: 'sha224', 4: 'sha256', 5: 'sha384', 6: 'sha512' };

function sigParams(sigScheme) {
  // RFC 8446 tarzı PSS şemaları TLS 1.2'de de kullanılabilir.
  switch (sigScheme) {
    case SIG_SCHEME.RSA_PSS_RSAE_SHA256:
    case SIG_SCHEME.RSA_PSS_PSS_SHA256:
      return { hash: 'sha256', kind: 'rsa-pss', saltLength: 32 };
    case SIG_SCHEME.RSA_PSS_RSAE_SHA384:
    case SIG_SCHEME.RSA_PSS_PSS_SHA384:
      return { hash: 'sha384', kind: 'rsa-pss', saltLength: 48 };
    case SIG_SCHEME.RSA_PSS_RSAE_SHA512:
    case SIG_SCHEME.RSA_PSS_PSS_SHA512:
      return { hash: 'sha512', kind: 'rsa-pss', saltLength: 64 };
    case SIG_SCHEME.ED25519: return { hash: null, kind: 'ed25519' };
    case SIG_SCHEME.ED448:   return { hash: null, kind: 'ed448' };
    default: break;
  }
  const hashCode = (sigScheme >> 8) & 0xff;
  const sigCode = sigScheme & 0xff;
  const hash = HASH_BY_CODE[hashCode];
  if (!hash) throw new Error(`desteklenmeyen hash kodu: ${hashCode}`);
  if (sigCode === 1) return { hash, kind: 'rsa-pkcs1' };
  if (sigCode === 3) return { hash, kind: 'ecdsa' };
  throw new Error(`desteklenmeyen imza kodu: ${sigCode}`);
}

function sign12(sigScheme, privateKey, data) {
  const p = sigParams(sigScheme);
  if (p.kind === 'ed25519' || p.kind === 'ed448') return crypto.sign(null, data, privateKey);
  if (p.kind === 'rsa-pss') {
    return crypto.sign(p.hash, data, {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: p.saltLength,
    });
  }
  if (p.kind === 'ecdsa') return crypto.sign(p.hash, data, { key: privateKey, dsaEncoding: 'der' });
  return crypto.sign(p.hash, data, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
}

function verify12(sigScheme, publicKey, data, signature) {
  const p = sigParams(sigScheme);
  if (p.kind === 'ed25519' || p.kind === 'ed448') return crypto.verify(null, data, publicKey, signature);
  if (p.kind === 'rsa-pss') {
    return crypto.verify(p.hash, data, {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: p.saltLength,
    }, signature);
  }
  if (p.kind === 'ecdsa') {
    return crypto.verify(p.hash, data, { key: publicKey, dsaEncoding: 'der' }, signature);
  }
  return crypto.verify(p.hash, data, {
    key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING,
  }, signature);
}

/** Anahtar tipine uyan, karşı tarafın da desteklediği imza şemasını seç. */
function chooseSigScheme12(keyType, peerSupported) {
  const prefs = {
    ec:      [SIG_SCHEME.ECDSA_SECP256R1_SHA256, SIG_SCHEME.ECDSA_SECP384R1_SHA384],
    rsa:     [SIG_SCHEME.RSA_PKCS1_SHA256, SIG_SCHEME.RSA_PSS_RSAE_SHA256, SIG_SCHEME.RSA_PKCS1_SHA384],
    ed25519: [SIG_SCHEME.ED25519],
    ed448:   [SIG_SCHEME.ED448],
  }[keyType];
  if (!prefs) throw new Error(`desteklenmeyen anahtar tipi: ${keyType}`);
  if (!peerSupported || peerSupported.length === 0) return prefs[0];
  const set = new Set(peerSupported);
  for (const s of prefs) if (set.has(s)) return s;
  // Karşı taraf listesi bizimkiyle kesişmiyor: RFC 5246 §7.4.1.4.1 uyarınca
  // sha1+uygun imza varsayılanı yerine, kendi ilk tercihimizle devam etmek daha
  // güvenli (SHA-1 asla kullanılmaz).
  return prefs[0];
}

function certTypesForKey() {
  return [CLIENT_CERT_TYPE.ECDSA_SIGN, CLIENT_CERT_TYPE.RSA_SIGN];
}

function sigSchemeName(id) {
  return NAMES.SIG_SCHEME[id] || `0x${Number(id).toString(16)}`;
}

module.exports = {
  // --- DTLS 1.3
  buildEncryptedExtensions, parseEncryptedExtensions,
  buildCertificate, parseCertificate,
  signCertVerify, parseCertVerify, verifyCertVerify, certVerifyInput,
  buildCertificateRequest, parseCertificateRequest, chooseSigScheme13,
  buildFinished, verifyFinished,

  // --- DTLS 1.2
  buildHelloVerifyRequest, parseHelloVerifyRequest,
  buildCertificate12, parseCertificate12,
  serverEcdhParams, buildServerKeyExchange, parseServerKeyExchange, verifyServerKeyExchange,
  buildClientKeyExchange, parseClientKeyExchange,
  SERVER_HELLO_DONE_BODY,
  buildCertificateRequest12, parseCertificateRequest12,
  buildCertificateVerify12, parseCertificateVerify12, verifyCertificateVerify12,
  buildCertificateStatus, parseCertificateStatus,

  // --- ortak imza katmanı
  sign12, verify12, sigParams, chooseSigScheme12, certTypesForKey, sigSchemeName,
};
