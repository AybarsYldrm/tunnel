'use strict';
// PKI — PEM/DER dönüşümü, sertifika zinciri kurma ve X.509 yol doğrulama.
//
// Sıfır bağımlılık: `node:crypto.X509Certificate` (imza/tarih/hostname) +
// kendi DER okuyucumuz (`x509.js`, uzantı alanları için).
//
// Yapılan doğrulama (RFC 5280 §6.1'in pratikte önemli olan alt kümesi):
//   • imza zinciri — geri izlemeli (backtracking) yol kurma, çapraz imzalı
//     CA'lar ve karışık sıralı zincirler dahil
//   • geçerlilik süresi — yoldaki HER sertifika için
//   • basicConstraints: CA bayrağı + pathLenConstraint
//   • keyUsage.keyCertSign — imzalayan CA'larda
//   • extendedKeyUsage — serverAuth / clientAuth amaç kontrolü
//   • tanınmayan KRİTİK uzantıların reddi (RFC 5280 §6.1.3-f)
//   • hostname (SAN/CN, IP dahil)
//
// İptal (OCSP/CRL) denetimi ayrı bir katmandır: `revocation.js`.
// İsim kısıtlamaları (nameConstraints) ve politika ağacı uygulanmaz;
// gerekiyorsa `verifyPeerCertificate` kancasıyla eklenebilir.

const crypto = require('node:crypto');
const x509 = require('./x509.js');

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

function isPem(buf) {
  if (typeof buf === 'string') return buf.includes('-----BEGIN');
  if (!Buffer.isBuffer(buf) || buf.length < 11) return false;
  // "-----B"
  return buf[0] === 0x2d && buf[1] === 0x2d && buf[2] === 0x2d &&
         buf[3] === 0x2d && buf[4] === 0x2d && buf[5] === 0x42;
}

function pemBlockToDer(pemBlock) {
  const b64 = pemBlock.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

function derToPem(derBuf, label = 'CERTIFICATE') {
  const b64 = Buffer.from(derBuf).toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/**
 * Girdiden DER sertifika listesi üretir.
 * Kabul edilenler: PEM string/Buffer (çoklu blok), ham DER Buffer, X509Certificate,
 * bunların (iç içe) dizisi.
 * @returns {Buffer[]}
 */
function toDerList(input) {
  if (input == null) return [];
  if (Array.isArray(input)) return input.flatMap(toDerList);
  if (input instanceof crypto.X509Certificate) return [input.raw];
  if (isPem(input)) {
    const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input);
    const blocks = text.match(PEM_CERT_RE);
    if (!blocks || blocks.length === 0) {
      throw new Error('PEM içinde CERTIFICATE bloğu bulunamadı');
    }
    return blocks.map(pemBlockToDer);
  }
  if (Buffer.isBuffer(input)) return [input];
  throw new TypeError('sertifika girdisi Buffer, string, X509Certificate veya dizi olmalı');
}

/**
 * Sertifika zincirini yükler ve leaf'i BAŞA alacak şekilde sıralar.
 *
 * Gerçek dünyada `cert` dosyası çoğu zaman bir demettir (leaf + ara CA'lar,
 * bazen kök de dahil) ve sıralaması garanti değildir — bazı CA'lar kökten
 * yaprağa, bazıları karışık verir. TLS ise leaf'in İLK sırada olmasını şart
 * koşar (RFC 8446 §4.4.2). Burada demet yapısal olarak çözülür:
 *   leaf = demetteki başka hiçbir sertifikayı imzalamamış olan sertifika.
 * Sonra her halka, bir öncekini imzalayan sertifikayla devam ettirilir.
 * Belirsizlik varsa kullanıcının verdiği sıra korunur.
 *
 * @returns {{der: Buffer[], x509: crypto.X509Certificate[], reordered: boolean}}
 */
function loadCertChain(input) {
  const derList = toDerList(input);
  if (derList.length === 0) throw new Error('sertifika zinciri boş');

  let certs;
  try {
    certs = derList.map((d) => new crypto.X509Certificate(d));
  } catch (e) {
    throw new Error(`sertifika çözümlenemedi: ${e.message}`);
  }
  if (certs.length === 1) return { der: derList, x509: certs, reordered: false };

  const ordered = orderChain(certs);
  const reordered = ordered.some((c, i) => c !== certs[i]);
  return { der: ordered.map((c) => c.raw), x509: ordered, reordered };
}

/** Karışık sıralı bir demeti leaf → … → kök sırasına dizer. */
function orderChain(certs) {
  // Bir sertifika, demetteki başka bir sertifikanın issuer'ıysa leaf olamaz.
  const isIssuerOfSomeone = certs.map((cand, i) =>
    certs.some((other, j) => i !== j && !selfSigned(other) && issuedBy(other, cand)));

  const leafIdx = certs.findIndex((c, i) => !isIssuerOfSomeone[i]);
  if (leafIdx === -1) return certs.slice();  // döngüsel/anlamsız demet — dokunma

  const used = new Set([leafIdx]);
  const out = [certs[leafIdx]];
  let current = certs[leafIdx];

  for (;;) {
    const nextIdx = certs.findIndex((c, i) => !used.has(i) && issuedBy(current, c));
    if (nextIdx === -1) break;
    used.add(nextIdx);
    out.push(certs[nextIdx]);
    current = certs[nextIdx];
  }
  // Zincire bağlanamayan sertifikaları sessizce atmayalım — sonda kalsınlar.
  certs.forEach((c, i) => { if (!used.has(i)) out.push(c); });
  return out;
}

/** CA deposu — güvenilen kök/ara sertifikalar. */
function loadCAStore(input) {
  return toDerList(input).map((d) => new crypto.X509Certificate(d));
}

function loadPrivateKey(input, passphrase) {
  if (input == null) throw new Error('private key eksik');
  if (typeof input === 'object' && input.asymmetricKeyType) return input; // KeyObject
  const opts = { key: input };
  if (passphrase) opts.passphrase = passphrase;
  try {
    return crypto.createPrivateKey(opts);
  } catch (e) {
    throw new Error(`private key okunamadı: ${e.message}` +
      (passphrase ? '' : ' (şifreli anahtar için `passphrase` verin)'));
  }
}

/** Sertifika ile özel anahtarın eşleştiğini doğrular (yanlış dosya kombinasyonu erken yakalanır). */
function assertKeyMatchesCert(privateKey, leafX509) {
  let ok = false;
  try { ok = leafX509.checkPrivateKey(privateKey); }
  catch { ok = false; }
  if (!ok) throw new Error('private key sertifikayla eşleşmiyor (cert/key karışmış olabilir)');
}

// ============================================================================
// Temel yüklemler
// ============================================================================
function certNotYetValid(cert, now) { return Date.parse(cert.validFrom) > now; }
function certExpired(cert, now)     { return Date.parse(cert.validTo)  < now; }

function selfSigned(cert) {
  try { return cert.checkIssued(cert) && cert.verify(cert.publicKey); }
  catch { return false; }
}

function issuedBy(cert, issuer) {
  try { return cert.checkIssued(issuer) && cert.verify(issuer.publicKey); }
  catch { return false; }
}

const infoCache = new WeakMap();
/** Bir sertifikanın uzantı bilgisini (pahalı DER ayrıştırması) önbellekli döner. */
function certInfo(cert) {
  let info = infoCache.get(cert);
  if (!info) {
    info = x509.parseCertificate(cert.raw);
    infoCache.set(cert, info);
  }
  return info;
}

/** Bir sertifikanın CA olarak imza atmaya yetkili olup olmadığı. */
function caUsable(cert, now) {
  if (certExpired(cert, now)) return 'CERT_HAS_EXPIRED';
  if (certNotYetValid(cert, now)) return 'CERT_NOT_YET_VALID';
  let info;
  try { info = certInfo(cert); }
  catch { return null; }                       // uzantı okunamadıysa imzaya güven

  const bc = x509.basicConstraints(info);
  if (bc.present && !bc.isCA) return 'INVALID_CA (basicConstraints CA=false)';
  // basicConstraints yoksa: RFC 5280 v3 sertifikalarında CA olamaz.
  if (!bc.present && info.version >= 3) return 'INVALID_CA (basicConstraints yok)';

  const ku = x509.keyUsage(info);
  if (ku.present && !ku.keyCertSign) return 'INVALID_CA (keyUsage.keyCertSign yok)';

  const unknown = x509.unknownCriticalExtensions(info);
  if (unknown.length) return `UNHANDLED_CRITICAL_EXTENSION (${unknown.join(', ')})`;
  return null;
}

/** pathLenConstraint: bu CA'nın ALTINDA kaç ara CA olabilir (RFC 5280 §4.2.1.9). */
function pathLenOf(cert) {
  try { return x509.basicConstraints(certInfo(cert)).pathLen; }
  catch { return null; }
}

/** Leaf sertifikanın amaca (serverAuth/clientAuth) uygunluğu. */
function checkPurpose(cert, purpose) {
  if (!purpose) return null;
  let info;
  try { info = certInfo(cert); }
  catch { return null; }

  const eku = x509.extKeyUsage(info);
  if (eku) {
    const want = purpose === 'server' ? x509.OID.kpServerAuth : x509.OID.kpClientAuth;
    if (!eku.includes(want) && !eku.includes(x509.OID.anyExtendedKeyUsage)) {
      return `INVALID_PURPOSE (extendedKeyUsage ${purpose}Auth içermiyor)`;
    }
  }
  const unknown = x509.unknownCriticalExtensions(info);
  if (unknown.length) return `UNHANDLED_CRITICAL_EXTENSION (${unknown.join(', ')})`;
  return null;
}

// ============================================================================
// Yol doğrulama
// ============================================================================
/**
 * Zincir doğrulama — geri izlemeli yol kurma.
 *
 * `chain` karşı tarafın gönderdiği demettir: [leaf, ...ara sertifikalar]. Kök
 * demette olabilir de olmayabilir de; güven YALNIZCA `ca` deposundan gelir.
 * `ca` deposundaki HER sertifika bir güven çıpasıdır (kök olmak zorunda değil) —
 * böylece "yalnızca şu ara CA'ya güven" senaryosu da çalışır.
 *
 * @param {object}   o
 * @param {crypto.X509Certificate[]} o.chain  [leaf, ...intermediates]
 * @param {crypto.X509Certificate[]} o.ca     güven çıpaları
 * @param {string}  [o.hostname]              beklenen sunucu adı (SAN/CN)
 * @param {number}  [o.now]
 * @param {boolean} [o.allowSelfSigned]
 * @param {number}  [o.maxDepth]
 * @param {'server'|'client'|null} [o.purpose]  leaf EKU kontrolü
 * @returns {{authorized:boolean, error:string|null, path:crypto.X509Certificate[]}}
 */
function verifyCertificateChain({
  chain, ca = [], hostname = null, now = Date.now(),
  allowSelfSigned = false, maxDepth = 10, purpose = null,
}) {
  if (!chain || chain.length === 0) {
    return { authorized: false, error: 'NO_CERTIFICATE', path: [] };
  }
  const leaf = chain[0];

  // --- 1) Leaf'in kendi geçerliliği
  if (certNotYetValid(leaf, now)) return { authorized: false, error: 'CERT_NOT_YET_VALID', path: [leaf] };
  if (certExpired(leaf, now))     return { authorized: false, error: 'CERT_HAS_EXPIRED',   path: [leaf] };

  // --- 2) Kimlik (hostname) — zincir güveninden bağımsız bir kontrol
  if (hostname && !checkHostname(leaf, hostname)) {
    return { authorized: false, error: 'HOSTNAME_MISMATCH', path: [leaf] };
  }

  const purposeErr = checkPurpose(leaf, purpose);
  if (purposeErr) return { authorized: false, error: purposeErr, path: [leaf] };

  // --- 3) Leaf doğrudan sabitlenmiş (pinned) olabilir
  if (ca.some((c) => c.raw.equals(leaf.raw))) {
    return { authorized: true, error: null, path: [leaf] };
  }

  // --- 4) Kendinden imzalı leaf (WebRTC / geliştirme senaryoları)
  if (selfSigned(leaf)) {
    if (allowSelfSigned) return { authorized: true, error: null, path: [leaf] };
    return {
      authorized: false, path: [leaf],
      error: ca.length === 0 ? 'DEPTH_ZERO_SELF_SIGNED_CERT' : 'SELF_SIGNED_CERT_IN_CHAIN',
    };
  }

  if (ca.length === 0) {
    return { authorized: false, error: 'UNABLE_TO_GET_ISSUER_CERT (CA yapılandırılmadı)', path: [leaf] };
  }

  // --- 5) Geri izlemeli yol kurma
  // Aday ara sertifikalar: karşı tarafın gönderdikleri. `ca` deposundakiler
  // zaten çıpa olarak denenir, bu yüzden ayrıca ara sertifika sayılmazlar.
  const pool = chain.slice(1);
  const used = new Array(pool.length).fill(false);
  const path = [leaf];
  let lastError = 'UNABLE_TO_GET_ISSUER_CERT';

  const walk = (current, depth) => {
    if (depth > maxDepth) { lastError = 'CERT_CHAIN_TOO_LONG'; return false; }

    // (a) Güven çıpasıyla bitirmeyi dene
    for (const anchor of ca) {
      if (!issuedBy(current, anchor)) continue;
      const bad = caUsable(anchor, now);
      if (bad) { lastError = `${bad} (trust anchor)`; continue; }
      if (!pathLenOk(anchor, path.length)) { lastError = 'PATH_LENGTH_EXCEEDED'; continue; }
      path.push(anchor);
      return true;
    }

    // (b) Ara sertifikalarla devam et
    for (let i = 0; i < pool.length; i++) {
      if (used[i]) continue;
      const cand = pool[i];
      if (cand.raw.equals(current.raw)) continue;          // kendine bağlanma
      if (!issuedBy(current, cand)) continue;

      const bad = caUsable(cand, now);
      if (bad) { lastError = `${bad} (intermediate)`; continue; }
      if (!pathLenOk(cand, path.length)) { lastError = 'PATH_LENGTH_EXCEEDED'; continue; }

      used[i] = true;
      path.push(cand);
      if (walk(cand, depth + 1)) return true;
      path.pop();
      used[i] = false;
    }
    return false;
  };

  /**
   * `issuer`, yolda `indexInPath` konumuna eklenecek. Altındaki ara CA sayısı
   * path[1..indexInPath-1] kadardır; pathLenConstraint bunu sınırlar.
   */
  function pathLenOk(issuer, indexInPath) {
    const pl = pathLenOf(issuer);
    return pl === null || pl === undefined || pl >= indexInPath - 1;
  }

  if (walk(leaf, 0)) return { authorized: true, error: null, path };

  // Kök karşı taraftan geldi ama depoda yok — en sık karşılaşılan yanlış
  // yapılandırma; hata mesajı bunu açıkça söylesin.
  if (pool.some((c) => selfSigned(c))) {
    return { authorized: false, error: 'SELF_SIGNED_CERT_IN_CHAIN (kök CA güven deposunda değil)', path };
  }
  return { authorized: false, error: lastError, path };
}

/** SAN/CN kontrolü; IP adresleri de desteklenir. */
function checkHostname(cert, hostname) {
  try {
    if (isIpAddress(hostname)) return cert.checkIP(hostname) !== undefined;
    return cert.checkHost(hostname, { subject: 'default' }) !== undefined;
  } catch {
    return false;
  }
}

function isIpAddress(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':');
}

/** WebRTC tarzı doğrulama: SDP'den gelen parmak izini karşılaştır. */
function matchFingerprint(cert, expected, algorithm = 'sha-256') {
  const map = { 'sha-1': 'fingerprint', 'sha-256': 'fingerprint256', 'sha-512': 'fingerprint512' };
  const prop = map[String(algorithm).toLowerCase()];
  if (!prop) throw new Error(`desteklenmeyen fingerprint algoritması: ${algorithm}`);
  const actual = cert[prop];
  if (!actual) return false;
  const norm = (s) => String(s).replace(/:/g, '').toLowerCase();
  const a = Buffer.from(norm(actual), 'hex');
  const b = Buffer.from(norm(expected), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Sertifikanın anahtar tipi — imza şeması seçiminde kullanılır. */
function certKeyType(cert) {
  return cert.publicKey.asymmetricKeyType; // 'ec' | 'rsa' | 'ed25519' | ...
}

/** Kullanıcıya dönen özet — node:tls'in getPeerCertificate()'ine benzer. */
function summarizeCertificate(cert) {
  if (!cert) return null;
  let ext = {};
  try {
    const info = certInfo(cert);
    const bc = x509.basicConstraints(info);
    ext = {
      basicConstraints: { isCA: bc.isCA, pathLen: bc.pathLen },
      keyUsage: x509.keyUsage(info),
      extKeyUsage: x509.extKeyUsage(info),
      ocspUrls: x509.authorityInfoAccess(info).ocsp,
      crlUrls: x509.crlDistributionPoints(info),
    };
  } catch { /* uzantılar okunamadıysa özet yine de dönsün */ }

  return {
    subject: cert.subject,
    issuer: cert.issuer,
    subjectAltName: cert.subjectAltName,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    serialNumber: cert.serialNumber,
    fingerprint: cert.fingerprint,
    fingerprint256: cert.fingerprint256,
    fingerprint512: cert.fingerprint512,
    keyType: cert.publicKey.asymmetricKeyType,
    ca: cert.ca,
    raw: cert.raw,
    ...ext,
  };
}

module.exports = {
  isPem, pemBlockToDer, derToPem, toDerList,
  loadCertChain, loadCAStore, loadPrivateKey, assertKeyMatchesCert, orderChain,
  verifyCertificateChain, checkHostname, matchFingerprint,
  certKeyType, summarizeCertificate, selfSigned, issuedBy, certInfo,
  x509,
};
