'use strict';
// Sertifika iptal denetimi — OCSP (RFC 6960) ve CRL (RFC 5280 §5).
//
// mTLS'te "sertifika geçerli mi?" sorusunun yalnızca yarısı zincir/tarih
// doğrulamasıdır. Diğer yarısı: sertifika İPTAL EDİLDİ Mİ? Çalınan bir istemci
// anahtarı, süresi dolana kadar (825 güne kadar) geçerli görünmeye devam eder.
// Bu modül zincirdeki her sertifikayı — KÖK HARİÇ — sırayla sorgular:
//
//   1. Zımbalanmış (stapled) OCSP yanıtı varsa onu kullan  — ağ turu yok
//   2. AIA'da OCSP responder URL'i varsa OCSP sorgusu yap   — RFC 6960
//   3. Yoksa CRLDistributionPoints'ten CRL indir             — RFC 5280 §5
//   4. Hiçbiri yoksa: politikaya göre karar ver
//
// Kök sertifika sorgulanmaz: kendi kendini iptal edemez, güveni yerel
// depodan gelir (RFC 5280 §6.1 — trust anchor doğrulama girdisidir, çıktısı
// değil).
//
// HTTP istekleri `node:http` / `node:https` ile yapılır (dış bağımlılık yok).
// OCSP ve CRL uç noktaları RFC 5280 §4.2.1.13 uyarınca zaten düz HTTP
// üzerinden sunulur — döngüsel güven bağımlılığını kırmak için imzalı
// nesnelere güvenilir, taşımaya değil.

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

const der = require('./der.js');
const x509 = require('./x509.js');

const { OID, OID_BY_HASH, HASH_BY_OID } = x509;

// OCSPResponseStatus — RFC 6960 §4.2.1
const RESPONSE_STATUS = Object.freeze({
  0: 'successful', 1: 'malformedRequest', 2: 'internalError',
  3: 'tryLater', 5: 'sigRequired', 6: 'unauthorized',
});

// CRLReason — RFC 5280 §5.3.1
const REASON_NAMES = Object.freeze({
  0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise', 3: 'affiliationChanged',
  4: 'superseded', 5: 'cessationOfOperation', 6: 'certificateHold',
  8: 'removeFromCRL', 9: 'privilegeWithdrawn', 10: 'aACompromise',
});

const DEFAULTS = Object.freeze({
  mode: 'off',              // 'off' | 'soft-fail' | 'hard-fail'
  ocsp: true,
  crl: true,
  timeoutMs: 5_000,
  maxResponseBytes: 1 << 20,   // 1 MiB — OCSP yanıtları KB mertebesindedir
  maxCrlBytes: 8 << 20,        // 8 MiB — büyük kurumsal CRL'ler için
  cacheTtlMs: 10 * 60_000,
  maxCacheEntries: 1024,
  clockSkewMs: 5 * 60_000,     // saat kayması toleransı (RFC 6960 §4.2.2.1)
  maxRedirects: 3,
  hashAlgorithm: 'sha256',     // CertID.hashAlgorithm
  checkLeafOnly: false,
});

// ============================================================================
// Politika normalizasyonu
// ============================================================================
/**
 * Kullanıcı seçeneğini ('off' | true | 'soft-fail' | {…}) normalleştirir.
 * @returns {object|null} null = kapalı
 */
function normalizeRevocation(input) {
  if (input === undefined || input === null || input === false || input === 'off') return null;

  let raw;
  if (input === true) raw = { mode: 'soft-fail' };
  else if (typeof input === 'string') raw = { mode: input };
  else if (typeof input === 'object') raw = { ...input };
  else throw new TypeError('revocation: boolean, string veya nesne olmalı');

  const cfg = { ...DEFAULTS, ...raw };
  if (raw.mode === undefined) cfg.mode = 'soft-fail';

  // Yaygın eş anlamlılar — node/openssl dünyasından gelen adlar da kabul edilir.
  const alias = {
    on: 'soft-fail', true: 'soft-fail', soft: 'soft-fail', 'best-effort': 'soft-fail',
    hard: 'hard-fail', strict: 'hard-fail', require: 'hard-fail', required: 'hard-fail',
  };
  cfg.mode = alias[cfg.mode] || cfg.mode;
  if (cfg.mode === 'off') return null;
  if (cfg.mode !== 'soft-fail' && cfg.mode !== 'hard-fail') {
    throw new Error(`revocation.mode geçersiz: '${cfg.mode}' — 'off', 'soft-fail' veya 'hard-fail'`);
  }
  if (!cfg.ocsp && !cfg.crl) {
    throw new Error('revocation: ocsp ve crl birlikte kapatılamaz — mode:"off" kullanın');
  }
  if (!OID_BY_HASH[cfg.hashAlgorithm]) {
    throw new Error(`revocation.hashAlgorithm desteklenmiyor: ${cfg.hashAlgorithm}`);
  }
  return cfg;
}

// ============================================================================
// OCSP istek üretimi — RFC 6960 §4.1.1
// ============================================================================
/**
 * @param {object} subject  x509.parseCertificate çıktısı (sorgulanan sertifika)
 * @param {object} issuer   x509.parseCertificate çıktısı (imzalayan CA)
 * @param {{hashAlgorithm?:string, nonce?:Buffer|false}} [opts]
 * @returns {{der:Buffer, nonce:Buffer|null, certId:object}}
 */
function buildOcspRequest(subject, issuer, opts = {}) {
  const hashAlg = opts.hashAlgorithm || 'sha256';
  const hashOid = OID_BY_HASH[hashAlg];
  if (!hashOid) throw new Error(`OCSP: desteklenmeyen hash ${hashAlg}`);

  const issuerNameHash = crypto.createHash(hashAlg).update(issuer.subjectDer).digest();
  const issuerKeyHash = crypto.createHash(hashAlg).update(issuer.spkiKeyBits).digest();

  const certIdDer = der.seq(
    der.seq(der.oid(hashOid), der.nullValue()),
    der.octetString(issuerNameHash),
    der.octetString(issuerKeyHash),
    der.integerFromBytes(subject.serialNumber),
  );

  let nonce = null;
  let requestExtensions = null;
  if (opts.nonce !== false) {
    nonce = Buffer.isBuffer(opts.nonce) ? opts.nonce : crypto.randomBytes(16);
    // extnValue OCTET STRING'in İÇERİĞİ, Nonce ::= OCTET STRING'in kendi DER'idir.
    requestExtensions = der.ctx(2, der.seq(
      der.seq(der.oid(OID.ocspNonce), der.octetString(der.octetString(nonce))),
    ));
  }

  const tbsRequest = der.seq(der.seq(der.seq(certIdDer)), requestExtensions);
  return {
    der: der.seq(tbsRequest),
    nonce,
    certId: { hashAlg, issuerNameHash, issuerKeyHash, serialNumber: subject.serialNumber },
  };
}

// ============================================================================
// OCSP yanıt çözümleme — RFC 6960 §4.2.1
// ============================================================================
function parseOcspResponse(responseDer) {
  const top = der.expect(der.readTLV(responseDer, 0), der.TAG.SEQUENCE, 'OCSPResponse');
  const kids = der.readChildren(top.content);
  const statusCode = der.expect(kids[0], der.TAG.ENUMERATED, 'responseStatus').content[0];
  const status = RESPONSE_STATUS[statusCode] || `unknown(${statusCode})`;
  if (statusCode !== 0) return { status, basic: null };

  const bytesNode = kids.find((k) => k.tag === 0xa0);
  if (!bytesNode) throw new Error('OCSP: successful yanıtta responseBytes yok');
  const rb = der.readChildren(der.readTLV(bytesNode.content, 0).content);
  const responseType = der.oidToString(rb[0].content);
  if (responseType !== OID.ocspBasic) {
    throw new Error(`OCSP: desteklenmeyen responseType ${responseType}`);
  }
  return { status, basic: parseBasicResponse(rb[1].content) };
}

function parseBasicResponse(basicDer) {
  const top = der.expect(der.readTLV(basicDer, 0), der.TAG.SEQUENCE, 'BasicOCSPResponse');
  const kids = der.readChildren(top.content);
  const tbsNode = kids[0];
  const alg = x509.parseAlgorithmIdentifier(kids[1]);
  const signature = der.bitStringBytes(kids[2].content);
  const certsNode = kids[3] && kids[3].tag === 0xa0 ? kids[3] : null;

  const certs = [];
  if (certsNode) {
    for (const c of der.readChildren(der.readTLV(certsNode.content, 0).content)) {
      certs.push(x509.wholeNode(c));
    }
  }

  return {
    tbsDer: x509.wholeNode(tbsNode),
    sigAlgOid: alg.oid, sigAlgParams: alg.params, signature, certs,
    ...parseResponseData(tbsNode),
  };
}

function parseResponseData(tbsNode) {
  const kids = der.readChildren(tbsNode.content);
  let i = 0;
  if (kids[i] && kids[i].tag === 0xa0) i++;                    // version [0]

  const responderNode = kids[i++];                             // ResponderID CHOICE
  const responderById = responderNode.tag === 0xa1
    ? { byName: x509.wholeNode(der.readTLV(responderNode.content, 0)) }
    : { byKey: der.readTLV(responderNode.content, 0).content };

  const producedAt = der.timeToMs(kids[i++]);
  const responsesNode = der.expect(kids[i++], der.TAG.SEQUENCE, 'responses');

  const responses = der.readChildren(responsesNode.content).map(parseSingleResponse);

  let nonce = null;
  for (; i < kids.length; i++) {
    if (kids[i].tag !== 0xa1) continue;                         // responseExtensions [1]
    const extsSeq = der.readTLV(kids[i].content, 0);
    for (const extNode of der.readChildren(extsSeq.content)) {
      const p = x509.parseExtension(extNode);
      if (p && p.oid === OID.ocspNonce) nonce = Buffer.from(der.readTLV(p.value, 0).content);
    }
  }

  return { responder: responderById, producedAt, responses, nonce };
}

function parseSingleResponse(node) {
  const kids = der.readChildren(node.content);
  const certIdKids = der.readChildren(kids[0].content);
  const certId = {
    hashAlg: HASH_BY_OID[der.oidToString(der.readChildren(certIdKids[0].content)[0].content)] || null,
    issuerNameHash: certIdKids[1].content,
    issuerKeyHash: certIdKids[2].content,
    serialNumber: der.unsignedInt(certIdKids[3].content),
  };

  const statusNode = kids[1];
  let certStatus = 'unknown';
  let revokedAt = null;
  let reasonCode = null;
  if (statusNode.tag === 0x80) certStatus = 'good';
  else if (statusNode.tag === 0xa1) {
    certStatus = 'revoked';
    const ri = der.readChildren(statusNode.content);
    revokedAt = der.timeToMs(ri[0]);
    if (ri[1] && ri[1].tag === 0xa0) reasonCode = der.readTLV(ri[1].content, 0).content[0];
  }

  const thisUpdate = der.timeToMs(kids[2]);
  let nextUpdate = null;
  let noCheck = false;
  for (let i = 3; i < kids.length; i++) {
    if (kids[i].tag === 0xa0) nextUpdate = der.timeToMs(der.readTLV(kids[i].content, 0));
    else if (kids[i].tag === 0xa1) {
      const extsSeq = der.readTLV(kids[i].content, 0);
      for (const extNode of der.readChildren(extsSeq.content)) {
        const p = x509.parseExtension(extNode);
        if (p && p.oid === OID.ocspNoCheck) noCheck = true;
      }
    }
  }
  return { certId, certStatus, revokedAt, reasonCode, thisUpdate, nextUpdate, noCheck };
}

// ============================================================================
// OCSP yanıt doğrulama
// ============================================================================
/**
 * BasicOCSPResponse'u kriptografik olarak doğrular ve istenen sertifikanın
 * durumunu döner.
 *
 * @param {object} o
 * @param {object} o.basic     parseBasicResponse çıktısı
 * @param {object} o.subject   sorgulanan sertifika (x509.parseCertificate)
 * @param {object} o.issuer    imzalayan CA (x509.parseCertificate)
 * @param {crypto.KeyObject} o.issuerPublicKey
 * @param {Buffer|null} [o.nonce]  gönderdiğimiz nonce
 * @param {number} [o.now]
 * @param {number} [o.skewMs]
 * @returns {{status:'good'|'revoked'|'unknown', reason?:string, revokedAt?:number,
 *            nextUpdate:number|null, error:string|null}}
 */
function verifyOcspResponse({ basic, subject, issuer, issuerPublicKey,
                              nonce = null, now = Date.now(), skewMs = DEFAULTS.clockSkewMs }) {
  // --- 1) İmzalayanı bul ve imzayı doğrula
  const signer = resolveOcspSigner(basic, issuer, issuerPublicKey, now);
  if (signer.error) return fail(signer.error);

  const sigOk = x509.verifySignature({
    tbs: basic.tbsDer, sigAlgOid: basic.sigAlgOid, sigAlgParams: basic.sigAlgParams,
    signature: basic.signature, publicKey: signer.publicKey,
  });
  if (!sigOk) return fail('OCSP_BAD_SIGNATURE');

  // --- 2) Nonce eşleşmesi (RFC 6960 §4.4.1)
  // Yanıtta nonce YOKSA kabul edilir: birçok responder önceden imzalanmış
  // yanıtları önbellekten sunar ve nonce'ı yansıtamaz (RFC 5019 §4).
  if (nonce && basic.nonce && !buffersEqual(nonce, basic.nonce)) {
    return fail('OCSP_NONCE_MISMATCH');
  }

  // --- 3) İstenen sertifikaya ait SingleResponse'u bul
  const single = basic.responses.find((r) => certIdMatches(r.certId, subject, issuer));
  if (!single) return fail('OCSP_NO_MATCHING_RESPONSE');

  // --- 4) Tazelik (RFC 6960 §4.2.2.1)
  if (single.thisUpdate > now + skewMs) return fail('OCSP_NOT_YET_VALID');
  if (single.nextUpdate !== null && single.nextUpdate < now - skewMs) {
    return fail('OCSP_RESPONSE_EXPIRED');
  }

  if (single.certStatus === 'revoked') {
    return {
      status: 'revoked',
      reason: REASON_NAMES[single.reasonCode] || (single.reasonCode == null ? 'unspecified' : `reason(${single.reasonCode})`),
      revokedAt: single.revokedAt,
      nextUpdate: single.nextUpdate,
      error: null,
    };
  }
  if (single.certStatus === 'unknown') {
    return { status: 'unknown', nextUpdate: single.nextUpdate, error: 'OCSP_STATUS_UNKNOWN' };
  }
  return { status: 'good', nextUpdate: single.nextUpdate, error: null };

  function fail(error) {
    return { status: 'unknown', nextUpdate: null, error };
  }
}

/**
 * Yanıtı imzalayanı belirler. İki meşru durum vardır (RFC 6960 §4.2.2.2):
 *   a) CA'nın kendisi imzalar
 *   b) CA'nın yetkilendirdiği bir "delegated responder" imzalar — bu sertifika
 *      yanıtın certs[] alanında gelir, CA tarafından imzalanmış olmalı ve
 *      id-kp-OCSPSigning EKU'sunu TAŞIMALIDIR.
 * Üçüncü bir durum yoktur; aksi hâlde herhangi bir sertifika sahibi başkasının
 * sertifikasını "iptal edilmemiş" ilan edebilirdi.
 */
function resolveOcspSigner(basic, issuer, issuerPublicKey, now) {
  if (responderMatches(basic.responder, issuer)) {
    return { publicKey: issuerPublicKey, delegated: false };
  }

  for (const certDer of basic.certs) {
    let info;
    let x;
    try {
      info = x509.parseCertificate(certDer);
      x = new crypto.X509Certificate(certDer);
    } catch { continue; }
    if (!responderMatches(basic.responder, info)) continue;

    // Delege responder CA tarafından imzalanmış olmalı.
    const issuedOk = x509.verifySignature({
      tbs: info.tbsDer, sigAlgOid: info.sigAlgOid, sigAlgParams: info.sigAlgParams,
      signature: info.signature, publicKey: issuerPublicKey,
    });
    if (!issuedOk) continue;
    if (!info.issuerDer.equals(issuer.subjectDer)) continue;
    if (now < info.notBefore || now > info.notAfter) continue;

    const eku = x509.extKeyUsage(info);
    if (!eku || !eku.includes(OID.kpOcspSigning)) {
      return { error: 'OCSP_RESPONDER_NOT_AUTHORIZED' };
    }
    return { publicKey: x.publicKey, delegated: true };
  }
  return { error: 'OCSP_UNKNOWN_RESPONDER' };
}

function responderMatches(responder, certInfo) {
  if (responder.byName) return responder.byName.equals(certInfo.subjectDer);
  if (responder.byKey) {
    // ResponderID.byKey PROTOKOLDE SABİT SHA-1'dir (RFC 6960 §4.2.1),
    // CertID.hashAlgorithm seçiminden bağımsızdır.
    const kh = crypto.createHash('sha1').update(certInfo.spkiKeyBits).digest();
    return buffersEqual(kh, responder.byKey);
  }
  return false;
}

function certIdMatches(certId, subject, issuer) {
  if (!certId.hashAlg) return false;
  if (!der.unsignedInt(certId.serialNumber).equals(der.unsignedInt(subject.serialNumber))) return false;
  const nameHash = crypto.createHash(certId.hashAlg).update(issuer.subjectDer).digest();
  const keyHash = crypto.createHash(certId.hashAlg).update(issuer.spkiKeyBits).digest();
  return buffersEqual(nameHash, certId.issuerNameHash) && buffersEqual(keyHash, certId.issuerKeyHash);
}

function buffersEqual(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && a.equals(b);
}

// ============================================================================
// CRL doğrulama — RFC 5280 §6.3
// ============================================================================
/**
 * @returns {{status:'good'|'revoked'|'unknown', reason?:string, revokedAt?:number,
 *            nextUpdate:number|null, error:string|null}}
 */
function verifyCrl({ crlDer, subject, issuer, issuerPublicKey,
                     now = Date.now(), skewMs = DEFAULTS.clockSkewMs }) {
  let crl;
  try { crl = x509.parseCrl(crlDer); }
  catch (e) { return { status: 'unknown', nextUpdate: null, error: `CRL_PARSE_ERROR (${e.message})` }; }

  // Delta CRL tek başına yeterli değildir — tam CRL ile birleştirilmesi gerekir.
  if (crl.isDelta) return { status: 'unknown', nextUpdate: null, error: 'CRL_IS_DELTA' };

  if (!crl.issuerDer.equals(issuer.subjectDer)) {
    return { status: 'unknown', nextUpdate: null, error: 'CRL_ISSUER_MISMATCH' };
  }

  // CRL imzalama yetkisi: keyUsage varsa cRLSign biti şart (RFC 5280 §4.2.1.3).
  const ku = x509.keyUsage(issuer);
  if (ku.present && !ku.cRLSign) {
    return { status: 'unknown', nextUpdate: null, error: 'CRL_SIGNER_NOT_AUTHORIZED' };
  }

  const sigOk = x509.verifySignature({
    tbs: crl.tbsDer, sigAlgOid: crl.sigAlgOid, sigAlgParams: crl.sigAlgParams,
    signature: crl.signature, publicKey: issuerPublicKey,
  });
  if (!sigOk) return { status: 'unknown', nextUpdate: null, error: 'CRL_BAD_SIGNATURE' };

  if (crl.thisUpdate > now + skewMs) {
    return { status: 'unknown', nextUpdate: crl.nextUpdate, error: 'CRL_NOT_YET_VALID' };
  }
  if (crl.nextUpdate !== null && crl.nextUpdate < now - skewMs) {
    return { status: 'unknown', nextUpdate: crl.nextUpdate, error: 'CRL_EXPIRED' };
  }

  const serialHex = der.unsignedInt(subject.serialNumber).toString('hex');
  const entry = crl.revoked.get(serialHex);
  if (!entry) return { status: 'good', nextUpdate: crl.nextUpdate, error: null };
  if (entry.reasonCode === 8) {          // removeFromCRL — iptal geri alınmış
    return { status: 'good', nextUpdate: crl.nextUpdate, error: null };
  }
  return {
    status: 'revoked',
    reason: REASON_NAMES[entry.reasonCode] || `reason(${entry.reasonCode})`,
    revokedAt: entry.revokedAt,
    nextUpdate: crl.nextUpdate,
    error: null,
  };
}

// ============================================================================
// HTTP taşıma — node:http / node:https
// ============================================================================
/**
 * @param {string} url
 * @param {{method?:string, body?:Buffer, contentType?:string, accept?:string,
 *          timeoutMs?:number, maxBytes?:number, redirectsLeft?:number}} o
 * @returns {Promise<Buffer>}
 */
function httpFetch(url, o = {}) {
  const {
    method = 'GET', body = null, contentType = null, accept = null,
    timeoutMs = DEFAULTS.timeoutMs, maxBytes = DEFAULTS.maxResponseBytes,
    redirectsLeft = DEFAULTS.maxRedirects,
  } = o;

  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); }
    catch { return reject(new Error(`geçersiz URL: ${url}`)); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return reject(new Error(`desteklenmeyen şema: ${u.protocol}`));
    }

    const transport = u.protocol === 'https:' ? https : http;
    const headers = {};
    if (contentType) headers['Content-Type'] = contentType;
    if (accept) headers.Accept = accept;
    if (body) headers['Content-Length'] = body.length;

    const req = transport.request(u, { method, headers, timeout: timeoutMs }, (res) => {
      // Yönlendirme takibi (bazı CDN'ler CRL'leri yönlendirir).
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('çok fazla yönlendirme'));
        const next = new URL(res.headers.location, u).toString();
        return resolve(httpFetch(next, { ...o, redirectsLeft: redirectsLeft - 1 }));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > maxBytes) {
          req.destroy();
          reject(new Error(`yanıt ${maxBytes} baytı aştı`));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks, total)));
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`istek ${timeoutMs}ms içinde tamamlanmadı`)));
    if (body) req.write(body);
    req.end();
  });
}

// ============================================================================
// Denetleyici
// ============================================================================
class RevocationChecker {
  /**
   * @param {object} cfg  normalizeRevocation çıktısı
   * @param {(url:string, o:object)=>Promise<Buffer>} [cfg.fetch]  test/proxy için enjekte edilebilir
   */
  constructor(cfg) {
    this.cfg = { ...DEFAULTS, ...cfg };
    this.fetch = cfg.fetch || httpFetch;
    this.cache = new Map();     // fingerprint256 -> { result, expiresAt }
    // Aynı sertifika için EŞ ZAMANLI süren sorgular. Bir sunucuya aynı anda
    // 100 istemci bağlandığında önbellek henüz dolmadığı için 100 ayrı OCSP
    // isteği çıkardı; artık ilkine iliştirilirler.
    this.inFlight = new Map();  // fingerprint256 -> Promise<result>
    this.stats = { ocsp: 0, crl: 0, cacheHits: 0, coalesced: 0, stapled: 0, failures: 0 };
  }

  /**
   * Doğrulanmış zinciri (leaf → … → kök) iptal açısından denetler.
   *
   * @param {crypto.X509Certificate[]} path  pki.verifyCertificateChain().path
   * @param {{staple?:Buffer|null, now?:number}} [o]
   * @returns {Promise<{ok:boolean, error:string|null, results:object[]}>}
   */
  async checkChain(path, { staple = null, now = Date.now() } = {}) {
    const results = [];
    if (!path || path.length < 2) {
      // Yol tek sertifikadan ibaret: o sertifika GÜVEN ÇIPASIDIR (sabitlenmiş
      // leaf ya da kabul edilmiş kendinden imzalı). Çıpa, doğrulamanın girdisidir
      // — çıktısı değil (RFC 5280 §6.1); kendi iptalini kendisi bildiremez.
      // Bu yüzden hard-fail modunda bile sorgulanacak bir şey yoktur.
      return { ok: true, error: null, results };
    }

    // KÖK HARİÇ her sertifika denetlenir: path[i]'nin durumunu path[i+1] söyler.
    const last = this.cfg.checkLeafOnly ? 1 : path.length - 1;
    for (let i = 0; i < last; i++) {
      const res = await this._checkOne(path[i], path[i + 1], {
        staple: i === 0 ? staple : null, now,
      });
      results.push(res);
      if (res.status === 'revoked') {
        return {
          ok: false,
          error: `CERT_REVOKED (${res.subject}: ${res.reason || 'bilinmiyor'})`,
          results,
        };
      }
    }

    const unresolved = results.find((r) => r.status !== 'good');
    if (unresolved && this.cfg.mode === 'hard-fail') {
      return {
        ok: false,
        error: `REVOCATION_CHECK_FAILED (${unresolved.subject}: ${unresolved.error || 'durum bilinmiyor'})`,
        results,
      };
    }
    return { ok: true, error: null, results };
  }

  async _checkOne(certX509, issuerX509, opts) {
    const key = certX509.fingerprint256;
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > opts.now) {
      this.stats.cacheHits++;
      return { ...cached.result, cached: true };
    }

    // Zımbalanmış yanıt oturuma özgüdür; onu paylaşılan sorguya katmayız.
    if (!opts.staple) {
      const pending = this.inFlight.get(key);
      if (pending) {
        this.stats.coalesced++;
        return pending;
      }
    }

    const p = this._resolveOne(certX509, issuerX509, opts)
      .finally(() => { this.inFlight.delete(key); });
    if (!opts.staple) this.inFlight.set(key, p);
    return p;
  }

  async _resolveOne(certX509, issuerX509, { staple, now }) {
    const key = certX509.fingerprint256;
    const subject = x509.parseCertificate(certX509.raw);
    const issuer = x509.parseCertificate(issuerX509.raw);
    const label = certX509.subject.split('\n')[0] || certX509.subject;

    // OCSP responder sertifikaları id-pkix-ocsp-nocheck taşır: onları sorgulamak
    // sonsuz döngü olur (RFC 6960 §4.2.2.2.1).
    if (x509.hasOcspNoCheck(subject)) {
      return this._store(key, { subject: label, method: 'skipped', status: 'good', error: null }, now);
    }

    const attempts = [];

    // --- 1) Zımbalanmış yanıt (ağ turu yok)
    if (staple && this.cfg.ocsp) {
      const r = this._evalStaple(staple, subject, issuerX509, issuer, now);
      if (r) {
        this.stats.stapled++;
        if (r.status !== 'unknown') {
          return this._store(key, { subject: label, method: 'ocsp-stapled', ...r }, now, r.nextUpdate);
        }
        attempts.push(`stapled:${r.error}`);
      }
    }

    // --- 2) OCSP (AIA)
    if (this.cfg.ocsp) {
      const urls = x509.authorityInfoAccess(subject).ocsp;
      for (const url of urls) {
        try {
          const r = await this._queryOcsp(url, subject, issuerX509, issuer, now);
          if (r.status !== 'unknown') {
            return this._store(key, { subject: label, method: 'ocsp', url, ...r }, now, r.nextUpdate);
          }
          attempts.push(`ocsp(${url}):${r.error}`);
        } catch (e) {
          this.stats.failures++;
          attempts.push(`ocsp(${url}):${e.message}`);
        }
      }
    }

    // --- 3) CRL (CDP)
    if (this.cfg.crl) {
      const urls = x509.crlDistributionPoints(subject);
      for (const url of urls) {
        try {
          const r = await this._queryCrl(url, subject, issuerX509, issuer, now);
          if (r.status !== 'unknown') {
            return this._store(key, { subject: label, method: 'crl', url, ...r }, now, r.nextUpdate);
          }
          attempts.push(`crl(${url}):${r.error}`);
        } catch (e) {
          this.stats.failures++;
          attempts.push(`crl(${url}):${e.message}`);
        }
      }
    }

    const error = attempts.length
      ? `REVOCATION_UNAVAILABLE (${attempts.join('; ')})`
      : 'REVOCATION_NO_DISTRIBUTION_POINT (sertifikada AIA/CDP yok)';
    // Başarısız denemeler önbelleğe alınmaz — geçici ağ arızası kalıcı hâle gelmemeli.
    return { subject: label, method: 'none', status: 'unknown', error };
  }

  _evalStaple(staple, subject, issuerX509, issuer, now) {
    try {
      const parsed = parseOcspResponse(staple);
      if (!parsed.basic) return { status: 'unknown', nextUpdate: null, error: `OCSP_${parsed.status}` };
      return verifyOcspResponse({
        basic: parsed.basic, subject, issuer, issuerPublicKey: issuerX509.publicKey,
        nonce: null, now, skewMs: this.cfg.clockSkewMs,
      });
    } catch (e) {
      return { status: 'unknown', nextUpdate: null, error: `OCSP_STAPLE_PARSE (${e.message})` };
    }
  }

  async _queryOcsp(url, subject, issuerX509, issuer, now) {
    const req = buildOcspRequest(subject, issuer, { hashAlgorithm: this.cfg.hashAlgorithm });
    this.stats.ocsp++;
    const body = await this.fetch(url, {
      method: 'POST', body: req.der,
      contentType: 'application/ocsp-request',
      accept: 'application/ocsp-response',
      timeoutMs: this.cfg.timeoutMs, maxBytes: this.cfg.maxResponseBytes,
    });

    const parsed = parseOcspResponse(body);
    if (!parsed.basic) return { status: 'unknown', nextUpdate: null, error: `OCSP_${parsed.status}` };
    return verifyOcspResponse({
      basic: parsed.basic, subject, issuer, issuerPublicKey: issuerX509.publicKey,
      nonce: req.nonce, now, skewMs: this.cfg.clockSkewMs,
    });
  }

  async _queryCrl(url, subject, issuerX509, issuer, now) {
    this.stats.crl++;
    const body = await this.fetch(url, {
      method: 'GET', accept: 'application/pkix-crl',
      timeoutMs: this.cfg.timeoutMs, maxBytes: this.cfg.maxCrlBytes,
    });
    // CRL'ler DER ya da PEM olarak sunulabilir.
    const crlDer = looksLikePem(body) ? pemToDer(body) : body;
    return verifyCrl({
      crlDer, subject, issuer, issuerPublicKey: issuerX509.publicKey,
      now, skewMs: this.cfg.clockSkewMs,
    });
  }

  _store(key, result, now, nextUpdate) {
    // Önbellek ömrü, yanıtın kendi geçerliliğini ASLA aşmaz.
    let ttl = this.cfg.cacheTtlMs;
    if (nextUpdate) ttl = Math.min(ttl, Math.max(0, nextUpdate - now));
    if (this.cache.size >= this.cfg.maxCacheEntries) {
      this.cache.delete(this.cache.keys().next().value);
    }
    this.cache.set(key, { result, expiresAt: now + ttl });
    return result;
  }

  clearCache() { this.cache.clear(); }

  snapshot() {
    return { ...this.stats, cacheSize: this.cache.size, inFlight: this.inFlight.size };
  }
}

function looksLikePem(buf) {
  return buf.length > 10 && buf.subarray(0, 5).toString('ascii') === '-----';
}
function pemToDer(buf) {
  const text = buf.toString('utf8');
  const b64 = text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

module.exports = {
  DEFAULTS, REASON_NAMES, RESPONSE_STATUS,
  normalizeRevocation, RevocationChecker,
  buildOcspRequest, parseOcspResponse, verifyOcspResponse, verifyCrl,
  httpFetch,
};
