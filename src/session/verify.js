'use strict';
// Karşı taraf sertifikası doğrulama politikası — mTLS'in karar merkezi.
//
// Üç güven yolu desteklenir (sırayla denenir):
//   1) peerFingerprint  — WebRTC tarzı: sertifika kendinden imzalı olabilir,
//                         güven SDP'den gelen parmak iziyle kurulur.
//   2) CA zinciri       — klasik PKI: yol kurma + süre + amaç + hostname,
//                         ardından İPTAL DENETİMİ (OCSP/CRL).
//   3) verifyPeerCertificate(cert, chain, result) — uygulamaya özel son söz.
//
// `rejectUnauthorized:false` doğrulamayı ATLAMAZ; sadece sonucu ölümcül
// saymaz. Sonuç her durumda `socket.authorized` / `authorizationError`
// üzerinden görülebilir.
//
// Fonksiyon ASENKRONDUR: iptal denetimi ağ turu gerektirebilir (OCSP POST /
// CRL indirme). `revocation` kapalıyken hiçbir await ağ işi yapmaz.

const crypto = require('node:crypto');
const pki = require('../crypto/pki.js');
const { ALERT_DESC } = require('../constants.js');

/**
 * @param {object} o
 * @param {Buffer[]} o.chainDER  karşı tarafın gönderdiği DER zinciri (leaf önce)
 * @param {object}   o.opts      normalizeOptions çıktısı
 * @param {'client'|'server'} o.role  DOĞRULAYAN tarafın rolü
 * @param {string|null} o.servername  istemci tarafında beklenen sunucu adı
 * @param {Buffer|null} [o.staple]    zımbalanmış OCSP yanıtı (DER)
 * @returns {Promise<{authorized:boolean, error:string|null, alert:number|null,
 *            cert:crypto.X509Certificate|null, chain:crypto.X509Certificate[],
 *            path:crypto.X509Certificate[], revocation:object|null}>}
 */
async function verifyPeer({ chainDER, opts, role, servername, staple = null }) {
  const empty = { authorized: false, cert: null, chain: [], path: [], revocation: null };

  if (!chainDER || chainDER.length === 0) {
    // Sunucu istemci sertifikası istediyse ve zorunlu tuttuysa bu ölümcüldür.
    const required = role === 'server' && opts.requestCert && opts.rejectUnauthorized;
    return {
      ...empty,
      error: 'NO_PEER_CERTIFICATE',
      alert: required ? ALERT_DESC.CERTIFICATE_REQUIRED : null,
    };
  }

  let chain;
  try {
    chain = chainDER.map((d) => new crypto.X509Certificate(d));
  } catch (e) {
    return { ...empty, error: `BAD_CERTIFICATE (${e.message})`, alert: ALERT_DESC.BAD_CERTIFICATE };
  }
  const cert = chain[0];

  // --- 1) Parmak izi tabanlı güven
  // Zincir/CA hiç devreye girmez: güven doğrudan bu tek sertifikaya sabitlenmiştir.
  if (opts.peerFingerprint) {
    const list = [].concat(opts.peerFingerprint);
    const ok = list.some((fp) => {
      try { return pki.matchFingerprint(cert, fp, opts.peerFingerprintAlgorithm); }
      catch { return false; }
    });
    if (!ok) {
      return { ...empty, cert, chain,
               error: 'FINGERPRINT_MISMATCH', alert: ALERT_DESC.BAD_CERTIFICATE };
    }
    const now = Date.now();
    if (Date.parse(cert.validTo) < now || Date.parse(cert.validFrom) > now) {
      return { ...empty, cert, chain,
               error: 'CERT_HAS_EXPIRED', alert: ALERT_DESC.CERTIFICATE_EXPIRED };
    }
    return finish({ authorized: true, error: null, alert: null, cert, chain,
                    path: [cert], revocation: null }, opts);
  }

  // --- 2) CA zinciri
  // Hostname kontrolü yalnızca istemci tarafında ve SNI verilmişse anlamlıdır;
  // sunucu, istemci sertifikasında hostname aramaz.
  const hostname = (role === 'client' && !opts.checkServerIdentity) ? servername : null;
  // Karşı tarafın rolü bizimkinin tersidir: istemci sunucuyu doğrularken
  // serverAuth, sunucu istemciyi doğrularken clientAuth arar.
  const purpose = opts.checkPurpose === false ? null : (role === 'client' ? 'server' : 'client');

  const res = pki.verifyCertificateChain({
    chain,
    ca: opts.secureContext.ca,
    hostname,
    purpose,
    allowSelfSigned: opts.allowSelfSigned,
  });

  if (!res.authorized) {
    return finish({
      authorized: false, error: res.error, alert: alertForError(res.error),
      cert, chain, path: res.path, revocation: null,
    }, opts);
  }

  // Özel hostname doğrulayıcı (node:tls'in checkServerIdentity muadili)
  if (role === 'client' && opts.checkServerIdentity && servername) {
    let err = null;
    try { err = opts.checkServerIdentity(servername, pki.summarizeCertificate(cert)); }
    catch (e) { err = e; }
    if (err) {
      return finish({
        authorized: false, error: `HOSTNAME_CHECK_FAILED (${err.message || err})`,
        alert: ALERT_DESC.BAD_CERTIFICATE, cert, chain, path: res.path, revocation: null,
      }, opts);
    }
  }

  // --- 2b) İptal denetimi (OCSP / CRL) — zincir GEÇERLİ olduktan SONRA.
  // Sıra önemlidir: doğrulanmamış bir zincirdeki URL'lere istek atmak,
  // saldırganın bizi istediği adrese yönlendirmesine izin verirdi.
  let revocation = null;
  if (opts.revocationChecker) {
    try {
      revocation = await opts.revocationChecker.checkChain(res.path, { staple });
    } catch (e) {
      revocation = { ok: opts.revocation.mode !== 'hard-fail', results: [],
                     error: `REVOCATION_ERROR (${e.message})` };
    }
    if (!revocation.ok) {
      return finish({
        authorized: false, error: revocation.error,
        alert: ALERT_DESC.CERTIFICATE_REVOKED, cert, chain, path: res.path, revocation,
      }, opts);
    }
  }

  return finish({ authorized: true, error: null, alert: null,
                  cert, chain, path: res.path, revocation }, opts);
}

/** Uygulamaya özel son doğrulama kancası. */
function finish(result, opts) {
  if (!opts.verifyPeerCertificate) return result;
  let err = null;
  try {
    err = opts.verifyPeerCertificate(pki.summarizeCertificate(result.cert), result.chain, result);
  } catch (e) {
    err = e;
  }
  if (err) {
    return {
      ...result, authorized: false,
      error: `VERIFY_HOOK_REJECTED (${err.message || err})`,
      alert: ALERT_DESC.BAD_CERTIFICATE,
    };
  }
  return result;
}

function alertForError(error) {
  if (!error) return null;
  if (error.startsWith('CERT_REVOKED') || error.startsWith('REVOCATION_')) {
    return ALERT_DESC.CERTIFICATE_REVOKED;
  }
  if (error.startsWith('CERT_HAS_EXPIRED') || error.startsWith('CERT_NOT_YET_VALID')) {
    return ALERT_DESC.CERTIFICATE_EXPIRED;
  }
  if (error.startsWith('UNABLE_TO_GET_ISSUER_CERT') ||
      error.startsWith('SELF_SIGNED') || error.startsWith('DEPTH_ZERO') ||
      error.startsWith('INVALID_CA') || error.startsWith('PATH_LENGTH')) {
    return ALERT_DESC.UNKNOWN_CA;
  }
  if (error.startsWith('UNHANDLED_CRITICAL_EXTENSION')) return ALERT_DESC.UNSUPPORTED_CERTIFICATE;
  if (error.startsWith('INVALID_PURPOSE')) return ALERT_DESC.UNSUPPORTED_CERTIFICATE;
  if (error.startsWith('HOSTNAME_MISMATCH')) return ALERT_DESC.BAD_CERTIFICATE;
  return ALERT_DESC.BAD_CERTIFICATE;
}

module.exports = { verifyPeer };
