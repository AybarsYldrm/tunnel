'use strict';
// Test için OCSP responder ve CRL dağıtım noktası — `node:http` üzerinde.
//
// Bunlar kütüphanenin PARÇASI DEĞİLDİR: iptal denetimi istemci tarafında
// yaşar, sunucu tarafı ise CA operatörünün işidir. Ama istemciyi gerçekten
// sınamak için standartlara uygun bir KARŞI TARAF gerekir — burada RFC 6960
// (OCSP) ve RFC 5280 §5 (CRL) nesneleri, kütüphanenin kendi DER yazıcısıyla
// üretilip node:crypto ile imzalanır.

const crypto = require('node:crypto');
const http = require('node:http');

const der = require('../src/crypto/der.js');
const x509 = require('../src/crypto/x509.js');

const ECDSA_SHA256 = '1.2.840.10045.4.3.2';

/** EC P-256 + SHA-256 AlgorithmIdentifier (parametre YOK — RFC 5758). */
const ecdsaSha256AlgId = () => der.seq(der.oid(ECDSA_SHA256));

function signEcdsaSha256(tbs, privateKey) {
  return crypto.sign('sha256', tbs, { key: privateKey, dsaEncoding: 'der' });
}

// ============================================================================
// OCSP request çözümleme (responder tarafı)
// ============================================================================
function parseOcspRequest(reqDer) {
  const top = der.readTLV(reqDer, 0);
  const tbs = der.readTLV(top.content, 0);
  const kids = der.readChildren(tbs.content);

  let i = 0;
  if (kids[i] && kids[i].tag === 0xa0) i++;      // version [0]
  if (kids[i] && kids[i].tag === 0xa1) i++;      // requestorName [1]

  const requestList = kids[i++];
  const requests = der.readChildren(requestList.content).map((reqNode) => {
    const certId = der.readChildren(der.readChildren(reqNode.content)[0].content);
    return {
      hashAlgOid: der.oidToString(der.readChildren(certId[0].content)[0].content),
      issuerNameHash: certId[1].content,
      issuerKeyHash: certId[2].content,
      serialNumber: der.unsignedInt(certId[3].content),
    };
  });

  let nonce = null;
  for (; i < kids.length; i++) {
    if (kids[i].tag !== 0xa2) continue;          // requestExtensions [2]
    const extsSeq = der.readTLV(kids[i].content, 0);
    for (const extNode of der.readChildren(extsSeq.content)) {
      const p = x509.parseExtension(extNode);
      if (p && p.oid === x509.OID.ocspNonce) nonce = der.readTLV(p.value, 0).content;
    }
  }
  return { requests, nonce };
}

// ============================================================================
// OCSP yanıt üretimi
// ============================================================================
/**
 * @param {object} o
 * @param {object} o.request        parseOcspRequest çıktısı
 * @param {crypto.X509Certificate} o.issuerCert  sorgulanan sertifikaları imzalayan CA
 * @param {crypto.KeyObject} o.responderKey      yanıtı imzalayan anahtar
 * @param {Buffer} [o.responderCertDer]          delege responder sertifikası (varsa)
 * @param {Map<string, {status, reason?, revokedAt?}>} o.statusMap  serial(hex) → durum
 * @param {'byName'|'byKey'} [o.responderIdType]
 * @param {number} [o.nextUpdateMs]
 */
function buildOcspResponse({
  request, issuerCert, responderKey, responderCertDer = null, statusMap,
  responderIdType = 'byKey', nextUpdateMs = 7 * 86400_000,
  producedAt = Date.now(), thisUpdate = Date.now(), reflectNonce = true,
}) {
  const issuerInfo = x509.parseCertificate(issuerCert.raw);

  const singles = request.requests.map((req) => {
    const hashAlg = x509.HASH_BY_OID[req.hashAlgOid] || 'sha256';
    const hashOid = x509.OID_BY_HASH[hashAlg];
    const certId = der.seq(
      der.seq(der.oid(hashOid), der.nullValue()),
      der.octetString(crypto.createHash(hashAlg).update(issuerInfo.subjectDer).digest()),
      der.octetString(crypto.createHash(hashAlg).update(issuerInfo.spkiKeyBits).digest()),
      der.integerFromBytes(req.serialNumber),
    );

    // RFC 6960 §2.2: BİLİNMEYEN seri için varsayılan 'unknown'dır, 'good' değil.
    const entry = statusMap.get(req.serialNumber.toString('hex').replace(/^0+/, '') || '0')
               || statusMap.get(req.serialNumber.toString('hex'))
               || { status: 'unknown' };

    let certStatus;
    if (entry.status === 'revoked') {
      // [1] IMPLICIT RevokedInfo — SEQUENCE olduğu için constructed (0xa1)
      const inner = entry.reason !== undefined
        ? Buffer.concat([der.generalizedTime(entry.revokedAt || Date.now()),
                         der.ctx(0, der.enumerated(entry.reason))])
        : der.generalizedTime(entry.revokedAt || Date.now());
      certStatus = der.ctx(1, inner);
    } else if (entry.status === 'unknown') {
      certStatus = der.ctxPrimitive(2, Buffer.alloc(0));   // [2] IMPLICIT NULL
    } else {
      certStatus = der.ctxPrimitive(0, Buffer.alloc(0));   // [0] IMPLICIT NULL = good
    }

    return der.seq(
      certId, certStatus,
      der.generalizedTime(thisUpdate),
      nextUpdateMs === null ? null : der.ctx(0, der.generalizedTime(thisUpdate + nextUpdateMs)),
    );
  });

  // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }
  // byKey PROTOKOLDE SABİT SHA-1'dir (RFC 6960 §4.2.1).
  const signerInfo = responderCertDer
    ? x509.parseCertificate(responderCertDer)
    : issuerInfo;
  const responderId = responderIdType === 'byName'
    ? der.ctx(1, signerInfo.subjectDer)
    : der.ctx(2, der.octetString(
        crypto.createHash('sha1').update(signerInfo.spkiKeyBits).digest()));

  const respExts = (reflectNonce && request.nonce)
    ? der.ctx(1, der.seq(der.seq(
        der.oid(x509.OID.ocspNonce),
        der.octetString(der.octetString(request.nonce)))))
    : null;

  const tbsResponseData = der.seq(
    responderId,
    der.generalizedTime(producedAt),
    der.seq(...singles),
    respExts,
  );

  const basicResponse = der.seq(
    tbsResponseData,
    ecdsaSha256AlgId(),
    der.bitString(signEcdsaSha256(tbsResponseData, responderKey)),
    responderCertDer ? der.ctx(0, der.seq(responderCertDer)) : null,
  );

  return der.seq(
    der.enumerated(0),                                   // successful
    der.ctx(0, der.seq(der.oid(x509.OID.ocspBasic), der.octetString(basicResponse))),
  );
}

/** İmzasız hata yanıtı (RFC 6960 §4.2.1). */
function buildOcspErrorResponse(code) {
  return der.seq(der.enumerated(code));
}

// ============================================================================
// CRL üretimi — RFC 5280 §5.1
// ============================================================================
/**
 * @param {object} o
 * @param {crypto.X509Certificate} o.issuerCert
 * @param {crypto.KeyObject} o.issuerKey
 * @param {Array<{serial: Buffer|string, revokedAt?: number, reason?: number}>} o.revoked
 */
function buildCrl({
  issuerCert, issuerKey, revoked = [],
  thisUpdate = Date.now(), nextUpdateMs = 7 * 86400_000, crlNumber = 1,
}) {
  const issuerInfo = x509.parseCertificate(issuerCert.raw);

  const entries = revoked.map((r) => {
    const serial = Buffer.isBuffer(r.serial) ? r.serial : Buffer.from(r.serial, 'hex');
    const extList = r.reason !== undefined
      ? der.seq(der.seq(der.oid(x509.OID.reasonCode),
                        der.octetString(der.enumerated(r.reason))))
      : null;
    return der.seq(
      der.integerFromBytes(serial),
      der.generalizedTime(r.revokedAt || Date.now()),
      extList,
    );
  });

  const tbsCertList = der.seq(
    der.tlv(der.TAG.INTEGER, Buffer.from([0x01])),       // version v2
    ecdsaSha256AlgId(),
    issuerInfo.subjectDer,
    der.generalizedTime(thisUpdate),
    nextUpdateMs === null ? null : der.generalizedTime(thisUpdate + nextUpdateMs),
    entries.length ? der.seq(...entries) : null,
    der.ctx(0, der.seq(
      der.seq(der.oid(x509.OID.crlNumber),
              der.octetString(der.integerFromBytes(Buffer.from([crlNumber & 0xff])))),
    )),
  );

  return der.seq(
    tbsCertList,
    ecdsaSha256AlgId(),
    der.bitString(signEcdsaSha256(tbsCertList, issuerKey)),
  );
}

// ============================================================================
// HTTP sunucu
// ============================================================================
/**
 * `/ocsp` (POST, application/ocsp-request) ve `/crl` (GET) uç noktalarını
 * sunan bir HTTP sunucusu başlatır.
 *
 * @returns {Promise<{port:number, url:string, close:()=>Promise<void>,
 *                    stats:{ocsp:number, crl:number}, setStatus:Function}>}
 */
async function startPkiServer({
  issuerCert, issuerKey, statusMap = new Map(), revoked = [],
  responderCertDer = null, responderKey = null, ocspOptions = {},
  crlOptions = {}, port = 0, host = '127.0.0.1',
  ocspHandler = null,
}) {
  const stats = { ocsp: 0, crl: 0 };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    try {
      if (url.pathname === '/ocsp') {
        stats.ocsp++;
        if (req.method !== 'POST') {
          res.writeHead(405).end('Method Not Allowed');
          return;
        }
        const body = await readBody(req);
        if (ocspHandler) return ocspHandler(req, res, body);

        let out;
        try {
          out = buildOcspResponse({
            request: parseOcspRequest(body),
            issuerCert, responderKey: responderKey || issuerKey,
            responderCertDer, statusMap, ...ocspOptions,
          });
        } catch {
          // Bozuk isteğe HTTP 500 DEĞİL, imzasız `malformedRequest` dönülür:
          // 500 "responder bozuk" demektir ve istemciler onu geçici arıza sayar.
          out = buildOcspErrorResponse(1);
        }
        res.writeHead(200, {
          'Content-Type': 'application/ocsp-response',
          'Content-Length': out.length,
        }).end(out);
        return;
      }

      if (url.pathname === '/crl') {
        stats.crl++;
        const crl = buildCrl({ issuerCert, issuerKey, revoked, ...crlOptions });
        res.writeHead(200, {
          'Content-Type': 'application/pkix-crl',
          'Content-Length': crl.length,
        }).end(crl);
        return;
      }

      res.writeHead(404).end('not found');
    } catch (e) {
      if (!res.headersSent) res.writeHead(500).end(String(e && e.message));
    }
  });

  await new Promise((resolve) => server.listen(port, host, resolve));
  const actualPort = server.address().port;

  return {
    port: actualPort,
    url: `http://${host}:${actualPort}`,
    ocspUrl: `http://${host}:${actualPort}/ocsp`,
    crlUrl: `http://${host}:${actualPort}/crl`,
    stats,
    setRevoked(list) { revoked = list; },
    setStatus(serialHex, status) { statusMap.set(serialHex, status); },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** X509Certificate'in seri numarasını, iptal listelerinde kullanılan hex biçiminde döner. */
function serialHexOf(certX509) {
  return x509.parseCertificate(certX509.raw).serialNumber.toString('hex');
}

module.exports = {
  startPkiServer, buildOcspResponse, buildOcspErrorResponse, buildCrl,
  parseOcspRequest, serialHexOf, ecdsaSha256AlgId,
};
