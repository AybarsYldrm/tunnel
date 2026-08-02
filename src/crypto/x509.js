'use strict';
// X.509 yapısal ayrıştırma — RFC 5280.
//
// `node:crypto.X509Certificate` imza doğrulama, tarih ve hostname kontrolü için
// yeterlidir; ancak zincir kurmak ve iptal (revocation) sorgusu yapmak için
// uzantıların İÇİNE bakmak gerekir:
//   • basicConstraints  → pathLen kısıtı
//   • keyUsage          → keyCertSign / cRLSign bitleri
//   • extKeyUsage       → serverAuth / clientAuth / OCSPSigning
//   • AIA               → OCSP responder URL'i
//   • CRLDistributionPoints → CRL URL'i
//   • AKID / SKID       → zincir kurma ipuçları
//
// Node bu alanları ya hiç açmaz ya da belirsiz biçimde (`keyUsage` alanı
// aslında extKeyUsage listesidir) döndürür; bu yüzden DER'i doğrudan okuruz.
// Bu saf yapısal ayrıştırmadır — kriptografik karar burada verilmez.

const crypto = require('node:crypto');
const der = require('./der.js');

const OID = Object.freeze({
  // uzantılar
  subjectKeyIdentifier:   '2.5.29.14',
  keyUsage:               '2.5.29.15',
  subjectAltName:         '2.5.29.17',
  basicConstraints:       '2.5.29.19',
  crlNumber:              '2.5.29.20',
  reasonCode:             '2.5.29.21',
  invalidityDate:         '2.5.29.24',
  deltaCrlIndicator:      '2.5.29.27',
  issuingDistributionPoint: '2.5.29.28',
  certificateIssuer:      '2.5.29.29',
  crlDistributionPoints:  '2.5.29.31',
  certificatePolicies:    '2.5.29.32',
  authorityKeyIdentifier: '2.5.29.35',
  extKeyUsage:            '2.5.29.37',
  freshestCrl:            '2.5.29.46',
  authorityInfoAccess:    '1.3.6.1.5.5.7.1.1',
  // AIA erişim yöntemleri
  adOcsp:                 '1.3.6.1.5.5.7.48.1',
  adCaIssuers:            '1.3.6.1.5.5.7.48.2',
  // OCSP
  ocspBasic:              '1.3.6.1.5.5.7.48.1.1',
  ocspNonce:              '1.3.6.1.5.5.7.48.1.2',
  ocspNoCheck:            '1.3.6.1.5.5.7.48.1.5',
  // EKU amaçları
  kpServerAuth:           '1.3.6.1.5.5.7.3.1',
  kpClientAuth:           '1.3.6.1.5.5.7.3.2',
  kpOcspSigning:          '1.3.6.1.5.5.7.3.9',
  anyExtendedKeyUsage:    '2.5.29.37.0',
  // hash
  sha1:                   '1.3.14.3.2.26',
  sha256:                 '2.16.840.1.101.3.4.2.1',
  sha384:                 '2.16.840.1.101.3.4.2.2',
  sha512:                 '2.16.840.1.101.3.4.2.3',
});

const HASH_BY_OID = Object.freeze({
  [OID.sha1]: 'sha1', [OID.sha256]: 'sha256', [OID.sha384]: 'sha384', [OID.sha512]: 'sha512',
});
const OID_BY_HASH = Object.freeze({
  sha1: OID.sha1, sha256: OID.sha256, sha384: OID.sha384, sha512: OID.sha512,
});

// İmza algoritması OID'i → node:crypto doğrulama parametreleri.
const SIG_ALGS = Object.freeze({
  '1.2.840.113549.1.1.5':  { hash: 'sha1',   kind: 'rsa' },
  '1.2.840.113549.1.1.11': { hash: 'sha256', kind: 'rsa' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', kind: 'rsa' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', kind: 'rsa' },
  '1.2.840.113549.1.1.10': { hash: null,     kind: 'rsa-pss' }, // parametrelerden okunur
  '1.2.840.10045.4.1':     { hash: 'sha1',   kind: 'ecdsa' },
  '1.2.840.10045.4.3.2':   { hash: 'sha256', kind: 'ecdsa' },
  '1.2.840.10045.4.3.3':   { hash: 'sha384', kind: 'ecdsa' },
  '1.2.840.10045.4.3.4':   { hash: 'sha512', kind: 'ecdsa' },
  '1.3.101.112':           { hash: null,     kind: 'ed25519' },
  '1.3.101.113':           { hash: null,     kind: 'ed448' },
});

const KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

// ============================================================================
// Sertifika
// ============================================================================
/**
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * @returns {{tbsDer:Buffer, sigAlgOid:string, sigAlgParams:Buffer|null,
 *            signature:Buffer, serialNumber:Buffer, issuerDer:Buffer,
 *            subjectDer:Buffer, spkiDer:Buffer, spkiKeyBits:Buffer,
 *            extensions:Map<string,{critical:boolean, value:Buffer}>}}
 */
function parseCertificate(certDer) {
  const top = der.expect(der.readTLV(certDer, 0), der.TAG.SEQUENCE, 'Certificate');
  const [tbsNode, sigAlgNode, sigNode] = der.readChildren(top.content);
  if (!tbsNode || !sigAlgNode || !sigNode) throw new Error('X.509: eksik Certificate alanı');

  const alg = parseAlgorithmIdentifier(sigAlgNode);
  const tbs = parseTbsCertificate(tbsNode);
  return {
    ...tbs,
    // DİKKAT: `tbsNode.contentOff`, `top.content` içindeki bir konumdur —
    // `certDer` içindeki DEĞİL. Doğrudan dilimlemek imzalanan baytları üst
    // başlığın uzunluğu kadar kaydırır ve HER imza doğrulaması sessizce
    // başarısız olur. Düğümü kendi başlığıyla yeniden kodlamak tek doğru yol.
    tbsDer: wholeNode(tbsNode),
    sigAlgOid: alg.oid,
    sigAlgParams: alg.params,
    signature: der.bitStringBytes(sigNode.content),
  };
}

function parseTbsCertificate(tbsNode) {
  const kids = der.readChildren(tbsNode.content);
  let i = 0;
  let version = 1;
  if (kids[i] && kids[i].tag === 0xa0) {           // [0] EXPLICIT version
    version = 1 + Number(der.intToBigInt(der.readTLV(kids[i].content, 0).content));
    i++;
  }
  const serialNumber = der.unsignedInt(der.expect(kids[i++], der.TAG.INTEGER, 'serialNumber').content);
  i++;                                             // signature AlgorithmIdentifier (tbs içindeki)
  const issuerNode = kids[i++];
  const validityNode = kids[i++];
  const subjectNode = kids[i++];
  const spkiNode = kids[i++];

  const validity = der.readChildren(validityNode.content);
  const notBefore = der.timeToMs(validity[0]);
  const notAfter = der.timeToMs(validity[1]);

  const spkiKids = der.readChildren(spkiNode.content);
  const spkiKeyBits = der.bitStringBytes(spkiKids[1].content);

  // Kalan alanlar: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
  const extensions = new Map();
  for (; i < kids.length; i++) {
    if (kids[i].tag !== 0xa3) continue;
    const extsSeq = der.readTLV(kids[i].content, 0);
    for (const extNode of der.readChildren(extsSeq.content)) {
      const parsed = parseExtension(extNode);
      if (parsed) extensions.set(parsed.oid, { critical: parsed.critical, value: parsed.value });
    }
  }

  return {
    version, serialNumber,
    issuerDer: wholeNode(issuerNode),
    subjectDer: wholeNode(subjectNode),
    spkiDer: wholeNode(spkiNode),
    spkiKeyBits,
    notBefore, notAfter,
    extensions,
  };
}

/** Bir düğümün başlığıyla birlikte tam DER kodlamasını yeniden üretir. */
function wholeNode(node) {
  return Buffer.concat([
    Buffer.from([node.tag]), der.encodeLen(node.len), node.content,
  ]);
}

function parseExtension(extNode) {
  const kids = der.readChildren(extNode.content);
  if (kids.length < 2) return null;
  const oid = der.oidToString(kids[0].content);
  let critical = false;
  let valueNode = kids[1];
  if (kids[1].tag === der.TAG.BOOLEAN) {
    critical = kids[1].content[0] !== 0x00;
    valueNode = kids[2];
  }
  if (!valueNode) return null;
  return { oid, critical, value: valueNode.content };
}

function parseAlgorithmIdentifier(node) {
  const kids = der.readChildren(node.content);
  return {
    oid: der.oidToString(kids[0].content),
    params: kids[1] ? wholeNode(kids[1]) : null,
  };
}

// ============================================================================
// Uzantı erişimcileri
// ============================================================================
/** BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL } */
function basicConstraints(info) {
  const ext = info.extensions.get(OID.basicConstraints);
  if (!ext) return { present: false, isCA: false, pathLen: null };
  const kids = der.readChildren(der.readTLV(ext.value, 0).content);
  let isCA = false;
  let pathLen = null;
  for (const k of kids) {
    if (k.tag === der.TAG.BOOLEAN) isCA = k.content[0] !== 0x00;
    else if (k.tag === der.TAG.INTEGER) pathLen = Number(der.intToBigInt(k.content));
  }
  return { present: true, critical: ext.critical, isCA, pathLen };
}

/** KeyUsage ::= BIT STRING — bit adlarına çözülür. */
function keyUsage(info) {
  const ext = info.extensions.get(OID.keyUsage);
  const out = Object.fromEntries(KEY_USAGE_BITS.map((n) => [n, false]));
  out.present = false;
  if (!ext) return out;
  out.present = true;
  const bits = der.bitStringBytes(der.readTLV(ext.value, 0).content);
  let idx = 0;
  for (const byte of bits) {
    for (let b = 0; b < 8 && idx < KEY_USAGE_BITS.length; b++, idx++) {
      out[KEY_USAGE_BITS[idx]] = (byte & (0x80 >> b)) !== 0;
    }
  }
  return out;
}

/** ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId — noktalı OID listesi döner. */
function extKeyUsage(info) {
  const ext = info.extensions.get(OID.extKeyUsage);
  if (!ext) return null;                              // yok = kısıtlama yok
  return der.readChildren(der.readTLV(ext.value, 0).content).map((n) => der.oidToString(n.content));
}

function subjectKeyIdentifier(info) {
  const ext = info.extensions.get(OID.subjectKeyIdentifier);
  if (!ext) return null;
  return Buffer.from(der.readTLV(ext.value, 0).content);
}

/** AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, ... } */
function authorityKeyIdentifier(info) {
  const ext = info.extensions.get(OID.authorityKeyIdentifier);
  if (!ext) return null;
  const kids = der.readChildren(der.readTLV(ext.value, 0).content);
  const kid = kids.find((k) => k.tag === 0x80);
  return kid ? Buffer.from(kid.content) : null;
}

/**
 * AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
 * AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
 * @returns {{ocsp:string[], caIssuers:string[]}}
 */
function authorityInfoAccess(info) {
  const out = { ocsp: [], caIssuers: [] };
  const ext = info.extensions.get(OID.authorityInfoAccess);
  if (!ext) return out;
  for (const ad of der.readChildren(der.readTLV(ext.value, 0).content)) {
    const kids = der.readChildren(ad.content);
    if (kids.length < 2) continue;
    const method = der.oidToString(kids[0].content);
    // GeneralName: uniformResourceIdentifier [6] IMPLICIT IA5String
    if (kids[1].tag !== 0x86) continue;
    const uri = kids[1].content.toString('ascii');
    if (method === OID.adOcsp) out.ocsp.push(uri);
    else if (method === OID.adCaIssuers) out.caIssuers.push(uri);
  }
  return out;
}

/**
 * CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
 * Yalnızca `distributionPoint [0] { fullName [0] GeneralNames }` biçimindeki
 * URI'ler döndürülür — pratikte dağıtılan tek biçim budur.
 */
function crlDistributionPoints(info, oidKey = OID.crlDistributionPoints) {
  const out = [];
  const ext = info.extensions.get(oidKey);
  if (!ext) return out;
  for (const dp of der.readChildren(der.readTLV(ext.value, 0).content)) {
    for (const field of der.readChildren(dp.content)) {
      if (field.tag !== 0xa0) continue;                       // distributionPoint [0]
      for (const nameChoice of der.readChildren(field.content)) {
        if (nameChoice.tag !== 0xa0) continue;                // fullName [0]
        for (const gn of der.readChildren(nameChoice.content)) {
          if (gn.tag === 0x86) out.push(gn.content.toString('ascii'));
        }
      }
    }
  }
  return out;
}

function hasOcspNoCheck(info) {
  return info.extensions.has(OID.ocspNoCheck);
}

/** Kritik ama tanımadığımız uzantı var mı? (RFC 5280 §6.1.3 (f)) */
const KNOWN_CRITICAL = new Set([
  OID.basicConstraints, OID.keyUsage, OID.extKeyUsage, OID.subjectAltName,
  OID.crlDistributionPoints, OID.authorityKeyIdentifier, OID.subjectKeyIdentifier,
  OID.certificatePolicies, OID.authorityInfoAccess,
]);
function unknownCriticalExtensions(info) {
  const out = [];
  for (const [oid, e] of info.extensions) {
    if (e.critical && !KNOWN_CRITICAL.has(oid)) out.push(oid);
  }
  return out;
}

// ============================================================================
// İmza doğrulama (sertifika/CRL/OCSP ortak)
// ============================================================================
/**
 * `tbs` baytlarını, `sigAlgOid` ile belirtilen algoritmaya göre `publicKey` ile
 * doğrular. RSASSA-PSS parametreleri AlgorithmIdentifier'dan okunur.
 * @returns {boolean}
 */
function verifySignature({ tbs, sigAlgOid, sigAlgParams, signature, publicKey }) {
  const spec = SIG_ALGS[sigAlgOid];
  if (!spec) throw new Error(`X.509: desteklenmeyen imza algoritması ${sigAlgOid}`);

  try {
    if (spec.kind === 'ed25519' || spec.kind === 'ed448') {
      return crypto.verify(null, tbs, publicKey, signature);
    }
    if (spec.kind === 'rsa-pss') {
      const p = parsePssParams(sigAlgParams);
      return crypto.verify(p.hash, tbs, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: p.saltLength,
      }, signature);
    }
    if (spec.kind === 'ecdsa') {
      return crypto.verify(spec.hash, tbs, { key: publicKey, dsaEncoding: 'der' }, signature);
    }
    return crypto.verify(spec.hash, tbs, {
      key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING,
    }, signature);
  } catch {
    return false;
  }
}

/** RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2] } */
function parsePssParams(paramsDer) {
  let hash = 'sha1';                    // RFC 4055 varsayılanı
  let saltLength = 20;
  if (!paramsDer) return { hash, saltLength };
  try {
    for (const field of der.readChildren(der.readTLV(paramsDer, 0).content)) {
      if (field.tag === 0xa0) {
        const algOid = der.oidToString(der.readChildren(der.readTLV(field.content, 0).content)[0].content);
        hash = HASH_BY_OID[algOid] || hash;
      } else if (field.tag === 0xa2) {
        saltLength = Number(der.intToBigInt(der.readTLV(field.content, 0).content));
      }
    }
  } catch { /* varsayılanlarla devam */ }
  return { hash, saltLength };
}

// ============================================================================
// CRL — RFC 5280 §5
// ============================================================================
/**
 * CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
 * @returns {{tbsDer, sigAlgOid, sigAlgParams, signature, issuerDer, thisUpdate,
 *            nextUpdate:number|null, revoked:Map<string,{reasonCode:number, revokedAt:number}>,
 *            isDelta:boolean, crlNumber:bigint|null}}
 */
function parseCrl(crlDer) {
  const top = der.expect(der.readTLV(crlDer, 0), der.TAG.SEQUENCE, 'CertificateList');
  const [tbsNode, sigAlgNode, sigNode] = der.readChildren(top.content);
  if (!tbsNode || !sigAlgNode || !sigNode) throw new Error('CRL: eksik alan');

  const kids = der.readChildren(tbsNode.content);
  let i = 0;
  if (kids[i] && kids[i].tag === der.TAG.INTEGER) i++;       // version (v2)
  i++;                                                        // signature AlgorithmIdentifier
  const issuerNode = kids[i++];
  const thisUpdate = der.timeToMs(kids[i++]);

  let nextUpdate = null;
  if (kids[i] && (kids[i].tag === der.TAG.UTC_TIME || kids[i].tag === der.TAG.GENERALIZED_TIME)) {
    nextUpdate = der.timeToMs(kids[i++]);
  }

  const revoked = new Map();
  if (kids[i] && kids[i].tag === der.TAG.SEQUENCE) {
    for (const entry of der.readChildren(kids[i].content)) {
      const e = der.readChildren(entry.content);
      const serialHex = der.unsignedInt(e[0].content).toString('hex');
      const revokedAt = der.timeToMs(e[1]);
      let reasonCode = 0;
      if (e[2] && e[2].tag === der.TAG.SEQUENCE) {
        for (const extNode of der.readChildren(e[2].content)) {
          const p = parseExtension(extNode);
          if (p && p.oid === OID.reasonCode) {
            reasonCode = der.readTLV(p.value, 0).content[0] ?? 0;
          }
        }
      }
      revoked.set(serialHex, { reasonCode, revokedAt });
    }
    i++;
  }

  let isDelta = false;
  let crlNumber = null;
  for (; i < kids.length; i++) {
    if (kids[i].tag !== 0xa0) continue;
    const extsSeq = der.readTLV(kids[i].content, 0);
    for (const extNode of der.readChildren(extsSeq.content)) {
      const p = parseExtension(extNode);
      if (!p) continue;
      if (p.oid === OID.deltaCrlIndicator) isDelta = true;
      else if (p.oid === OID.crlNumber) crlNumber = der.intToBigInt(der.readTLV(p.value, 0).content);
    }
  }

  const alg = parseAlgorithmIdentifier(sigAlgNode);
  return {
    tbsDer: wholeNode(tbsNode),
    sigAlgOid: alg.oid, sigAlgParams: alg.params,
    signature: der.bitStringBytes(sigNode.content),
    issuerDer: wholeNode(issuerNode),
    thisUpdate, nextUpdate, revoked, isDelta, crlNumber,
  };
}

module.exports = {
  OID, HASH_BY_OID, OID_BY_HASH, SIG_ALGS, KEY_USAGE_BITS,
  parseCertificate, parseTbsCertificate, parseAlgorithmIdentifier, parseExtension,
  basicConstraints, keyUsage, extKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier,
  authorityInfoAccess, crlDistributionPoints, hasOcspNoCheck, unknownCriticalExtensions,
  verifySignature, parseCrl, wholeNode,
};
