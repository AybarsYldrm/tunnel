'use strict';
// PKCS#10 sertifika imzalama isteği (CSR) üretimi.
//
// Node'un `crypto` modülü sertifika OKUYABİLİR (X509Certificate) ama CSR
// ÜRETEMEZ. Bir openssl alt süreci çağırmak da bir seçenek değil: bu paketin
// tamamı sıfır bağımlılıklı ve openssl'in her yerde kurulu olduğu varsayımı,
// tam da tünel istemcisinin çalışacağı yerlerde (küçük konteynerler, gömülü
// cihazlar) tutmuyor.
//
// Kütüphanenin kendi DER yazıcısı (src/crypto/der.js) zaten OCSP istekleri
// için ASN.1 üretiyor; CSR de aynı yazıcıyla kuruluyor.
//
//   CertificationRequest ::= SEQUENCE {
//     certificationRequestInfo  CertificationRequestInfo,
//     signatureAlgorithm        AlgorithmIdentifier,
//     signature                 BIT STRING }
//
//   CertificationRequestInfo ::= SEQUENCE {
//     version        INTEGER (0),
//     subject        Name,
//     subjectPKInfo  SubjectPublicKeyInfo,
//     attributes     [0] IMPLICIT SET OF Attribute }

const crypto = require('node:crypto');

const der = require('../../../src/crypto/der.js');

const OID = Object.freeze({
  CN: '2.5.4.3',
  O: '2.5.4.10',
  OU: '2.5.4.11',
  C: '2.5.4.6',
  EMAIL: '1.2.840.113549.1.9.1',
  EXTENSION_REQUEST: '1.2.840.113549.1.9.14',
  SUBJECT_ALT_NAME: '2.5.29.17',
  KEY_USAGE: '2.5.29.15',
  EXT_KEY_USAGE: '2.5.29.37',
  CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
  SERVER_AUTH: '1.3.6.1.5.5.7.3.1',
  ECDSA_SHA256: '1.2.840.10045.4.3.2',
});

function utf8String(value) {
  return der.tlv(der.TAG.UTF8_STRING, Buffer.from(String(value), 'utf8'));
}

function ia5String(value) {
  return der.tlv(der.TAG.IA5_STRING, Buffer.from(String(value), 'ascii'));
}

/** RelativeDistinguishedName: SET OF SEQUENCE { type, value } */
function rdn(typeOid, value, encoder = utf8String) {
  return der.set(der.seq(der.oid(typeOid), encoder(value)));
}

function buildName(subject) {
  const parts = [];
  if (subject.country) parts.push(rdn(OID.C, subject.country, (v) => der.tlv(der.TAG.PRINTABLE_STRING, Buffer.from(v, 'ascii'))));
  if (subject.organization) parts.push(rdn(OID.O, subject.organization));
  if (subject.organizationalUnit) parts.push(rdn(OID.OU, subject.organizationalUnit));
  if (subject.commonName) parts.push(rdn(OID.CN, subject.commonName));
  if (subject.email) parts.push(rdn(OID.EMAIL, subject.email, ia5String));
  if (parts.length === 0) throw new Error('CSR: en az bir subject alanı gerekli (commonName)');
  return der.seq(...parts);
}

/** GeneralName seçimleri: dNSName [2], iPAddress [7]. */
function generalName(value) {
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (ipv4) {
    const bytes = ipv4.slice(1).map(Number);
    if (bytes.every((b) => b >= 0 && b <= 255)) return der.ctxPrimitive(7, Buffer.from(bytes));
  }
  return der.ctxPrimitive(2, Buffer.from(value, 'ascii'));
}

function extension(oidStr, critical, valueDer) {
  return der.seq(
    der.oid(oidStr),
    critical ? der.boolean(true) : null,
    der.octetString(valueDer),
  );
}

function buildAttributes({ altNames = [], extendedKeyUsage = [] }) {
  const extensions = [];

  if (altNames.length) {
    extensions.push(extension(OID.SUBJECT_ALT_NAME, false, der.seq(...altNames.map(generalName))));
  }
  if (extendedKeyUsage.length) {
    extensions.push(extension(OID.EXT_KEY_USAGE, false, der.seq(...extendedKeyUsage.map((o) => der.oid(o)))));
  }

  // İstek gövdesinde attributes alanı ZORUNLUDUR — boş bile olsa yazılmalı.
  // Atlanırsa yapı PKCS#10 değildir ve karşı taraftaki ayrıştırıcı, hatanın
  // nerede olduğunu söyleyemeyen bir "beklenmeyen etiket" hatası verir.
  if (extensions.length === 0) return der.ctx(0, Buffer.alloc(0));

  return der.ctx(0, der.seq(
    der.oid(OID.EXTENSION_REQUEST),
    der.set(der.seq(...extensions)),
  ));
}

/**
 * P-256 anahtar çifti üretir.
 *
 * Her yenilemede YENİ anahtar: aynı anahtarı yeniden sertifikalandırmak, geçmiş
 * bir sızıntıyı bir ömür daha ileri taşımak demektir.
 */
function generateKeyPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

/**
 * @param {object} o
 * @param {crypto.KeyObject} o.privateKey
 * @param {crypto.KeyObject} o.publicKey
 * @param {object} o.subject { commonName, organization, email, ... }
 * @param {string[]} [o.altNames]
 * @param {string[]} [o.extendedKeyUsage] varsayılan: clientAuth
 * @returns {{csrPem: string, csrDer: Buffer}}
 */
function createCsr({
  privateKey, publicKey, subject, altNames = [], extendedKeyUsage = [OID.CLIENT_AUTH],
}) {
  const spki = publicKey.export({ type: 'spki', format: 'der' });

  const requestInfo = der.seq(
    der.integerFromBytes(Buffer.from([0])),   // version 0
    buildName(subject),
    spki,                                     // SubjectPublicKeyInfo, hazır DER
    buildAttributes({ altNames, extendedKeyUsage }),
  );

  // EC anahtarla `crypto.sign` zaten DER kodlu ECDSA-Sig-Value üretir —
  // X.509'un beklediği biçim tam olarak budur, ayrıca dönüştürmek gerekmez.
  const signature = crypto.sign('sha256', requestInfo, privateKey);

  const csrDer = der.seq(
    requestInfo,
    der.seq(der.oid(OID.ECDSA_SHA256)),       // ecdsa-with-SHA256, parametresiz
    der.bitString(signature),
  );

  return { csrDer, csrPem: toPem(csrDer, 'CERTIFICATE REQUEST') };
}

function toPem(derBuf, label) {
  const b64 = derBuf.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

module.exports = {
  createCsr, generateKeyPair, toPem, OID,
};
