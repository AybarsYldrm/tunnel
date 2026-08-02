'use strict';
// Cipher Suite Metadata — RFC 8446 §B.4 (TLS 1.3) + RFC 5289/7905 (TLS 1.2)
// + RFC 9147 §4.2.3 (DTLS 1.3 sequence-number şifrelemesi).
//
// Tek bir tablo hem 1.3 hem 1.2 suite'lerini taşır; `tls13` bayrağı hangi
// protokolde geçerli olduğunu söyler. Runtime'da ihtiyaç duyulan tüm ölçüler
// (key/iv/tag/hash/sn) burada tek yerde toplanır — hot path'te tablo araması yok.

const { CIPHER_SUITE, NAMES } = require('../constants.js');

// TLS 1.3'te iv uzunluğu daima 12 (RFC 8446 §5.3), tag AES-GCM/ChaCha için 16.
// TLS 1.2 AEAD'de "fixed_iv" (salt) + "explicit nonce" ayrımı vardır:
//   AES-GCM  : saltLen=4,  explicitNonceLen=8  (RFC 5288)
//   ChaCha20 : saltLen=12, explicitNonceLen=0  (RFC 7905 — nonce seq ile XOR)
const SUITES = Object.freeze({
  // ---------------------------------------------------------------- TLS 1.3
  [CIPHER_SUITE.TLS_AES_128_GCM_SHA256]: Object.freeze({
    id: CIPHER_SUITE.TLS_AES_128_GCM_SHA256, name: 'TLS_AES_128_GCM_SHA256',
    tls13: true, hash: 'sha256', hashLen: 32,
    aead: 'aes-128-gcm', keyLen: 16, ivLen: 12, tagLen: 16,
    sn_cipher: 'aes-128-ecb', sn_keyLen: 16,
  }),
  [CIPHER_SUITE.TLS_AES_256_GCM_SHA384]: Object.freeze({
    id: CIPHER_SUITE.TLS_AES_256_GCM_SHA384, name: 'TLS_AES_256_GCM_SHA384',
    tls13: true, hash: 'sha384', hashLen: 48,
    aead: 'aes-256-gcm', keyLen: 32, ivLen: 12, tagLen: 16,
    sn_cipher: 'aes-256-ecb', sn_keyLen: 32,
  }),
  [CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256]: Object.freeze({
    id: CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256, name: 'TLS_CHACHA20_POLY1305_SHA256',
    tls13: true, hash: 'sha256', hashLen: 32,
    aead: 'chacha20-poly1305', keyLen: 32, ivLen: 12, tagLen: 16,
    sn_cipher: 'chacha20', sn_keyLen: 32,
  }),

  // ---------------------------------------------------------------- TLS 1.2
  // Sadece AEAD suite'leri. CBC/MAC-then-encrypt (Lucky13, POODLE) bilinçli olarak YOK.
  [CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]: Object.freeze({
    id: CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    tls13: false, auth: 'ec', kx: 'ecdhe', hash: 'sha256', hashLen: 32,
    aead: 'aes-128-gcm', keyLen: 16, saltLen: 4, explicitNonceLen: 8, ivLen: 12, tagLen: 16,
  }),
  [CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]: Object.freeze({
    id: CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    tls13: false, auth: 'ec', kx: 'ecdhe', hash: 'sha384', hashLen: 48,
    aead: 'aes-256-gcm', keyLen: 32, saltLen: 4, explicitNonceLen: 8, ivLen: 12, tagLen: 16,
  }),
  [CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]: Object.freeze({
    id: CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    tls13: false, auth: 'rsa', kx: 'ecdhe', hash: 'sha256', hashLen: 32,
    aead: 'aes-128-gcm', keyLen: 16, saltLen: 4, explicitNonceLen: 8, ivLen: 12, tagLen: 16,
  }),
  [CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]: Object.freeze({
    id: CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    tls13: false, auth: 'rsa', kx: 'ecdhe', hash: 'sha384', hashLen: 48,
    aead: 'aes-256-gcm', keyLen: 32, saltLen: 4, explicitNonceLen: 8, ivLen: 12, tagLen: 16,
  }),
  [CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256]: Object.freeze({
    id: CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    tls13: false, auth: 'ec', kx: 'ecdhe', hash: 'sha256', hashLen: 32,
    aead: 'chacha20-poly1305', keyLen: 32, saltLen: 12, explicitNonceLen: 0, ivLen: 12, tagLen: 16,
  }),
  [CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256]: Object.freeze({
    id: CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    tls13: false, auth: 'rsa', kx: 'ecdhe', hash: 'sha256', hashLen: 32,
    aead: 'chacha20-poly1305', keyLen: 32, saltLen: 12, explicitNonceLen: 0, ivLen: 12, tagLen: 16,
  }),
});

// Öncelik sırası: AES-GCM donanım hızlandırması olan makinelerde neredeyse her
// zaman daha hızlıdır; varsayılan olarak AES-NI varsayıyoruz.
const DEFAULT_SUITES_13 = Object.freeze([
  CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
  CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
  CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
]);

const DEFAULT_SUITES_12 = Object.freeze([
  CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
]);

// Geriye dönük uyum — eski kod bu adı bekliyordu.
const DEFAULT_SERVER_PRIORITY = DEFAULT_SUITES_13;

function getSuite(id) {
  const s = SUITES[id];
  if (!s) throw new Error(`unsupported cipher suite: 0x${id.toString(16)}`);
  return s;
}

function findSuite(id) {
  return SUITES[id] || null;
}

// İsim veya sayısal ID kabul eder — options katmanı kullanıcı girdisini buradan geçirir.
function resolveSuiteId(nameOrId) {
  if (typeof nameOrId === 'number') {
    if (!SUITES[nameOrId]) throw new Error(`unknown cipher suite id: 0x${nameOrId.toString(16)}`);
    return nameOrId;
  }
  const id = CIPHER_SUITE[String(nameOrId).toUpperCase()];
  if (id === undefined || !SUITES[id]) throw new Error(`unknown cipher suite: ${nameOrId}`);
  return id;
}

/**
 * Sunucu tarafı suite seçimi.
 * @param {number[]} clientList     ClientHello'daki suite ID'leri
 * @param {number[]} serverPriority sunucunun tercih sırası
 * @param {object}   [filter]       { tls13:boolean, auth:'ec'|'rsa'|'ed25519' }
 */
function selectSuite(clientList, serverPriority = DEFAULT_SUITES_13, filter = null) {
  const clientSet = new Set(clientList);
  for (const id of serverPriority) {
    const s = SUITES[id];
    if (!s || !clientSet.has(id)) continue;
    if (filter) {
      if (filter.tls13 !== undefined && s.tls13 !== filter.tls13) continue;
      // TLS 1.2'de suite adı sunucunun anahtar tipini sabitler: ECDSA anahtarla
      // ECDHE_RSA suite'i seçilemez.
      if (filter.auth && s.auth && s.auth !== filter.auth) continue;
    }
    return s;
  }
  return null;
}

function suiteName(id) {
  return NAMES.CIPHER_SUITE[id] || `UNKNOWN(0x${Number(id).toString(16)})`;
}

module.exports = {
  SUITES,
  DEFAULT_SUITES_13, DEFAULT_SUITES_12, DEFAULT_SERVER_PRIORITY,
  getSuite, findSuite, selectSuite, resolveSuiteId, suiteName,
};
