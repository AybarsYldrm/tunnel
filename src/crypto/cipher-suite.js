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

// ===========================================================================
// Adlandırılmış şifreleme politikaları
//
// Tek tek suite ID'si yazmak, kullanıcıyı DTLS 1.3 ve 1.2 listelerini elle
// eşlemeye zorlar; bir tanesini unutmak "el sıkışma başarısız" olarak geri
// döner ve sebebi görünmez. Politika adı bu eşlemeyi tek yerde yapar.
//
// Hangi politika ne zaman:
//
//   balanced   (varsayılan) AES-128-GCM önce. AES-NI olan her makinede — yani
//              2010 sonrası hemen her sunucu ve masaüstünde — en hızlısı.
//   aes256     Daha uzun anahtar isteyen kurumsal politikalar için. AES-128'in
//              kırıldığına dair bir bulgu YOKTUR; bu bir uyum tercihidir,
//              güvenlik yükseltmesi değil.
//   chacha20   AES donanım hızlandırması OLMAYAN uçlar için: ARM Cortex-A
//              (eski Raspberry Pi), bazı gömülü yönlendiriciler, düşük seviye
//              mobil yongalar. Oralarda ChaCha20 AES'ten kat kat hızlıdır ve
//              yazılım AES'in önbellek zamanlaması sızıntısı riski de yoktur.
//   mobile     ChaCha20 önce, AES yedek — karışık istemci parkı için doğru
//              olan: hızlı ucun seçimini yavaş uca dayatmıyoruz.
//   fips       Yalnızca AES-GCM. ChaCha20-Poly1305 FIPS 140-3 onaylı değildir.
//
// Politika SIRALAMADIR, yasak listesi değil: sunucu kendi sırasına göre
// istemcinin sunduklarından ilk eşleşeni seçer (selectSuite).
// ===========================================================================
const CIPHER_POLICY = Object.freeze({
  balanced: [
    CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  ],
  aes128: [
    CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  ],
  aes256: [
    CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  ],
  aes: [
    CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  ],
  chacha20: [
    CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  ],
  mobile: [
    CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  ],
});

/** Takma adlar — kullanıcı 'chacha' ya da 'aes-128' yazdığında da çalışsın. */
const POLICY_ALIASES = Object.freeze({
  default: 'balanced', auto: 'balanced', balanced: 'balanced',
  aes: 'aes', 'aes-gcm': 'aes', fips: 'aes',
  aes128: 'aes128', 'aes-128': 'aes128', 'aes128gcm': 'aes128', 'aes-128-gcm': 'aes128',
  aes256: 'aes256', 'aes-256': 'aes256', 'aes256gcm': 'aes256', 'aes-256-gcm': 'aes256',
  strong: 'aes256',
  chacha: 'chacha20', chacha20: 'chacha20', 'chacha20-poly1305': 'chacha20',
  poly1305: 'chacha20',
  mobile: 'mobile', 'chacha-first': 'mobile', arm: 'mobile', embedded: 'mobile',
});

/**
 * Politika adını suite listesine çevirir.
 * @param {string} name
 * @returns {number[]|null} tanınmayan ad için null (arayan suite adı sanabilir)
 */
function resolveCipherPolicy(name) {
  if (typeof name !== 'string') return null;
  const key = POLICY_ALIASES[name.trim().toLowerCase()];
  return key ? CIPHER_POLICY[key].slice() : null;
}

/** Kullanıcıya gösterilecek politika adları. */
function cipherPolicyNames() { return Object.keys(CIPHER_POLICY); }

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
  CIPHER_POLICY, POLICY_ALIASES,
  getSuite, findSuite, selectSuite, resolveSuiteId, suiteName,
  resolveCipherPolicy, cipherPolicyNames,
};
