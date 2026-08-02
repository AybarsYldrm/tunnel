'use strict';
// Anahtar türetme — HER İKİ DTLS SÜRÜMÜ İÇİN TEK DOSYA.
//
//   BÖLÜM 1: DTLS 1.3 key schedule (HKDF ağacı)  — RFC 8446 §7.1 / RFC 9147 §5.9
//   BÖLÜM 2: DTLS 1.2 PRF ve key block           — RFC 5246 §5, §6.3 / RFC 7627
//
// İki şema kriptografik olarak tamamen farklıdır (HKDF ağacı vs. P_hash), ama
// ÇAĞRILDIKLARI YER aynıdır: handshake makinesi hangi sürümü müzakere ettiyse
// buradan karşılığını ister. Ayrı dosyalarda tutmak, "hangi türetme hangi
// sürümde?" sorusunu iki yere dağıtıyordu; tek dosyada yan yana durunca
// farklar okunur hâle geliyor.
//
// ============================================================================
// BÖLÜM 1 — DTLS 1.3 (RFC 8446 §7.1)
// ============================================================================
//
// Ağaç:
//
//             0  (salt)
//             |
//             v
//   PSK ->  HKDF-Extract = Early Secret
//             |
//             +---> Derive-Secret(., "ext binder" | "res binder", "") = binder_key
//             +---> Derive-Secret(., "c e traffic", ClientHello)      = client_early_traffic_secret
//             +---> Derive-Secret(., "e exp master", ClientHello)     = early_exporter_master_secret
//             v
//        Derive-Secret(., "derived", "")
//             |
//             v
//   (EC)DHE -> HKDF-Extract = Handshake Secret
//             |
//             +---> Derive-Secret(., "c hs traffic", CH..SH) = client_handshake_traffic_secret
//             +---> Derive-Secret(., "s hs traffic", CH..SH) = server_handshake_traffic_secret
//             v
//        Derive-Secret(., "derived", "")
//             |
//             v
//   0      -> HKDF-Extract = Master Secret
//             |
//             +---> Derive-Secret(., "c ap traffic", CH..SF)  = client_application_traffic_secret_0
//             +---> Derive-Secret(., "s ap traffic", CH..SF)  = server_application_traffic_secret_0
//             +---> Derive-Secret(., "exp master", CH..SF)    = exporter_master_secret
//             +---> Derive-Secret(., "res master", CH..CF)    = resumption_master_secret
//
// Traffic secret -> traffic key/iv/sn_key:
//   key    = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
//   iv     = HKDF-Expand-Label(traffic_secret, "iv",  "", iv_length)
//   sn_key = HKDF-Expand-Label(traffic_secret, "sn",  "", sn_key_length) [RFC 9147 §4.2.3]
//
// Finished MAC için:
//   finished_key = HKDF-Expand-Label(Base-Key, "finished", "", Hash.length)
//
// KeyUpdate:
//   application_traffic_secret_N+1 =
//     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)

const crypto = require('node:crypto');
const {
  hkdfExtract, hkdfExpandLabel, deriveSecret, hashEmpty, hashLen,
  TLS13_LABEL_PREFIX, DTLS13_LABEL_PREFIX,
} = require('./hkdf.js');

// RFC 9147 §5.9: "Section 7.1 of [TLS13] specifies that HKDF-Expand-Label uses
// a label prefix of 'tls13 '. For DTLS 1.3, that label SHALL be 'dtls13'."
// Yani DTLS 1.3, TLS 1.3 ile AYNI key-schedule ağacını kullanır ama HER
// HKDF-Expand-Label çağrısında (Derive-Secret dahil — o da Expand-Label'i sarar)
// prefix "dtls13" olur. İki prefix asla birbirinin yerine geçmez.
//
// Aşağıdaki ilkel fonksiyonlar `prefix` parametresini varsayılan olarak
// "tls13 " ile alır; böylece RFC 8448 (TLS 1.3) test vektörleri doğrudan
// çalıştırılabilir. Yüksek seviyeli deriveHandshakeStage/deriveApplicationStage
// ise DAİMA KM_PREFIX ("dtls13") geçer.
const KM_PREFIX = DTLS13_LABEL_PREFIX;

// --------------------------------------------------------------------------
// Early Secret
// --------------------------------------------------------------------------
function earlySecret(hash, psk = null) {
  const ikm = psk || Buffer.alloc(hashLen(hash), 0);
  return hkdfExtract(hash, Buffer.alloc(0), ikm);
}

// Derive-Secret(Early Secret, "derived", "") — Handshake Secret için salt
function derivedFromEarly(hash, earlyS, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, earlyS, 'derived', hashEmpty(hash), prefix);
}

// --------------------------------------------------------------------------
// Handshake Secret
// --------------------------------------------------------------------------
function handshakeSecret(hash, earlyS, ecdheSharedSecret, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExtract(hash, derivedFromEarly(hash, earlyS, prefix), ecdheSharedSecret);
}

function clientHandshakeTrafficSecret(hash, hsS, th, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, hsS, 'c hs traffic', th, prefix);
}
function serverHandshakeTrafficSecret(hash, hsS, th, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, hsS, 's hs traffic', th, prefix);
}

function derivedFromHandshake(hash, hsS, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, hsS, 'derived', hashEmpty(hash), prefix);
}

// --------------------------------------------------------------------------
// Master Secret
// --------------------------------------------------------------------------
function masterSecret(hash, hsS, prefix = TLS13_LABEL_PREFIX) {
  const salt = derivedFromHandshake(hash, hsS, prefix);
  return hkdfExtract(hash, salt, Buffer.alloc(hashLen(hash), 0));
}

function clientApplicationTrafficSecret(hash, masterS, th, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, masterS, 'c ap traffic', th, prefix);
}
function serverApplicationTrafficSecret(hash, masterS, th, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, masterS, 's ap traffic', th, prefix);
}
function exporterMasterSecret(hash, masterS, th, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, masterS, 'exp master', th, prefix);
}
function resumptionMasterSecret(hash, masterS, th, prefix = TLS13_LABEL_PREFIX) {
  return deriveSecret(hash, masterS, 'res master', th, prefix);
}

// --------------------------------------------------------------------------
// Traffic secret -> key/iv/sn
// --------------------------------------------------------------------------
// trafficKeyIv / snKey / finishedKey / updateTrafficSecret all take an
// optional `prefix` arg so RFC 8448 (TLS 1.3) KAT tests can still call them
// directly with the "tls13 " default. The high-level deriveHandshakeStage /
// deriveApplicationStage helpers also pass TLS13_LABEL_PREFIX (KM_PREFIX),
// since DTLS 1.3 reuses the exact same "tls13 " label as TLS 1.3 — see the
// KM_PREFIX comment above.
function trafficKeyIv(hash, trafficSecret, { keyLen, ivLen }, prefix = TLS13_LABEL_PREFIX) {
  return {
    key: hkdfExpandLabel(hash, trafficSecret, 'key', Buffer.alloc(0), keyLen, prefix),
    iv:  hkdfExpandLabel(hash, trafficSecret, 'iv',  Buffer.alloc(0), ivLen, prefix),
  };
}

// RFC 9147 §4.2.3 — sequence number mask anahtarı sadece DTLS 1.3 özgüdür.
function snKey(hash, trafficSecret, snKeyLen, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExpandLabel(hash, trafficSecret, 'sn', Buffer.alloc(0), snKeyLen, prefix);
}

// Finished key
function finishedKey(hash, baseKey, hashLen, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExpandLabel(hash, baseKey, 'finished', Buffer.alloc(0), hashLen, prefix);
}

// KeyUpdate — yeni application traffic secret
function updateTrafficSecret(hash, prevSecret, hashLen, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExpandLabel(hash, prevSecret, 'traffic upd', Buffer.alloc(0), hashLen, prefix);
}

// NOT: DTLS-SRTP anahtar dışa aktarımı buradan KALDIRILDI. RFC 5764, RFC 8446
// §7.5'teki tam exporter'ı ister — yani Derive-Secret + HKDF-Expand-Label("exporter")
// iki adımını. Tek bir HKDF-Expand-Label çağrısı YANLIŞ anahtar üretir ve hiçbir
// gerçek peer ile çalışmaz. Doğru uygulama: src/crypto/exporter.js.

// --------------------------------------------------------------------------
// Yüksek seviyeli yardımcı — server/client ortak: ClientHello..ServerHello transcript
// ile handshake tarafındaki tüm türetmeleri tek seferde yap.
// --------------------------------------------------------------------------
function deriveHandshakeStage({
  suite,          // cipher-suite.js metadata
  sharedSecret,   // ECDHE çıktısı
  transcriptCH_SH, // Transcript-Hash(ClientHello || ServerHello)  (veya HRR dönüşümlü)
  psk = null,
}) {
  const { hash, keyLen, ivLen, sn_keyLen, hashLen: hLen } = suite;

  const early = earlySecret(hash, psk);
  const hs    = handshakeSecret(hash, early, sharedSecret, KM_PREFIX);
  const cHS   = clientHandshakeTrafficSecret(hash, hs, transcriptCH_SH, KM_PREFIX);
  const sHS   = serverHandshakeTrafficSecret(hash, hs, transcriptCH_SH, KM_PREFIX);

  return {
    earlySecret:          early,
    handshakeSecret:      hs,
    clientHandshakeSecret: cHS,
    serverHandshakeSecret: sHS,
    clientHandshake: {
      ...trafficKeyIv(hash, cHS, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, cHS, sn_keyLen, KM_PREFIX),
      finishedKey:  finishedKey(hash, cHS, hLen, KM_PREFIX),
      trafficSecret: cHS,
    },
    serverHandshake: {
      ...trafficKeyIv(hash, sHS, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, sHS, sn_keyLen, KM_PREFIX),
      finishedKey:  finishedKey(hash, sHS, hLen, KM_PREFIX),
      trafficSecret: sHS,
    },
  };
}

function deriveApplicationStage({ suite, handshakeSecret, transcriptCH_SF }) {
  const { hash, keyLen, ivLen, sn_keyLen, hashLen: hLen } = suite;

  const master = masterSecret(hash, handshakeSecret, KM_PREFIX);
  const cAP    = clientApplicationTrafficSecret(hash, master, transcriptCH_SF, KM_PREFIX);
  const sAP    = serverApplicationTrafficSecret(hash, master, transcriptCH_SF, KM_PREFIX);
  const exp    = exporterMasterSecret(hash, master, transcriptCH_SF, KM_PREFIX);

  return {
    masterSecret: master,
    exporterSecret: exp,
    clientApplication: {
      ...trafficKeyIv(hash, cAP, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, cAP, sn_keyLen, KM_PREFIX),
      trafficSecret: cAP,
    },
    serverApplication: {
      ...trafficKeyIv(hash, sAP, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, sAP, sn_keyLen, KM_PREFIX),
      trafficSecret: sAP,
    },
  };
}

// ============================================================================
// BÖLÜM 2 — DTLS 1.2 (RFC 5246 §5, §6.3, §8.1 + RFC 7627)
// ============================================================================
//
// PRF (RFC 5246 §5):
//   P_hash(secret, seed) = HMAC(secret, A(1) + seed) ||
//                          HMAC(secret, A(2) + seed) || ...
//   A(0) = seed ;  A(i) = HMAC(secret, A(i-1))
//   PRF(secret, label, seed) = P_<hash>(secret, label || seed)
// Kullanılan hash cipher suite tarafından belirlenir (SHA-256 veya SHA-384).
//
//   master_secret = PRF(pre_master_secret, "master secret",
//                       ClientHello.random + ServerHello.random)[0..47]
//
// Extended Master Secret (RFC 7627) — üçlü-handshake saldırısına karşı
// varsayılan olarak AÇIK tuttuğumuz varyant:
//   master_secret = PRF(pre_master_secret, "extended master secret",
//                       session_hash)[0..47]
//   session_hash  = Hash(ClientHello .. ClientKeyExchange)
//
//   key_block = PRF(master_secret, "key expansion",
//                   server_random + client_random)
// AEAD suite'lerinde MAC anahtarı YOKTUR; blok şu sırayla bölünür:
//   client_write_key | server_write_key | client_write_IV | server_write_IV
//
//   verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]

const MASTER_SECRET_LEN = 48;
const VERIFY_DATA_LEN = 12;

/**
 * TLS 1.2 PRF.
 * @param {string} hash   'sha256' | 'sha384'
 * @param {Buffer} secret
 * @param {string|Buffer} label
 * @param {Buffer} seed
 * @param {number} length çıktı bayt sayısı
 */
function prf12(hash, secret, label, seed, length) {
  const labelBuf = Buffer.isBuffer(label) ? label : Buffer.from(label, 'ascii');
  return pHash(hash, secret, Buffer.concat([labelBuf, seed]), length);
}

function pHash(hash, secret, seed, length) {
  const out = Buffer.allocUnsafe(length);
  let written = 0;
  let a = crypto.createHmac(hash, secret).update(seed).digest();   // A(1)
  while (written < length) {
    const block = crypto.createHmac(hash, secret).update(a).update(seed).digest();
    const take = Math.min(block.length, length - written);
    block.copy(out, written, 0, take);
    written += take;
    if (written < length) a = crypto.createHmac(hash, secret).update(a).digest();
  }
  return out;
}

function masterSecret12({ hash, preMasterSecret, clientRandom, serverRandom }) {
  const seed = Buffer.concat([clientRandom, serverRandom]);
  return prf12(hash, preMasterSecret, 'master secret', seed, MASTER_SECRET_LEN);
}

function extendedMasterSecret12({ hash, preMasterSecret, sessionHash }) {
  return prf12(hash, preMasterSecret, 'extended master secret', sessionHash, MASTER_SECRET_LEN);
}

/**
 * key_block'u üret ve AEAD suite düzenine göre böl.
 * @param {object} suite cipher-suite metadata (hash, keyLen, saltLen)
 */
function keyBlock12({ suite, masterSecret: ms, clientRandom, serverRandom }) {
  const { hash, keyLen, saltLen } = suite;
  const seed = Buffer.concat([serverRandom, clientRandom]); // DİKKAT: ters sıra (RFC 5246 §6.3)
  const block = prf12(hash, ms, 'key expansion', seed, 2 * keyLen + 2 * saltLen);

  let o = 0;
  const clientWriteKey = block.subarray(o, o += keyLen);
  const serverWriteKey = block.subarray(o, o += keyLen);
  const clientWriteIv  = block.subarray(o, o += saltLen);
  const serverWriteIv  = block.subarray(o, o += saltLen);

  return {
    client: { key: clientWriteKey, salt: clientWriteIv },
    server: { key: serverWriteKey, salt: serverWriteIv },
  };
}

function verifyData12({ hash, masterSecret: ms, label, handshakeHash }) {
  return prf12(hash, ms, label, handshakeHash, VERIFY_DATA_LEN);
}

module.exports = {
  // --- DTLS 1.3
  earlySecret, derivedFromEarly,
  handshakeSecret, derivedFromHandshake,
  masterSecret,
  clientHandshakeTrafficSecret, serverHandshakeTrafficSecret,
  clientApplicationTrafficSecret, serverApplicationTrafficSecret,
  exporterMasterSecret, resumptionMasterSecret,
  trafficKeyIv, snKey, finishedKey, updateTrafficSecret,
  deriveHandshakeStage, deriveApplicationStage,

  // --- DTLS 1.2
  MASTER_SECRET_LEN, VERIFY_DATA_LEN,
  prf12, pHash,
  masterSecret12, extendedMasterSecret12, keyBlock12, verifyData12,
};