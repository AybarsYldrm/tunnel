'use strict';
// DTLS Protocol Constants — RFC 9147 (1.3), RFC 6347 (1.2), RFC 8446, RFC 5246.
// Her sabit RFC bölümüyle ilişkilendirildi; değiştirmek ≈ wire-format kırılması demektir.

// ===== Protocol Versions =====
// DTLS sürüm encoding'i TLS'in 1's-complement'i: DTLS 1.x = 0xFEFF - x
const VERSION = Object.freeze({
  DTLS_1_0: 0xfeff,
  DTLS_1_2: 0xfefd,
  DTLS_1_3: 0xfefc, // RFC 9147 §5.3
  TLS_1_2:  0x0303, // legacy_version field'larında görülür
  TLS_1_3:  0x0304,
});

// İnsan okunur sürüm adları — options katmanı bunları kabul eder.
const VERSION_NAMES = Object.freeze({
  'DTLSv1.2': VERSION.DTLS_1_2,
  'DTLSv1.3': VERSION.DTLS_1_3,
});

// Sürüm karşılaştırması: DTLS'te sayısal değer TERS sıralıdır (1.3 = 0xfefc < 1.2 = 0xfefd).
// Bu yüzden "rank" ile karşılaştırırız; büyük rank = yeni sürüm.
const VERSION_RANK = Object.freeze({
  [VERSION.DTLS_1_0]: 10,
  [VERSION.DTLS_1_2]: 12,
  [VERSION.DTLS_1_3]: 13,
});

// ===== Record Content Type (RFC 9147 §4 + RFC 8446 §5.1) =====
const CONTENT_TYPE = Object.freeze({
  INVALID:             0,
  CHANGE_CIPHER_SPEC: 20, // DTLS 1.2'de zorunlu; 1.3'te middlebox-compat, yoksayılır
  ALERT:              21,
  HANDSHAKE:          22,
  APPLICATION_DATA:   23,
  HEARTBEAT:          24, // RFC 6520
  TLS12_CID:          25, // RFC 9146 (legacy)
  ACK:                26, // RFC 9147 §7
});

// ===== Handshake Message Types (RFC 8446 §4 + RFC 5246 §7.4) =====
const HS_TYPE = Object.freeze({
  HELLO_REQUEST:         0, // DTLS 1.2 (renegotiation — biz reddediyoruz)
  CLIENT_HELLO:          1,
  SERVER_HELLO:          2,
  HELLO_VERIFY_REQUEST:  3, // DTLS 1.2 cookie exchange — RFC 6347 §4.2.1
  NEW_SESSION_TICKET:    4,
  END_OF_EARLY_DATA:     5,
  ENCRYPTED_EXTENSIONS:  8,
  REQUEST_CONNECTION_ID: 9,  // RFC 9146
  NEW_CONNECTION_ID:    10,  // RFC 9146
  CERTIFICATE:          11,
  SERVER_KEY_EXCHANGE:  12,  // DTLS 1.2
  CERTIFICATE_REQUEST:  13,
  SERVER_HELLO_DONE:    14,  // DTLS 1.2
  CERTIFICATE_VERIFY:   15,
  CERTIFICATE_STATUS:   22,  // DTLS 1.2 OCSP zımbalama — RFC 6066 §8
  CLIENT_KEY_EXCHANGE:  16,  // DTLS 1.2
  FINISHED:             20,
  KEY_UPDATE:           24,
  MESSAGE_HASH:        254,
});

// HelloRetryRequest: ServerHello formatında fakat sabit "magic" random ile.
// RFC 8446 §4.1.3.
const HRR_RANDOM = Buffer.from(
  'CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C',
  'hex',
);

// RFC 8446 §4.1.3 — downgrade sentinel'leri. Sunucu daha düşük sürüm seçtiyse
// ServerHello.random'ın son 8 byte'ına bunları koyar; istemci görürse ve daha
// yükseğini teklif ettiyse handshake'i keser (downgrade attack koruması).
const DOWNGRADE_SENTINEL_12 = Buffer.from('444F574E47524401', 'hex'); // "DOWNGRD\x01"
const DOWNGRADE_SENTINEL_11 = Buffer.from('444F574E47524400', 'hex'); // "DOWNGRD\x00"

// ===== Cipher Suites =====
// TLS 1.3 (RFC 8446 §B.4) — DTLS 1.3 aynı ID'leri kullanır.
const CIPHER_SUITE = Object.freeze({
  TLS_AES_128_GCM_SHA256:       0x1301,
  TLS_AES_256_GCM_SHA384:       0x1302,
  TLS_CHACHA20_POLY1305_SHA256: 0x1303,
  TLS_AES_128_CCM_SHA256:       0x1304,
  TLS_AES_128_CCM_8_SHA256:     0x1305,

  // TLS 1.2 AEAD suite'leri (RFC 5289, RFC 7905) — DTLS 1.2 için.
  // Sadece AEAD; CBC/MAC-then-encrypt suite'leri (Lucky13, POODLE) bilinçli olarak YOK.
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       0xc02b,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       0xc02c,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         0xc02f,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         0xc030,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca9,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   0xcca8,
});

// ===== Extension Types (RFC 8446 §4.2 + ek RFC'ler) =====
const EXT_TYPE = Object.freeze({
  SERVER_NAME:                     0, // RFC 6066
  MAX_FRAGMENT_LENGTH:             1,
  STATUS_REQUEST:                  5,
  SUPPORTED_GROUPS:               10, // RFC 8422, 7919
  EC_POINT_FORMATS:               11, // RFC 8422 §5.1.2 (TLS 1.2)
  SIGNATURE_ALGORITHMS:           13,
  USE_SRTP:                       14, // RFC 5764
  HEARTBEAT:                      15, // RFC 6520
  ALPN:                           16, // RFC 7301
  SIGNED_CERTIFICATE_TIMESTAMP:   18,
  PADDING:                        21,
  EXTENDED_MASTER_SECRET:         23, // RFC 7627 (TLS 1.2 — triple handshake koruması)
  SESSION_TICKET:                 35,
  PRE_SHARED_KEY:                 41,
  EARLY_DATA:                     42,
  SUPPORTED_VERSIONS:             43,
  COOKIE:                         44,
  PSK_KEY_EXCHANGE_MODES:         45,
  CERTIFICATE_AUTHORITIES:        47,
  OID_FILTERS:                    48,
  POST_HANDSHAKE_AUTH:            49,
  SIGNATURE_ALGORITHMS_CERT:      50,
  KEY_SHARE:                      51,
  CONNECTION_ID:                  54, // RFC 9146
  RENEGOTIATION_INFO:         0xff01, // RFC 5746
});

// ===== SRTP Protection Profiles (RFC 5764 §4.1.2, RFC 7714 §14.2) =====
const SRTP_PROFILE = Object.freeze({
  SRTP_AES128_CM_HMAC_SHA1_80: 0x0001,
  SRTP_AES128_CM_HMAC_SHA1_32: 0x0002,
  SRTP_NULL_HMAC_SHA1_80:      0x0005,
  SRTP_NULL_HMAC_SHA1_32:      0x0006,
  SRTP_AEAD_AES_128_GCM:       0x0007,
  SRTP_AEAD_AES_256_GCM:       0x0008,
});

// Her profil için anahtar materyali ölçüleri — exporter'dan çekilecek toplam bayt
// sayısı 2*(keyLen + saltLen). RFC 5764 §4.1.2.
const SRTP_PROFILE_PARAMS = Object.freeze({
  [SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80]: Object.freeze({
    name: 'SRTP_AES128_CM_HMAC_SHA1_80',
    kind: 'ctr', keyLen: 16, saltLen: 14, tagLen: 10, authKeyLen: 20, cipher: 'aes-128-ctr',
  }),
  [SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_32]: Object.freeze({
    name: 'SRTP_AES128_CM_HMAC_SHA1_32',
    kind: 'ctr', keyLen: 16, saltLen: 14, tagLen: 4, authKeyLen: 20, cipher: 'aes-128-ctr',
  }),
  [SRTP_PROFILE.SRTP_AEAD_AES_128_GCM]: Object.freeze({
    name: 'SRTP_AEAD_AES_128_GCM',
    kind: 'gcm', keyLen: 16, saltLen: 12, tagLen: 16, authKeyLen: 0, cipher: 'aes-128-gcm',
  }),
  [SRTP_PROFILE.SRTP_AEAD_AES_256_GCM]: Object.freeze({
    name: 'SRTP_AEAD_AES_256_GCM',
    kind: 'gcm', keyLen: 32, saltLen: 12, tagLen: 16, authKeyLen: 0, cipher: 'aes-256-gcm',
  }),
});

// ===== Named Groups (RFC 8446 §4.2.7) =====
const NAMED_GROUP = Object.freeze({
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  SECP521R1: 0x0019,
  X25519:    0x001d,
  X448:      0x001e,
  FFDHE2048: 0x0100,
  FFDHE3072: 0x0101,
});

// ===== Signature Schemes (RFC 8446 §4.2.3) =====
const SIG_SCHEME = Object.freeze({
  RSA_PKCS1_SHA256:       0x0401,
  RSA_PKCS1_SHA384:       0x0501,
  RSA_PKCS1_SHA512:       0x0601,
  ECDSA_SECP256R1_SHA256: 0x0403,
  ECDSA_SECP384R1_SHA384: 0x0503,
  ECDSA_SECP521R1_SHA512: 0x0603,
  RSA_PSS_RSAE_SHA256:    0x0804,
  RSA_PSS_RSAE_SHA384:    0x0805,
  RSA_PSS_RSAE_SHA512:    0x0806,
  ED25519:                0x0807,
  ED448:                  0x0808,
  RSA_PSS_PSS_SHA256:     0x0809,
  RSA_PSS_PSS_SHA384:     0x080a,
  RSA_PSS_PSS_SHA512:     0x080b,
});

// TLS 1.2 ClientCertificateType (RFC 5246 §7.4.4)
const CLIENT_CERT_TYPE = Object.freeze({
  RSA_SIGN:      1,
  DSS_SIGN:      2,
  RSA_FIXED_DH:  3,
  DSS_FIXED_DH:  4,
  ECDSA_SIGN:   64,
});

// ===== Alerts (RFC 8446 §6) =====
const ALERT_LEVEL = Object.freeze({ WARNING: 1, FATAL: 2 });
const ALERT_DESC  = Object.freeze({
  CLOSE_NOTIFY:             0,
  UNEXPECTED_MESSAGE:      10,
  BAD_RECORD_MAC:          20,
  RECORD_OVERFLOW:         22,
  HANDSHAKE_FAILURE:       40,
  NO_CERTIFICATE:          41,
  BAD_CERTIFICATE:         42,
  UNSUPPORTED_CERTIFICATE: 43,
  CERTIFICATE_REVOKED:     44,
  CERTIFICATE_EXPIRED:     45,
  CERTIFICATE_UNKNOWN:     46,
  ILLEGAL_PARAMETER:       47,
  UNKNOWN_CA:              48,
  ACCESS_DENIED:           49,
  DECODE_ERROR:            50,
  DECRYPT_ERROR:           51,
  PROTOCOL_VERSION:        70,
  INSUFFICIENT_SECURITY:   71,
  INTERNAL_ERROR:          80,
  INAPPROPRIATE_FALLBACK:  86,
  USER_CANCELED:           90,
  NO_RENEGOTIATION:       100,
  MISSING_EXTENSION:      109,
  UNSUPPORTED_EXTENSION:  110,
  UNRECOGNIZED_NAME:      112,
  BAD_CERTIFICATE_STATUS: 113,
  UNKNOWN_PSK_IDENTITY:   115,
  CERTIFICATE_REQUIRED:   116,
  NO_APPLICATION_PROTOCOL: 120,
});

// ===== Epoch Semantics (RFC 9147 §6.1) =====
// DTLS 1.3: 0=plaintext, 1=early_data, 2=handshake, 3=app, 3+N=KeyUpdate.
// DTLS 1.2: 0=plaintext, 1=CCS sonrası (her renegotiation'da +1 — biz reneg yok).
const EPOCH = Object.freeze({
  INITIAL:     0,
  EARLY_DATA:  1,
  HANDSHAKE:   2,
  APPLICATION: 3,
});

// Log için ters eşleştirme.
function reverseLookup(obj) {
  const out = Object.create(null);
  for (const [k, v] of Object.entries(obj)) if (out[v] === undefined) out[v] = k;
  return out;
}
const NAMES = Object.freeze({
  CONTENT_TYPE: reverseLookup(CONTENT_TYPE),
  HS_TYPE:      reverseLookup(HS_TYPE),
  CIPHER_SUITE: reverseLookup(CIPHER_SUITE),
  EXT_TYPE:     reverseLookup(EXT_TYPE),
  NAMED_GROUP:  reverseLookup(NAMED_GROUP),
  SIG_SCHEME:   reverseLookup(SIG_SCHEME),
  ALERT_LEVEL:  reverseLookup(ALERT_LEVEL),
  ALERT_DESC:   reverseLookup(ALERT_DESC),
  VERSION:      reverseLookup(VERSION),
  SRTP_PROFILE: reverseLookup(SRTP_PROFILE),
});

module.exports = {
  VERSION, VERSION_NAMES, VERSION_RANK,
  CONTENT_TYPE, HS_TYPE, HRR_RANDOM,
  DOWNGRADE_SENTINEL_11, DOWNGRADE_SENTINEL_12,
  CIPHER_SUITE, EXT_TYPE, NAMED_GROUP, SIG_SCHEME,
  SRTP_PROFILE, SRTP_PROFILE_PARAMS,
  CLIENT_CERT_TYPE,
  ALERT_LEVEL, ALERT_DESC, EPOCH, NAMES,
};
