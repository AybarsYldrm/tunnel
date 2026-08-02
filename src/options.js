'use strict';
// Seçenek normalizasyonu ve doğrulaması — hem sunucu hem istemci için tek kapı.
//
// Amaç: kullanıcı `cert`, `key`, `ca`, `srtp: true` gibi basit alanlar versin;
// alt katmanlar (session, record, srtp) yalnızca doğrulanmış, tipi kesinleşmiş
// yapılarla çalışsın. Hatalı yapılandırma handshake'te değil, BURADA patlasın.

const {
  VERSION, VERSION_NAMES, VERSION_RANK, NAMED_GROUP, SIG_SCHEME, SRTP_PROFILE,
} = require('./constants.js');
const {
  DEFAULT_SUITES_13, DEFAULT_SUITES_12, resolveSuiteId, SUITES,
} = require('./crypto/cipher-suite.js');
const pki = require('./crypto/pki.js');
const { normalizeRevocation, RevocationChecker } = require('./crypto/revocation.js');

const DEFAULT_GROUPS = [NAMED_GROUP.X25519, NAMED_GROUP.SECP256R1];

const DEFAULT_SIG_SCHEMES = [
  SIG_SCHEME.ECDSA_SECP256R1_SHA256,
  SIG_SCHEME.ECDSA_SECP384R1_SHA384,
  SIG_SCHEME.ED25519,
  SIG_SCHEME.RSA_PSS_RSAE_SHA256,
  SIG_SCHEME.RSA_PSS_RSAE_SHA384,
  SIG_SCHEME.RSA_PKCS1_SHA256, // yalnızca DTLS 1.2 ve sertifika imzaları için
];

const DEFAULT_SRTP_PROFILES = [
  SRTP_PROFILE.SRTP_AEAD_AES_128_GCM,
  SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80,
];

const DEFAULTS = Object.freeze({
  minVersion: 'DTLSv1.2',
  maxVersion: 'DTLSv1.3',
  mtu: 1200,
  handshakeTimeout: 30_000,
  idleTimeout: 300_000,
  maxSessions: 10_000,
  cookie: true,
  rejectUnauthorized: true,
  requestCert: false,
  allowSelfSigned: false,
  replayWindow: 64,
});

// ============================================================================
// Secure context — sertifika/anahtar/CA üçlüsü
// ============================================================================
/**
 * @param {object} o
 * @param {Buffer|string|Array} [o.cert]  PEM zinciri veya DER (leaf önce)
 * @param {Buffer|string}       [o.key]
 * @param {string}              [o.passphrase]
 * @param {Buffer|string|Array} [o.ca]    güvenilen kökler
 */
function createSecureContext(o = {}) {
  const ctx = {
    certDER: null, certX509: null, leaf: null,
    privateKey: null, keyType: null,
    ca: o.ca ? pki.loadCAStore(o.ca) : [],
    // Zımbalanacak OCSP yanıtı (DER) ya da onu üreten fonksiyon.
    ocspResponse: o.ocspResponse ?? null,
  };

  if (o.cert || o.key) {
    if (!o.cert) throw new Error('key verildi ama cert eksik');
    if (!o.key) throw new Error('cert verildi ama key eksik');
    const { der, x509, reordered } = pki.loadCertChain(o.cert);
    ctx.certDER = der;
    ctx.certX509 = x509;
    ctx.leaf = x509[0];
    ctx.chainReordered = reordered;
    ctx.privateKey = pki.loadPrivateKey(o.key, o.passphrase);
    ctx.keyType = ctx.privateKey.asymmetricKeyType;

    // Demet leaf'i başa alacak şekilde yeniden sıralandıysa bunu belirt:
    // "key sertifikayla eşleşmiyor" hatası, aslında sırası bozuk bir zincir
    // yüzünden çıkıyorsa kullanıcı saatlerce yanlış yerde arar.
    try {
      pki.assertKeyMatchesCert(ctx.privateKey, ctx.leaf);
    } catch (e) {
      throw new Error(`${e.message}` + (der.length > 1
        ? ` — verilen demette ${der.length} sertifika var; leaf olarak ` +
          `"${ctx.leaf.subject.split('\n')[0]}" seçildi`
        : ''));
    }
  }
  return ctx;
}

// ============================================================================
// Yardımcılar
// ============================================================================
function resolveVersion(v, field) {
  if (typeof v === 'number') {
    if (!VERSION_RANK[v]) throw new Error(`${field}: bilinmeyen sürüm 0x${v.toString(16)}`);
    return v;
  }
  const n = VERSION_NAMES[v];
  if (n === undefined) {
    throw new Error(`${field}: '${v}' geçersiz — 'DTLSv1.2' veya 'DTLSv1.3' olmalı`);
  }
  return n;
}

function resolveGroups(list) {
  if (!list) return DEFAULT_GROUPS.slice();
  return list.map((g) => {
    if (typeof g === 'number') return g;
    const id = NAMED_GROUP[String(g).toUpperCase()];
    if (id === undefined) throw new Error(`bilinmeyen named group: ${g}`);
    return id;
  });
}

function resolveSigSchemes(list) {
  if (!list) return DEFAULT_SIG_SCHEMES.slice();
  return list.map((s) => {
    if (typeof s === 'number') return s;
    const id = SIG_SCHEME[String(s).toUpperCase()];
    if (id === undefined) throw new Error(`bilinmeyen signature scheme: ${s}`);
    return id;
  });
}

function resolveSrtpProfiles(list) {
  if (!list) return DEFAULT_SRTP_PROFILES.slice();
  return list.map((p) => {
    if (typeof p === 'number') return p;
    const id = SRTP_PROFILE[String(p).toUpperCase()];
    if (id === undefined) throw new Error(`bilinmeyen SRTP profili: ${p}`);
    return id;
  });
}

function normalizeSrtp(srtp) {
  if (!srtp) return { enabled: false, profiles: [] };
  if (srtp === true) return { enabled: true, profiles: DEFAULT_SRTP_PROFILES.slice() };
  if (typeof srtp !== 'object') throw new TypeError('srtp: boolean veya nesne olmalı');
  return {
    enabled: srtp.enabled !== false,
    profiles: resolveSrtpProfiles(srtp.profiles),
    replayProtection: srtp.replayProtection !== false,
    // WebRTC'de medya ile aynı soketten RTP/RTCP akar; DTLS dışı paketleri
    // ayırt edip 'media' olarak yukarı vermek için.
    demux: srtp.demux !== false,
  };
}

/**
 * Güvenilir kanal seçenekleri. Kanal RFC 9002 (QUIC) terminolojisini kullanır
 * (RTT tahmini + PTO); eski `rto` adları geriye dönük uyumluluk için kabul
 * edilir ve karşılıklarına eşlenir.
 */
function normalizeReliable(reliable, mtu) {
  if (!reliable) return null;
  const base = (reliable === true) ? {} : reliable;
  if (typeof base !== 'object') throw new TypeError('reliable: boolean veya nesne olmalı');
  if (base.enabled === false) return null;

  const pick = (...vals) => vals.find((v) => v !== undefined);
  return {
    // DTLS kayıt ek yükü (unified header + AEAD tag + inner content type) için pay bırak.
    mtu: base.mtu ?? Math.max(256, mtu - 64),
    ordered: base.ordered === true,       // varsayılan SIRASIZ (QUIC datagram tarzı)
    // RTT/PTO — `rto` ve `initialRto` eski adlardır.
    initialRtt: pick(base.initialRtt, base.rtt, base.rto, base.initialRto),
    minPto: pick(base.minPto, base.minRto),
    maxPto: pick(base.maxPto, base.maxRto),
    maxAckDelay: base.maxAckDelay,
    ackDelay: base.ackDelay,
    maxRetransmits: base.maxRetransmits,
    maxTrackedPackets: pick(base.maxTrackedPackets, base.maxInFlight),
    maxReassembly: base.maxReassembly,
    maxOrderedBuffer: base.maxOrderedBuffer,
  };
}

function versionList(minVersion, maxVersion) {
  const lo = VERSION_RANK[minVersion];
  const hi = VERSION_RANK[maxVersion];
  if (lo > hi) throw new Error('minVersion, maxVersion\'dan büyük olamaz');
  const out = [];
  if (hi >= 13 && lo <= 13) out.push(VERSION.DTLS_1_3);
  if (hi >= 12 && lo <= 12) out.push(VERSION.DTLS_1_2);
  if (out.length === 0) throw new Error('desteklenen sürüm aralığı boş');
  return out; // yeniden eskiye
}

// ============================================================================
// Ana normalizasyon
// ============================================================================
/**
 * @param {'client'|'server'} role
 * @param {object} raw kullanıcı seçenekleri
 */
function normalizeOptions(role, raw = {}) {
  const o = { ...DEFAULTS, ...raw };

  const minVersion = resolveVersion(o.minVersion, 'minVersion');
  const maxVersion = resolveVersion(o.maxVersion, 'maxVersion');
  const versions = versionList(minVersion, maxVersion);
  const allow13 = versions.includes(VERSION.DTLS_1_3);
  const allow12 = versions.includes(VERSION.DTLS_1_2);

  // --- güvenlik bağlamı
  const secureContext = raw.secureContext || createSecureContext(o);

  if (role === 'server' && !secureContext.certDER) {
    throw new Error('sunucu için cert ve key zorunludur');
  }
  if (role === 'client' && (o.requestCert || o.cert) && !secureContext.certDER && o.cert) {
    throw new Error('istemci sertifikası verildi ama yüklenemedi');
  }

  // --- SNI (sunucu): hostname -> secure context tablosu
  let contexts = null;
  if (role === 'server' && raw.contexts) {
    contexts = new Map();
    for (const [host, ctxOpts] of Object.entries(raw.contexts)) {
      contexts.set(String(host).toLowerCase(),
                   ctxOpts.certDER ? ctxOpts : createSecureContext(ctxOpts));
    }
  }
  if (raw.SNICallback && typeof raw.SNICallback !== 'function') {
    throw new TypeError('SNICallback bir fonksiyon olmalı');
  }

  // --- cipher suite listeleri
  let suites13 = DEFAULT_SUITES_13.slice();
  let suites12 = DEFAULT_SUITES_12.slice();
  if (raw.cipherSuites) {
    const ids = raw.cipherSuites.map(resolveSuiteId);
    suites13 = ids.filter((id) => SUITES[id].tls13);
    suites12 = ids.filter((id) => !SUITES[id].tls13);
    if (allow13 && suites13.length === 0 && !allow12) {
      throw new Error('cipherSuites içinde DTLS 1.3 suite\'i yok');
    }
  }

  // --- DTLS 1.2'de sunucu suite'i anahtar tipiyle uyumlu olmalı
  if (role === 'server' && allow12 && secureContext.keyType) {
    const kt = secureContext.keyType;
    const usable = suites12.filter((id) => SUITES[id].auth === kt);
    if (usable.length === 0 && !allow13) {
      throw new Error(
        `DTLS 1.2 için ${kt} anahtarına uygun cipher suite yok — ` +
        'ECDSA (P-256/P-384) veya RSA anahtar kullanın');
    }
    suites12 = usable.length ? usable : suites12;
  }

  const mtu = Number(o.mtu);
  if (!Number.isFinite(mtu) || mtu < 256 || mtu > 65535) {
    throw new RangeError('mtu 256..65535 aralığında olmalı');
  }

  // --- iptal denetimi (OCSP / CRL)
  const revocationCfg = normalizeRevocation(raw.revocation);
  if (revocationCfg && role === 'server' && !o.requestCert) {
    throw new Error('revocation açık ama requestCert kapalı — sunucuda iptal ' +
                    'denetimi yalnızca istemci sertifikaları için anlamlıdır');
  }

  const norm = {
    role,
    // sürüm
    minVersion, maxVersion, versions, allow13, allow12,
    // kimlik
    secureContext, contexts, SNICallback: raw.SNICallback || null,
    servername: raw.servername || raw.sni || null,
    // doğrulama politikası
    requestCert: !!o.requestCert,
    rejectUnauthorized: o.rejectUnauthorized !== false,
    allowSelfSigned: !!o.allowSelfSigned,
    checkServerIdentity: raw.checkServerIdentity || null,
    verifyPeerCertificate: raw.verifyPeerCertificate || null,
    peerFingerprint: raw.peerFingerprint || null,
    peerFingerprintAlgorithm: raw.peerFingerprintAlgorithm || 'sha-256',
    // iptal denetimi (OCSP/CRL) — normalize edilmiş yapılandırma + paylaşılan
    // denetleyici (önbelleği tüm oturumlar ortak kullanır)
    revocation: revocationCfg,
    revocationChecker: revocationCfg ? new RevocationChecker(revocationCfg) : null,
    // OCSP zımbalama: istemci istesin mi / sunucu yanıt taşısın mı
    requestOCSP: raw.requestOCSP !== undefined ? !!raw.requestOCSP : !!revocationCfg,
    checkPurpose: raw.checkPurpose !== false,
    // kripto tercihleri
    groups: resolveGroups(raw.groups),
    sigSchemes: resolveSigSchemes(raw.sigSchemes),
    cipherSuites13: suites13,
    cipherSuites12: suites12,
    // özellikler
    srtp: normalizeSrtp(raw.srtp),
    reliable: normalizeReliable(raw.reliable, mtu),
    alpn: raw.alpn ? [].concat(raw.alpn) : null,
    extendedMasterSecret: raw.extendedMasterSecret !== false,
    // ağ / kaynak
    mtu,
    cookie: o.cookie !== false,
    handshakeTimeout: Number(o.handshakeTimeout),
    idleTimeout: Number(o.idleTimeout),
    maxSessions: Number(o.maxSessions),
    replayWindow: Number(o.replayWindow),
    keylogFile: raw.keylogFile || process.env.SSLKEYLOGFILE || null,
  };

  if (norm.srtp.enabled && norm.reliable) {
    throw new Error('srtp ve reliable aynı anda kullanılamaz — SRTP medya akışı ' +
                    'kendi kayıp toleransına sahiptir, güvenilir kanal ona uygulanmaz');
  }
  if (role === 'client' && norm.rejectUnauthorized &&
      secureContext.ca.length === 0 && !norm.allowSelfSigned && !norm.peerFingerprint &&
      !norm.verifyPeerCertificate) {
    throw new Error(
      'rejectUnauthorized:true ama doğrulama için hiçbir dayanak yok. ' +
      'ca, peerFingerprint veya verifyPeerCertificate verin; ' +
      'ya da bilinçli olarak allowSelfSigned:true / rejectUnauthorized:false yapın');
  }

  return norm;
}

module.exports = {
  normalizeOptions, createSecureContext,
  DEFAULTS, DEFAULT_GROUPS, DEFAULT_SIG_SCHEMES, DEFAULT_SRTP_PROFILES,
  versionList,
};
