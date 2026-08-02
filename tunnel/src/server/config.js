'use strict';
// Tek yapılandırma noktası.
//
// Kural: bir sırrın koda gömülü varsayılanı YOKTUR ve eksikse süreç AÇILIŞTA
// durur. Sessiz bir varsayılan ('changeme', boş dize) en kötü sonucu verir —
// sistem çalışır görünür ve gerçekte korumasızdır.
//
// Sır olmayan her şeyin makul bir varsayılanı vardır: tek makinelik bir
// kurulumun on beş ortam değişkeni yazması gerekmemeli.

const path = require('node:path');

class ConfigError extends Error {
  constructor(message) { super(message); this.name = 'ConfigError'; }
}

const env = (name, fallback) => {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
};

const envInt = (name, fallback) => {
  const v = env(name);
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new ConfigError(`${name} sayı olmalı, '${v}' alındı`);
  return Math.floor(n);
};

const envBool = (name, fallback) => {
  const v = env(name);
  if (v === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(v);
};

/** Mbit/s → bayt/s. Panel ve ortam değişkenleri Mbit konuşur, motor bayt. */
const mbitToBytes = (mbit) => (mbit > 0 ? Math.floor((mbit * 1_000_000) / 8) : 0);

function loadServerConfig(overrides = {}) {
  const root = path.join(__dirname, '..', '..');
  const dataDir = env('FITFAK_TUNNEL_DATA_DIR', path.join(root, '.tunnel-data'));

  const cfg = {
    // ---- DTLS dinleyicisi -----------------------------------------------------------------
    host: env('FITFAK_TUNNEL_HOST', '0.0.0.0'),
    port: envInt('FITFAK_TUNNEL_PORT', 4443),
    mtu: envInt('FITFAK_TUNNEL_MTU', 1200),

    /** Sunucunun kendi sertifikası (trust.fitfak.net'ten alınmış). */
    certPath: env('FITFAK_TUNNEL_CERT'),
    keyPath: env('FITFAK_TUNNEL_KEY'),
    /** İstemci sertifikalarının doğrulanacağı güven çıpası — kök CA. */
    caPath: env('FITFAK_TUNNEL_CA'),
    /** CA dosya olarak verilmediyse buradan indirilir. */
    trustAnchorUrl: env('FITFAK_TUNNEL_ROOT_CA_URL', 'http://status.trust.fitfak.net/root.crt'),
    servername: env('FITFAK_TUNNEL_SERVERNAME', 'tunnel.fitfak.net'),

    /**
     * İptal denetimi. Varsayılan 'hard-fail': bir tünel istemcisi ağın içine
     * doğrudan yol açtığı için, "durumunu öğrenemedim ama devam edeyim"
     * demenin bedeli çalınmış bir anahtarın süresi dolana kadar geçerli
     * kalmasıdır. OCSP/CRL erişilemiyorsa bağlanmamak doğru olan.
     */
    revocation: env('FITFAK_TUNNEL_REVOCATION', 'hard-fail'),

    // ---- genel (dış dünyaya bakan) yüzey --------------------------------------------------
    publicHost: env('FITFAK_TUNNEL_PUBLIC_HOST', '0.0.0.0'),
    /** Panelde ve istemciye gösterilen ad; bağlama adresi DEĞİL. */
    publicHostname: env('FITFAK_TUNNEL_PUBLIC_HOSTNAME', ''),
    portMin: envInt('FITFAK_TUNNEL_PORT_MIN', 20000),
    portMax: envInt('FITFAK_TUNNEL_PORT_MAX', 30000),
    portLingerMs: envInt('FITFAK_TUNNEL_PORT_LINGER_MS', 20_000),

    // ---- politika -------------------------------------------------------------------------
    /** İstemci kendi başına uygulama tanımlayabilir mi (CLI kullanımı). */
    allowClientBinds: envBool('FITFAK_TUNNEL_ALLOW_CLIENT_BINDS', true),
    /** İstemci SABİT bir genel port isteyebilir mi. Varsayılan hayır. */
    allowClientPortChoice: envBool('FITFAK_TUNNEL_ALLOW_CLIENT_PORT_CHOICE', false),
    maxTunnels: envInt('FITFAK_TUNNEL_MAX_TUNNELS', 2000),
    /** Tünel başına varsayılan çıkış sınırı (0 = sınırsız). */
    defaultTunnelEgressBps: mbitToBytes(envInt('FITFAK_TUNNEL_DEFAULT_EGRESS_MBIT', 0)),

    // ---- yönetim yüzeyi -------------------------------------------------------------------
    admin: {
      enabled: envBool('FITFAK_TUNNEL_ADMIN_ENABLED', true),
      host: env('FITFAK_TUNNEL_ADMIN_HOST', '127.0.1.3'),
      port: envInt('FITFAK_TUNNEL_ADMIN_PORT', 80),
      idpUrl: env('FITFAK_TUNNEL_IDP_URL', 'https://session.fitfak.net'),
      clientId: env('FITFAK_TUNNEL_OAUTH_CLIENT_ID'),
      clientSecret: env('FITFAK_TUNNEL_OAUTH_CLIENT_SECRET'),
      redirectUri: env('FITFAK_TUNNEL_OAUTH_REDIRECT_URI'),
      /** userinfo'daki role=admin dışında ayrıca kabul edilecek e-posta. */
      adminEmail: (env('FITFAK_TUNNEL_ADMIN_EMAIL', '') || '').toLowerCase(),
      sessionTtlMs: envInt('FITFAK_TUNNEL_ADMIN_SESSION_TTL_MS', 8 * 3600_000),
      /** Kimlik doğrulaması olmadan çalıştırma — YALNIZCA yerel geliştirme. */
      insecureNoAuth: envBool('FITFAK_TUNNEL_ADMIN_INSECURE_NO_AUTH', false),
    },

    // ---- veritabanı -----------------------------------------------------------------------
    db: {
      target: env('FITFAK_TUNNEL_DB_TARGET'),
      serviceName: env('FITFAK_TUNNEL_DB_SERVICE_NAME', 'tunnel-service'),
      databaseName: env('FITFAK_TUNNEL_DB_NAME', 'tunnel'),
      enrolmentSecret: env('FITFAK_TUNNEL_DB_ENROLMENT_SECRET'),
      caFingerprint: env('FITFAK_TUNNEL_DB_CA_FINGERPRINT'),
      caPath: env('FITFAK_TUNNEL_DB_CA_PATH'),
      dbId: env('FITFAK_TUNNEL_DB_ID'),
      clientSecret: env('FITFAK_TUNNEL_DB_CLIENT_SECRET'),
      identityDir: env('FITFAK_TUNNEL_DB_IDENTITY_DIR', path.join(dataDir, 'identity')),
    },

    // ---- çoklayıcı sınırları --------------------------------------------------------------
    limits: {
      segmentBytes: envInt('FITFAK_TUNNEL_SEGMENT_BYTES', 16 * 1024),
      streamWindow: envInt('FITFAK_TUNNEL_STREAM_WINDOW', 256 * 1024),
      connectionWindow: envInt('FITFAK_TUNNEL_CONNECTION_WINDOW', 8 * 1024 * 1024),
      maxStreams: envInt('FITFAK_TUNNEL_MAX_STREAMS', 4096),
    },

    // ---- koruma ---------------------------------------------------------------------------
    guard: {
      acceptPerIpPerSec: envInt('FITFAK_TUNNEL_ACCEPT_PER_IP', 30),
      acceptGlobalPerSec: envInt('FITFAK_TUNNEL_ACCEPT_GLOBAL', 2000),
      maxConnectionsPerIp: envInt('FITFAK_TUNNEL_CONNS_PER_IP', 128),
      maxConnectionsPerApp: envInt('FITFAK_TUNNEL_CONNS_PER_APP', 2048),
      maxConnectionsGlobal: envInt('FITFAK_TUNNEL_CONNS_GLOBAL', 20000),
      firstByteTimeoutMs: envInt('FITFAK_TUNNEL_FIRST_BYTE_MS', 15_000),
      udpPacketsPerIpPerSec: envInt('FITFAK_TUNNEL_UDP_PPS_PER_IP', 500),
      udpBytesPerIpPerSec: envInt('FITFAK_TUNNEL_UDP_BPS_PER_IP', 2 * 1024 * 1024),
      udpMaxFlowsPerIp: envInt('FITFAK_TUNNEL_UDP_FLOWS_PER_IP', 64),
    },

    dataDir,
    metricsIntervalMs: envInt('FITFAK_TUNNEL_METRICS_INTERVAL_MS', 60_000),
  };

  Object.assign(cfg, overrides);
  if (overrides.admin) cfg.admin = { ...cfg.admin, ...overrides.admin };
  if (overrides.db) cfg.db = { ...cfg.db, ...overrides.db };
  if (overrides.limits) cfg.limits = { ...cfg.limits, ...overrides.limits };
  if (overrides.guard) cfg.guard = { ...cfg.guard, ...overrides.guard };

  if (cfg.portMin > cfg.portMax) {
    throw new ConfigError(`FITFAK_TUNNEL_PORT_MIN (${cfg.portMin}) > FITFAK_TUNNEL_PORT_MAX (${cfg.portMax})`);
  }
  if (cfg.admin.enabled && !cfg.admin.insecureNoAuth) {
    const missing = ['clientId', 'clientSecret', 'redirectUri'].filter((k) => !cfg.admin[k]);
    if (missing.length) {
      throw new ConfigError(
        `Yönetim yüzeyi açık ama OAuth yapılandırması eksik: ${missing.join(', ')}\n`
        + '  FITFAK_TUNNEL_OAUTH_CLIENT_ID / _SECRET / FITFAK_TUNNEL_OAUTH_REDIRECT_URI verin,\n'
        + '  ya da yönetimi kapatın (FITFAK_TUNNEL_ADMIN_ENABLED=0).\n'
        + '  Yerel geliştirmede kimlik doğrulamasız çalıştırmak için:\n'
        + '  FITFAK_TUNNEL_ADMIN_INSECURE_NO_AUTH=1',
      );
    }
  }
  return cfg;
}

module.exports = {
  loadServerConfig, ConfigError, mbitToBytes, env, envInt, envBool,
};
