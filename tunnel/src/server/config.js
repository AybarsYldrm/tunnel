'use strict';
// Tek yapılandırma noktası.
//
// Kural: bir sırrın koda gömülü varsayılanı YOKTUR ve eksikse süreç AÇILIŞTA
// durur. Sessiz bir varsayılan ('changeme', boş dize) en kötü sonucu verir —
// sistem çalışır görünür ve gerçekte korumasızdır.
//
// Sır olmayan her şeyin makul bir varsayılanı vardır: tek makinelik bir
// kurulumun on beş ortam değişkeni yazması gerekmemeli.
//
// ÜÇ KATMAN, net bir öncelik sırasıyla (sonraki öncekini ezer):
//
//   1. koddaki varsayılanlar
//   2. ortam değişkenleri            — kapsayıcı/systemd dünyasının dili
//   3. yapılandırma DOSYASI          — `config.js`, elle yönetilen kurulumların
//   4. çağrıya geçilen `overrides`   — testler ve gömülü kullanım
//
// Dosya neden ortamın ÜSTÜNDE? Çünkü dosyayı yazan kişi onu bilerek yazmıştır;
// ortam değişkeni ise kabuktan, kapsayıcı imajından ya da CI'dan sızmış
// olabilir. "Dosyada ne yazıyorsa o çalışır" kuralı, teşhis edilebilir tek
// davranış.

const fs = require('node:fs');
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

/** İç içe nesneleri birleştirir; dizi ve ilkel değerler ezilir. */
function deepMerge(base, patch) {
  if (!patch || typeof patch !== 'object') return base;
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) continue;
    if (v && typeof v === 'object' && !Array.isArray(v)
        && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) {
      deepMerge(base[k], v);
    } else {
      base[k] = v;
    }
  }
  return base;
}

/**
 * Yapılandırma dosyasını bulur ve yükler.
 *
 * Arama sırası: açıkça verilen yol → FITFAK_TUNNEL_CONFIG → paket kökündeki
 * `config.js`. Hiçbiri yoksa `null` — dosya ZORUNLU DEĞİL.
 *
 * Dosya bir nesne ya da nesne döndüren bir fonksiyon dışa aktarabilir;
 * `loadServerConfig` adında bir dışa aktarım varsa (bu dosyanın kendi biçimi)
 * o çağrılır. Böylece kullanıcı, tam gövdeli bir yapılandırma dosyasını da
 * kısmi bir yamayı da aynı yere koyabilir.
 */
function loadConfigFile(explicitPath) {
  const root = path.join(__dirname, '..', '..');
  const candidates = [
    explicitPath,
    process.env.FITFAK_TUNNEL_CONFIG,
    path.join(root, 'config.js'),
    path.join(root, 'config.json'),
  ].filter(Boolean);

  for (const candidate of candidates) {
    const file = path.resolve(candidate);
    if (!fs.existsSync(file)) {
      // Açıkça istenen bir dosyanın yokluğu sessiz geçilmez: kullanıcı onu
      // yazdığını sanıp neden hiçbir ayarının tutmadığını arar.
      if (candidate === explicitPath || candidate === process.env.FITFAK_TUNNEL_CONFIG) {
        throw new ConfigError(`yapılandırma dosyası bulunamadı: ${file}`);
      }
      continue;
    }
    let loaded;
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      loaded = require(file);
    } catch (err) {
      throw new ConfigError(`yapılandırma dosyası okunamadı (${file}): ${err.message}`);
    }
    const value = typeof loaded === 'function' ? loaded()
      : (typeof loaded?.loadServerConfig === 'function' ? loaded.loadServerConfig() : loaded);
    if (!value || typeof value !== 'object') {
      throw new ConfigError(`yapılandırma dosyası bir nesne döndürmeli: ${file}`);
    }
    return { file, value };
  }
  return null;
}

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

    /**
     * Şifreleme paketi tercihi. Politika adı ya da açık suite listesi.
     *
     *   balanced  (varsayılan) AES-128-GCM önce — AES-NI olan her makinede en hızlı
     *   aes256    daha uzun anahtar isteyen kurumsal politikalar için
     *   chacha20  AES donanım hızlandırması olmayan uçlar (ARM, gömülü)
     *   mobile    ChaCha20 önce, AES yedek — karışık istemci parkı
     *
     * Ayrıntı ve tam liste: src/crypto/cipher-suite.js
     */
    cipher: env('FITFAK_TUNNEL_CIPHER', 'balanced'),

    /**
     * Tıkanıklık denetimi: 'bbr3' (varsayılan) ya da 'newreno'.
     *
     * BBRv3 hattın darboğaz hızını ve en küçük gecikmesini ÖLÇER; kaybı
     * tıkanıklık sanmaz. Kayıplı ya da uzun mesafeli hatlarda fark kat
     * cinsindendir. Gerekçenin tamamı: src/reliable/congestion.js
     */
    congestionControl: env('FITFAK_TUNNEL_CONGESTION_CONTROL', 'bbr3'),

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

      /**
       * İçerik güvenliği politikası.
       *
       * Varsayılan: panel kendi kaynaklarından başka HİÇBİR yere gitmez.
       * Üçüncü taraf bir betiğe (ör. Cloudflare Web Analytics) izin vermek
       * bilinçli bir karardır ve burada açıkça verilir — sessiz bir varsayılan
       * olarak değil.
       *
       * `'unsafe-inline'` / `'unsafe-eval'` buradan da AÇILAMAZ; listeye
       * yazılsalar bile süzülürler (admin/server.js buildCsp).
       */
      csp: {
        /** Cloudflare'in enjekte ettiği beacon.min.js'e izin ver. */
        cloudflareInsights: envBool('FITFAK_TUNNEL_ADMIN_CSP_CLOUDFLARE', false),
        /** Ek betik kaynakları (tam köken: https://cdn.example.com). */
        scriptSrc: (env('FITFAK_TUNNEL_ADMIN_CSP_SCRIPT_SRC', '') || '').split(/[\s,]+/).filter(Boolean),
        /** Ek bağlantı hedefleri (fetch/XHR/EventSource). */
        connectSrc: (env('FITFAK_TUNNEL_ADMIN_CSP_CONNECT_SRC', '') || '').split(/[\s,]+/).filter(Boolean),
        imgSrc: (env('FITFAK_TUNNEL_ADMIN_CSP_IMG_SRC', '') || '').split(/[\s,]+/).filter(Boolean),
        /** Trusted Types — innerHTML'i tarayıcı seviyesinde yasaklar. */
        trustedTypes: envBool('FITFAK_TUNNEL_ADMIN_CSP_TRUSTED_TYPES', true),
        /** İhlal raporlarının gönderileceği uç (isteğe bağlı). */
        reportUri: env('FITFAK_TUNNEL_ADMIN_CSP_REPORT_URI', ''),
      },
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

  // --- katman 3: yapılandırma dosyası (varsa)
  const file = overrides.configFile === false
    ? null
    : loadConfigFile(overrides.configFile);
  if (file) {
    deepMerge(cfg, file.value);
    cfg.configFile = file.file;
  }

  // --- katman 4: çağrıya geçilen değerler
  const direct = { ...overrides };
  delete direct.configFile;
  deepMerge(cfg, direct);

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
  loadConfigFile, deepMerge,
};
