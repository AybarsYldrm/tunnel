#!/usr/bin/env node
'use strict';
// Tünel istemcisi.
//
//   fitfak-tunnel --server tunnel.fitfak.net:4443 --tcp 127.0.0.2:8080
//   fitfak-tunnel --udp 127.0.0.9:5353 --lossy
//
// İlk çalıştırmada tarayıcıda oturum açmanız istenir (RFC 8628 cihaz kodu);
// alınan sertifika diske yazılır ve sonraki çalıştırmalarda giriş sorulmaz.
//
// Yönetim panelinden tanımlanmış uygulamalar bağlanır bağlanmaz kendiliğinden
// gelir; --tcp/--udp yalnızca bu oturuma özgü ek tanımlardır ve sunucu
// politikası izin veriyorsa kabul edilir.

const path = require('node:path');
const os = require('node:os');

const { startTunnelClient } = require('../src/client/index.js');
const { PROTO, DELIVERY, PROTO_NAME } = require('../src/protocol/constants.js');
const { createLogger, forceLevel } = require('../src/common/log.js');
const { cipherPolicyNames } = require('../../src/crypto/cipher-suite.js');
const pkg = require('../../package.json');

/** Kabul edilen şifreleme politikaları — tek kaynak cipher-suite.js. */
const CIPHER_POLICIES = cipherPolicyNames();

const USAGE = `
fitfak-tunnel — @fitfak/dtls tünel istemcisi

Kullanım:
  fitfak-tunnel [seçenekler]

BAĞLANTI
  --server <host:port>     Tünel sunucusu (FITFAK_TUNNEL_SERVER)
  --servername <ad>        SNI / hostname doğrulaması (varsayılan: --server'ın host'u)
  --name <ad>              Panelde görünecek ad (varsayılan: makine adı)
  --no-reconnect           Kopunca yeniden bağlanma

YAYIN
  --tcp <host:port>        Yerel bir TCP servisini yayınla (birden çok kez verilebilir)
  --udp <host:port>        Yerel bir UDP servisini yayınla
  --lossy                  Sonraki --udp için kayıp toleranslı teslim (varsayılan)
  --reliable               Sonraki --udp için kayıpsız teslim

TAŞIMA AYARI
  --cipher <politika>      balanced | aes128 | aes256 | aes | chacha20 | mobile
                           (varsayılan: balanced — AES-NI olan makinelerde en hızlı)
                           chacha20/mobile: AES hızlandırması olmayan uçlar için
  --cc <motor>             bbr3 (varsayılan) | newreno — tıkanıklık denetimi
  --mtu <bayt>             Datagram yükü tavanı (varsayılan: 1200)

KİMLİK VE GÜVEN
  --data-dir <yol>         Kimlik ve kök sertifikanın saklanacağı dizin
  --idp <url>              Kimlik sağlayıcı (varsayılan: https://session.fitfak.net)
  --trust <url>            Sertifika otoritesi (varsayılan: https://trust.fitfak.net)
  --client-id <id>         OAuth istemci kimliği (cihaz kodu akışı için)
  --root-ca-url <url>      Kök sertifika (varsayılan: http://status.trust.fitfak.net/root.crt)
  --root-ca-fingerprint <hex>  Kök sertifikanın beklenen SHA-256'sı — SABİTLEYİN
  --root-ca <dosya>        Kök sertifikayı indirmek yerine dosyadan oku
  --revocation <mod>       off | soft-fail | hard-fail (varsayılan: soft-fail)
  --no-enroll              Kimlik yoksa tarayıcı akışı BAŞLATMA, hata ver
                           (servis/otomasyon kullanımı için — bkz. aşağıda)

ÇIKTI
  --quiet                  Yalnızca uyarı ve hataları yaz
  --json                   Olayları satır başına bir JSON nesnesi olarak yaz
  --print-config           Çözümlenmiş yapılandırmayı yaz ve çık (sır içermez)
  -h, --help               Bu yardım
  -V, --version            Sürüm

OTOMASYON HAKKINDA
  İlk çalıştırmada kimlik yoksa tarayıcıda oturum açmanız istenir (RFC 8628
  cihaz kodu). Bu, İNSAN kullanımı için doğru varsayılandır ama bir servisin
  altında sessizce asılı kalır. systemd/konteyner altında --no-enroll verin:
  kimlik yoksa istemci beklemek yerine anlaşılır bir hatayla çıkar.

Her seçeneğin bir ortam değişkeni karşılığı vardır: FITFAK_TUNNEL_SERVER,
FITFAK_TUNNEL_SERVERNAME, FITFAK_TUNNEL_NAME, FITFAK_TUNNEL_CIPHER,
FITFAK_TUNNEL_CONGESTION_CONTROL, FITFAK_TUNNEL_MTU, FITFAK_TUNNEL_IDP_URL,
FITFAK_TUNNEL_TRUST_URL, FITFAK_TUNNEL_OAUTH_CLIENT_ID,
FITFAK_TUNNEL_ROOT_CA_URL, FITFAK_TUNNEL_ROOT_CA_FINGERPRINT,
FITFAK_TUNNEL_ROOT_CA_FILE, FITFAK_TUNNEL_REVOCATION, FITFAK_TUNNEL_DATA_DIR,
FITFAK_TUNNEL_LOG_LEVEL. Komut satırı ortamı ezer.
`;

/** Seçenek değerini kapalı bir kümeye karşı doğrular. */
function oneOf(value, allowed, flag) {
  const v = String(value).toLowerCase();
  if (!allowed.includes(v)) {
    throw new Error(`${flag}: '${value}' geçersiz — ${allowed.join(' | ')} olmalı`);
  }
  return v;
}

function parsePositiveInt(value, flag, { min = 1, max = 65535 } = {}) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${flag}: ${min}-${max} aralığında bir tam sayı olmalı, '${value}' alındı`);
  }
  return n;
}

function parseTarget(value, fallbackHost) {
  const s = String(value || '').trim();
  const m = /^(?:\[([^\]]+)\]|([^:]*)):(\d{1,5})$/.exec(s);
  if (m) {
    const host = m[1] || m[2] || fallbackHost;
    const port = Number(m[3]);
    if (port >= 1 && port <= 65535) return { host, port };
  }
  if (/^\d{1,5}$/.test(s)) {
    const port = Number(s);
    if (port >= 1 && port <= 65535) return { host: fallbackHost, port };
  }
  throw new Error(`geçersiz adres: '${value}' (beklenen host:port ya da port)`);
}

function parseArgs(argv) {
  const opts = {
    binds: [],
    delivery: DELIVERY.UNRELIABLE,
    reconnect: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} bir değer bekliyor`);
      return v;
    };
    switch (a) {
      case '-h': case '--help': opts.help = true; break;
      case '-V': case '--version': opts.version = true; break;
      case '--print-config': opts.printConfig = true; break;
      case '--quiet': opts.quiet = true; break;
      case '--json': opts.json = true; break;
      case '--no-enroll': opts.enroll = false; break;
      case '--cipher':
        opts.cipher = oneOf(next(), CIPHER_POLICIES, '--cipher');
        break;
      case '--cc': case '--congestion-control':
        opts.congestionControl = oneOf(next(), ['bbr3', 'bbr', 'newreno', 'reno'], a);
        break;
      case '--mtu':
        opts.mtu = parsePositiveInt(next(), '--mtu', { min: 256, max: 9000 });
        break;
      case '--server': opts.server = next(); break;
      case '--servername': opts.servername = next(); break;
      case '--name': opts.name = next(); break;
      case '--data-dir': opts.dataDir = next(); break;
      case '--idp': opts.idpUrl = next(); break;
      case '--trust': opts.trustUrl = next(); break;
      case '--client-id': opts.oauthClientId = next(); break;
      case '--root-ca-url': opts.rootCaUrl = next(); break;
      case '--root-ca-fingerprint': opts.rootCaFingerprint = next(); break;
      case '--root-ca': opts.caPath = next(); break;
      case '--revocation': opts.revocation = next(); break;
      case '--no-reconnect': opts.reconnect = false; break;
      case '--lossy': opts.delivery = DELIVERY.UNRELIABLE; break;
      case '--reliable': opts.delivery = DELIVERY.RELIABLE; break;
      case '--tcp': {
        const t = parseTarget(next(), '127.0.0.1');
        opts.binds.push({
          proto: PROTO.TCP, delivery: DELIVERY.RELIABLE, localHost: t.host, localPort: t.port, name: `tcp-${t.port}`,
        });
        break;
      }
      case '--udp': {
        const t = parseTarget(next(), '127.0.0.1');
        opts.binds.push({
          proto: PROTO.UDP, delivery: opts.delivery, localHost: t.host, localPort: t.port, name: `udp-${t.port}`,
        });
        break;
      }
      default:
        throw new Error(`bilinmeyen seçenek: ${a}`);
    }
  }
  return opts;
}

/**
 * Komut satırı > ortam değişkeni > varsayılan.
 *
 * Sıra tersine çevrilirse (ortam CLI'yı ezerse) kullanıcı, açıkça yazdığı
 * seçeneğin neden tutmadığını asla bulamaz.
 */
function resolveConfig(opts) {
  const pick = (cli, envName, fallback) => {
    if (cli !== undefined && cli !== null && cli !== '') return cli;
    const v = process.env[envName];
    return v === undefined || v === '' ? fallback : v;
  };

  const serverSpec = pick(opts.server, 'FITFAK_TUNNEL_SERVER');
  if (!serverSpec) {
    const err = new Error('--server verilmedi (ya da FITFAK_TUNNEL_SERVER)');
    err.usage = true;
    throw err;
  }
  const target = parseTarget(serverSpec, '127.0.0.1');
  const mtuRaw = pick(opts.mtu, 'FITFAK_TUNNEL_MTU', 1200);

  return {
    host: target.host,
    port: target.port,
    servername: pick(opts.servername, 'FITFAK_TUNNEL_SERVERNAME', target.host),
    name: pick(opts.name, 'FITFAK_TUNNEL_NAME', os.hostname()),
    cipher: oneOf(pick(opts.cipher, 'FITFAK_TUNNEL_CIPHER', 'balanced'), CIPHER_POLICIES, '--cipher'),
    congestionControl: oneOf(
      pick(opts.congestionControl, 'FITFAK_TUNNEL_CONGESTION_CONTROL', 'bbr3'),
      ['bbr3', 'bbr', 'newreno', 'reno'], '--cc',
    ),
    mtu: parsePositiveInt(mtuRaw, '--mtu', { min: 256, max: 9000 }),
    idpUrl: pick(opts.idpUrl, 'FITFAK_TUNNEL_IDP_URL', 'https://session.fitfak.net'),
    trustUrl: pick(opts.trustUrl, 'FITFAK_TUNNEL_TRUST_URL', 'https://trust.fitfak.net'),
    oauthClientId: pick(opts.oauthClientId, 'FITFAK_TUNNEL_OAUTH_CLIENT_ID'),
    rootCaUrl: pick(opts.rootCaUrl, 'FITFAK_TUNNEL_ROOT_CA_URL', 'http://status.trust.fitfak.net/root.crt'),
    rootCaFingerprint: pick(opts.rootCaFingerprint, 'FITFAK_TUNNEL_ROOT_CA_FINGERPRINT'),
    caPath: pick(opts.caPath, 'FITFAK_TUNNEL_ROOT_CA_FILE'),
    revocation: oneOf(
      pick(opts.revocation, 'FITFAK_TUNNEL_REVOCATION', 'soft-fail'),
      ['off', 'soft-fail', 'hard-fail'], '--revocation',
    ),
    dataDir: pick(opts.dataDir, 'FITFAK_TUNNEL_DATA_DIR', path.join(os.homedir(), '.fitfak-tunnel')),
    binds: opts.binds,
    reconnect: opts.reconnect,
    enroll: opts.enroll !== false,
    quiet: !!opts.quiet,
    json: !!opts.json,
  };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(USAGE); return; }
  if (opts.version) { process.stdout.write(`fitfak-tunnel ${pkg.version}\n`); return; }

  const cfg = resolveConfig(opts);

  if (cfg.quiet) forceLevel('WARN');
  const log = createLogger('tunnel:cli');

  // Çözümlenmiş yapılandırmayı göstermek, "neden benim ayarım tutmuyor"
  // sorusunu tek komutla bitiriyor. Sır içeren hiçbir alan YOK.
  if (opts.printConfig) {
    const { binds, ...rest } = cfg;
    process.stdout.write(`${JSON.stringify({
      ...rest,
      binds: binds.map((b) => ({
        proto: PROTO_NAME[b.proto],
        local: `${b.localHost}:${b.localPort}`,
        delivery: b.delivery === DELIVERY.RELIABLE ? 'reliable' : 'unreliable',
      })),
    }, null, 2)}\n`);
    return;
  }

  const emit = (event, data) => {
    if (cfg.json) { process.stdout.write(`${JSON.stringify({ event, ...data })}\n`); return; }
    if (event === 'bound') {
      process.stdout.write(`  yayında  ${data.public}/${data.proto}\n`);
    }
  };

  const client = await startTunnelClient({
    host: cfg.host,
    port: cfg.port,
    servername: cfg.servername,
    idpUrl: cfg.idpUrl,
    trustUrl: cfg.trustUrl,
    oauthClientId: cfg.oauthClientId,
    rootCaUrl: cfg.rootCaUrl,
    rootCaFingerprint: cfg.rootCaFingerprint,
    caPath: cfg.caPath,
    revocation: cfg.revocation,
    cipher: cfg.cipher,
    congestionControl: cfg.congestionControl,
    mtu: cfg.mtu,
    dataDir: cfg.dataDir,
    name: cfg.name,
    binds: cfg.binds,
    reconnect: cfg.reconnect,
    onPrompt: (p) => {
      // --no-enroll: kimlik yoksa BEKLEME. Bir servisin altında "tarayıcıda
      // şu adresi aç" satırını kimse görmez; süreç sessizce asılı kalır ve
      // yeniden başlatma döngüsüne girer. Açık bir hata, sessiz bir asılmadan
      // her zaman iyidir.
      if (!cfg.enroll) {
        throw Object.assign(new Error(
          'kayıtlı kimlik yok ve --no-enroll verildi.\n'
          + `  Kimliği bir kez etkileşimli oluşturun:  fitfak-tunnel --server ${cfg.host}:${cfg.port}\n`
          + `  ya da hazır kimliği şu dizine koyun:    ${cfg.dataDir}`,
        ), { code: 'ENROLLMENT_REQUIRED' });
      }
      if (cfg.json) { emit('enrollment', { url: p.verificationUriComplete || p.verificationUri, code: p.userCode }); return; }
      process.stdout.write(
        '\n  Tarayıcında şu adresi aç:  '
        + `${p.verificationUriComplete || p.verificationUri}\n`
        + `  Kod:                       ${p.userCode}\n\n`,
      );
    },
  });

  client.on('bound', (b) => emit('bound', {
    public: `${b.publicHost || ''}:${b.publicPort}`,
    proto: PROTO_NAME[b.proto],
    appId: b.appId,
  }));
  client.on('ready', (r) => emit('ready', { tunnelId: r.tunnelId }));
  client.on('disconnected', () => emit('disconnected', {}));

  let stopping = false;
  const shutdown = async (signal) => {
    if (stopping) process.exit(1);
    stopping = true;
    process.stderr.write(`\n${signal} alındı, kapatılıyor…\n`);
    const timer = setTimeout(() => process.exit(1), 5000);
    timer.unref();
    await client.stop();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  log.info('tünel istemcisi çalışıyor — kapatmak için Ctrl+C');
}

main().catch((err) => {
  // Kullanım hatası ile çalışma zamanı hatası ayrı çıkış kodları alır:
  // bir betik, "yanlış yazdım" ile "sunucuya ulaşamadım"ı ayırt edebilmeli.
  if (err.usage) {
    process.stderr.write(`${err.message}\n${USAGE}`);
    process.exit(2);
  }
  if (err.code === 'ENROLLMENT_REQUIRED') {
    process.stderr.write(`${err.message}\n`);
    process.exit(3);
  }
  process.stderr.write(`tünel istemcisi başlatılamadı: ${err.stack || err.message}\n`);
  process.exit(1);
});
