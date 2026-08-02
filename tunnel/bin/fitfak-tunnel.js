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
const { createLogger } = require('../src/common/log.js');

const USAGE = `
fitfak-tunnel — @fitfak/dtls tünel istemcisi

Kullanım:
  fitfak-tunnel [seçenekler]

Seçenekler:
  --server <host:port>     Tünel sunucusu (FITFAK_TUNNEL_SERVER)
  --servername <ad>        SNI / hostname doğrulaması (varsayılan: --server'ın host'u)
  --tcp <host:port>        Yerel bir TCP servisini yayınla (birden çok kez verilebilir)
  --udp <host:port>        Yerel bir UDP servisini yayınla
  --lossy                  Sonraki --udp için kayıp toleranslı teslim (varsayılan)
  --reliable               Sonraki --udp için kayıpsız teslim
  --name <ad>              Panelde görünecek ad (varsayılan: makine adı)
  --data-dir <yol>         Kimlik ve kök sertifikanın saklanacağı dizin
  --idp <url>              Kimlik sağlayıcı (varsayılan: https://session.fitfak.net)
  --trust <url>            Sertifika otoritesi (varsayılan: https://trust.fitfak.net)
  --client-id <id>         OAuth istemci kimliği (cihaz kodu akışı için)
  --root-ca-url <url>      Kök sertifika (varsayılan: http://status.trust.fitfak.net/root.crt)
  --root-ca-fingerprint <hex>  Kök sertifikanın beklenen SHA-256'sı — SABİTLEYİN
  --root-ca <dosya>        Kök sertifikayı indirmek yerine dosyadan oku
  --revocation <mod>       off | soft-fail | hard-fail (varsayılan: soft-fail)
  --no-reconnect           Kopunca yeniden bağlanma
  -h, --help               Bu yardım

Ortam değişkenleri her seçeneğin karşılığıdır: FITFAK_TUNNEL_SERVER,
FITFAK_TUNNEL_IDP_URL, FITFAK_TUNNEL_TRUST_URL, FITFAK_TUNNEL_OAUTH_CLIENT_ID,
FITFAK_TUNNEL_ROOT_CA_URL, FITFAK_TUNNEL_ROOT_CA_FINGERPRINT,
FITFAK_TUNNEL_DATA_DIR, FITFAK_TUNNEL_LOG_LEVEL.
`;

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

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(USAGE); return; }

  const log = createLogger('tunnel:cli');

  const serverSpec = opts.server || process.env.FITFAK_TUNNEL_SERVER;
  if (!serverSpec) {
    process.stderr.write('--server verilmedi (ya da FITFAK_TUNNEL_SERVER).\n' + USAGE);
    process.exit(2);
  }
  const target = parseTarget(serverSpec, '127.0.0.1');

  const dataDir = opts.dataDir
    || process.env.FITFAK_TUNNEL_DATA_DIR
    || path.join(os.homedir(), '.fitfak-tunnel');

  const client = await startTunnelClient({
    host: target.host,
    port: target.port,
    servername: opts.servername || process.env.FITFAK_TUNNEL_SERVERNAME || target.host,
    idpUrl: opts.idpUrl || process.env.FITFAK_TUNNEL_IDP_URL || 'https://session.fitfak.net',
    trustUrl: opts.trustUrl || process.env.FITFAK_TUNNEL_TRUST_URL || 'https://trust.fitfak.net',
    oauthClientId: opts.oauthClientId || process.env.FITFAK_TUNNEL_OAUTH_CLIENT_ID,
    rootCaUrl: opts.rootCaUrl || process.env.FITFAK_TUNNEL_ROOT_CA_URL || 'http://status.trust.fitfak.net/root.crt',
    rootCaFingerprint: opts.rootCaFingerprint || process.env.FITFAK_TUNNEL_ROOT_CA_FINGERPRINT,
    caPath: opts.caPath || process.env.FITFAK_TUNNEL_ROOT_CA_FILE,
    revocation: opts.revocation || process.env.FITFAK_TUNNEL_REVOCATION || 'soft-fail',
    dataDir,
    name: opts.name || process.env.FITFAK_TUNNEL_NAME || os.hostname(),
    binds: opts.binds,
    reconnect: opts.reconnect,
    onPrompt: (p) => {
      process.stdout.write(
        '\n  Tarayıcında şu adresi aç:  '
        + `${p.verificationUriComplete || p.verificationUri}\n`
        + `  Kod:                       ${p.userCode}\n\n`,
      );
    },
  });

  client.on('bound', (b) => {
    process.stdout.write(
      `  yayında  ${b.publicHost || ''}:${b.publicPort}/${PROTO_NAME[b.proto]}\n`,
    );
  });

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
  process.stderr.write(`tünel istemcisi başlatılamadı: ${err.stack || err.message}\n`);
  process.exit(1);
});
