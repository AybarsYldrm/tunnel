#!/usr/bin/env node
'use strict';
// Tünel sunucusu.
//
//   fitfak-tunneld
//
// Yapılandırma ortam değişkenlerinden gelir (bkz. tunnel/README.md ve
// src/server/config.js). Zorunlu olanlar:
//
//   FITFAK_TUNNEL_CERT / FITFAK_TUNNEL_KEY   sunucu sertifikası
//   FITFAK_TUNNEL_OAUTH_CLIENT_ID / _SECRET  yönetim yüzeyi girişi
//   FITFAK_TUNNEL_OAUTH_REDIRECT_URI

const { startTunnelServer } = require('../src/server/index.js');
const { ConfigError } = require('../src/server/config.js');

async function main() {
  const server = await startTunnelServer();

  let stopping = false;
  const shutdown = async (signal) => {
    if (stopping) {
      // İkinci sinyal "beklemeyi bırak" demektir; süresiz kapanan bir servis,
      // hiç kapanmayan bir servisten farksızdır.
      process.exit(1);
    }
    stopping = true;
    process.stderr.write(`\n${signal} alındı, kapatılıyor…\n`);
    const timer = setTimeout(() => process.exit(1), 10_000);
    timer.unref();
    await server.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  if (err instanceof ConfigError) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
  }
  process.stderr.write(`tünel sunucusu başlatılamadı: ${err.stack || err.message}\n`);
  process.exit(1);
});
