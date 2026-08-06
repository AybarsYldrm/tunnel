#!/usr/bin/env node
'use strict';
// Tüm test dosyalarını sırayla çalıştırır ve toplu sonuç raporlar.

const { spawn } = require('node:child_process');
const path = require('node:path');
const { certsAvailable } = require('./helpers.js');

const SUITES = [
  'test-kat.js',
  'test-unit.js',
  'test-e2e.js',
  'test-mtls.js',
  'test-revocation.js',
  'test-srtp.js',
  'test-reliable.js',
  'test-bbr.js',
  'test-retransmit.js',
  'test-robustness.js',
  // Tünel katmanı: aynı çekirdeği kullanıyor ve aynı test PKI'sına dayanıyor,
  // bu yüzden ayrı bir koşucu değil bu listenin devamı.
  '../tunnel/test/test-protocol.js',
  '../tunnel/test/test-qos.js',
  '../tunnel/test/test-hardening.js',
  '../tunnel/test/test-tunnel.js',
  '../tunnel/test/test-admin.js',
];

if (!certsAvailable()) {
  console.error('\nTest sertifikaları yok. Önce çalıştırın:\n\n  npm run certs\n');
  process.exit(1);
}

function run(file) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, file)], {
      stdio: 'inherit',
      env: { ...process.env, DTLS_LOG_LEVEL: process.env.DTLS_LOG_LEVEL || 'ERROR' },
    });
    child.on('close', (code) => resolve(code === 0));
  });
}

(async () => {
  const t0 = Date.now();
  const failed = [];
  for (const file of SUITES) {
    if (!(await run(file))) failed.push(file);
  }
  const secs = ((Date.now() - t0) / 1000).toFixed(1);

  console.log('\n' + '='.repeat(58));
  if (failed.length === 0) {
    console.log(`TÜM TESTLER GEÇTİ — ${SUITES.length} paket, ${secs}s`);
    process.exit(0);
  }
  console.log(`${failed.length}/${SUITES.length} paket BAŞARISIZ (${secs}s):`);
  for (const f of failed) console.log(`  - ${f}`);
  process.exit(1);
})();
