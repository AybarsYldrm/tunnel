#!/usr/bin/env node
'use strict';
// Düz DTLS echo sunucusu — mTLS açık.
//
//   npm run certs
//   node examples/echo-server.js
//
// Ortam değişkenleri: DTLS_HOST, DTLS_PORT, DTLS_MTLS=0 (mTLS kapat)

const fs = require('node:fs');
const path = require('node:path');
const dtls = require('..');

const CERTS = path.join(__dirname, '..', 'certs');
const read = (f) => fs.readFileSync(path.join(CERTS, f));

const HOST = process.env.DTLS_HOST || '127.0.0.1';
const PORT = Number(process.env.DTLS_PORT || 4444);
const MTLS = process.env.DTLS_MTLS !== '0';

async function main() {
  const server = dtls.createServer({
    cert: read('server.crt'),
    key: read('server.key'),
    ca: read('ca.crt'),

    // mTLS: istemciden sertifika iste ve CA'ya karşı doğrula
    requestCert: MTLS,
    rejectUnauthorized: MTLS,

    // DTLS 1.3 tercih edilir, 1.2'ye düşebilir
    minVersion: 'DTLSv1.2',
    maxVersion: 'DTLSv1.3',
  });

  server.on('secureConnection', (sock) => {
    const peer = `${sock.remoteAddress}:${sock.remotePort}`;
    const cert = sock.getPeerCertificate();
    console.log(`[+] ${peer} — ${sock.protocol} / ${sock.cipher}` +
                (cert ? ` / istemci: ${cert.subject.replace(/\n/g, ' ')}` : ''));

    sock.on('data', (buf) => {
      console.log(`    <- ${buf.length}B: ${buf.toString('utf8').slice(0, 60)}`);
      sock.send(Buffer.from(`echo: ${buf}`)).catch((e) => console.error('    send:', e.message));
    });
    sock.on('close', () => console.log(`[-] ${peer} kapandı`));
  });

  server.on('sessionError', (err, sock) => {
    console.warn(`[!] handshake hatası ${sock.remoteAddress}:${sock.remotePort} — ${err.message}`);
  });
  server.on('error', (e) => console.error('[!] sunucu hatası:', e.message));

  const addr = await server.listen(PORT, HOST);
  console.log(`DTLS sunucu dinliyor: ${addr.address}:${addr.port} (mTLS=${MTLS})`);

  process.on('SIGINT', () => { server.close().then(() => process.exit(0)); });
}

main().catch((e) => { console.error('fatal:', e); process.exit(1); });
