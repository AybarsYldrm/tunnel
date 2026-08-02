#!/usr/bin/env node
'use strict';
// Düz DTLS echo istemcisi — mTLS ile.
//
//   node examples/echo-client.js "gönderilecek mesaj"

const fs = require('node:fs');
const path = require('node:path');
const dtls = require('..');

const CERTS = path.join(__dirname, '..', 'certs');
const read = (f) => fs.readFileSync(path.join(CERTS, f));

const HOST = process.env.DTLS_HOST || '127.0.0.1';
const PORT = Number(process.env.DTLS_PORT || 4444);
const SNI  = process.env.DTLS_SNI || 'localhost';
const MESSAGE = process.argv[2] || 'merhaba DTLS';

async function main() {
  const sock = await dtls.connect({
    host: HOST,
    port: PORT,
    servername: SNI,             // SNI + hostname doğrulaması
    ca: read('ca.crt'),
    cert: read('client.crt'),    // mTLS istemci kimliği
    key: read('client.key'),
    rejectUnauthorized: true,
    minVersion: 'DTLSv1.2',
    maxVersion: 'DTLSv1.3',
  });

  const cert = sock.getPeerCertificate();
  console.log(`bağlandı: ${sock.protocol} / ${sock.cipher}`);
  console.log(`sunucu  : ${cert.subject.replace(/\n/g, ' ')}`);
  console.log(`doğrulama: authorized=${sock.authorized}`);

  sock.on('data', (buf) => {
    console.log(`<- ${buf.toString('utf8')}`);
    sock.close().then(() => process.exit(0));
  });
  sock.on('close', (err) => {
    if (err) { console.error('kapandı:', err.message); process.exit(2); }
  });

  await sock.send(Buffer.from(MESSAGE));
  console.log(`-> ${MESSAGE}`);

  setTimeout(() => { console.error('yanıt gelmedi'); process.exit(3); }, 5000).unref();
}

main().catch((e) => { console.error('fatal:', e.message); process.exit(1); });
