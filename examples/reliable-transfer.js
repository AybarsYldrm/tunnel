#!/usr/bin/env node
'use strict';
// Güvenilir / sırasız veri kanalı örneği.
//
// `reliable` açıldığında application_data içine QUIC benzeri bir çerçeveleme
// katmanı girer: kaybolan parçalar yeniden gönderilir, mesajlar MTU'ya göre
// bölünüp yeniden birleştirilir. `ordered:false` (varsayılan) ile bir mesajın
// gecikmesi arkasındakileri BEKLETMEZ.
//
//   node examples/reliable-transfer.js

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dtls = require('..');

const CERTS = path.join(__dirname, '..', 'certs');
const read = (f) => fs.readFileSync(path.join(CERTS, f));

async function main() {
  const reliable = {
    ordered: false,      // sırasız teslim (head-of-line blocking yok)
    maxRetransmits: 20,
    rto: 150,
  };

  const server = dtls.createServer({
    cert: read('server.crt'), key: read('server.key'), ca: read('ca.crt'),
    reliable,
  });

  server.on('secureConnection', (sock) => {
    sock.on('data', (buf, meta) => {
      const sum = crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);
      console.log(`[srv] <- ${buf.length} bayt (msgId=${meta && meta.msgId}) sha256=${sum}…`);
    });
  });

  const addr = await server.listen(0, '127.0.0.1');
  const client = await dtls.connect({
    host: '127.0.0.1', port: addr.port, servername: 'localhost',
    ca: read('ca.crt'), reliable,
  });

  console.log(`bağlandı: ${client.protocol} / ${client.cipher} (reliable kanal aktif)`);

  // 1 MB — tek çağrı, otomatik parçalanır ve teyitlenir
  const payload = crypto.randomBytes(1024 * 1024);
  console.log(`gönderiliyor: ${payload.length} bayt, sha256=` +
              crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16) + '…');

  const t0 = Date.now();
  await client.send(payload);
  const dt = Date.now() - t0;

  const st = client.reliable.stats;
  console.log(`teslim edildi: ${dt}ms — ${st.sent} paket, ${st.resent} yeniden gönderim, ` +
              `RTT≈${client.reliable.rttMs?.toFixed(1) ?? '?'}ms`);

  // Güvenilirlik istemeyen tek atımlık veri (telemetri gibi)
  await client.send(Buffer.from('bu kaybolabilir'), { reliable: false });

  await new Promise((r) => setTimeout(r, 300));
  await client.close();
  await server.close();
}

main().catch((e) => { console.error('fatal:', e); process.exit(1); });
