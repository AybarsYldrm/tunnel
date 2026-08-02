#!/usr/bin/env node
'use strict';
// DTLS-SRTP örneği — WebRTC'deki medya yolunun aynısı.
//
// Handshake DTLS ile yapılır, sonrasında RTP/RTCP paketleri AYNI UDP soketinden
// SRTP olarak akar (RFC 5764 + RFC 7983 demux). DTLS kayıt katmanı medyaya
// dokunmaz — sadece anahtarları üretir.
//
//   node examples/srtp-media.js

const fs = require('node:fs');
const path = require('node:path');
const dtls = require('..');

const CERTS = path.join(__dirname, '..', 'certs');
const read = (f) => fs.readFileSync(path.join(CERTS, f));

/** Basit bir RTP paketi kurar (V=2, PT=96). */
function makeRtp(seq, ssrc, timestamp, payload) {
  const pkt = Buffer.allocUnsafe(12 + payload.length);
  pkt[0] = 0x80;
  pkt[1] = 96;
  pkt.writeUInt16BE(seq & 0xffff, 2);
  pkt.writeUInt32BE(timestamp >>> 0, 4);
  pkt.writeUInt32BE(ssrc >>> 0, 8);
  payload.copy(pkt, 12);
  return pkt;
}

async function main() {
  const srtp = {
    profiles: ['SRTP_AEAD_AES_128_GCM', 'SRTP_AES128_CM_HMAC_SHA1_80'],
  };

  const server = dtls.createServer({
    cert: read('server.crt'), key: read('server.key'), ca: read('ca.crt'),
    srtp,
  });

  server.on('secureConnection', (sock) => {
    console.log(`[srv] ${sock.protocol} / SRTP profili: ${sock.srtpProfile}`);
    sock.on('media', (rtp) => {
      const seq = rtp.readUInt16BE(2);
      console.log(`[srv] <- RTP seq=${seq} payload="${rtp.subarray(12)}"`);
      // Aynı medyayı geri yolla
      sock.sendMedia(makeRtp(seq, 0xCAFEBABE, seq * 160, Buffer.from(`yankı-${seq}`)));
    });
    sock.on('rtcp', (pkt) => console.log(`[srv] <- RTCP ${pkt.length}B`));
  });

  const addr = await server.listen(0, '127.0.0.1');

  const client = await dtls.connect({
    host: '127.0.0.1', port: addr.port, servername: 'localhost',
    ca: read('ca.crt'), srtp,
  });
  console.log(`[cli] ${client.protocol} / SRTP profili: ${client.srtpProfile}`);

  client.on('media', (rtp) => {
    console.log(`[cli] <- RTP seq=${rtp.readUInt16BE(2)} payload="${rtp.subarray(12)}"`);
  });

  for (let i = 0; i < 3; i++) {
    client.sendMedia(makeRtp(1000 + i, 0xDEADBEEF, i * 960, Buffer.from(`kare-${i}`)));
    await new Promise((r) => setTimeout(r, 60));
  }

  await new Promise((r) => setTimeout(r, 300));
  await client.close();
  await server.close();
}

main().catch((e) => { console.error('fatal:', e); process.exit(1); });
