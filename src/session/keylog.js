'use strict';
// SSLKEYLOGFILE — NSS Key Log Format.
//
// Format: "<LABEL> <client_random_hex> <secret_hex>\n"
// Labels (TLS 1.3 / DTLS 1.3 — Wireshark aynı parser'ı kullanır):
//   CLIENT_HANDSHAKE_TRAFFIC_SECRET
//   SERVER_HANDSHAKE_TRAFFIC_SECRET
//   CLIENT_TRAFFIC_SECRET_0
//   SERVER_TRAFFIC_SECRET_0
//   EXPORTER_SECRET
//
// Ref: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
//
// Kullanım:
//   const { attachKeyLog } = require('./src/session/keylog');
//   attachKeyLog(session, process.env.SSLKEYLOGFILE);
//
// Wireshark'ta: Edit → Preferences → Protocols → TLS →
//   (Pre)-Master-Secret log filename = <dosya yolu>
//
// Sonuç: DTLS 1.3 datagram'ları decrypt edilmiş halde görünür.

const fs = require('node:fs');

function attachKeyLog(session, filePath) {
  if (!filePath) return;
  const write = (line) => {
    try { fs.appendFileSync(filePath, line + '\n'); }
    catch (e) { session.emit('log', 'warn', 'keylog write failed', { err: e.message }); }
  };

  // Handshake anahtarları türetildiği anda (SH sonrası) yaz.
  // Session.clientOnSH ve serverOnCH senaryolarının ikisinde de handshakeKeys set edildikten
  // sonra tek bir 'log' event'i ile tetiklemek zor — en temiz yöntem: 'handshake' event
  // tetiklendiğinde app secret'ları, ondan önce de bir polling/hook... ama biz Session'a
  // özel bir 'secrets' event'i eklemeliyiz.
  session.on('secrets', ({ stage, keys, clientRandom }) => {
    if (!clientRandom) return;
    const cr = Buffer.isBuffer(clientRandom) ? clientRandom.toString('hex') : clientRandom;
    if (stage === 'handshake') {
      write(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${cr} ${keys.clientHandshakeSecret.toString('hex')}`);
      write(`SERVER_HANDSHAKE_TRAFFIC_SECRET ${cr} ${keys.serverHandshakeSecret.toString('hex')}`);
    } else if (stage === 'application') {
      write(`CLIENT_TRAFFIC_SECRET_0 ${cr} ${keys.clientApplication.trafficSecret.toString('hex')}`);
      write(`SERVER_TRAFFIC_SECRET_0 ${cr} ${keys.serverApplication.trafficSecret.toString('hex')}`);
      if (keys.exporterSecret) {
        write(`EXPORTER_SECRET ${cr} ${keys.exporterSecret.toString('hex')}`);
      }
    }
  });
}

module.exports = { attachKeyLog };
