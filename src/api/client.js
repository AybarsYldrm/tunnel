'use strict';
// İstemci tarafı — dtls.connect()
//
//   const sock = await dtls.connect({
//     host: 'example.com', port: 4444, servername: 'example.com',
//     ca, cert, key,            // mTLS
//   });
//   sock.on('data', (buf) => ...);
//   await sock.send(Buffer.from('merhaba'));

const { UdpEndpoint } = require('../transport/udp.js');
const { Session } = require('../session/session.js');
const { attachKeyLog } = require('../session/keylog.js');
const { normalizeOptions } = require('../options.js');

/**
 * Handshake tamamlanana kadar bekleyen bağlantı kurucu.
 * @param {object} rawOptions
 * @returns {Promise<Session>}
 */
function connect(rawOptions = {}) {
  const host = rawOptions.host || rawOptions.address || '127.0.0.1';
  const port = Number(rawOptions.port);
  if (!Number.isInteger(port) || port <= 0) throw new Error('geçerli bir port gerekli');

  const options = normalizeOptions('client', {
    // SNI verilmemişse hostname'i kullan (IP ise gönderme — RFC 6066 yasaklar).
    servername: rawOptions.servername ?? rawOptions.sni ?? (isHostname(host) ? host : null),
    ...rawOptions,
  });

  return new Promise((resolve, reject) => {
    const transport = new UdpEndpoint({
      logComponent: 'dtls:udp',
      type: host.includes(':') ? 'udp6' : 'udp4',
      recvBufferSize: options.recvBufferSize || (1 << 20),
      sendBufferSize: options.sendBufferSize || 0,
    });

    let settled = false;
    const finish = (err, session) => {
      if (settled) return;
      settled = true;
      if (err) {
        transport.close().catch(() => {});
        reject(err);
      } else {
        resolve(session);
      }
    };

    transport.bind(rawOptions.localPort || 0, rawOptions.localAddress || (host.includes(':') ? '::' : '0.0.0.0'))
      .then(() => {
        const session = new Session({
          role: 'client', transport, peer: { address: host, port }, options,
        });
        // Soket oturuma ait: oturum kapanınca UDP soketi de kapansın.
        session.once('close', () => { transport.close().catch(() => {}); });

        if (options.keylogFile) attachKeyLog(session, options.keylogFile);
        if (rawOptions.onLog) session.on('log', rawOptions.onLog);

        transport.on('datagram', (dg, rinfo) => session.handleDatagram(dg, rinfo));
        transport.on('error', (e) => { session.destroy(e); finish(e); });

        session.once('connect', () => finish(null, session));
        session.once('error', (e) => finish(e));

        return session.start().catch((e) => { session.destroy(e); finish(e); });
      })
      .catch(finish);
  });
}

function isHostname(h) {
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(h) && !h.includes(':');
}

module.exports = { connect };
