'use strict';
// Uçuş (flight) yeniden gönderimi — RFC 9147 §5.8 / RFC 6347 §4.2.4.
// Handshake uçuşlarının kaybı simüle edilir; bağlantı kurtarılmalıdır.

const assert = require('node:assert/strict');
const { Runner, loadCerts, once, sleep, dtls } = require('./helpers.js');

const c = loadCerts();
const SRV = { cert: c.serverCert, key: c.serverKey, ca: c.ca };
const CLI = { ca: c.ca, servername: 'localhost' };

const r = new Runner('yeniden gönderim');

/**
 * Sunucu ile istemci arasına kayıp enjekte edilebilen bir aktarım kurar.
 * `dropRule(direction, count)` true dönerse paket düşürülür.
 */
async function lossyPair(versionOpts, dropRule) {
  const server = dtls.createServer({ ...SRV, ...versionOpts });
  const errors = [];
  server.on('sessionError', (e) => errors.push(e));

  let serverSocket = null;
  const connected = new Promise((res) => server.on('secureConnection', (s) => {
    serverSocket = s;
    s.on('data', (b) => s.send(Buffer.concat([Buffer.from('echo:'), b])).catch(() => {}));
    res(s);
  }));

  // Sunucu tarafı çıkışına kayıp enjekte et
  let srvOut = 0;
  server.on('connection', (s) => {
    const orig = s._sendRaw.bind(s);
    s._sendRaw = (buf) => (dropRule('server', srvOut++) ? Promise.resolve(0) : orig(buf));
  });

  const addr = await server.listen(0, '127.0.0.1');
  const clientPromise = dtls.connect({
    host: '127.0.0.1', port: addr.port, handshakeTimeout: 15_000, ...CLI, ...versionOpts,
  });

  return { server, clientPromise, connected, errors, getServerSocket: () => serverSocket };
}

(async () => {
  for (const [label, versionOpts] of [
    ['DTLSv1.3', { minVersion: 'DTLSv1.3', maxVersion: 'DTLSv1.3' }],
    ['DTLSv1.2', { minVersion: 'DTLSv1.2', maxVersion: 'DTLSv1.2' }],
  ]) {
    await r.test(`[${label}] sunucu uçuşunun ilk datagramı kaybolursa kurtarılır`, async () => {
      // Sunucunun 2. çıkış datagramını düşür (1. = cookie/HVR uçuşu)
      const { server, clientPromise } = await lossyPair(versionOpts, (dir, n) => dir === 'server' && n === 1);
      const client = await clientPromise;
      const got = once(client, 'data', 10_000);
      await client.send(Buffer.from('kurtarildi'));
      assert.equal((await got).toString(), 'echo:kurtarildi');
      await client.close();
      await server.close();
    });

    await r.test(`[${label}] arka arkaya iki kayıp da kurtarılır`, async () => {
      const { server, clientPromise } = await lossyPair(
        versionOpts, (dir, n) => dir === 'server' && (n === 1 || n === 2));
      const client = await clientPromise;
      const got = once(client, 'data', 10_000);
      await client.send(Buffer.from('iki-kayip'));
      assert.equal((await got).toString(), 'echo:iki-kayip');
      await client.close();
      await server.close();
    });

    await r.test(`[${label}] istemci uçuşu kaybolursa sunucu tekrar ister`, async () => {
      const server = dtls.createServer({ ...SRV, ...versionOpts });
      server.on('secureConnection', (s) => s.on('data', (b) => s.send(b).catch(() => {})));
      const addr = await server.listen(0, '127.0.0.1');

      // İstemcinin ilk ClientHello'sunu düşür
      const { UdpEndpoint } = require('../src/transport/udp.js');
      const { Session } = require('../src/session/session.js');
      const { normalizeOptions } = require('../src/options.js');

      const ep = new UdpEndpoint({ logComponent: 'test' });
      await ep.bind(0, '127.0.0.1');
      const session = new Session({
        role: 'client', transport: ep, peer: { address: '127.0.0.1', port: addr.port },
        options: normalizeOptions('client', { ...CLI, ...versionOpts, handshakeTimeout: 15_000 }),
      });
      let n = 0;
      const orig = session._sendRaw.bind(session);
      session._sendRaw = (buf) => (n++ === 0 ? Promise.resolve(0) : orig(buf));

      ep.on('datagram', (dg, rinfo) => session.handleDatagram(dg, rinfo));
      session.startHandshakeTimer();
      const connected = once(session, 'connect', 12_000);
      await session.start();
      await connected;

      const got = once(session, 'data', 10_000);
      await session.send(Buffer.from('ch-kayboldu'));
      assert.equal((await got).toString(), 'ch-kayboldu');
      await session.close();
      await server.close();
    });
  }

  await r.test('yinelenen ClientHello son uçuşu tekrarlatır', async () => {
    const server = dtls.createServer(SRV);
    let retransmits = 0;
    server.on('connection', (s) => {
      const orig = s.retransmitNow.bind(s);
      s.retransmitNow = () => { retransmits++; return orig(); };
    });
    server.on('secureConnection', (s) => s.on('data', (b) => s.send(b).catch(() => {})));
    const addr = await server.listen(0, '127.0.0.1');

    const client = await dtls.connect({ host: '127.0.0.1', port: addr.port, ...CLI });
    // Handshake bittikten sonra ilk ClientHello'yu tekrar yolla
    await client._sendRaw(require('../src/record/plaintext.js').encodePlaintext({
      type: 22, epoch: 0, sequenceNumber: 99, fragment: client.ch1Wire,
    }));
    await sleep(150);
    assert.ok(retransmits > 0, 'sunucu son uçuşu tekrar göndermeliydi');
    await client.close();
    await server.close();
  });

  await r.test('yeniden gönderim sınırı aşılırsa oturum düşer', async () => {
    const server = dtls.createServer(SRV);
    // Sunucunun TÜM çıkışını (ilk cookie uçuşu hariç) engelle
    server.on('connection', (s) => {
      let n = 0;
      const orig = s._sendRaw.bind(s);
      s._sendRaw = (buf) => (n++ >= 1 ? Promise.resolve(0) : orig(buf));
    });
    const addr = await server.listen(0, '127.0.0.1');
    await assert.rejects(
      dtls.connect({ host: '127.0.0.1', port: addr.port, handshakeTimeout: 2500, ...CLI }),
      /zaman aşımı/);
    await server.close();
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
