'use strict';
// Dayanıklılık ve saldırı yüzeyi testleri — bozuk girdi, replay, kaynak sınırları.
// Ölçüt: sunucu HİÇBİR durumda çökmez ve sağlıklı istemciler etkilenmez.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const { Runner, loadCerts, pair, once, sleep, dtls } = require('./helpers.js');

const c = loadCerts();
const SRV = { cert: c.serverCert, key: c.serverKey, ca: c.ca };
const CLI = { ca: c.ca, servername: 'localhost' };

const r = new Runner('dayanıklılık');

/** Ham UDP paketi gönderen yardımcı. */
function rawSend(port, buf) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    s.send(buf, port, '127.0.0.1', (err) => { s.close(); err ? reject(err) : resolve(); });
  });
}

async function withServer(opts, fn) {
  const server = dtls.createServer({ ...SRV, ...opts });
  const errors = [];
  server.on('sessionError', (e) => errors.push(e));
  server.on('error', (e) => errors.push(e));
  server.on('secureConnection', (s) => s.on('data', (b) => s.send(b).catch(() => {})));
  const addr = await server.listen(0, '127.0.0.1');
  try { return await fn(server, addr, errors); }
  finally { await server.close(); }
}

/** Sunucunun hâlâ sağlıklı handshake yapabildiğini kanıtlar. */
async function assertStillHealthy(port) {
  const cl = await dtls.connect({ host: '127.0.0.1', port, ...CLI });
  const got = once(cl, 'data');
  await cl.send(Buffer.from('saglik'));
  assert.equal((await got).toString(), 'saglik');
  await cl.close();
}

(async () => {
  await r.test('rastgele çöp datagramlar sunucuyu düşürmez', async () => {
    await withServer({}, async (server, addr) => {
      for (let i = 0; i < 200; i++) {
        await rawSend(addr.port, crypto.randomBytes(1 + Math.floor(Math.random() * 300)));
      }
      await sleep(80);
      await assertStillHealthy(addr.port);
    });
  });

  await r.test('boş ve tek baytlık datagramlar yoksayılır', async () => {
    await withServer({}, async (server, addr) => {
      await rawSend(addr.port, Buffer.alloc(0));
      for (let b = 0; b < 256; b++) await rawSend(addr.port, Buffer.from([b]));
      await sleep(80);
      await assertStillHealthy(addr.port);
    });
  });

  await r.test('geçersiz uzunluk alanlı kayıtlar reddedilir', async () => {
    await withServer({}, async (server, addr) => {
      // type=22, version, epoch=0, seq, length=0xFFFF ama gövde yok
      const bad = Buffer.alloc(13);
      bad[0] = 22; bad.writeUInt16BE(0xfefd, 1); bad.writeUInt16BE(0xffff, 11);
      for (let i = 0; i < 50; i++) await rawSend(addr.port, bad);
      await sleep(80);
      await assertStillHealthy(addr.port);
    });
  });

  await r.test('bozuk ClientHello gövdeleri oturumu düşürür ama sunucuyu değil', async () => {
    await withServer({}, async (server, addr) => {
      for (let i = 0; i < 30; i++) {
        const body = crypto.randomBytes(60);
        const hs = Buffer.alloc(12 + body.length);
        hs[0] = 1;                                   // ClientHello
        hs.writeUIntBE(body.length, 1, 3);
        hs.writeUIntBE(body.length, 9, 3);
        body.copy(hs, 12);
        const rec = Buffer.alloc(13 + hs.length);
        rec[0] = 22; rec.writeUInt16BE(0xfefd, 1);
        rec.writeUInt16BE(hs.length, 11);
        hs.copy(rec, 13);
        await rawSend(addr.port, rec);
      }
      await sleep(120);
      await assertStillHealthy(addr.port);
    });
  });

  await r.test('DTLS 1.0-only istemci reddedilir, sunucu ayakta kalır', async () => {
    await withServer({ minVersion: 'DTLSv1.2' }, async (server, addr) => {
      // legacy_version = DTLS 1.0, supported_versions yok
      const body = Buffer.concat([
        Buffer.from([0xfe, 0xff]), crypto.randomBytes(32),
        Buffer.from([0x00, 0x00]),               // session_id, cookie boş
        Buffer.from([0x00, 0x02, 0x00, 0x2f]),   // eski bir suite
        Buffer.from([0x01, 0x00]),               // compression
        Buffer.from([0x00, 0x00]),               // uzantı yok
      ]);
      const hs = Buffer.alloc(12 + body.length);
      hs[0] = 1; hs.writeUIntBE(body.length, 1, 3); hs.writeUIntBE(body.length, 9, 3);
      body.copy(hs, 12);
      const rec = Buffer.alloc(13 + hs.length);
      rec[0] = 22; rec.writeUInt16BE(0xfefd, 1); rec.writeUInt16BE(hs.length, 11);
      hs.copy(rec, 13);
      await rawSend(addr.port, rec);
      await sleep(120);
      await assertStillHealthy(addr.port);
    });
  });

  await r.test('replay edilen şifreli kayıt iki kez teslim edilmez', async () => {
    const p = await pair(SRV, CLI, { echo: false });
    const s = await p.waitConnected();
    let count = 0;
    s.on('data', () => count++);

    // Gönderilen kaydı yakala ve aynısını tekrar yolla
    let captured = null;
    const orig = p.client._sendRaw.bind(p.client);
    p.client._sendRaw = (buf) => { captured = buf; return orig(buf); };
    await p.client.send(Buffer.from('bir-kere'));
    await sleep(60);
    await orig(captured);
    await sleep(80);
    assert.equal(count, 1, 'replay reddedilmeliydi');
    await p.close();
  });

  await r.test('bit bozulmuş şifreli kayıt sessizce düşer, oturum yaşar', async () => {
    const p = await pair(SRV, CLI, { echo: false });
    const s = await p.waitConnected();
    const seen = [];
    s.on('data', (b) => seen.push(b.toString()));

    const orig = p.client._sendRaw.bind(p.client);
    p.client._sendRaw = (buf) => {
      const bad = Buffer.from(buf);
      bad[bad.length - 1] ^= 0xff;
      return orig(bad);
    };
    await p.client.send(Buffer.from('bozuk'));
    await sleep(80);
    p.client._sendRaw = orig;
    await p.client.send(Buffer.from('saglam'));
    await sleep(80);

    assert.deepEqual(seen, ['saglam']);
    assert.equal(s.closed, false);
    await p.close();
  });

  await r.test('hız sınırlayıcı aşırı ClientHello selini keser', async () => {
    await withServer({ rateLimitBurst: 5, rateLimitPerSec: 1 }, async (server, addr) => {
      // Aynı kaynak porttan çok sayıda ClientHello benzeri paket
      const sock = dgram.createSocket('udp4');
      await new Promise((res) => sock.bind(0, '127.0.0.1', res));
      const rec = Buffer.alloc(13 + 12 + 40);
      rec[0] = 22; rec.writeUInt16BE(0xfefd, 1); rec.writeUInt16BE(12 + 40, 11);
      rec[13] = 1; rec.writeUIntBE(40, 14, 3); rec.writeUIntBE(40, 22, 3);
      for (let i = 0; i < 40; i++) {
        await new Promise((res) => sock.send(rec, addr.port, '127.0.0.1', res));
      }
      await sleep(120);
      sock.close();
      assert.ok(server.stats.rateLimited > 0, 'hız sınırı devreye girmeliydi');
      await assertStillHealthy(addr.port);
    });
  });

  await r.test('maxSessions sınırı uygulanır', async () => {
    await withServer({ maxSessions: 2 }, async (server, addr) => {
      const clients = [];
      for (let i = 0; i < 2; i++) {
        clients.push(await dtls.connect({ host: '127.0.0.1', port: addr.port, ...CLI }));
      }
      assert.equal(server.sessions.size, 2);
      await assert.rejects(
        dtls.connect({ host: '127.0.0.1', port: addr.port, handshakeTimeout: 1500, ...CLI }),
        /zaman aşımı/);
      assert.ok(server.stats.rejected > 0);
      await Promise.all(clients.map((cl) => cl.close()));
    });
  });

  await r.test('handshake zaman aşımı oturumu temizler', async () => {
    await withServer({ handshakeTimeout: 800 }, async (server, addr) => {
      // ClientHello gönder ama devam etme
      const sock = dgram.createSocket('udp4');
      await new Promise((res) => sock.bind(0, '127.0.0.1', res));
      const rec = Buffer.alloc(13 + 12 + 40);
      rec[0] = 22; rec.writeUInt16BE(0xfefd, 1); rec.writeUInt16BE(12 + 40, 11);
      rec[13] = 1; rec.writeUIntBE(40, 14, 3); rec.writeUIntBE(40, 22, 3);
      await new Promise((res) => sock.send(rec, addr.port, '127.0.0.1', res));
      await sleep(200);
      await sleep(900);
      sock.close();
      assert.equal(server.sessions.size, 0, 'zaman aşımına uğrayan oturum temizlenmeli');
    });
  });

  await r.test('bir oturumun hatası diğerlerini etkilemez', async () => {
    await withServer({}, async (server, addr) => {
      const good = await dtls.connect({ host: '127.0.0.1', port: addr.port, ...CLI });
      // Kötü niyetli ikinci kaynak
      for (let i = 0; i < 40; i++) await rawSend(addr.port, crypto.randomBytes(200));
      await sleep(100);
      const got = once(good, 'data');
      await good.send(Buffer.from('hala-buradayim'));
      assert.equal((await got).toString(), 'hala-buradayim');
      await good.close();
    });
  });

  await r.test('DTLS dışı paketler "unhandled" olayına yönlenir', async () => {
    await withServer({}, async (server, addr) => {
      const seen = [];
      server.on('unhandled', (dg) => seen.push(dg));
      await rawSend(addr.port, Buffer.from([0x00, 0x01, 0x00, 0x00])); // STUN benzeri
      await sleep(80);
      assert.equal(seen.length, 1);
      assert.equal(seen[0][0], 0x00);
    });
  });

  await r.test('sunucu kapanınca tüm oturumlar temizlenir', async () => {
    const server = dtls.createServer(SRV);
    const addr = await server.listen(0, '127.0.0.1');
    const cl = await dtls.connect({ host: '127.0.0.1', port: addr.port, ...CLI });
    const srvSock = [...server.sessions.values()][0];
    await server.close();
    assert.equal(server.sessions.size, 0);
    assert.equal(srvSock.closed, true);
    await cl.close().catch(() => {});
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
