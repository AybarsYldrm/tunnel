'use strict';
// Uçtan uca testler — HER İKİ DTLS SÜRÜMÜ TEK DOSYADA.
//
//   BÖLÜM 1: DTLS 1.3 — handshake, uygulama verisi, KeyUpdate,
//            HelloRetryRequest, ALPN, SNI, exporter, kapanış
//   BÖLÜM 2: DTLS 1.2 — HelloVerifyRequest, ECDHE, Extended Master Secret,
//            ChangeCipherSpec, ALPN/SNI, exporter
//   BÖLÜM 3: Sürüm müzakeresi — iki sürüm arasındaki geçiş ve düşüş kuralları
//
// Bölüm 3, iki bölümün ayrı dosyalarda durmasının neden yanlış olduğunun
// kanıtı: "iki taraf da esnekse 1.3 seçilir", "sunucu yalnızca 1.2
// destekliyorsa 1.2'ye düşülür" gibi testler tanım gereği İKİ SÜRÜMÜ BİRDEN
// ilgilendirir ve hangi dosyaya ait oldukları belirsizdi.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Runner, loadCerts, pair, once, sleep, dtls } = require('./helpers.js');

const c = loadCerts();

const V13 = { minVersion: 'DTLSv1.3', maxVersion: 'DTLSv1.3' };
const SRV = { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...V13 };
const CLI = { ca: c.ca, servername: 'localhost', ...V13 };

const V12 = { minVersion: 'DTLSv1.2', maxVersion: 'DTLSv1.2' };
const SRV12 = { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...V12 };
const CLI12 = { ca: c.ca, servername: 'localhost', ...V12 };

const r = new Runner('uçtan uca (DTLS 1.3 + 1.2)');

(async () => {
  // ==========================================================================
  // BÖLÜM 1 — DTLS 1.3
  // ==========================================================================

  await r.test('[1.3] handshake kurulur ve parametreler doğru', async () => {
    const p = await pair(SRV, CLI);
    const s = await p.waitConnected();
    assert.equal(p.client.protocol, 'DTLSv1.3');
    assert.equal(s.protocol, 'DTLSv1.3');
    assert.equal(p.client.cipher, 'TLS_AES_128_GCM_SHA256');
    assert.equal(p.client.authorized, true);
    assert.equal(p.client.authorizationError, null);
    assert.equal(s.servername, 'localhost');
    assert.equal(p.client.getPeerCertificate().subject.includes('localhost'), true);
    await p.close();
  });

  await r.test('[1.3] uygulama verisi gidiş-dönüş', async () => {
    const p = await pair(SRV, CLI);
    await p.waitConnected();
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('merhaba'));
    assert.equal((await got).toString(), 'echo:merhaba');
    await p.close();
  });

  await r.test('[1.3] büyük veri tek kayıtta taşınır', async () => {
    const p = await pair(SRV, CLI, { echo: false });
    const s = await p.waitConnected();
    const payload = crypto.randomBytes(8000);
    const got = once(s, 'data');
    await p.client.send(payload);
    assert.deepEqual(await got, payload);
    await p.close();
  });

  await r.test('[1.3] çok sayıda ardışık mesaj sırayla ulaşır', async () => {
    const p = await pair(SRV, CLI, { echo: false });
    const s = await p.waitConnected();
    const seen = [];
    s.on('data', (b) => seen.push(b.toString()));
    for (let i = 0; i < 50; i++) await p.client.send(Buffer.from(`m${i}`));
    await sleep(150);
    assert.equal(seen.length, 50);
    assert.equal(seen[0], 'm0');
    assert.equal(seen[49], 'm49');
    await p.close();
  });

  await r.test('[1.3] KeyUpdate epoch\'u ilerletir ve veri akmaya devam eder', async () => {
    const p = await pair(SRV, CLI);
    await p.waitConnected();
    assert.equal(p.client.sendEpoch, 3);
    await p.client.requestKeyUpdate(false);
    assert.equal(p.client.sendEpoch, 4);
    await sleep(60);
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('yeni-epoch'));
    assert.equal((await got).toString(), 'echo:yeni-epoch');
    await p.close();
  });

  await r.test('[1.3] karşılıklı KeyUpdate (update_requested)', async () => {
    const p = await pair(SRV, CLI);
    const s = await p.waitConnected();
    await p.client.requestKeyUpdate(true);
    await sleep(120);
    assert.equal(s.sendEpoch, 4, 'sunucu da epoch ilerletmeli');
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('cift-update'));
    assert.equal((await got).toString(), 'echo:cift-update');
    await p.close();
  });

  await r.test('[1.3] HelloRetryRequest (grup uyuşmazlığı) tamamlanır', async () => {
    const p = await pair(
      { ...SRV, groups: ['SECP256R1'] },
      { ...CLI, groups: ['X25519', 'SECP256R1'] });
    await p.waitConnected();
    assert.equal(p.client.chosenGroup, 0x0017, 'P-256 seçilmeli');
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('hrr'));
    assert.equal((await got).toString(), 'echo:hrr');
    await p.close();
  });

  await r.test('[1.3] cookie kapalıyken de handshake tamamlanır', async () => {
    const p = await pair({ ...SRV, cookie: false }, CLI);
    await p.waitConnected();
    assert.equal(p.client.protocol, 'DTLSv1.3');
    await p.close();
  });

  await r.test('[1.3] close_notify karşı tarafı kapatır', async () => {
    const p = await pair(SRV, CLI);
    const s = await p.waitConnected();
    const closed = once(s, 'close');
    await p.client.close();
    await closed;
    assert.equal(s.closed, true);
    await p.server.close();
  });

  await r.test('[1.3] ALPN müzakeresi', async () => {
    const p = await pair({ ...SRV, alpn: ['h3', 'echo'] }, { ...CLI, alpn: ['echo'] });
    const s = await p.waitConnected();
    assert.equal(p.client.alpnProtocol, 'echo');
    assert.equal(s.alpnProtocol, 'echo');
    await p.close();
  });

  await r.test('[1.3] ALPN kesişimi yoksa handshake reddedilir', async () => {
    await assert.rejects(
      pair({ ...SRV, alpn: ['h3'] }, { ...CLI, alpn: ['ftp'] }),
      /ALPN|alert/i);
  });

  await r.test('[1.3] SNI ile sertifika bağlamı seçilir', async () => {
    const p = await pair(
      { ...SRV, contexts: { 'dtls.local': { cert: c.serverCert, key: c.serverKey, ca: c.ca } } },
      { ...CLI, servername: 'dtls.local' });
    const s = await p.waitConnected();
    assert.equal(s.servername, 'dtls.local');
    await p.close();
  });

  await r.test('[1.3] SNICallback ile dinamik sertifika', async () => {
    let asked = null;
    const p = await pair(
      { ...SRV, SNICallback: (name, cb) => { asked = name; cb(null, { cert: c.serverCert, key: c.serverKey, ca: c.ca }); } },
      { ...CLI, servername: 'dtls.local' });
    await p.waitConnected();
    assert.equal(asked, 'dtls.local');
    await p.close();
  });

  await r.test('[1.3] exportKeyingMaterial iki tarafta aynı sonucu verir', async () => {
    const p = await pair(SRV, CLI);
    const s = await p.waitConnected();
    const a = p.client.exportKeyingMaterial('TEST-label', null, 32);
    const b = s.exportKeyingMaterial('TEST-label', null, 32);
    assert.deepEqual(a, b);
    assert.equal(a.length, 32);
    // Farklı etiket farklı anahtar üretmeli
    assert.notDeepEqual(a, p.client.exportKeyingMaterial('OTHER-label', null, 32));
    await p.close();
  });

  await r.test('[1.3] tüm 1.3 cipher suite\'leri çalışır', async () => {
    for (const name of ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384',
                        'TLS_CHACHA20_POLY1305_SHA256']) {
      const p = await pair({ ...SRV, cipherSuites: [name] }, CLI);
      await p.waitConnected();
      assert.equal(p.client.cipher, name);
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('x'));
      assert.equal((await got).toString(), 'echo:x');
      await p.close();
    }
  });

  await r.test('[1.3] küçük MTU handshake\'i parçalar ve yine tamamlanır', async () => {
    const p = await pair(
      { ...SRV, cert: Buffer.concat([c.serverCert, c.ca]), mtu: 320 },
      { ...CLI, mtu: 320 });
    await p.waitConnected();
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('parcali'));
    assert.equal((await got).toString(), 'echo:parcali');
    await p.close();
  });

  await r.test('[1.3] aynı sunucuya birden çok istemci', async () => {
    const server = dtls.createServer(SRV);
    server.on('secureConnection', (s) => s.on('data', (b) => s.send(b)));
    const addr = await server.listen(0, '127.0.0.1');
    const clients = await Promise.all([0, 1, 2, 3, 4].map(() =>
      dtls.connect({ host: '127.0.0.1', port: addr.port, ...CLI })));
    assert.equal(server.sessions.size, 5);
    const replies = await Promise.all(clients.map((cl, i) => {
      const got = once(cl, 'data');
      return cl.send(Buffer.from(`c${i}`)).then(() => got);
    }));
    replies.forEach((b, i) => assert.equal(b.toString(), `c${i}`));
    await Promise.all(clients.map((cl) => cl.close()));
    await server.close();
  });

  // ==========================================================================
  // BÖLÜM 2 / 3 — DTLS 1.2 ve sürüm müzakeresi
  // ==========================================================================

  await r.test('[1.2] handshake kurulur ve parametreler doğru', async () => {
    const p = await pair(SRV12, CLI12);
    const s = await p.waitConnected();
    assert.equal(p.client.protocol, 'DTLSv1.2');
    assert.equal(s.protocol, 'DTLSv1.2');
    assert.equal(p.client.cipher, 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256');
    assert.equal(p.client.authorized, true);
    assert.equal(s.servername, 'localhost');
    await p.close();
  });

  await r.test('[1.2] HelloVerifyRequest cookie takası yapılır', async () => {
    const p = await pair(SRV12, CLI12);
    await p.waitConnected();
    assert.ok(p.client.ch2Wire, 'istemci cookie ile ikinci ClientHello göndermeli');
    await p.close();
  });

  await r.test('[1.2] cookie kapalıyken tek turda tamamlanır', async () => {
    const p = await pair({ ...SRV12, cookie: false }, CLI12);
    await p.waitConnected();
    assert.equal(p.client.ch2Wire, undefined, 'HelloVerifyRequest olmamalı');
    await p.close();
  });

  await r.test('[1.2] Extended Master Secret (RFC 7627) müzakere edilir', async () => {
    const p = await pair(SRV12, CLI12);
    const s = await p.waitConnected();
    assert.equal(p.client.useEms, true);
    assert.equal(s.useEms, true);
    await p.close();
  });

  await r.test('[1.2] EMS kapatılabilir ve handshake yine çalışır', async () => {
    const p = await pair({ ...SRV12, extendedMasterSecret: false }, CLI12);
    const s = await p.waitConnected();
    assert.equal(s.useEms, false);
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('no-ems'));
    assert.equal((await got).toString(), 'echo:no-ems');
    await p.close();
  });

  await r.test('[1.2] iki taraf aynı master secret\'ı türetir', async () => {
    const p = await pair(SRV12, CLI12);
    const s = await p.waitConnected();
    assert.deepEqual(p.client.masterSecret, s.masterSecret);
    assert.equal(p.client.masterSecret.length, 48);
    await p.close();
  });

  await r.test('[1.2] epoch 1\'e geçiş (ChangeCipherSpec)', async () => {
    const p = await pair(SRV12, CLI12);
    const s = await p.waitConnected();
    assert.equal(p.client.sendEpoch, 1);
    assert.equal(p.client.recvCipherActive, true);
    assert.equal(s.sendEpoch, 1);
    assert.equal(s.recvCipherActive, true);
    await p.close();
  });

  await r.test('[1.2] uygulama verisi gidiş-dönüş', async () => {
    const p = await pair(SRV12, CLI12);
    await p.waitConnected();
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('merhaba 1.2'));
    assert.equal((await got).toString(), 'echo:merhaba 1.2');
    await p.close();
  });

  await r.test('[1.2] büyük veri ve ardışık mesajlar', async () => {
    const p = await pair(SRV12, CLI12, { echo: false });
    const s = await p.waitConnected();
    const seen = [];
    s.on('data', (b) => seen.push(b));
    const big = crypto.randomBytes(6000);
    await p.client.send(big);
    for (let i = 0; i < 20; i++) await p.client.send(Buffer.from(`m${i}`));
    await sleep(150);
    assert.deepEqual(seen[0], big);
    assert.equal(seen.length, 21);
    await p.close();
  });

  await r.test('[1.2] tüm 1.2 ECDSA cipher suite\'leri çalışır', async () => {
    for (const name of ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256']) {
      const p = await pair({ ...SRV12, cipherSuites: [name] }, CLI12);
      await p.waitConnected();
      assert.equal(p.client.cipher, name);
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('x'));
      assert.equal((await got).toString(), 'echo:x');
      await p.close();
    }
  });

  await r.test('[1.2] her iki named group ile çalışır', async () => {
    for (const g of ['X25519', 'SECP256R1']) {
      const p = await pair({ ...SRV12, groups: [g] }, { ...CLI12, groups: [g] });
      await p.waitConnected();
      await p.close();
    }
  });

  await r.test('[1.2] küçük MTU handshake\'i parçalar', async () => {
    const p = await pair(
      { ...SRV12, cert: Buffer.concat([c.serverCert, c.ca]), mtu: 340 },
      { ...CLI12, mtu: 340 });
    await p.waitConnected();
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('parcali12'));
    assert.equal((await got).toString(), 'echo:parcali12');
    await p.close();
  });

  await r.test('[1.2] close_notify karşı tarafı kapatır', async () => {
    const p = await pair(SRV12, CLI12);
    const s = await p.waitConnected();
    const closed = once(s, 'close');
    await p.client.close();
    await closed;
    await p.server.close();
  });

  // ======================================================================
  // Sürüm müzakeresi
  // ======================================================================
  const BOTH = { minVersion: 'DTLSv1.2', maxVersion: 'DTLSv1.3' };

  await r.test('[1.2] iki taraf da esnekse DTLS 1.3 seçilir', async () => {
    const p = await pair(
      { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...BOTH },
      { ca: c.ca, servername: 'localhost', ...BOTH });
    assert.equal(p.client.protocol, 'DTLSv1.3');
    await p.close();
  });

  await r.test('[1.2] sunucu yalnızca 1.2 destekliyorsa 1.2\'ye düşülür', async () => {
    const p = await pair(
      { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...V12 },
      { ca: c.ca, servername: 'localhost', ...BOTH });
    assert.equal(p.client.protocol, 'DTLSv1.2');
    const got = once(p.client, 'data');
    await p.client.send(Buffer.from('downgrade'));
    assert.equal((await got).toString(), 'echo:downgrade');
    await p.close();
  });

  await r.test('[1.2] istemci yalnızca 1.2 destekliyorsa 1.2 seçilir', async () => {
    const p = await pair(
      { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...BOTH },
      { ca: c.ca, servername: 'localhost', ...V12 });
    assert.equal(p.client.protocol, 'DTLSv1.2');
    await p.close();
  });

  await r.test('[1.2] ortak sürüm yoksa handshake başarısız', async () => {
    await assert.rejects(pair(
      { cert: c.serverCert, key: c.serverKey, ca: c.ca, minVersion: 'DTLSv1.3', maxVersion: 'DTLSv1.3' },
      { ca: c.ca, servername: 'localhost', ...V12 }));
  });

  await r.test('[1.2] ALPN ve SNI DTLS 1.2\'de de çalışır', async () => {
    const p = await pair(
      { ...SRV12, alpn: ['h3', 'echo'],
        contexts: { 'dtls.local': { cert: c.serverCert, key: c.serverKey, ca: c.ca } } },
      { ...CLI12, alpn: ['echo'], servername: 'dtls.local' });
    const s = await p.waitConnected();
    assert.equal(p.client.alpnProtocol, 'echo');
    assert.equal(s.servername, 'dtls.local');
    await p.close();
  });

  await r.test('[1.2] exportKeyingMaterial (RFC 5705) iki tarafta aynı', async () => {
    const p = await pair(SRV12, CLI12);
    const s = await p.waitConnected();
    const a = p.client.exportKeyingMaterial('TEST-label', null, 32);
    assert.deepEqual(a, s.exportKeyingMaterial('TEST-label', null, 32));
    assert.notDeepEqual(a, p.client.exportKeyingMaterial('TEST-label', Buffer.from('ctx'), 32));
    await p.close();
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
