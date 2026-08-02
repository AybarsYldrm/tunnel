'use strict';
// Tünelin uçtan uca testi — GERÇEK DTLS, gerçek mTLS, gerçek TCP/UDP soketleri.
//
// Sahte bir taşıma katmanı kullanılmıyor. Bu tünelin çözdüğü sorunların çoğu
// (baş tıkanması, geri basınç, port yaşam döngüsü) yalnızca gerçek soketler
// ve gerçek zamanlama altında ortaya çıkar; bellek-içi bir kanal üzerinde
// hepsi "çalışıyor" görünürdü.

const assert = require('node:assert');
const net = require('node:net');
const dgram = require('node:dgram');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { Runner } = require('../../tests/helpers.js');
const { TunnelServer } = require('../src/server/index.js');
const { TunnelClient } = require('../src/client/index.js');
const { loadServerConfig } = require('../src/server/config.js');
const { PROTO, DELIVERY } = require('../src/protocol/constants.js');

const CERTS = path.join(__dirname, '..', '..', 'certs');
const read = (f) => fs.readFileSync(path.join(CERTS, f), 'utf8');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Bir koşulun gerçekleşmesini bekler — sabit `sleep`'ten hem hızlı hem sağlam. */
async function waitFor(fn, { timeoutMs = 8000, stepMs = 25, what = 'koşul' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`zaman aşımı: ${what}`);
    await sleep(stepMs);
  }
}

// ---------------------------------------------------------------------------
// Test altyapısı
// ---------------------------------------------------------------------------

/** İstemcinin yerel ağındaki "asıl servis": gelen baytları büyük harfe çevirir. */
function startOriginTcp({ onConnection } = {}) {
  return new Promise((resolve) => {
    const conns = new Set();
    const server = net.createServer((socket) => {
      conns.add(socket);
      socket.on('close', () => conns.delete(socket));
      socket.on('error', () => {});
      if (onConnection) onConnection(socket);
      else socket.on('data', (chunk) => socket.write(chunk.toString().toUpperCase()));
    });
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      port: server.address().port,
      conns,
      close: () => new Promise((r) => { for (const c of conns) c.destroy(); server.close(r); }),
    }));
  });
}

function startOriginUdp() {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    socket.on('message', (msg, rinfo) => {
      socket.send(Buffer.concat([Buffer.from('echo:'), msg]), rinfo.port, rinfo.address);
    });
    socket.bind(0, '127.0.0.1', () => resolve({
      socket,
      port: socket.address().port,
      close: () => new Promise((r) => socket.close(r)),
    }));
  });
}

async function startStack({ serverOverrides = {}, clientOverrides = {} } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitfak-tunnel-test-'));

  const config = loadServerConfig({
    host: '127.0.0.1',
    port: 0,
    publicHost: '127.0.0.1',
    publicHostname: 'test.local',
    certPath: path.join(CERTS, 'server.crt'),
    keyPath: path.join(CERTS, 'server.key'),
    caPath: path.join(CERTS, 'ca.crt'),
    revocation: 'off',            // test PKI'sında OCSP/CRL sunucusu yok
    portMin: 41000,
    portMax: 41999,
    portLingerMs: 400,
    dataDir,
    allowClientBinds: true,
    allowClientPortChoice: true,
    metricsIntervalMs: 3_600_000, // testte ölçüm yazmayalım
    admin: { enabled: false },
    db: { target: null, identityDir: path.join(dataDir, 'identity') },
    ...serverOverrides,
  });

  const server = new TunnelServer(config);
  const addr = await server.start();

  const client = new TunnelClient({
    host: '127.0.0.1',
    port: addr.port,
    servername: 'localhost',
    caPem: read('ca.crt'),
    identity: { certPem: read('client.crt'), privateKeyPem: read('client.key') },
    revocation: 'off',
    reconnect: false,
    name: 'test-client',
    ...clientOverrides,
  });

  await client.start();
  await waitFor(() => client.connected, { what: 'istemci hazır' });
  const tunnel = await waitFor(
    () => [...server.tunnels.values()].find((t) => t.ready),
    { what: 'sunucu tarafı tünel hazır' },
  );

  return {
    server,
    client,
    tunnel,
    addr,
    dataDir,
    async close() {
      await client.stop().catch(() => {});
      await server.stop().catch(() => {});
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** Genel porta bağlanıp yaz-oku yapan küçük yardımcı. */
function tcpRequest(port, payload, { expectBytes = 0, timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    const socket = net.connect({ host: '127.0.0.1', port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('tcpRequest zaman aşımı')); }, timeoutMs);

    socket.on('connect', () => socket.write(payload));
    socket.on('data', (c) => {
      chunks.push(c);
      total += c.length;
      if (expectBytes && total >= expectBytes) { clearTimeout(timer); socket.end(); resolve(Buffer.concat(chunks)); }
    });
    socket.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    socket.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

// ---------------------------------------------------------------------------
(async () => {
  const r = new Runner('tünel — uçtan uca (DTLS 1.3 + mTLS)');

  // =========================================================================
  await r.test('el sıkışma: istemci sertifikasıyla tanınır, kimlik sertifikadan gelir', async () => {
    const s = await startStack();
    try {
      assert.strictEqual(s.tunnel.state, 'ready');
      assert.ok(s.tunnel.socket.authorized, 'mTLS doğrulanmış olmalı');
      assert.match(s.tunnel.identity.commonName, /dtls-client/);
      assert.strictEqual(s.tunnel.identity.fingerprint256.length, 64);
      // İstemcinin BİLDİRDİĞİ ad görüntü içindir; kimlik değil.
      assert.strictEqual(s.tunnel.clientInfo.name, 'test-client');
      assert.notStrictEqual(s.tunnel.clientId, 'test-client');
      assert.strictEqual(s.tunnel.socket.protocol, 'DTLSv1.3');
    } finally { await s.close(); }
  });

  // =========================================================================
  await r.test('TCP: yerel servis rastgele bir genel porttan yayınlanır ve veri iki yönde akar', async () => {
    const origin = await startOriginTcp();
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'echo',
      });

      assert.ok(bound.publicPort >= 41000 && bound.publicPort <= 41999, 'port havuzdan gelmeli');
      assert.strictEqual(bound.publicHost, 'test.local');

      const reply = await tcpRequest(bound.publicPort, Buffer.from('merhaba dünya'), { expectBytes: 13 });
      assert.strictEqual(reply.toString(), 'MERHABA DÜNYA'.normalize());
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('port havuzu: her uygulama farklı port alır, kapanınca linger sonrası serbest kalır', async () => {
    const origin = await startOriginTcp();
    const s = await startStack();
    try {
      const a = await s.client.requestBind({ proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'a' });
      const b = await s.client.requestBind({ proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'b' });
      assert.notStrictEqual(a.publicPort, b.publicPort, 'iki uygulama aynı portu alamaz');

      const before = s.server.ports.stats();
      assert.strictEqual(before.active, 2);

      await s.client.stop();
      await waitFor(() => s.server.tunnels.size === 0, { what: 'tünel kapandı' });

      // Kopar kopmaz LINGER: port hemen başkasına verilmez, dönen istemci
      // aynı adresi geri alabilsin diye.
      const lingering = s.server.ports.stats();
      assert.strictEqual(lingering.active, 0);
      assert.strictEqual(lingering.linger, 2);

      await waitFor(() => {
        s.server.ports.sweep();
        return s.server.ports.stats().linger === 0;
      }, { what: 'linger süresi doldu' });
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('yerel hedef kapalıysa dış bağlantı reddedilir (asılı kalmaz)', async () => {
    const s = await startStack();
    try {
      // 1 numaralı port kesinlikle dinlenmiyor.
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: 1, name: 'kapali',
      });
      const t0 = Date.now();
      const reply = await tcpRequest(bound.publicPort, Buffer.from('x'), { timeoutMs: 5000 });
      assert.strictEqual(reply.length, 0, 'veri gelmemeli');
      assert.ok(Date.now() - t0 < 4000, 'bağlantı hızlıca düşmeli, OPEN zaman aşımını beklememeli');
    } finally { await s.close(); }
  });

  // =========================================================================
  await r.test('büyük aktarım: 4 MB veri bozulmadan geçer', async () => {
    const SIZE = 4 * 1024 * 1024;
    const payload = Buffer.alloc(SIZE);
    for (let i = 0; i < SIZE; i++) payload[i] = i & 0xff;

    const origin = await startOriginTcp({
      onConnection: (socket) => {
        socket.on('data', () => {});
        socket.write(payload);
        socket.end();
      },
    });
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'bulk',
      });
      const got = await tcpRequest(bound.publicPort, Buffer.from('go'), { timeoutMs: 60_000 });
      assert.strictEqual(got.length, SIZE, `beklenen ${SIZE} bayt, gelen ${got.length}`);
      assert.ok(got.equals(payload), 'baytlar birebir aynı olmalı');
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('adil sıralama: büyük aktarım küçük isteği baştan tıkamaz', async () => {
    // Doğrulanan davranış: 8 MB'lık bir indirme sürerken açılan küçük bir
    // bağlantı, indirme bitene KADAR BEKLEMEZ. Naif bir çoklayıcıda (her
    // mesajı doğrudan kanala vermek) tam tersi olur.
    const BULK = 8 * 1024 * 1024;
    const bulkPayload = Buffer.alloc(BULK, 0x41);

    const origin = await startOriginTcp({
      onConnection: (socket) => {
        socket.once('data', (chunk) => {
          if (chunk[0] === 0x42) { socket.write(bulkPayload); socket.end(); } // 'B' → bulk
          else { socket.write('kucuk-yanit'); socket.end(); }
        });
      },
    });
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'mix',
      });

      let bulkDone = false;
      const bulk = tcpRequest(bound.publicPort, Buffer.from('B'), { timeoutMs: 90_000 })
        .then((b) => { bulkDone = true; return b; });

      // Büyük aktarımın gerçekten akmaya başlaması için kısa bir soluk.
      await sleep(250);

      const t0 = Date.now();
      const small = await tcpRequest(bound.publicPort, Buffer.from('s'), { expectBytes: 11, timeoutMs: 20_000 });
      const elapsed = Date.now() - t0;

      assert.strictEqual(small.toString(), 'kucuk-yanit');
      assert.strictEqual(bulkDone, false, 'küçük istek, büyük aktarım BİTMEDEN yanıtlanmalı');
      assert.ok(elapsed < 5000, `küçük istek ${elapsed}ms sürdü — baş tıkanması var`);

      const bulkResult = await bulk;
      assert.strictEqual(bulkResult.length, BULK);
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('akış denetimi: yavaş alıcıda bellek pencereyle sınırlı kalır', async () => {
    // Dış istemci hiç okumaz. Doğru davranış: pencere dolar, gönderen durur
    // ve tünel süreci sınırsız tampon biriktirmez.
    const HUGE = 32 * 1024 * 1024;
    const origin = await startOriginTcp({
      onConnection: (socket) => {
        socket.on('error', () => {});
        socket.on('data', () => {});
        const chunk = Buffer.alloc(64 * 1024, 0x5a);
        let sent = 0;
        const pump = () => {
          while (sent < HUGE) {
            sent += chunk.length;
            if (!socket.write(chunk)) { socket.once('drain', pump); return; }
          }
          socket.end();
        };
        pump();
      },
    });
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'slow',
      });

      const socket = net.connect({ host: '127.0.0.1', port: bound.publicPort });
      socket.on('error', () => {});
      await new Promise((res) => socket.once('connect', res));
      socket.pause();                       // hiç okumuyoruz
      socket.write(Buffer.from('go'));

      await sleep(2500);

      const snap = s.tunnel.mux.snapshot();
      const limits = s.server.limits;
      // Tünel geneli pencere tavanı + kanalın kendi kuyruğu dışında bir yerde
      // sınırsız birikme OLMAMALI.
      assert.ok(
        snap.outstandingBytes <= limits.connectionWindow,
        `uçuştaki bayt (${snap.outstandingBytes}) tünel penceresini (${limits.connectionWindow}) aşmamalı`,
      );
      assert.ok(snap.connSendWindow >= 0, 'tünel penceresi negatife düşmemeli');
      assert.ok(snap.flowViolations === 0, 'akış denetimi ihlali olmamalı');

      socket.destroy();
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('UDP (kayıp toleranslı): datagramlar tek atım olarak iki yönde gider', async () => {
    const origin = await startOriginUdp();
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.UDP, delivery: DELIVERY.UNRELIABLE,
        localHost: '127.0.0.1', localPort: origin.port, name: 'dns',
      });

      const sock = dgram.createSocket('udp4');
      const replies = [];
      sock.on('message', (m) => replies.push(m.toString()));
      await new Promise((res) => sock.bind(0, '127.0.0.1', res));

      // Tek atım bir kanalda ilk paket kaybolabilir; birkaç deneme yapmak
      // testin kendisini kırılgan olmaktan çıkarır (UDP'nin doğası bu).
      await waitFor(async () => {
        sock.send(Buffer.from('ping'), bound.publicPort, '127.0.0.1');
        await sleep(150);
        return replies.length > 0;
      }, { timeoutMs: 6000, stepMs: 0, what: 'UDP yanıtı' });

      assert.ok(replies.some((x) => x === 'echo:ping'), `beklenen yanıt gelmedi: ${JSON.stringify(replies)}`);
      sock.close();
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('UDP (kayıpsız): aynı yol güvenilir akış üzerinden de çalışır', async () => {
    const origin = await startOriginUdp();
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.UDP, delivery: DELIVERY.RELIABLE,
        localHost: '127.0.0.1', localPort: origin.port, name: 'dns-reliable',
      });
      assert.strictEqual(bound.delivery, DELIVERY.RELIABLE);

      const sock = dgram.createSocket('udp4');
      const replies = [];
      sock.on('message', (m) => replies.push(m.toString()));
      await new Promise((res) => sock.bind(0, '127.0.0.1', res));

      sock.send(Buffer.from('sorgu'), bound.publicPort, '127.0.0.1');
      await waitFor(() => replies.length > 0, { timeoutMs: 8000, what: 'güvenilir UDP yanıtı' });
      assert.strictEqual(replies[0], 'echo:sorgu');
      sock.close();
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('TCP her zaman kayıpsız: kayıplı teslim istense bile düzeltilir', async () => {
    const origin = await startOriginTcp();
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, delivery: DELIVERY.UNRELIABLE,
        localHost: '127.0.0.1', localPort: origin.port, name: 'tcp-lossy-istegi',
      });
      assert.strictEqual(bound.delivery, DELIVERY.RELIABLE,
        'TCP için kayıplı teslim kabul edilmemeli — sessizce bozulma üretirdi');
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('bant genişliği sınırı: uygulama başına hız gerçekten uygulanır', async () => {
    const LIMIT_BPS = 256 * 1024;         // 256 KB/s ≈ 2 Mbit/s
    const SIZE = 512 * 1024;              // ~2 saniyelik yük

    const origin = await startOriginTcp({
      onConnection: (socket) => {
        socket.on('data', () => {});
        socket.write(Buffer.alloc(SIZE, 0x37));
        socket.end();
      },
    });
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'sinirli',
      });
      const app = [...s.tunnel.apps.values()].find((a) => a.name === 'sinirli');
      app.rateOutBps = LIMIT_BPS;
      app.bucketOut.setRate(LIMIT_BPS);

      const t0 = Date.now();
      const got = await tcpRequest(bound.publicPort, Buffer.from('go'), { timeoutMs: 60_000 });
      const elapsed = Date.now() - t0;

      assert.strictEqual(got.length, SIZE);
      const observed = (SIZE / elapsed) * 1000;
      // Kova bir patlama bütçesi taşıdığı için kısa vadede sınırın üstüne
      // çıkabilir; kontrol edilen şey sürekli hızın makul bir üst sınırda
      // kalması.
      assert.ok(observed < LIMIT_BPS * 2.5,
        `gözlenen hız ${Math.round(observed)} B/s, sınır ${LIMIT_BPS} B/s — şekillendirme çalışmıyor`);
      assert.ok(elapsed > 800, `aktarım ${elapsed}ms sürdü — sınır hiç uygulanmamış görünüyor`);
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('koruma: kaynak başına eşzamanlı bağlantı tavanı uygulanır', async () => {
    const origin = await startOriginTcp({ onConnection: (socket) => socket.on('data', () => {}) });
    const s = await startStack({
      serverOverrides: { guard: { maxConnectionsPerIp: 3, acceptPerIpPerSec: 1000 } },
    });
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'limitli',
      });

      const sockets = [];
      for (let i = 0; i < 3; i++) {
        const sock = net.connect({ host: '127.0.0.1', port: bound.publicPort });
        sock.on('error', () => {});
        sockets.push(sock);
        await new Promise((res) => sock.once('connect', res));
      }
      await waitFor(() => s.server.guard.snapshot().connectionsGlobal >= 3, { what: 'üç bağlantı sayıldı' });

      // Dördüncü bağlantı kabul edilir (TCP el sıkışması çekirdekte biter) ama
      // hemen düşürülür: veri hiç akmaz.
      const extra = net.connect({ host: '127.0.0.1', port: bound.publicPort });
      extra.on('error', () => {});
      const closed = await new Promise((res) => {
        extra.once('close', () => res(true));
        setTimeout(() => res(false), 3000);
      });
      assert.ok(closed, 'tavanın üstündeki bağlantı düşürülmeliydi');
      assert.ok(s.server.guard.stats['refused:conn-limit-ip'] >= 1, 'red sebebi sayaca yazılmalı');

      for (const sock of sockets) sock.destroy();
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('koruma: ısrarlı ihlal üstel yasakla sonuçlanır ve sönümlenir', async () => {
    const s = await startStack({
      serverOverrides: { guard: { acceptPerIpPerSec: 2, banAfterViolations: 3, banBaseMs: 300 } },
    });
    try {
      const guard = s.server.guard;
      for (let i = 0; i < 12; i++) guard.checkAccept('203.0.113.7', 'app-1');

      assert.ok(guard.isBanned('203.0.113.7'), 'ısrarlı kaynak yasaklanmalı');
      const bans = guard.listBans();
      assert.strictEqual(bans.length, 1);
      assert.ok(bans[0].remainingMs > 0);

      await waitFor(() => !guard.isBanned('203.0.113.7'), { timeoutMs: 3000, what: 'yasak sönümlendi' });

      // Aynı kaynak yeniden ihlal ederse ceza UZAR (üstel).
      for (let i = 0; i < 12; i++) guard.checkAccept('203.0.113.7', 'app-1');
      const second = guard.listBans()[0];
      assert.strictEqual(second.offences, 2);
      assert.ok(second.remainingMs > 300, 'ikinci yasak ilkinden uzun olmalı');
    } finally { await s.close(); }
  });

  // =========================================================================
  await r.test('koruma: UDP yükseltme oranı, doğrulanmamış kaynağa büyük yanıt vermeyi engeller', async () => {
    const s = await startStack();
    try {
      const guard = s.server.guard;
      const flow = {
        established: false, packetsIn: 1, bytesIn: 50, bytesOut: 0,
      };
      assert.strictEqual(guard.checkUdpOutbound(flow, 100), true, '50×3 bütçesi içinde kalan yanıt geçmeli');
      flow.bytesOut = 100;
      assert.strictEqual(guard.checkUdpOutbound(flow, 500), false, 'oranı aşan yanıt engellenmeli');

      // İki yönlü trafik görülünce akış "kurulmuş" sayılır ve sınır kalkar.
      flow.packetsIn = 2;
      assert.strictEqual(guard.checkUdpOutbound(flow, 100_000), true);
    } finally { await s.close(); }
  });

  // =========================================================================
  await r.test('yönetim: uygulama panelden eklenir, güncellenir ve silinir', async () => {
    const origin = await startOriginTcp();
    const s = await startStack();
    try {
      const created = await s.server.createApp({
        clientId: s.tunnel.clientId,
        name: 'panelden',
        localHost: '127.0.0.1',
        localPort: origin.port,
        protocol: 'tcp',
      }, { actor: 'test@fitfak.net' });

      assert.ok(created.publicPort, 'uygulama hemen yayına alınmalı');
      const reply = await tcpRequest(created.publicPort, Buffer.from('ab'), { expectBytes: 2 });
      assert.strictEqual(reply.toString(), 'AB');

      // İstemci tabloyu görüyor mu?
      await waitFor(
        () => [...s.client.apps.values()].some((a) => a.appId === created.appId),
        { what: 'APP_SYNC istemciye ulaştı' },
      );

      await s.server.updateApp(created.appId, { enabled: false }, { actor: 'test@fitfak.net' });
      await waitFor(async () => {
        const apps = await s.server.listApps();
        return apps.find((a) => a.appId === created.appId && !a.enabled);
      }, { what: 'uygulama kapatıldı' });

      // Kapalı uygulamanın portu artık dinlemiyor.
      await assert.rejects(
        () => tcpRequest(created.publicPort, Buffer.from('x'), { timeoutMs: 1500 }),
        /ECONNREFUSED|zaman aşımı/,
      );

      await s.server.deleteApp(created.appId, { actor: 'test@fitfak.net' });
      const after = await s.server.listApps();
      assert.ok(!after.some((a) => a.appId === created.appId), 'uygulama silinmeliydi');

      const events = await s.server.store.listEvents(20);
      const kinds = events.map((e) => e.kind);
      assert.ok(kinds.includes('app.create') && kinds.includes('app.update') && kinds.includes('app.delete'),
        `denetim kaydı eksik: ${kinds.join(', ')}`);
    } finally { await s.close(); await origin.close(); }
  });

  // =========================================================================
  await r.test('yönetim: aynı sertifikayla ikinci tünel gelince eskisi yerini bırakır', async () => {
    const s = await startStack();
    try {
      const first = s.tunnel;
      const second = new TunnelClient({
        host: '127.0.0.1',
        port: s.addr.port,
        servername: 'localhost',
        caPem: read('ca.crt'),
        identity: { certPem: read('client.crt'), privateKeyPem: read('client.key') },
        revocation: 'off',
        reconnect: false,
        name: 'ikinci',
      });
      await second.start();
      await waitFor(() => second.connected, { what: 'ikinci istemci hazır' });
      await waitFor(() => first.state === 'closed', { what: 'ilk tünel kapandı' });

      assert.strictEqual(s.server.byClient.size, 1, 'bir sertifika için tek canlı tünel olmalı');
      await second.stop();
    } finally { await s.close(); }
  });

  // =========================================================================
  await r.test('yönetim: engellenen istemci bağlanamaz', async () => {
    const s = await startStack();
    try {
      const clientId = s.tunnel.clientId;
      await s.server.setClientBlocked(clientId, true, { actor: 'test@fitfak.net' });
      await waitFor(() => s.server.tunnels.size === 0, { what: 'engellenen tünel kapandı' });

      const retry = new TunnelClient({
        host: '127.0.0.1',
        port: s.addr.port,
        servername: 'localhost',
        caPem: read('ca.crt'),
        identity: { certPem: read('client.crt'), privateKeyPem: read('client.key') },
        revocation: 'off',
        reconnect: false,
      });
      await retry.start();
      // El sıkışma tamamlanır (sertifika geçerli) ama tünel hazır olmaz.
      await sleep(1200);
      assert.strictEqual(retry.connected, false, 'engelli istemcinin tüneli hazır olmamalı');
      await retry.stop();
    } finally { await s.close(); }
  });

  // =========================================================================
  await r.test('ölçüm: RTT, bant genişliği ve kayıp sayaçları raporlanır', async () => {
    const origin = await startOriginTcp();
    const s = await startStack();
    try {
      const bound = await s.client.requestBind({
        proto: PROTO.TCP, localHost: '127.0.0.1', localPort: origin.port, name: 'olcum',
      });
      await tcpRequest(bound.publicPort, Buffer.from('veri'), { expectBytes: 4 });

      s.tunnel.mux.ping();
      await waitFor(() => s.tunnel.mux.rttMs != null, { what: 'PING/PONG turu' });

      const snap = s.tunnel.snapshot();
      assert.ok(snap.link.appRttMs >= 0, 'uygulama RTT ölçülmeli');
      assert.ok(snap.traffic.bytesIn > 0 && snap.traffic.bytesOut > 0);
      assert.strictEqual(typeof snap.link.lossRate, 'number');
      assert.ok(snap.apps.length >= 1);
      assert.ok(snap.certificate.fingerprint256);

      const overview = s.server.overview();
      assert.strictEqual(overview.tunnels.online, 1);
      assert.ok(overview.ports.active >= 1);
      assert.strictEqual(overview.persistence, 'memory');
    } finally { await s.close(); await origin.close(); }
  });

  r.exit();
})();
