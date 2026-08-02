'use strict';
// Güvenilir / sırasız veri kanalı — gerçek DTLS oturumu üzerinde,
// yapay paket kaybı altında.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Runner, loadCerts, pair, once, sleep, injectLoss } = require('./helpers.js');

const c = loadCerts();
const SRV = { cert: c.serverCert, key: c.serverKey, ca: c.ca };
const CLI = { ca: c.ca, servername: 'localhost' };

const r = new Runner('güvenilir veri kanalı');

/** Handshake tamamlandıktan SONRA kayıp enjekte eder. */
async function connectedPair(reliable, lossRate = 0) {
  const p = await pair({ ...SRV, reliable }, { ...CLI, reliable }, { echo: false });
  const s = await p.waitConnected();
  if (lossRate > 0) {
    injectLoss(p.client, () => Math.random() < lossRate);
    injectLoss(s, () => Math.random() < lossRate);
  }
  return { ...p, s };
}

(async () => {
  await r.test('kanal handshake sonrası kurulur', async () => {
    const p = await connectedPair(true);
    assert.ok(p.client.reliable, 'istemcide kanal olmalı');
    assert.ok(p.s.reliable, 'sunucuda kanal olmalı');
    await p.close();
  });

  await r.test('küçük mesaj teyitlenerek ulaşır', async () => {
    const p = await connectedPair(true);
    const got = once(p.s, 'data');
    await p.client.send(Buffer.from('merhaba'));
    assert.equal((await got).toString(), 'merhaba');
    assert.equal(p.client.reliable.inFlight, 0, 'ACK sonrası uçuşta paket kalmamalı');
    await p.close();
  });

  await r.test('MTU üstü mesaj parçalanır ve bütün olarak teslim edilir', async () => {
    const p = await connectedPair(true);
    const payload = crypto.randomBytes(256 * 1024);
    const got = once(p.s, 'data', 20_000);
    await p.client.send(payload);
    assert.deepEqual(await got, payload);
    await p.close();
  });

  await r.test('%25 paket kaybı altında veri bütünlüğü korunur', async () => {
    const p = await connectedPair({ maxRetransmits: 40, rto: 40, ackDelay: 5 }, 0.25);
    const payload = crypto.randomBytes(64 * 1024);
    const got = once(p.s, 'data', 30_000);
    await p.client.send(payload);
    assert.deepEqual(await got, payload);
    assert.ok(p.client.reliable.stats.resent > 0, 'yeniden gönderim olmalıydı');
    await p.close();
  });

  await r.test('%50 paket kaybı altında bile teslim edilir', async () => {
    const p = await connectedPair({ maxRetransmits: 60, rto: 40, ackDelay: 5 }, 0.5);
    const payload = crypto.randomBytes(16 * 1024);
    const got = once(p.s, 'data', 30_000);
    // Gönderim başarısız olursa `got` sahipsiz kalıp süreç düşürmesin.
    const [, received] = await Promise.all([p.client.send(payload), got]);
    assert.deepEqual(received, payload);
    await p.close();
  });

  await r.test('sırasız mod: geciken mesaj arkasındakini bekletmez', async () => {
    const p = await connectedPair({ ordered: false, rto: 60 });
    const order = [];
    p.s.on('data', (d) => order.push(d.toString()));

    // İlk gönderimin ilk paketini düşür
    const restore = injectLoss(p.client, (n) => n === 0);
    const first = p.client.send(Buffer.from('BIRINCI'));
    await sleep(15);
    restore();
    await p.client.send(Buffer.from('IKINCI'));
    await first;
    await sleep(250);

    assert.deepEqual(order, ['IKINCI', 'BIRINCI'],
                     'sırasız modda ikinci mesaj önce teslim edilmeli');
    await p.close();
  });

  await r.test('sıralı mod: teslim sırası korunur', async () => {
    const p = await connectedPair({ ordered: true, rto: 60 });
    const order = [];
    p.s.on('data', (d) => order.push(d.toString()));

    const restore = injectLoss(p.client, (n) => n === 0);
    const first = p.client.send(Buffer.from('BIRINCI'));
    await sleep(15);
    restore();
    await p.client.send(Buffer.from('IKINCI'));
    await first;
    await sleep(250);

    assert.deepEqual(order, ['BIRINCI', 'IKINCI']);
    await p.close();
  });

  await r.test('çift yönlü güvenilir akış', async () => {
    const p = await connectedPair({ rto: 60 }, 0.15);
    const up = crypto.randomBytes(20_000);
    const down = crypto.randomBytes(20_000);
    const gotUp = once(p.s, 'data', 20_000);
    const gotDown = once(p.client, 'data', 20_000);
    await Promise.all([p.client.send(up), p.s.send(down)]);
    assert.deepEqual(await gotUp, up);
    assert.deepEqual(await gotDown, down);
    await p.close();
  });

  await r.test('reliable:false gönderimi teyit beklemez', async () => {
    const p = await connectedPair(true);
    const received = new Promise((res) => p.s.once('data', (d, meta) => res({ d, meta })));
    await p.client.send(Buffer.from('tek-atim'), { reliable: false });
    const { d, meta } = await received;
    assert.equal(d.toString(), 'tek-atim');
    assert.equal(meta.reliable, false);
    assert.equal(p.client.reliable.inFlight, 0, 'takip edilen paket olmamalı');
    await p.close();
  });

  await r.test('birden çok akış (streamId) bağımsız sıralanır', async () => {
    const p = await connectedPair({ ordered: true, rto: 60 });
    const byStream = new Map();
    p.s.on('data', (d, meta) => {
      const list = byStream.get(meta.streamId) || [];
      list.push(d.toString());
      byStream.set(meta.streamId, list);
    });
    await Promise.all([
      p.client.send(Buffer.from('a1'), { streamId: 1 }),
      p.client.send(Buffer.from('b1'), { streamId: 2 }),
      p.client.send(Buffer.from('a2'), { streamId: 1 }),
      p.client.send(Buffer.from('b2'), { streamId: 2 }),
    ]);
    await sleep(200);
    assert.deepEqual(byStream.get(1), ['a1', 'a2']);
    assert.deepEqual(byStream.get(2), ['b1', 'b2']);
    await p.close();
  });

  await r.test('RTT ölçülür ve istatistikler tutulur', async () => {
    const p = await connectedPair(true);
    await p.client.send(Buffer.from('olcum'));
    await sleep(50);
    const st = p.client.reliable.stats;
    assert.ok(st.sent > 0 && st.acked > 0);
    assert.ok(p.client.reliable.rttMs !== null, 'RTT tahmini oluşmalı');
    await p.close();
  });

  await r.test('kalıcı kayıpta gönderim makul sürede vazgeçer', async () => {
    const p = await connectedPair({ maxRetransmits: 3, rto: 50, minRto: 50 });
    injectLoss(p.client, () => true); // her şeyi düşür
    await assert.rejects(p.client.send(Buffer.from('asla-gitmez')), /başarısız/);
    await p.close();
  });

  await r.test('DTLS 1.2 üzerinde de çalışır', async () => {
    const V = { minVersion: 'DTLSv1.2', maxVersion: 'DTLSv1.2' };
    const p = await pair(
      { ...SRV, reliable: { rto: 60 }, ...V },
      { ...CLI, reliable: { rto: 60 }, ...V }, { echo: false });
    const s = await p.waitConnected();
    injectLoss(p.client, () => Math.random() < 0.2);
    const payload = crypto.randomBytes(32 * 1024);
    const got = once(s, 'data', 20_000);
    await p.client.send(payload);
    assert.deepEqual(await got, payload);
    await p.close();
  });

  // ==========================================================================
  // RFC 9002 davranışları
  // ==========================================================================
  await r.test('kayıp altında tıkanıklık penceresi küçülür (RFC 9002 §7.3.2)', async () => {
    const p = await connectedPair({ maxRetransmits: 40, rto: 40, ackDelay: 5 }, 0.3);
    const rec = p.client.reliable.recovery;

    // Tıkanıklık olayı anındaki pencereyi yakala: aktarım boyunca pencere
    // büyüdüğü için ÖNCEKİ değerle karşılaştırmak anlamsız olurdu — RFC 9002
    // §7.3.2'nin söylediği, ssthresh'in KAYBIN GÖRÜLDÜĞÜ ANDAKİ pencerenin
    // yarısı olduğudur.
    const events = [];
    const origEvent = rec._onCongestionEvent.bind(rec);
    rec._onCongestionEvent = (sentTime, now) => {
      const cwndBefore = rec.congestionWindow;
      const inRecovery = rec._inCongestionRecovery(sentTime);
      origEvent(sentTime, now);
      if (!inRecovery) events.push({ cwndBefore, cwndAfter: rec.congestionWindow });
    };

    const got = once(p.s, 'data', 30_000);
    await p.client.send(crypto.randomBytes(48 * 1024));
    await got;

    const st = p.client.reliable.getStats();
    assert.ok(st.packetsLost > 0, 'kayıp tespit edilmeliydi');
    assert.ok(events.length > 0, 'kayıp tıkanıklık olayı üretmeliydi');
    const minWindow = 2 * p.client.reliable.opts.mtu;
    for (const e of events) {
      assert.ok(e.cwndAfter <= Math.max(Math.floor(e.cwndBefore / 2), minWindow),
                `pencere yarılanmalıydı: ${e.cwndBefore} → ${e.cwndAfter}`);
      assert.ok(e.cwndAfter >= minWindow, 'pencere asgari değerin altına inmemeli');
    }
    await p.close();
  });

  await r.test('kayıpsız akışta pencere büyür (yavaş başlangıç)', async () => {
    const p = await connectedPair(true);
    const start = p.client.reliable.congestionWindow;
    const got = once(p.s, 'data', 20_000);
    await p.client.send(crypto.randomBytes(128 * 1024));
    await got;
    const st = p.client.reliable.getStats();
    assert.ok(p.client.reliable.congestionWindow > start,
              `pencere büyümeliydi (${start} → ${p.client.reliable.congestionWindow})`);
    assert.equal(st.congestionEvents, 0, 'kayıpsız akışta tıkanıklık olayı olmamalı');
    await p.close();
  });

  await r.test('PTO sondaları tıkanıklık penceresini küçültmez (RFC 9002 §6.2.4)', async () => {
    const p = await connectedPair({ rto: 60 });
    const rec = p.client.reliable.recovery;
    // Tek bir paketi kaybettir: ardından ACK gelmeyeceği için PTO tetiklenir.
    const restore = injectLoss(p.client, () => true);
    p.client.send(Buffer.from('sonda')).catch(() => {});
    await sleep(400);
    restore();
    assert.ok(rec.stats.probesSent > 0, 'PTO sondası gönderilmeliydi');
    assert.equal(rec.stats.congestionEvents, 0,
                 'PTO bir kayıp bildirimi değildir — pencere küçülmemeli');
    await p.close();
  });

  await r.test('RTT tahmini ACK gecikmesini düşer (RFC 9002 §5.3)', async () => {
    const p = await connectedPair(true);
    await p.client.send(Buffer.from('olcum'));
    await sleep(60);
    const st = p.client.reliable.getStats();
    assert.ok(st.minRtt !== null, 'min_rtt oluşmalı');
    assert.ok(st.smoothedRtt >= st.minRtt, 'smoothed_rtt min_rtt\'nin altına düşmemeli');
    assert.ok(st.pto > st.smoothedRtt, 'PTO smoothed_rtt + payı içermeli');
    await p.close();
  });

  await r.test('reliable kapalıyken kanal kurulmaz (sıfır maliyet)', async () => {
    const p = await pair(SRV, CLI, { echo: false });
    const s = await p.waitConnected();
    assert.equal(p.client.reliable, null);
    const got = once(s, 'data');
    await p.client.send(Buffer.from('duz-datagram'));
    assert.equal((await got).toString(), 'duz-datagram');
    await p.close();
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
