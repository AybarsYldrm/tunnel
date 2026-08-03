'use strict';
// BBRv3 tıkanıklık denetimi — deterministik hat benzetimi üzerinde.
//
// Neden gerçek soket değil? BBR'ın iddiası "şu hatta şu kadar verim" biçiminde
// SAYISALDIR ve gerçek bir loopback soketinde ne darboğaz bant genişliği ne
// tampon derinliği ne de kayıp oranı kontrol edilebilir. Buradaki benzetim
// LossRecovery'yi doğrudan sürer: zaman parametredir, rastgelelik tohumludur,
// aynı girdi her koşuda aynı çıktıyı verir.
//
// Benzetilen hat (tek darboğaz, tek yön):
//
//   gönderen ──► [ tampon ][ darboğaz: bw bayt/ms ] ──► alıcı ──► ACK
//                    ▲ taşarsa kuyruk sonundan düşer
//   tek yön gecikmesi = rtt/2, ACK dönüşü = rtt/2

const assert = require('node:assert/strict');
const { Runner } = require('./helpers.js');

const { LossRecovery, DEFAULT_CONGESTION_CONTROL } = require('../src/reliable/recovery.js');
const {
  createCongestionController, WindowedFilter, RateSampler, BBR_STATE,
} = require('../src/reliable/congestion.js');
const { Pacer } = require('../src/reliable/pacing.js');

const r = new Runner('BBRv3 tıkanıklık denetimi');

// ===========================================================================
// Tohumlu rastgelelik — testin tekrarlanabilir olması için şart.
// ===========================================================================
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ===========================================================================
// Hat benzetimi
// ===========================================================================
/**
 * @param {object} o
 * @param {number} o.bw          darboğaz hızı (bayt/ms)
 * @param {number} o.rtt         gidiş-dönüş yayılım gecikmesi (ms)
 * @param {number} o.loss        rastgele kayıp oranı (0..1) — tıkanıklıktan bağımsız
 * @param {number} o.bufferBytes darboğaz tamponu
 * @param {number} o.durationMs
 * @param {string} o.cc          'bbr3' | 'newreno'
 * @param {number} [o.appLimitAfterMs] bu andan sonra uygulama veri üretmez
 */
function simulate({
  bw, rtt, loss = 0, bufferBytes = 64 * 1024, durationMs = 20_000,
  cc, mtu = 1200, seed = 1337, appLimitAfterMs = 0,
}) {
  const rnd = mulberry32(seed);
  const rec = new LossRecovery({
    maxDatagramSize: mtu,
    congestionControl: cc,
    initialRtt: rtt,
    maxAckDelay: 0,
    minPto: 5,
  });

  let now = 0;
  let nextPn = 1;
  let lastDepart = 0;
  let queueBytes = 0;
  let maxQueueBytes = 0;
  let queueBytesSum = 0;
  let deliveredBytes = 0;
  let droppedByBuffer = 0;
  let droppedRandom = 0;

  /** Yolda olan paketler: darboğazdan çıkış ve ACK varış anlarıyla. */
  const wire = [];           // { pn, bytes, deQueueAt, ackAt, lost, dequeued }
  const ackQueue = [];

  const send = () => {
    let guard = 0;
    while (guard++ < 512) {
      if (appLimitAfterMs && now >= appLimitAfterMs) { rec.markAppLimited(); return; }
      if (!rec.hasCongestionRoom(mtu)) return;
      if (rec.pacingDelay(mtu, now) > 0) return;
      if (rec.sent.size > 8192) return;

      const pn = nextPn++;
      rec.onPacketSent({ pn, bytes: mtu, now });

      // --- darboğaz: kuyruk taşarsa kuyruk sonundan düşer (tail drop)
      if (queueBytes + mtu > bufferBytes) { droppedByBuffer++; continue; }
      queueBytes += mtu;

      // --- seri servis: darboğaz aynı anda tek paket taşır
      const startService = Math.max(now + rtt / 2, lastDepart);
      const depart = startService + mtu / bw;
      lastDepart = depart;

      // Rastgele kayıp da kuyruktan GEÇER (bit hatası çıkışta olur): kuyruk
      // muhasebesini atlarsak tampon sonsuza kadar dolu görünür.
      const lost = loss > 0 && rnd() < loss;
      if (lost) droppedRandom++;
      wire.push({
        pn, bytes: mtu, deQueueAt: depart, ackAt: depart + rtt / 2, lost, dequeued: false,
      });
    }
  };

  const drainWire = () => {
    for (let i = wire.length - 1; i >= 0; i--) {
      const p = wire[i];
      if (!p.dequeued && p.deQueueAt <= now) {
        p.dequeued = true;
        queueBytes = Math.max(0, queueBytes - p.bytes);
      }
      if (p.ackAt <= now) {
        if (!p.lost) { deliveredBytes += p.bytes; ackQueue.push(p.pn); }
        wire.splice(i, 1);
      }
    }
  };

  const flushAcks = () => {
    if (ackQueue.length === 0) return;
    ackQueue.sort((a, b) => a - b);
    const ranges = [];
    let start = ackQueue[0];
    let prev = start;
    for (let i = 1; i < ackQueue.length; i++) {
      if (ackQueue[i] === prev + 1) { prev = ackQueue[i]; continue; }
      ranges.push([start, prev]);
      start = ackQueue[i];
      prev = start;
    }
    ranges.push([start, prev]);
    ackQueue.length = 0;
    rec.onAckReceived({ ranges, ackDelay: 0, now });
  };

  for (now = 0; now <= durationMs; now++) {
    drainWire();
    flushAcks();

    const t = rec.getLossDetectionTime();
    if (t !== null && t <= now) {
      const { probes } = rec.onLossDetectionTimeout(now);
      // Sonda: yeni paket numarasıyla tekrar gönderim (kanalın yaptığı iş).
      for (let i = 0; i < probes; i++) {
        const pn = nextPn++;
        rec.onPacketSent({ pn, bytes: mtu, now });
        wire.push({
          pn, bytes: mtu, deQueueAt: now, ackAt: now + rtt, lost: false, dequeued: true,
        });
      }
    }

    send();
    maxQueueBytes = Math.max(maxQueueBytes, queueBytes);
    queueBytesSum += queueBytes;
  }

  const snap = rec.snapshot();
  return {
    rec,
    snapshot: snap,
    deliveredBytes,
    throughputBytesPerMs: deliveredBytes / durationMs,
    /** Hattın taşıyabileceğinin yüzde kaçı kullanıldı. */
    utilization: deliveredBytes / (bw * durationMs),
    maxQueueBytes,
    avgQueueBytes: queueBytesSum / durationMs,
    /** Ortalama kuyruk gecikmesi (ms) — bufferbloat ölçüsü. */
    avgQueueDelayMs: queueBytesSum / durationMs / bw,
    droppedByBuffer,
    droppedRandom,
  };
}

(async () => {
  // ========================================================================
  // Yapı taşları
  // ========================================================================
  await r.test('varsayılan denetleyici BBRv3', () => {
    assert.equal(DEFAULT_CONGESTION_CONTROL, 'bbr3');
    const rec = new LossRecovery({});
    assert.equal(rec.congestionControl, 'bbr3');
    assert.equal(rec.snapshot().cc, 'bbr3');
  });

  await r.test('bilinmeyen denetleyici adı açıkça reddedilir', () => {
    assert.throws(() => new LossRecovery({ congestionControl: 'cubic' }), /bilinmeyen/i);
  });

  await r.test('NewReno açıkça seçilebilir ve pacer kapalı gelir', () => {
    const rec = new LossRecovery({ congestionControl: 'newreno' });
    assert.equal(rec.congestionControl, 'newreno');
    assert.equal(rec.pacer, null, 'NewReno hız şekillendirmez');
    assert.equal(rec.snapshot().ssthresh, null);
  });

  await r.test('pencereli maksimum süzgeci eski tepeyi unutur', () => {
    const f = new WindowedFilter(2, 1);
    f.update(0, 100);
    assert.equal(f.get(), 100);
    f.update(1, 50);
    assert.equal(f.get(), 100, 'pencere içindeki tepe korunmalı');
    f.update(2, 40);
    f.update(3, 30);
    assert.ok(f.get() < 100, 'pencere kayınca tepe düşmeli');
  });

  await r.test('pencereli minimum süzgeci', () => {
    const f = new WindowedFilter(3, -1);
    f.update(0, 90);
    f.update(1, 40);
    assert.equal(f.get(), 40);
    f.update(2, 70);
    assert.equal(f.get(), 40, 'pencere içindeki dip korunmalı');
  });

  await r.test('teslim hızı örnekleyicisi: aralık max(gönderim, ack)', () => {
    const s = new RateSampler();
    // Tek paket, sıfırıncı milisaniyede: ilk örnek doğrudan RTT'yi verir.
    const p1 = { bytes: 1000, sentTime: 0 };
    s.onPacketSent(p1, 0, 0);
    s.beginAck();
    s.onPacketAcked(p1, 100);
    const first = s.endAck(1);
    assert.ok(first.valid, 'ilk örnek geçerli olmalı (t=0 geçerli bir zamandır)');
    assert.equal(first.intervalMs, 100);
    assert.equal(first.delivered, 1000);
    assert.ok(Math.abs(first.deliveryRate - 10) < 1e-9, 'bayt/ms cinsinden hız');

    // İkinci tur: iki paket, ACK'ler sıkışık gelirse payda gönderim
    // aralığından gelir — formülün tamamı max(gönderim, ack).
    const p2 = { bytes: 1000, sentTime: 100 };
    s.onPacketSent(p2, 0, 100);
    const p3 = { bytes: 1000, sentTime: 160 };
    s.onPacketSent(p3, 1000, 160);
    s.beginAck();
    s.onPacketAcked(p2, 200);
    s.onPacketAcked(p3, 205);
    const rs = s.endAck(1);
    assert.ok(rs.valid);
    assert.equal(rs.intervalMs, Math.max(rs.sendElapsed, rs.ackElapsed),
                 'aralık iki ölçünün büyüğü olmalı');
    assert.ok(rs.deliveryRate > 0);
  });

  await r.test('teslim hızı örnekleyicisi: min_rtt altındaki aralık atılır', () => {
    const s = new RateSampler();
    const p = { bytes: 1000, sentTime: 0 };
    s.onPacketSent(p, 0, 0);
    s.beginAck();
    s.onPacketAcked(p, 2);
    // Aralık 2 ms; min_rtt 40 ms ise bu ölçüm zamanlayıcı gürültüsüdür.
    assert.equal(s.endAck(40).valid, false);
  });

  await r.test('uygulama sınırlı örnek bant genişliğini DÜŞÜRMEZ', () => {
    const cc = createCongestionController('bbr3', { maxDatagramSize: 1200 });
    const base = {
      delivered: 100_000, bytesInFlight: 0, bytesLost: 0, packetsLost: 0,
      minRtt: 20, latestRtt: 20, now: 1000,
    };
    cc.onAck({ ...base, rs: { valid: true, deliveryRate: 100, delivered: 12_000, lost: 0, priorDelivered: 0, isAppLimited: false, intervalMs: 120 } });
    const fast = cc.maxBw;
    assert.ok(fast > 0);

    cc.onAck({ ...base, now: 1100, rs: { valid: true, deliveryRate: 1, delivered: 120, lost: 0, priorDelivered: 100_000, isAppLimited: true, intervalMs: 120 } });
    assert.equal(cc.maxBw, fast, 'uygulama sınırlı yavaş örnek tahmini bozmamalı');
  });

  await r.test('pacer: patlama payı biter, sonra hıza uyar', () => {
    const p = new Pacer({ maxDatagramSize: 1000 });
    assert.equal(p.enabled, false, 'hız verilmeden şekillendirme yok');
    assert.equal(p.delayUntilSend(1000, 0), 0);

    p.setRate(1_000_000);            // 1 MB/s = 1000 bayt/ms
    let now = 0;
    let sent = 0;
    while (p.canSend(1000, now) && sent < 100) { p.onSent(1000, now); sent++; }
    assert.ok(sent >= 2 && sent <= 16, `patlama makul olmalı, ${sent} paket çıktı`);
    const wait = p.delayUntilSend(1000, now);
    assert.ok(wait >= 1, 'kova boşalınca beklenmeli');

    now += 100;                      // 100 ms → 100 KB hak
    assert.ok(p.canSend(1000, now), 'zaman geçince yeniden gönderilebilmeli');
  });

  // ========================================================================
  // Hat üzerinde davranış
  // ========================================================================
  await r.test('temiz hatta model darboğazı bulur ve hattı doldurur', () => {
    // 10 Mbit/s, 40 ms RTT, kayıpsız, makul tampon.
    const bw = 1250;   // bayt/ms
    const out = simulate({
      bw, rtt: 40, loss: 0, bufferBytes: 128 * 1024, durationMs: 20_000, cc: 'bbr3',
    });

    assert.ok(out.utilization > 0.85,
              `hat kullanımı yüksek olmalı, ${(out.utilization * 100).toFixed(1)}% ölçüldü`);
    const est = out.snapshot.bandwidthBps / 1000;   // bayt/ms
    assert.ok(est > bw * 0.7 && est < bw * 1.3,
              `bant genişliği tahmini ${est.toFixed(0)} ≈ ${bw} olmalı`);
    assert.ok(out.snapshot.filledPipe, 'başlangıç evresinden çıkılmış olmalı');
    assert.ok(out.snapshot.state.startsWith('probe-'),
              `kararlı hâlde ProbeBW beklenir, ${out.snapshot.state} bulundu`);
  });

  await r.test('rastgele kayıp altında BBRv3 NewReno\'dan belirgin hızlı', () => {
    // Bu, BBR'a geçmenin asıl gerekçesi: %1 kayıp TIKANIKLIKTAN gelmiyor
    // (hat boş, tampon derin). NewReno yine de pencereyi yarılar; Mathis
    // formülünün verdiği tavan hattın onda biridir.
    const link = {
      bw: 1250, rtt: 40, loss: 0.01, bufferBytes: 256 * 1024, durationMs: 30_000,
    };
    const bbr = simulate({ ...link, cc: 'bbr3', seed: 7 });
    const reno = simulate({ ...link, cc: 'newreno', seed: 7 });

    assert.ok(bbr.deliveredBytes > reno.deliveredBytes * 2,
              `BBRv3 ${(bbr.utilization * 100).toFixed(1)}% vs NewReno `
              + `${(reno.utilization * 100).toFixed(1)}% — en az 2 kat beklenir`);
    assert.ok(bbr.utilization > 0.6,
              `BBRv3 rastgele kayba rağmen hattı kullanmalı (${(bbr.utilization * 100).toFixed(1)}%)`);
  });

  await r.test('derin tamponda BBRv3 kuyruk gecikmesi üretmez (bufferbloat)', () => {
    // Tampon BDP'nin katı: kayıp odaklı denetleyici onu doldurmadan kayıp
    // görmez, dolayısıyla gecikmeyi yüzlerce milisaniyeye çıkarır.
    const link = {
      bw: 1250, rtt: 40, loss: 0, bufferBytes: 512 * 1024, durationMs: 20_000,
    };
    const bbr = simulate({ ...link, cc: 'bbr3' });
    const reno = simulate({ ...link, cc: 'newreno' });

    assert.ok(bbr.avgQueueDelayMs < reno.avgQueueDelayMs,
              `BBRv3 kuyruğu daha kısa tutmalı: ${bbr.avgQueueDelayMs.toFixed(1)} ms `
              + `vs ${reno.avgQueueDelayMs.toFixed(1)} ms`);
    // Verim de kaybedilmemeli: düşük gecikme, boş hat pahasına gelmemeli.
    assert.ok(bbr.utilization > reno.utilization * 0.85,
              'düşük gecikme verim pahasına olmamalı');
  });

  await r.test('başlangıç evresi bant genişliği düzleşince biter', () => {
    const out = simulate({
      bw: 1250, rtt: 40, loss: 0, bufferBytes: 256 * 1024, durationMs: 8_000, cc: 'bbr3',
    });
    assert.ok(out.snapshot.filledPipe, 'boru dolmuş sayılmalı');
    assert.equal(out.snapshot.startupExit, 'bandwidth-plateau');
    assert.ok(out.snapshot.rounds > 5, 'birden çok tur tamamlanmalı');
  });

  await r.test('min_rtt bayatlayınca ProbeRTT yapılır', () => {
    // minRttWindowMs varsayılanı 10 s; 25 s'lik koşuda en az bir kez girilmeli.
    const out = simulate({
      bw: 1250, rtt: 40, loss: 0, bufferBytes: 256 * 1024, durationMs: 25_000, cc: 'bbr3',
    });
    assert.ok(out.snapshot.probeRttCount >= 1,
              `ProbeRTT en az bir kez yapılmalı (${out.snapshot.probeRttCount})`);
  });

  await r.test('hız şekillendirme gerçekten uygulanıyor', () => {
    const out = simulate({
      bw: 1250, rtt: 40, loss: 0, bufferBytes: 128 * 1024, durationMs: 10_000, cc: 'bbr3',
    });
    assert.equal(out.snapshot.pacingEnabled, true);
    assert.ok(out.snapshot.pacingRateBps > 0);
    assert.ok(out.snapshot.pacingDelays > 0, 'en az bir kez hız sınırına takılmalı');
  });

  await r.test('uygulama veri üretmeyi kesince tahmin çökmez', () => {
    const out = simulate({
      bw: 1250,
      rtt: 40,
      loss: 0,
      bufferBytes: 128 * 1024,
      durationMs: 20_000,
      cc: 'bbr3',
      appLimitAfterMs: 10_000,
    });
    const est = out.snapshot.bandwidthBps / 1000;
    assert.ok(est > 1250 * 0.6,
              `sessizlik sonrası tahmin korunmalı, ${est.toFixed(0)} bayt/ms kaldı`);
    assert.equal(out.snapshot.appLimited, true);
  });

  await r.test('kalıcı tıkanıklıkta model sıfırlanır', () => {
    const rec = new LossRecovery({ maxDatagramSize: 1200, initialRtt: 20, maxAckDelay: 0 });
    // Önce sağlıklı bir tur: RTT örneği ve bant genişliği oluşsun.
    for (let i = 1; i <= 10; i++) rec.onPacketSent({ pn: i, bytes: 1200, now: i });
    rec.onAckReceived({ ranges: [[1, 10]], now: 20 });
    assert.ok(rec.cc.maxBw > 0);

    // Sonra uzun bir kopma: paketler saniyelerce akıyor, hiçbiri dönmüyor.
    // Sonunda EN SON paket normal bir RTT ile ACK'leniyor — yani hat geri
    // geldi, ama arada kalan her şey kayboldu.
    for (let i = 11; i <= 40; i++) rec.onPacketSent({ pn: i, bytes: 1200, now: 100 * i });
    rec.onAckReceived({ ranges: [[40, 40]], now: 4020 });

    assert.ok(rec.stats.persistentCongestion >= 1, 'kalıcı tıkanıklık görülmeli');
    assert.equal(rec.cc.state, BBR_STATE.STARTUP, 'model başlangıca dönmeli');
    assert.equal(rec.cc.maxBw, 0, 'bant genişliği tahmini sıfırlanmalı');
  });

  await r.test('PTO sondası tıkanıklık olayı saymaz', () => {
    const rec = new LossRecovery({ maxDatagramSize: 1200, initialRtt: 20, minPto: 5 });
    rec.onPacketSent({ pn: 1, bytes: 1200, now: 0 });
    const { lost, probes } = rec.onLossDetectionTimeout(10_000);
    assert.equal(lost.length, 0);
    assert.equal(probes, 2);
    assert.equal(rec.snapshot().congestionEvents, 0);
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
