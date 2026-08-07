'use strict';
// Hizmet sınıfı (QoS) ve öncelikli zamanlayıcı.
//
// Senaryo, bildirilen üretim sorununun birebir modeli:
//
//   25 Mbit'lik bir yükleme hattında AYNI TÜNELDEN
//     • bir web uygulaması (dosya indirmesi — hacimli, sürekli)
//     • bir oyun sunucusu  (küçük paketler — gecikmeye duyarlı)
//     • ve indirme sürerken web sitesine gelen YENİ bir ziyaretçi
//
// Ölçtüğümüz şey verim değil SIRA: küçük ve kritik olan, hacimli olanın
// arkasında kaç bayt beklemek zorunda kalıyor.

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const { Runner } = require('../../tests/helpers.js');
const {
  Mux, STARVATION_GUARD_MS, normalizePriority,
} = require('../src/common/mux.js');
const { ReliableChannel } = require('../../src/reliable/channel.js');
const { QOS, DATA, LIMITS } = require('../src/protocol/constants.js');
const { normalizeApp, appToWire, appToPublic } = require('../src/server/app-model.js');

const r = new Runner('tünel — hizmet sınıfı (QoS)');

const noopLog = {
  trace() {}, debug() {}, info() {}, warn() {}, error() {},
  child() { return noopLog; }, hex() {},
};

/**
 * Kanalı taklit eden soket.
 *
 * Gerçek kanalın burada gerekmeyen tek şeyi ağdır: paketlerin NE ZAMAN
 * gittiğini değil, HANGİ SIRAYLA verildiğini ölçüyoruz. `flush()` ile ACK
 * benzetimi elle yapılır; böylece test zamandan bağımsız ve deterministik.
 */
function fakeSocket({ cwnd = 256 * 1024, pacingRate = 3_125_000 } = {}) {
  const sock = new EventEmitter();
  const sent = [];
  const pending = [];

  sock.reliable = { congestionWindow: cwnd, pacingRate, queuedBytes: 0 };

  sock.send = (frame, opts = {}) => {
    sent.push({ frame, opts, len: frame.length });
    sock.reliable.queuedBytes += frame.length;
    return new Promise((resolve) => {
      pending.push(() => {
        sock.reliable.queuedBytes -= frame.length;
        resolve();
      });
    });
  };

  /** Kanalın n paketi teslim ettiğini varsay (ACK geldi). */
  sock.flush = (n) => {
    const list = pending.splice(0, n === undefined ? pending.length : n);
    for (const done of list) done();
  };
  sock.sent = sent;
  sock.pendingCount = () => pending.length;
  return sock;
}

/** Gönderilen çerçeveler arasında veri taşıyanları akış numarasına göre sayar. */
function dataFramesByStream(sock) {
  const out = new Map();
  sock.sent.forEach((s, i) => {
    if (s.opts.streamId === undefined || s.frame[0] !== DATA.BYTES) return;
    if (!out.has(s.opts.streamId)) out.set(s.opts.streamId, []);
    out.get(s.opts.streamId).push({ index: i, bytes: s.frame.length - 1 });
  });
  return out;
}

function makeMux(sock, limits = {}) {
  return new Mux({
    socket: sock, role: 'server', log: noopLog, limits,
  });
}

(async () => {
  // ========================================================================
  // Sınıf çıkarımı ve yapılandırma
  // ========================================================================
  await r.test('QoS uygulamanın doğasından çıkarılır ve elle ezilebilir', () => {
    // UDP + kayıp toleranslı = "geciken paket düşen paketten kötü" demektir.
    const game = normalizeApp({
      localPort: 25565, protocol: 'udp', delivery: 'unreliable', name: 'mc',
    });
    assert.equal(game.qos, QOS.REALTIME);

    const web = normalizeApp({ localPort: 8443, protocol: 'tcp', name: 'web' });
    assert.equal(web.qos, QOS.INTERACTIVE, 'TCP varsayılanı etkileşimli');

    // Panelden açık seçim her zaman kazanır.
    const backup = normalizeApp({ localPort: 873, protocol: 'tcp', qos: 'bulk' });
    assert.equal(backup.qos, QOS.BULK);
    assert.equal(appToPublic(backup, {}).qos, 'bulk');

    // Sınıf istemciye de gider: yükleme yönü ONUN darboğazından geçiyor.
    assert.equal(appToWire(game).qos, QOS.REALTIME);

    // Geçersiz değer varsayılana düşer, hata fırlatmaz: yapılandırma hatası
    // yüzünden uygulama hiç yayına girmemesinden iyidir.
    assert.equal(normalizeApp({ localPort: 80, qos: 'acil' }).qos, QOS.INTERACTIVE);
  });

  await r.test('veri akışları denetim sınıfını talep edemez', () => {
    // CONTROL bandı kredi ve kalp atışı içindir. Bir uygulama oraya girebilseydi
    // kendini akış denetiminin önüne koyabilirdi.
    assert.equal(normalizePriority(QOS.CONTROL), QOS.INTERACTIVE);
    assert.equal(normalizePriority(QOS.REALTIME), QOS.REALTIME);
    assert.equal(normalizePriority(99), QOS.INTERACTIVE);
    assert.equal(normalizePriority(undefined), QOS.INTERACTIVE);
  });

  // ========================================================================
  // Çoklayıcı sıralaması
  // ========================================================================
  await r.test('oyun paketi, süren indirmenin ARKASINDA beklemez', () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);

    const bulk = mux.openStream({ appId: 'web', qos: QOS.BULK });
    const game = mux.openStream({ appId: 'mc', qos: QOS.REALTIME });

    // İndirme başlıyor ve kanalı doldurana kadar akıyor.
    bulk.write(Buffer.alloc(4 * 1024 * 1024));
    const beforeGame = sock.sent.length;
    assert.ok(beforeGame > 0, 'hacimli akış gönderime başlamalı');

    // Tam bu sırada oyun paketi geliyor.
    game.write(Buffer.alloc(240));

    const after = sock.sent.slice(beforeGame);
    assert.ok(after.length > 0,
              'gerçek zamanlı paket, kanal kuyruğu dolu olsa bile verilmeli');
    assert.equal(after[0].opts.streamId, game.id,
                 'oyun paketi sıradaki İLK çerçeve olmalı');
    assert.equal(after[0].opts.priority, QOS.REALTIME);
  });

  await r.test('katı öncelik: gerçek zamanlı bant tükenene kadar hacimli beklemez ama sonra devam eder', () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);

    const bulk = mux.openStream({ appId: 'web', qos: QOS.BULK });
    const game = mux.openStream({ appId: 'mc', qos: QOS.REALTIME });

    game.write(Buffer.alloc(3 * 1024));
    bulk.write(Buffer.alloc(512 * 1024));

    const byStream = dataFramesByStream(sock);
    const gameFrames = byStream.get(game.id) || [];
    const bulkFrames = byStream.get(bulk.id) || [];

    assert.ok(gameFrames.length > 0 && bulkFrames.length > 0);
    assert.ok(gameFrames[gameFrames.length - 1].index < bulkFrames[0].index,
              'gerçek zamanlı verinin TAMAMI hacimli veriden önce gitmeli');
  });

  await r.test('aynı sınıftaki iki akış birbirini aç bırakmaz (bant içi DRR)', () => {
    // "İndirme sürerken siteye yeni giren ziyaretçi 15 saniye bekliyor"
    // sorunu tam olarak budur: ikisi de etkileşimli sınıfta.
    const sock = fakeSocket();
    const mux = makeMux(sock);

    const download = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });
    download.write(Buffer.alloc(4 * 1024 * 1024));
    const beforeVisitor = sock.sent.length;

    const visitor = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });
    visitor.write(Buffer.alloc(8 * 1024));

    // Kanal boşaldıkça besleme sürsün.
    for (let i = 0; i < 40; i++) { sock.flush(4); mux._pump(); }

    const byStream = dataFramesByStream(sock);
    const visitorFrames = (byStream.get(visitor.id) || []).filter((f) => f.index >= beforeVisitor);
    assert.ok(visitorFrames.length > 0, 'yeni ziyaretçinin verisi akmalı');

    // Yeni akışın İLK baytı, indirmenin kaç baytı arkasında kaldı?
    const bulkAhead = (byStream.get(download.id) || [])
      .filter((f) => f.index >= beforeVisitor && f.index < visitorFrames[0].index)
      .reduce((n, f) => n + f.bytes, 0);

    // Bir DRR kuantumu (32 KiB) makul üst sınır. Eski sürümde bu değer
    // besleme bütçesi kadardı — 4 MiB'e kadar çıkabiliyordu.
    assert.ok(bulkAhead <= 64 * 1024,
              `yeni akış en fazla bir tur beklemeli, ${bulkAhead} bayt arkada kaldı`);
  });

  await r.test('açlık koruması: gerçek zamanlı bant doymuşken bile hacimli ilerler', async () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);

    const bulk = mux.openStream({ appId: 'web', qos: QOS.BULK });
    const flood = mux.openStream({ appId: 'kotu', qos: QOS.REALTIME });

    bulk.write(Buffer.alloc(1024 * 1024));
    // "Gerçek zamanlı" işaretlenmiş ama hattı doyurmaya çalışan bir akış.
    flood.write(Buffer.alloc(4 * 1024 * 1024));

    const bulkBefore = (dataFramesByStream(sock).get(bulk.id) || []).length;

    // Açlık penceresi dolsun ve pompa yeniden çalışsın.
    await new Promise((res) => setTimeout(res, STARVATION_GUARD_MS + 20));
    for (let i = 0; i < 20; i++) { sock.flush(8); mux._pump(); }

    const bulkAfter = (dataFramesByStream(sock).get(bulk.id) || []).length;
    assert.ok(bulkAfter > bulkBefore,
              'katı öncelik alt bandı SONSUZA KADAR bekletmemeli');
  });

  await r.test('denetim çerçeveleri en yüksek önceliği alır', () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);

    const bulk = mux.openStream({ appId: 'web', qos: QOS.BULK });
    bulk.write(Buffer.alloc(2 * 1024 * 1024));

    const before = sock.sent.length;
    mux._flushCredits.call(mux);           // kredi üret
    mux.sendControl(Buffer.from([0x40, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]));

    const control = sock.sent.slice(before).find((s) => s.opts.streamId === 0);
    assert.ok(control, 'denetim mesajı kuyruğa girmeli');
    assert.equal(control.opts.priority, QOS.CONTROL,
                 'kredi/kalp atışı, serbest bırakacağı verinin arkasında beklememeli');
  });

  // ========================================================================
  // Besleme derinliği — 15 saniyelik baş-tıkanmasının kaynağı
  // ========================================================================
  await r.test('kanal kuyruğu BAYT değil ZAMAN cinsinden sınırlanır', () => {
    // 25 Mbit/s = 3.125 MB/s. 20 ms hedefte ~62 KB kuyruk beklenir.
    const sock = fakeSocket({ cwnd: 4 * 1024 * 1024, pacingRate: 3_125_000 });
    const mux = makeMux(sock, { targetQueueMs: 20 });

    const bulk = mux.openStream({ appId: 'web', qos: QOS.BULK });
    bulk.write(Buffer.alloc(8 * 1024 * 1024));

    const allowance = mux._queueAllowance();
    assert.ok(allowance >= 32 * 1024 && allowance <= 96 * 1024,
              `20 ms @ 25 Mbit ≈ 62 KB olmalı, ${allowance} bulundu`);
    assert.ok(sock.reliable.queuedBytes <= allowance + mux.segmentBytes,
              'besleme, izin verilen kuyruğun ötesine geçmemeli');

    // Eski davranış (tıkanıklık penceresinin iki katı, 4 MiB tavan) bu hatta
    // saniyelerce baş-tıkanması demekti. Şimdi süre sabit:
    const queueDelayMs = (sock.reliable.queuedBytes / sock.reliable.pacingRate) * 1000;
    assert.ok(queueDelayMs < 60, `kuyruk gecikmesi ${queueDelayMs.toFixed(0)} ms olmamalı`);
  });

  await r.test('hız düştükçe kuyruk da küçülür (gecikme sabit kalır)', () => {
    const slow = fakeSocket({ cwnd: 4 * 1024 * 1024, pacingRate: 625_000 }); // 5 Mbit
    const fast = fakeSocket({ cwnd: 4 * 1024 * 1024, pacingRate: 12_500_000 }); // 100 Mbit
    const slowMux = makeMux(slow, { targetQueueMs: 20 });
    const fastMux = makeMux(fast, { targetQueueMs: 20 });

    const toMs = (sock, mux) => (mux._queueAllowance() / sock.reliable.pacingRate) * 1000;
    // Bayt cinsinden kuyruk hızla birlikte küçülür...
    assert.ok(slowMux._queueAllowance() < fastMux._queueAllowance(),
              'yavaş hatta bayt cinsinden kuyruk daha küçük olmalı');
    // ...ve ürettiği GECİKME iki hatta da aynı mertebede kalır. Asıl kazanç
    // budur: hattın hızı ne olursa olsun baş-tıkanması sabit bir üst sınırda.
    for (const [sock, mux, ad] of [[slow, slowMux, '5 Mbit'], [fast, fastMux, '100 Mbit']]) {
      assert.ok(toMs(sock, mux) <= 30,
                `${ad}: kuyruk gecikmesi ${toMs(sock, mux).toFixed(0)} ms — tavan aşıldı`);
    }
  });

  await r.test('kuyruk bütçesi besleme biriminin ALTINA inmez', () => {
    // Zamana bağlı bütçe tek başına bırakılırsa, hız düştükçe bütçe de düşer
    // ve bir noktada segment boyutunun altına iner: hiçbir segment kuyruğa
    // giremez, hiçbir şey ACK'lenmez, bütçe hiç serbest kalmaz. Kilitlenme
    // tam da hattın en dar olduğu anda başlar — bu yüzden taban BAYT
    // cinsindendir.
    for (const [ad, bps] of [['1 Mbit', 125_000], ['256 kbit', 32_000], ['64 kbit', 8_000]]) {
      const sock = fakeSocket({ cwnd: 64 * 1024, pacingRate: bps });
      const mux = makeMux(sock, { targetQueueMs: 20 });

      const allowance = mux._queueAllowance();
      assert.ok(allowance >= LIMITS.SEGMENT_BYTES,
                `${ad}: bütçe (${allowance}) bir segmentin altına inmemeli`);
      assert.ok(allowance > LIMITS.SEGMENT_BYTES,
                `${ad}: taban, kuyrukta bir segment varken bile besleme yapılmasına izin vermeli`);

      // Ve gerçekten akıyor: en dar hatta bile veri kanala verilebilmeli.
      const s = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });
      s.write(Buffer.alloc(256 * 1024));
      assert.ok((dataFramesByStream(sock).get(s.id) || []).length > 0,
                `${ad}: besleme kilitlenmemeli`);
    }
  });

  // ========================================================================
  // Yeni bağlantı — "indirme sürerken sayfa açılmıyor"
  // ========================================================================
  await r.test('yeni akış DRR sırasının BAŞINA girer', () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);

    // Aynı sınıfta üç hacimli aktarım: sıranın sonuna eklenen yeni bir akış,
    // her birinin 32 KiB'lik kuantumunu beklerdi.
    const bulks = [0, 1, 2].map(() => mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE }));
    for (const b of bulks) b.write(Buffer.alloc(2 * 1024 * 1024));

    const before = sock.sent.length;
    const visitor = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });
    visitor.write(Buffer.from('GET / HTTP/1.1\r\n\r\n'));

    const after = sock.sent.slice(before).filter((s) => s.frame[0] === DATA.BYTES);
    assert.ok(after.length > 0, 'yeni akışın ilk baytı çıkmalı');
    assert.equal(after[0].opts.streamId, visitor.id,
                 'yeni bağlantının ilk segmenti sıradaki İLK segment olmalı');
  });

  await r.test('yeni akış ayrıcalığı ömür boyu BİR KEREdir', () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);

    const older = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });
    const newer = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });

    older.write(Buffer.alloc(64 * 1024));
    newer.write(Buffer.alloc(64 * 1024));
    assert.ok(newer.bytesOut > 0, 'yeni akış ilk turunu almalı');

    // Artık "yeni" değil: bir daha sıranın başına geçemez, yoksa her yazımdan
    // önce kısa bir duraklama yapan bir akış hattı kalıcı olarak sahiplenirdi.
    assert.equal(mux._isFresh(newer), false);
    mux._deactivate(newer);
    newer.write(Buffer.alloc(1024));
    const band = mux.bands[QOS.INTERACTIVE];
    assert.equal(band[band.length - 1], newer,
                 'konuşmuş bir akış sıranın sonuna eklenmeli');
  });

  await r.test('açılış çerçeveleri kanala fast-track ile verilir', () => {
    const sock = fakeSocket();
    const mux = makeMux(sock);
    const stream = mux.openStream({ appId: 'web', qos: QOS.INTERACTIVE });

    mux.sendOpen(stream, { appIdx: 0, remoteAddress: '203.0.113.7', remotePort: 44321 });
    const open = sock.sent[sock.sent.length - 1];
    assert.equal(open.frame[0], DATA.OPEN);
    assert.equal(open.opts.expedite, true, 'OPEN kuyruğun sonuna girmemeli');

    mux.sendOpenAck(stream);
    const ack = sock.sent[sock.sent.length - 1];
    assert.equal(ack.frame[0], DATA.OPEN_ACK);
    assert.equal(ack.opts.expedite, true,
                 'OPEN_ACK gecikirse karşı taraf akışı OPEN_TIMEOUT ile düşürür');

    // Veri çerçeveleri ayrıcalık ALMAZ: alsalardı ayrıcalık anlamsız olurdu.
    stream.write(Buffer.alloc(1024));
    const data = sock.sent[sock.sent.length - 1];
    assert.equal(data.frame[0], DATA.BYTES);
    assert.ok(!data.opts.expedite, 'veri çerçevesi açılış ayrıcalığı almamalı');
  });

  // ========================================================================
  // Kanal katmanı: öncelik gerçekten aşağı iniyor mu
  // ========================================================================
  await r.test('kanal kuyruğu da önceliklidir (sıralama en altta korunur)', () => {
    const wire = [];
    const ch = new ReliableChannel({ mtu: 300, send: (b) => wire.push(b) });

    // Pencereyi doldur: bundan sonrası kuyrukta bekleyecek.
    ch.sendMessage(Buffer.alloc(64 * 1024), { streamId: 1, priority: QOS.BULK });
    const afterBulk = wire.length;
    assert.ok(ch.queuedChunks > 0, 'hacimli veri kuyrukta beklemeli');

    ch.sendMessage(Buffer.from('oyun-paketi'), { streamId: 2, priority: QOS.REALTIME });
    // Pencere dolu olduğu için hemen çıkmaz; ama kuyruğun BAŞINDA olmalı.
    const nextKey = ch._peek();
    const nextChunk = ch.chunks.get(nextKey);
    assert.equal(nextChunk.streamId, 2,
                 'gerçek zamanlı parça, kuyruktaki hacimli parçaların önüne geçmeli');
    assert.equal(wire.length, afterBulk, 'pencere dolu: yeni paket henüz çıkmamalı');
  });

  await r.test('akış başlatan çerçeve aynı bandın hacimli verisini ATLAR', () => {
    // Süren bir indirme ile yeni bir sekme AYNI sınıftadır (etkileşimli).
    // Bandı yükseltmeden, yalnızca bandın başına geçerek çözülür.
    const wire = [];
    const ch = new ReliableChannel({ mtu: 300, send: (b) => wire.push(b) });

    ch.sendMessage(Buffer.alloc(64 * 1024), { streamId: 1, priority: QOS.INTERACTIVE });
    assert.ok(ch.queuedChunks > 0, 'indirme kuyrukta beklemeli');
    assert.equal(ch.chunks.get(ch._peek()).streamId, 1);

    ch.sendMessage(Buffer.from([DATA.OPEN, 0, 0]), {
      streamId: 2, priority: QOS.INTERACTIVE, expedite: true,
    });
    assert.equal(ch.chunks.get(ch._peek()).streamId, 2,
                 'açılış çerçevesi, aynı bandın hacimli verisinin önüne geçmeli');
  });

  await r.test('fast-track bandı ATLAMAZ', () => {
    // Ayrıcalık bant İÇİNDEdir: etkileşimli bir açılış, gerçek zamanlı bir
    // paketin önüne geçemez. Aksi hâlde her yeni bağlantı oyun trafiğini
    // bölerdi.
    const wire = [];
    const ch = new ReliableChannel({ mtu: 300, send: (b) => wire.push(b) });

    ch.sendMessage(Buffer.alloc(64 * 1024), { streamId: 1, priority: QOS.BULK });
    ch.sendMessage(Buffer.from('oyun'), { streamId: 2, priority: QOS.REALTIME });
    ch.sendMessage(Buffer.from([DATA.OPEN, 0, 0]), {
      streamId: 3, priority: QOS.INTERACTIVE, expedite: true,
    });

    assert.equal(ch.chunks.get(ch._peek()).streamId, 2,
                 'gerçek zamanlı paket en önde kalmalı');
  });

  await r.test('fast-track veri taşımak için kullanılamaz', () => {
    // Ayrıcalık küçük çerçevelerle sınırlı: "acil" işaretli 32 KiB'lik bir
    // mesaj bandın tamamını atlayabilseydi bandın bir anlamı kalmazdı.
    const wire = [];
    const ch = new ReliableChannel({ mtu: 300, send: (b) => wire.push(b) });

    ch.sendMessage(Buffer.alloc(64 * 1024), { streamId: 1, priority: QOS.INTERACTIVE });
    ch.sendMessage(Buffer.alloc(32 * 1024), {
      streamId: 2, priority: QOS.INTERACTIVE, expedite: true,
    });
    assert.equal(ch.chunks.get(ch._peek()).streamId, 1,
                 'hacimli mesaj "acil" işaretiyle sıra atlayamamalı');
  });

  await r.test('yeniden gönderim KENDİ bandının başına döner', () => {
    const wire = [];
    const ch = new ReliableChannel({ mtu: 300, send: (b) => wire.push(b) });

    ch.sendMessage(Buffer.alloc(32 * 1024), { streamId: 1, priority: QOS.BULK });
    ch.sendMessage(Buffer.alloc(2 * 1024), { streamId: 2, priority: QOS.REALTIME });

    // Hacimli bandın uçtaki paketlerini kaybettir.
    const lost = [...ch.recovery.sent.values()].filter((e) => {
      const chunk = ch.chunks.get(e.meta);
      return chunk && chunk.priority === QOS.BULK;
    }).slice(0, 3);
    assert.ok(lost.length > 0, 'kaybettirilecek hacimli paket bulunmalı');
    ch._handleLost(lost);

    // Kuyruğun başı hâlâ gerçek zamanlı bant olmalı: kurtarma, bandını atlamaz.
    const head = ch.chunks.get(ch._peek());
    assert.equal(head.priority, QOS.REALTIME,
                 'hacimli yeniden gönderim, gerçek zamanlı verinin önüne geçmemeli');
  });

  await r.test('kuyruk sayaçları parça silinse bile sızdırmaz', () => {
    const ch = new ReliableChannel({ mtu: 300, send: () => {} });
    // Vazgeçme hatası bekleniyor: yakalanmazsa süreç düşer.
    ch.sendMessage(Buffer.alloc(16 * 1024), { streamId: 1, priority: QOS.BULK })
      .catch(() => {});
    assert.ok(ch.queuedBytes > 0);

    // Mesajı sonlandır: kuyruk da sayaçlar da temizlenmeli.
    const msgKey = [...ch.messages.keys()][0];
    ch._settleMessage(msgKey, new Error('vazgeçildi'));
    assert.equal(ch.queuedChunks, 0);
    assert.equal(ch.queuedBytes, 0, 'bayt sayacı sıfırlanmalı — aksi hâlde kuyruk kalıcı olarak dolu görünür');
  });

  await r.test('gerçek zamanlı bant daha küçük segment kullanır', () => {
    assert.ok(LIMITS.REALTIME_SEGMENT_BYTES < LIMITS.SEGMENT_BYTES);
    const sock = fakeSocket();
    const mux = makeMux(sock);
    const game = mux.openStream({ appId: 'mc', qos: QOS.REALTIME });
    game.write(Buffer.alloc(64 * 1024));

    const frames = dataFramesByStream(sock).get(game.id) || [];
    assert.ok(frames.length > 0);
    for (const f of frames) {
      assert.ok(f.bytes <= LIMITS.REALTIME_SEGMENT_BYTES,
                `gerçek zamanlı segment ${f.bytes} bayt — tavan aşıldı`);
    }
  });

  // ========================================================================
  // Hız şekillendirme kapsamı
  // ========================================================================
  await r.test('güvenilir olmayan datagram beklemez ama şekillendiriciye sayılır', () => {
    const ch = new ReliableChannel({ mtu: 1200, send: () => {} });
    ch.recovery.pacer.setRate(1_000_000);
    const before = ch.recovery.pacer.tokens;

    ch.sendUnreliable(Buffer.alloc(800));

    assert.equal(ch.stats.unreliableSent, 1);
    assert.ok(ch.recovery.stats.unpacedBytes >= 800,
              'gecikmeye duyarlı yük sayılmalı');
    assert.ok(ch.recovery.pacer.tokens < before,
              'jeton harcanmalı: güvenilir taraf hattı boş sanmamalı');
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
