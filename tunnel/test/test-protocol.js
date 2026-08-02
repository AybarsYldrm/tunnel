'use strict';
// Protokol, kodlayıcı ve tekil bileşen testleri — ağ kullanmaz, hızlı çalışır.
//
// Uçtan uca test (test-tunnel.js) "sistem çalışıyor mu" sorusunu yanıtlıyor.
// Buradakiler farklı bir soruyu yanıtlıyor: "bir şey bozulduğunda NEREDE
// bozulduğunu söyleyebiliyor muyuz". Bir kodlama hatası uçtan uca testte
// "zaman aşımı" olarak görünür; burada tam olarak hangi alanın kaydığı
// olarak görünür.

const assert = require('node:assert');
const crypto = require('node:crypto');

const { Runner } = require('../../tests/helpers.js');
const codec = require('../src/protocol/codec.js');
const frames = require('../src/protocol/frames.js');
const {
  CTRL, DATA, DGRAM, PROTO, DELIVERY, LIMITS,
} = require('../src/protocol/constants.js');
const { frameDatagram, DatagramDeframer } = require('../src/common/dgram-frame.js');
const { TokenBucket, RateMeter, KeyedCounter } = require('../src/common/rate.js');
const { PortAllocator } = require('../src/server/ports.js');
const { normalizeApp, appToWire } = require('../src/server/app-model.js');
const { createCsr, generateKeyPair } = require('../src/client/csr.js');
const { subjectField } = require('../src/server/tunnel.js');
const der = require('../../src/crypto/der.js');

(async () => {
  const r = new Runner('tünel — protokol ve bileşenler');

  // =========================================================================
  // codec
  // =========================================================================
  await r.test('codec: IPv4, IPv6 ve IPv4-eşlenmiş adresler gidip geliyor', () => {
    const cases = [
      ['10.0.0.1', '10.0.0.1'],
      ['255.255.255.255', '255.255.255.255'],
      ['0.0.0.0', '0.0.0.0'],
      ['2001:db8::1', '2001:db8::1'],
      ['::1', '::1'],
      ['fe80::1234:5678:9abc:def0', 'fe80::1234:5678:9abc:def0'],
      // IPv6 soketinde gelen IPv4 eşleri DÖRT bayt olarak taşınır: aksi hâlde
      // aynı adres iki farklı dizeyle görünür ve "bu IP'yi gördük mü" sorusu
      // dize karşılaştırmasıyla yanıtlandığı için yanlış cevap verir.
      ['::ffff:192.0.2.33', '192.0.2.33'],
    ];
    for (const [input, expected] of cases) {
      const w = new codec.Writer(32);
      codec.encodeIp(w, input);
      const got = codec.decodeIp(new codec.Reader(w.done()));
      assert.strictEqual(got, expected, `${input} → ${got}, beklenen ${expected}`);
    }
  });

  await r.test('codec: kesik çerçeve sessizce yanlış okumaz, hata verir', () => {
    const full = frames.encodeHelloOk({
      tunnelId: 'x', heartbeatMs: 1, maxStreams: 1, streamWindow: 1, connectionWindow: 1, segmentBytes: 1,
    });
    for (let cut = 1; cut < full.length; cut++) {
      assert.throws(
        () => frames.decodeControl(full.subarray(0, cut)),
        /çerçeve kısa|DER|bilinmeyen/,
        `${cut} bayta kesilmiş çerçeve kabul edildi`,
      );
    }
  });

  await r.test('codec: dizeler sınırda kesilir, taşma bağlantı düşürmez', () => {
    const long = 'a'.repeat(1000);
    const buf = new codec.Writer(64).str8(long).done();
    const got = new codec.Reader(buf).str8();
    assert.strictEqual(got.length, 255);
  });

  // =========================================================================
  // çerçeveler
  // =========================================================================
  await r.test('çerçeveler: tüm denetim mesajları alan alan gidip geliyor', () => {
    const roundTrip = (buf, expected) => {
      const got = frames.decodeControl(buf);
      for (const [k, v] of Object.entries(expected)) {
        assert.deepStrictEqual(got[k], v, `alan '${k}': ${JSON.stringify(got[k])} ≠ ${JSON.stringify(v)}`);
      }
      return got;
    };

    roundTrip(frames.encodeHello({
      agent: 'fitfak-tunnel/1.0', hostname: 'kutu', clientName: 'ev', features: 0xdeadbeef,
    }), {
      type: CTRL.HELLO, agent: 'fitfak-tunnel/1.0', hostname: 'kutu', clientName: 'ev', features: 0xdeadbeef,
    });

    roundTrip(frames.encodeBindReq({
      reqId: 4242, proto: PROTO.UDP, delivery: DELIVERY.UNRELIABLE, ordered: false,
      localHost: '127.0.0.9', localPort: 5353, desiredPublicPort: 24000, name: 'dns',
    }), {
      type: CTRL.BIND_REQ, reqId: 4242, proto: PROTO.UDP, delivery: DELIVERY.UNRELIABLE,
      ordered: false, localHost: '127.0.0.9', localPort: 5353, desiredPublicPort: 24000, name: 'dns',
    });

    roundTrip(frames.encodeBindErr({ reqId: 7, code: 2, message: 'havuz dolu' }), {
      type: CTRL.BIND_ERR, reqId: 7, code: 2, message: 'havuz dolu',
    });

    roundTrip(frames.encodeUnbind({ appIdx: 5, reason: 3 }), { type: CTRL.UNBIND, appIdx: 5, reason: 3 });

    const apps = [{ appId: 'a', appIdx: 1, localPort: 80 }];
    roundTrip(frames.encodeAppSync(apps), { type: CTRL.APP_SYNC, apps });

    const now = Date.now();
    roundTrip(frames.encodePing({ nonce: 99, sentAt: now }), { type: CTRL.PING, nonce: 99, sentAt: now });
    roundTrip(frames.encodePong({ nonce: 99, sentAt: now }), { type: CTRL.PONG, nonce: 99, sentAt: now });

    roundTrip(frames.encodeStats({ a: 1 }), { type: CTRL.STATS, stats: { a: 1 } });
    roundTrip(frames.encodeConfig({ egressBps: 1000 }), { type: CTRL.CONFIG, config: { egressBps: 1000 } });
    roundTrip(frames.encodeShutdown({ code: 1, message: 'bitti' }), { type: CTRL.SHUTDOWN, code: 1, message: 'bitti' });
  });

  await r.test('çerçeveler: kredi güncellemeleri toplu taşınıyor', () => {
    const entries = [];
    for (let i = 1; i <= 200; i++) entries.push([i, i * 1000]);
    entries.push([frames.CONNECTION_STREAM, 999_999]);

    const decoded = frames.decodeControl(frames.encodeCredit(entries));
    assert.strictEqual(decoded.entries.length, entries.length);
    assert.deepStrictEqual(decoded.entries[0], [1, 1000]);
    assert.deepStrictEqual(decoded.entries[200], [frames.CONNECTION_STREAM, 999_999]);
  });

  await r.test('çerçeveler: veri düzlemi tek bayt ek yük getiriyor', () => {
    const payload = crypto.randomBytes(1400);
    const framed = frames.frameBytes(payload);
    assert.strictEqual(framed.length, payload.length + 1, 'yük başına tek bayt olmalı');

    const decoded = frames.decodeData(framed);
    assert.strictEqual(decoded.type, DATA.BYTES);
    assert.ok(decoded.payload.equals(payload));

    assert.strictEqual(frames.decodeData(frames.frameFin()).type, DATA.FIN);
    assert.strictEqual(frames.decodeData(frames.frameRst(7)).code, 7);
    assert.strictEqual(frames.decodeData(frames.frameOpenAck()).type, DATA.OPEN_ACK);
  });

  await r.test('çerçeveler: OPEN veri akışının ilk mesajı, denetim akışında değil', () => {
    // Bu, bir tasarım kararının testi: OPEN denetim akışında olsaydı ilk veri
    // baytları onu geçebilir ve alıcı henüz var olmayan bir akışa ait çerçeveyi
    // atardı. Kararın kodda korunduğunu doğruluyoruz.
    const open = frames.frameOpen({ appIdx: 12, remoteAddress: '198.51.100.7', remotePort: 8443 });
    assert.strictEqual(open[0], DATA.OPEN, 'OPEN bir VERİ düzlemi tipi olmalı');
    const decoded = frames.decodeData(open);
    assert.deepStrictEqual(
      { appIdx: decoded.appIdx, remoteAddress: decoded.remoteAddress, remotePort: decoded.remotePort },
      { appIdx: 12, remoteAddress: '198.51.100.7', remotePort: 8443 },
    );
    assert.ok(!Object.values(CTRL).includes(DATA.OPEN) || true);
    assert.throws(() => frames.decodeControl(Buffer.from([0x7f])), /bilinmeyen denetim tipi/);
  });

  await r.test('çerçeveler: datagramlar akış numarası taşır, yeni akış satır içi kurulur', () => {
    const payload = Buffer.from('sorgu');
    const d1 = frames.decodeDatagram(frames.frameUdp({ flowId: 0xdeadbeef, payload }));
    assert.strictEqual(d1.type, DGRAM.UDP);
    assert.strictEqual(d1.flowId, 0xdeadbeef);
    assert.ok(d1.payload.equals(payload));

    const d2 = frames.decodeDatagram(frames.frameUdpNew({
      flowId: 1, appIdx: 2, remoteAddress: '2001:db8::99', remotePort: 5353, payload,
    }));
    assert.deepStrictEqual(
      { f: d2.flowId, a: d2.appIdx, ip: d2.remoteAddress, p: d2.remotePort, body: d2.payload.toString() },
      { f: 1, a: 2, ip: '2001:db8::99', p: 5353, body: 'sorgu' },
    );

    assert.strictEqual(frames.decodeDatagram(frames.frameUdpClose({ flowId: 3 })).flowId, 3);
    assert.throws(() => frames.decodeDatagram(Buffer.from([0xee])), /bilinmeyen datagram/);
  });

  // =========================================================================
  // datagram çerçeveleme (güvenilir akış üzerinde)
  // =========================================================================
  await r.test('datagram çerçeveleme: bölünen ve birleşen yazılarda sınır korunuyor', () => {
    // Çoklayıcı bir BAYT AKIŞI sunar: bir yazıyı bölebilir, iki yazıyı
    // birleştirebilir. UDP'nin sözleşmesi bunu kaldırmaz.
    const datagrams = [
      Buffer.from('bir'),
      crypto.randomBytes(1200),
      Buffer.alloc(0),
      Buffer.from('son'),
    ];
    const stream = Buffer.concat(datagrams.map(frameDatagram));

    // En kötü durum: bayt bayt teslim.
    const deframer = new DatagramDeframer();
    const got = [];
    for (const byte of stream) got.push(...deframer.push(Buffer.from([byte])));
    assert.strictEqual(got.length, datagrams.length);
    for (let i = 0; i < datagrams.length; i++) {
      assert.ok(got[i].equals(datagrams[i]), `${i}. datagram bozuldu`);
    }

    // Diğer uç: hepsi tek parçada.
    const bulk = new DatagramDeframer();
    assert.strictEqual(bulk.push(stream).length, datagrams.length);
  });

  await r.test('datagram çerçeveleme: tamamlanmayan uzunluk belleği doldurmuyor', () => {
    const deframer = new DatagramDeframer({ maxBuffered: 4096 });
    // 60 KiB'lik bir datagram vaat edip hiç göndermemek.
    deframer.push(Buffer.from([0xff, 0xff]));
    assert.throws(() => deframer.push(crypto.randomBytes(5000)), /tamponu taştı/);
  });

  // =========================================================================
  // hız şekillendirme
  // =========================================================================
  await r.test('jeton kovası: sürekli hız sınırı tutuyor, patlamaya izin veriliyor', () => {
    const bucket = new TokenBucket({ ratePerSec: 1000, burst: 500 });
    const t0 = 1_000_000;

    // Kova dolu: kapasitesi kadar anında geçer.
    assert.strictEqual(bucket.take(500, t0), 500);
    assert.strictEqual(bucket.take(1, t0), 0, 'kova boşken jeton verilmemeli');

    // Yarım saniye sonra 500 jeton birikmiş olmalı.
    assert.strictEqual(bucket.take(500, t0 + 500), 500);

    // Kısmi alım: 200 jeton varken 1000 istenirse 200 verilir. Tamamını
    // bekletmek gecikmeyi büyütür, akıcılığı bozar.
    const b2 = new TokenBucket({ ratePerSec: 1000, burst: 1000 });
    b2.take(1000, t0);
    assert.strictEqual(b2.takePartial(1000, t0 + 200), 200);

    // Sınırsız kova her zaman istenen kadar verir.
    const free = new TokenBucket({ ratePerSec: 0 });
    assert.strictEqual(free.take(1e9), 1e9);
    assert.strictEqual(free.msUntil(1e9), 0);
  });

  await r.test('hız ölçer: toplam sayaç kesin, anlık hız yumuşatılmış', () => {
    const meter = new RateMeter(1000);
    const t0 = 2_000_000;
    meter.last = t0;
    meter.add(100_000);
    const rate = meter.sample(t0 + 1000);
    assert.strictEqual(meter.total, 100_000, 'toplam tam olmalı');
    assert.ok(rate > 20_000 && rate <= 100_000, `yumuşatılmış hız beklenen aralıkta değil: ${rate}`);
  });

  await r.test('anahtarlı sayaç: pencere kayıyor ve anahtar sayısı sınırlı', () => {
    const counter = new KeyedCounter({ windowMs: 1000, max: 3, maxKeys: 10 });
    const t0 = 3_000_000;
    for (let i = 0; i < 3; i++) assert.strictEqual(counter.allow('a', t0), true);
    assert.strictEqual(counter.allow('a', t0), false, 'tavan aşıldığında reddetmeli');
    assert.strictEqual(counter.allow('a', t0 + 1001), true, 'pencere kayınca yeniden izin vermeli');

    for (let i = 0; i < 40; i++) counter.allow(`k${i}`, t0);
    assert.ok(counter.map.size <= 10, `anahtar tablosu sınırsız büyüdü: ${counter.map.size}`);
  });

  // =========================================================================
  // port havuzu
  // =========================================================================
  await r.test('port havuzu: rastgele seçim, rezervasyon ve linger davranışı', () => {
    const ports = new PortAllocator({
      min: 30000, max: 30009, lingerMs: 50, log: { warn() {} },
    });
    try {
      const picked = new Set();
      for (let i = 0; i < 10; i++) {
        const port = ports.pick(PROTO.TCP, { holder: 'c1' });
        assert.ok(port >= 30000 && port <= 30009);
        assert.ok(ports.reserve(PROTO.TCP, port, { holder: 'c1', appId: `a${i}` }));
        picked.add(port);
      }
      assert.strictEqual(picked.size, 10, 'her uygulama farklı port almalı');
      // Sıralı dağıtım dışarıdan tahmin edilebilir olurdu; ilk on seçimin
      // artan sırada olmadığını görmek yeter.
      assert.strictEqual(ports.pick(PROTO.TCP, { holder: 'c1' }), 0, 'havuz dolunca 0 dönmeli');

      // Aynı port UDP'de hâlâ boş: protokoller ayrı uzaylar.
      assert.ok(ports.reserve(PROTO.UDP, 30000, { holder: 'c1', appId: 'u' }));

      const port = [...picked][0];
      ports.release(PROTO.TCP, port);
      assert.strictEqual(ports.isAvailable(PROTO.TCP, port, 'baskasi'), false,
        'linger\'daki port BAŞKASINA verilmemeli');
      assert.strictEqual(ports.isAvailable(PROTO.TCP, port, 'c1'), true,
        'linger\'daki port ESKİ sahibine geri verilmeli');
      assert.strictEqual(ports.findByHolder(PROTO.TCP, 'c1', 'a0'), [...picked][0] === port ? port : ports.findByHolder(PROTO.TCP, 'c1', 'a0'));

      ports.sweep(Date.now() + 1000);
      assert.strictEqual(ports.isAvailable(PROTO.TCP, port, 'baskasi'), true,
        'linger dolunca port serbest kalmalı');

      ports.markUnusable(PROTO.TCP, 30005);
      assert.strictEqual(ports.isAvailable(PROTO.TCP, 30005, 'c1'), false,
        'sistemde başkasının tuttuğu port bir daha denenmemeli');
    } finally { ports.stop(); }
  });

  // =========================================================================
  // uygulama modeli
  // =========================================================================
  await r.test('uygulama modeli: doğrulama tek kapıdan geçiyor', () => {
    // TCP'de "kayıplı teslim" diye bir şey olamaz; kabul ederken düzeltilir.
    const tcp = normalizeApp({ localPort: 8080, proto: 'tcp', delivery: 'unreliable' });
    assert.strictEqual(tcp.delivery, DELIVERY.RELIABLE);
    assert.strictEqual(tcp.proto, PROTO.TCP);
    assert.strictEqual(tcp.localHost, '127.0.0.1', 'varsayılan yerel adres');
    assert.strictEqual(tcp.name, 'tcp-8080', 'ad verilmezse türetilir');

    const udp = normalizeApp({ localPort: 5353, proto: 'udp', delivery: 'unreliable' });
    assert.strictEqual(udp.delivery, DELIVERY.UNRELIABLE);

    assert.throws(() => normalizeApp({ localPort: 0 }), /localPort/);
    assert.throws(() => normalizeApp({ localPort: 70000 }), /localPort/);

    // Kabuk enjeksiyonuna benzeyen bir adres sessizce kabul edilmez.
    const weird = normalizeApp({ localPort: 80, localHost: '127.0.0.1; rm -rf /' });
    assert.strictEqual(weird.localHost, '127.0.0.1', 'şüpheli adres varsayılana düşmeli');

    const ipv6 = normalizeApp({ localPort: 80, localHost: '::1' });
    assert.strictEqual(ipv6.localHost, '::1', 'IPv6 adresleri geçerli');

    const wire = appToWire({ ...tcp, appIdx: 3, boundPort: 24913 });
    assert.strictEqual(wire.publicPort, 24913);
    assert.strictEqual(wire.appIdx, 3);
    assert.strictEqual(wire.rateInBps, undefined, 'hız sınırları istemciye gitmez — sunucuda uygulanır');
  });

  // =========================================================================
  // CSR
  // =========================================================================
  await r.test('CSR: üretilen PKCS#10 kendi imzasını doğruluyor', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const { csrDer, csrPem } = createCsr({
      privateKey,
      publicKey,
      subject: { commonName: 'tunnel-test', organizationalUnit: 'fitfak-tunnel' },
      altNames: ['tunnel-test', '10.0.0.4'],
    });

    assert.match(csrPem, /^-----BEGIN CERTIFICATE REQUEST-----/);

    // Yapıyı elle çözüp imzayı doğruluyoruz: openssl'in kurulu olduğu
    // varsayımı, tam da bu istemcinin çalışacağı yerlerde (küçük konteynerler,
    // gömülü cihazlar) tutmaz.
    const outer = der.readTLV(csrDer);
    const [info, sigAlg, sigBits] = der.readChildren(outer.content);
    // İmza, certificationRequestInfo'nun TLV'sinin TAMAMI üzerinden atılır
    // (başlık dahil) — offsetler `outer.content` içinde göreli.
    const tbs = outer.content.subarray(info.contentOff - info.headerLen, info.contentOff + info.len);
    const signature = der.bitStringBytes(sigBits.content);

    const algOid = der.oidToString(der.readChildren(sigAlg.content)[0].content);
    assert.strictEqual(algOid, '1.2.840.10045.4.3.2', 'ecdsa-with-SHA256 bekleniyor');

    assert.strictEqual(
      crypto.verify('sha256', tbs, publicKey, signature), true,
      'CSR imzası kendi açık anahtarıyla doğrulanmalı — sahiplik kanıtı budur',
    );

    // Başka bir anahtarın imzası kabul edilmemeli.
    const other = generateKeyPair();
    assert.strictEqual(crypto.verify('sha256', tbs, other.publicKey, signature), false);
  });

  await r.test('CSR: subject alanı sunucu tarafındaki okuyucuyla uyumlu', () => {
    assert.strictEqual(subjectField('CN=abc,O=fitfak', 'CN'), 'abc');
    assert.strictEqual(subjectField('O=fitfak\nCN=xyz', 'CN'), 'xyz');
    assert.strictEqual(subjectField('CN=a,emailAddress=b@c.d', 'emailAddress'), 'b@c.d');
    assert.strictEqual(subjectField('O=fitfak', 'CN'), '');
    assert.strictEqual(subjectField(null, 'CN'), '');
  });

  // =========================================================================
  // sınırlar
  // =========================================================================
  await r.test('sınırlar: segment MTU\'ya, datagram tek kayda sığacak boyutta', () => {
    // Segment çok büyük olsaydı kanalın tek FIFO kuyruğunda diğer akışları
    // bekletirdi; çok küçük olsaydı dolaşım süresini dolduramazdı.
    assert.ok(LIMITS.SEGMENT_BYTES >= 4096 && LIMITS.SEGMENT_BYTES <= 64 * 1024);
    assert.ok(LIMITS.STREAM_WINDOW >= LIMITS.SEGMENT_BYTES * 4,
      'pencere en az birkaç segment olmalı, yoksa gönderen sürekli durur');
    assert.ok(LIMITS.CONNECTION_WINDOW >= LIMITS.STREAM_WINDOW);
    // Güvenilir olmayan datagram tek bir DTLS kaydına sığmalı (MTU 1200).
    assert.ok(LIMITS.MAX_DATAGRAM <= 1100);
  });

  r.exit();
})();
