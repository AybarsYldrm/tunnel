'use strict';
// Sertleştirme denetimi — bulunan açıkların kapalı KALDIĞINI sabitler.
//
// Buradaki her test, gerçekten var olmuş bir zafiyetin ya da sessiz bir
// yanlış davranışın yeniden ortaya çıkmasını engelliyor. Bir güvenlik
// düzeltmesi, onu koruyan bir test olmadan bir sonraki yeniden yazımda
// kaybolur.

const assert = require('node:assert/strict');

const { Runner } = require('../../tests/helpers.js');
const { Guard } = require('../src/server/guard.js');
const { PeerRegistry } = require('../src/server/peers.js');
const { canonicalIp } = require('../src/protocol/codec.js');
const { AdminAuth, MAX_PENDING_FLOWS } = require('../src/server/admin/auth.js');
const { buildCsp } = require('../src/server/admin/server.js');
const { ReliableChannel } = require('../../src/reliable/channel.js');
const { DatagramDeframer } = require('../src/common/dgram-frame.js');
const { decodeControl, decodeDatagram, decodeData } = require('../src/protocol/frames.js');

const r = new Runner('tünel — sertleştirme');

const noopLog = {
  trace() {}, debug() {}, info() {}, warn() {}, error() {},
  child() { return noopLog; }, hex() {},
};

(async () => {
  // ========================================================================
  // Adres normalizasyonu — engelin SESSİZCE çalışmaması
  // ========================================================================
  await r.test('IPv4-eşlenmiş IPv6 ile düz IPv4 aynı adrestir', () => {
    assert.equal(canonicalIp('::ffff:203.0.113.7'), '203.0.113.7');
    assert.equal(canonicalIp('203.0.113.7'), '203.0.113.7');
    // IPv6 gösterimi sıkıştırılır ve küçük harfe indirilir (RFC 5952).
    assert.equal(canonicalIp('2001:DB8:0:0:0:0:0:1'), '2001:db8::1');
    assert.equal(canonicalIp('2001:db8::1'), '2001:db8::1');
    // Bölge kimliği (zone) düşer: fe80::1%eth0 ile fe80::1 aynı uç.
    assert.equal(canonicalIp('fe80::1%eth0'), 'fe80::1');
  });

  await r.test('engel, adres BAŞKA BİÇİMDE geldiğinde de tutar', () => {
    const g = new Guard({}, noopLog);
    // Yönetici panele düz IPv4 yazıyor...
    g.blockAddress('203.0.113.7', { reason: 'test', actor: 'admin' });

    // ...ama çift yığınlı bir soketten bağlantı eşlenmiş biçimde geliyor.
    assert.equal(g.isBlocked('::ffff:203.0.113.7'), true,
                 'engel eşlenmiş biçimi de kapsamalı — yoksa sessizce çalışmaz');
    assert.equal(g.checkAccept('::ffff:203.0.113.7', 'app1').ok, false);
    assert.equal(g.checkUdpInbound('::ffff:203.0.113.7', 100, true).ok, false);

    // Kaldırma da her iki biçimle çalışmalı.
    g.unblockAddress('::ffff:203.0.113.7');
    assert.equal(g.isBlocked('203.0.113.7'), false);
    g.stop();
  });

  await r.test('kaynak başına sayaçlar biçim yüzünden ikiye bölünmez', () => {
    const g = new Guard({ maxConnectionsPerIp: 2 }, noopLog);
    g.noteOpen('203.0.113.9', 'app1');
    g.noteOpen('::ffff:203.0.113.9', 'app1');
    // İki farklı biçim aynı kaynağı gösteriyor: sınır AŞILMIŞ olmalı.
    assert.equal(g.checkAccept('203.0.113.9', 'app1').ok, false,
                 'aynı kaynağın iki gösterimi tek sayaçta toplanmalı');
    g.stop();
  });

  await r.test('geçersiz adres engellenemez — yanlış güven hissi üretmez', () => {
    const g = new Guard({}, noopLog);
    for (const bad of [
      '203.0.113.', 'değil', '999.1.1.1', '', '1.2.3.4.5',
      '0x10.0.0.1',      // onaltılık: Number() kabul ederdi
      '7. 0.0.1',        // İÇERİDE boşluk
      '1.2.3',
      '1.2.3.4:80',      // port eklenmiş
    ]) {
      assert.throws(() => g.blockAddress(bad), /geçersiz IP|adres gerekli/,
                    `reddedilmeliydi: ${JSON.stringify(bad)}`);
    }
    assert.equal(g.listBlocks().length, 0);

    // Kenarlardaki boşluk BİLİNÇLİ olarak kırpılır: panele yapıştırılan bir
    // adresin başındaki boşluk yüzünden "geçersiz" demek, kullanıcıyı
    // görünmeyen bir karakteri aramaya gönderirdi.
    g.blockAddress('  198.51.100.9  ', { actor: 'test' });
    assert.equal(g.isBlocked('198.51.100.9'), true);
    g.stop();
  });

  await r.test('ziyaretçi defteri de kanonik adres tutar', () => {
    const peers = new PeerRegistry({ log: noopLog });
    const peer = peers.open({
      appId: 'a', appName: 'mc', protocol: 'tcp', publicPort: 25565,
      tunnelId: 't', tunnelName: 'ev', address: '::ffff:198.51.100.5', port: 5000,
      kick: () => {},
    });
    assert.equal(peer.address, '198.51.100.5');
    // Panelden gelen düz biçimle atma da çalışmalı.
    assert.equal(peers.kickAddress('198.51.100.5'), 1);
    assert.equal(peers.list().length, 0);
  });

  // ========================================================================
  // Bellek tükenmesi — alıcı tarafın belleği GÖNDERENİN elinde olmamalı
  // ========================================================================
  await r.test('mesaj tavanı: aşırı parça sayısı bildiren çerçeve reddedilir', () => {
    const ch = new ReliableChannel({ mtu: 1200, maxMessageBytes: 64 * 1024, send: () => {} });
    const errors = [];
    ch.on('error', (e) => errors.push(e));

    // 65535 parça × ~1182 bayt ≈ 78 MB iddiası. Tek bayt bile ayrılmamalı.
    const frame = Buffer.alloc(18 + 100);
    frame[0] = 0x01;            // DATA
    frame.writeUIntBE(1, 2, 6); // pn
    frame.writeUInt16BE(1, 8);  // streamId
    frame.writeUInt32BE(1, 10); // msgId
    frame.writeUInt16BE(0, 14); // idx
    frame.writeUInt16BE(65535, 16); // count
    ch.onData(frame);

    assert.equal(ch.reassembly.size, 0, 'hiçbir şey ayrılmamalı');
    assert.equal(ch.stats.oversized, 1);
    assert.match(errors[0].message, /çok büyük/);
    ch.close();
  });

  await r.test('mesaj tavanı: parça BOYUTU şişirilerek de aşılamaz', () => {
    // Parça SAYISI ön denetimi, gönderenin bildirdiği `count` ile MTU'yu
    // çarpar. Ama gelen çerçevenin boyutunu gönderen belirler: MTU 1200
    // denilip 16 KB'lık parçalar gönderilebilir. Bu yüzden biriken baytları
    // da saymak gerekir — ön denetim tek başına yeterli değil.
    const ch = new ReliableChannel({ mtu: 1200, maxMessageBytes: 8 * 1024, send: () => {} });
    const errors = [];
    ch.on('error', (e) => errors.push(e));

    const oversizedPayload = 16 * 1024;
    const count = 4;                     // ön denetim: 4 × 1182 = 4.7 KB, geçer
    let pn = 1;
    for (let idx = 0; idx < count; idx++) {
      const frame = Buffer.alloc(18 + oversizedPayload);
      frame[0] = 0x01;
      frame.writeUIntBE(pn++, 2, 6);
      frame.writeUInt16BE(1, 8);
      frame.writeUInt32BE(7, 10);
      frame.writeUInt16BE(idx, 14);
      frame.writeUInt16BE(count, 16);
      ch.onData(frame);
    }
    assert.ok(ch.stats.oversized >= 1, 'biriken bayt tavanı aşılınca mesaj düşürülmeli');
    assert.equal(ch.reassembly.size, 0);
    assert.equal(ch.reassemblyBytes, 0, 'sayaç sızdırmamalı');
    assert.match(errors[0].message, /tavan/);
    ch.close();
  });

  await r.test('mesaj tavanı: bildirilen parça sayısı her seferinde reddedilir', () => {
    // Reddedilen bir mesaj için gelen HER çerçeve yeniden reddedilmeli;
    // "bir kez reddet sonra unut" bir durum tutar ve o durum da şişebilirdi.
    const ch = new ReliableChannel({ mtu: 1200, maxMessageBytes: 64 * 1024, send: () => {} });
    ch.on('error', () => {});
    for (let idx = 0; idx < 5; idx++) {
      const frame = Buffer.alloc(18 + 100);
      frame[0] = 0x01;
      frame.writeUIntBE(idx + 1, 2, 6);
      frame.writeUInt16BE(1, 8);
      frame.writeUInt32BE(1, 10);
      frame.writeUInt16BE(idx, 14);
      frame.writeUInt16BE(65535, 16);
      ch.onData(frame);
    }
    assert.equal(ch.reassembly.size, 0, 'hiçbir durum tutulmamalı');
    assert.equal(ch.stats.oversized, 5);
    ch.close();
  });

  await r.test('toplam yeniden birleştirme tavanı uygulanır', () => {
    const ch = new ReliableChannel({
      mtu: 1200, maxMessageBytes: 1024 * 1024, maxReassemblyBytes: 16 * 1024, send: () => {},
    });
    ch.on('error', () => {});

    // Her biri yarım kalan çok sayıda mesaj: tek tek küçük, toplamda büyük.
    let pn = 1;
    for (let msg = 1; msg <= 60; msg++) {
      const frame = Buffer.alloc(18 + 1000);
      frame[0] = 0x01;
      frame.writeUIntBE(pn++, 2, 6);
      frame.writeUInt16BE(1, 8);
      frame.writeUInt32BE(msg, 10);
      frame.writeUInt16BE(0, 14);
      frame.writeUInt16BE(10, 16);   // 10 parça bekleniyor, 1 tanesi geldi
      ch.onData(frame);
    }
    assert.ok(ch.reassemblyBytes <= 16 * 1024,
              `toplam tavan aşıldı: ${ch.reassemblyBytes}`);
    assert.ok(ch.stats.reassemblyDropped > 0, 'yer açmak için eski mesajlar düşmeli');
    ch.close();
  });

  await r.test('sıralı teslim tamponunun BAYT tavanı var', () => {
    // Eski hâlde yalnızca MESAJ SAYISI sınırlıydı. Mesaj başına tavan 16 MiB
    // olduğu için tek bir akışta gigabaytlarca tampon açılabiliyordu ve bunu
    // tetikleyen taraf UZAKTAKİ EŞTİ: sırayı bilerek bozup (ilk mesajı hiç
    // göndermeyip) arkasındakileri yığmak yeterli.
    const ch = new ReliableChannel({
      mtu: 300, ordered: true, send: () => {},
      maxOrderedBuffer: 10_000, maxOrderedBytes: 64 * 1024,
    });

    const delivered = [];
    const gaps = [];
    ch.on('message', (d) => delivered.push(d.length));
    ch.on('gap', (g) => gaps.push(g));

    // msgId 1 HİÇ gelmiyor: 2..N sıralı teslim tamponunda birikir.
    for (let msgId = 2; msgId <= 200; msgId++) {
      ch._deliver(7, msgId, Buffer.alloc(1024), true);
    }

    assert.ok(gaps.length > 0, 'bayt tavanı aşılınca sıra atlanmalı');
    assert.ok(ch.orderedBytes <= 64 * 1024,
              `sıralı tampon tavanı aşılmamalı: ${ch.orderedBytes}`);
  });

  await r.test('sıralı tampon muhasebesi teslimde ve kapanışta sızdırmaz', () => {
    const ch = new ReliableChannel({ mtu: 300, ordered: true, send: () => {} });
    ch.on('message', () => {});

    // Sırayla gelen mesajlar hiç birikmez.
    for (let msgId = 1; msgId <= 20; msgId++) {
      ch._deliver(3, msgId, Buffer.alloc(2048), true);
    }
    assert.equal(ch.orderedBytes, 0, 'teslim edilen bayt sayaçtan düşmeli');

    // Sırası gelmeyenler birikir; akış bırakılınca payları geri verilmeli.
    // Aksi hâlde kapanan her akış tavandan kalıcı bir pay götürür ve tavan
    // yavaşça tükenir — teşhisi en zor arıza türü.
    ch._deliver(4, 5, Buffer.alloc(4096), true);
    assert.equal(ch.orderedBytes, 4096);
    ch._dropOrderedState(4);
    assert.equal(ch.orderedBytes, 0);
  });

  await r.test('datagram çözücüsü sınırsız tampon biriktirmez', () => {
    const d = new DatagramDeframer({ maxBuffered: 4096 });
    // Hiç tamamlanmayan bir uzunluk bildirip beslemeye devam etmek.
    const head = Buffer.alloc(2);
    head.writeUInt16BE(0xffff, 0);
    d.push(head);
    assert.throws(() => {
      for (let i = 0; i < 10; i++) d.push(Buffer.alloc(1024));
    }, /taştı/);
  });

  // ========================================================================
  // Çerçeve ayrıştırıcıları — kısa/bozuk girdi çökertmemeli
  // ========================================================================
  await r.test('bozuk çerçeveler çökme değil ProtocolError üretir', () => {
    const decoders = [decodeControl, decodeDatagram, decodeData];
    for (const decode of decoders) {
      assert.throws(() => decode(Buffer.alloc(0)), /boş|ProtocolError/i);
      for (let type = 0; type < 256; type++) {
        for (const len of [1, 2, 5, 9, 17]) {
          const buf = Buffer.alloc(len);
          buf[0] = type;
          try { decode(buf); } catch (e) {
            assert.equal(e.name, 'ProtocolError',
                         `beklenmeyen hata tipi (${decode.name}, tip ${type}): ${e.stack}`);
          }
        }
      }
    }
  });

  await r.test('rastgele girdi ayrıştırıcıları çökertmez', () => {
    const crypto = require('node:crypto');
    for (let i = 0; i < 3000; i++) {
      const buf = crypto.randomBytes(1 + (i % 64));
      for (const decode of [decodeControl, decodeDatagram, decodeData]) {
        try { decode(buf); } catch (e) {
          assert.equal(e.name, 'ProtocolError', `beklenmeyen hata: ${e.stack}`);
        }
      }
    }
  });

  // ========================================================================
  // Yönetim yüzeyi — kimlik doğrulamasız erişilebilen yollar
  // ========================================================================
  await r.test('bekleyen giriş akışları sınırsız büyümez', () => {
    // `/login` kimlik doğrulaması İSTEMEZ; tavan olmadan panele ulaşabilen
    // biri süreç belleğini büyütebilirdi.
    const auth = new AdminAuth({
      config: {
        idpUrl: 'http://idp.local', clientId: 'x', clientSecret: 'y',
        redirectUri: 'http://localhost/cb', sessionTtlMs: 1000, insecureNoAuth: false,
      },
      log: noopLog,
    });
    for (let i = 0; i < MAX_PENDING_FLOWS * 2; i++) auth.beginLogin({ returnTo: '/' });
    assert.ok(auth.flows.size <= MAX_PENDING_FLOWS,
              `akış tavanı aşıldı: ${auth.flows.size}`);
    auth.stop();
  });

  await r.test('CSP: unsafe-* yapılandırmayla dahi açılamaz', () => {
    const csp = buildCsp({
      scriptSrc: ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", 'https://ok.example'],
      connectSrc: ["'unsafe-inline'"],
      imgSrc: ["'unsafe-inline'"],
    });
    assert.ok(!/unsafe-/.test(csp), `politikaya unsafe sızdı: ${csp}`);
    assert.ok(csp.includes('https://ok.example'), 'meşru köken eklenmeli');
  });

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
