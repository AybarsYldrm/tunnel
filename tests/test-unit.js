'use strict';
// Birim testleri — kayıt katmanı, çerçeveleme, uzantılar, kripto ilkelleri,
// SRTP/SRTCP, güvenilir kanal, PKI ve seçenek doğrulaması.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Runner, readCert, certsAvailable } = require('./helpers.js');

const {
  CONTENT_TYPE, HS_TYPE, VERSION, NAMED_GROUP, SRTP_PROFILE, SRTP_PROFILE_PARAMS, EXT_TYPE,
  CIPHER_SUITE,
} = require('../src/constants.js');
const {
  encodePlaintext, decodePlaintext, readUInt48BE, writeUInt48BE,
} = require('../src/record/plaintext.js');
const {
  protectRecord, unprotectRecord, protectRecord12, unprotectRecord12,
} = require('../src/record/protected.js');
const { ReplayWindow } = require('../src/record/replay-window.js');
const { buildAck, parseAck } = require('../src/record/ack.js');
const {
  buildAeadNonce, buildInnerPlaintext, parseInnerPlaintext, snMask, reconstructSeq,
} = require('../src/crypto/aead.js');
const { prf12 } = require('../src/crypto/key-schedule.js');
const { getSuite, selectSuite, resolveSuiteId } = require('../src/crypto/cipher-suite.js');
const ecdhe = require('../src/crypto/ecdhe.js');
const {
  buildClientHello, parseClientHello, buildServerHello, parseServerHello,
  encodeHandshake, decodeHandshake,
} = require('../src/handshake/framing.js');
const ext = require('../src/handshake/extensions.js');
const m12 = require('../src/handshake/messages.js');
const { HsReassembler } = require('../src/handshake/reassembler.js');
const { CookieMinter } = require('../src/handshake/cookie.js');
const { Transcript, Transcript12 } = require('../src/handshake/transcript.js');
const { SrtpContext, demuxPacket, rtpHeaderLength, estimateIndex } = require('../src/record/srtp.js');
const { ReliableChannel, DEFAULTS } = require('../src/reliable/channel.js');
const der = require('../src/crypto/der.js');
const x509mod = require('../src/crypto/x509.js');
const revocationMod = require('../src/crypto/revocation.js');
const pki = require('../src/crypto/pki.js');
const { normalizeOptions, createSecureContext } = require('../src/options.js');

const r = new Runner('birim testleri');
const HAVE_CERTS = certsAvailable();

const makeRtp = (seq, ssrc, payload) => {
  const p = Buffer.alloc(12 + payload.length);
  p[0] = 0x80; p[1] = 96;
  p.writeUInt16BE(seq, 2); p.writeUInt32BE(seq * 160, 4); p.writeUInt32BE(ssrc, 8);
  payload.copy(p, 12);
  return p;
};

(async () => {
  // ======================================================================
  // Kayıt katmanı — plaintext
  // ======================================================================
  await r.test('DTLSPlaintext encode/decode roundtrip', () => {
    const frag = Buffer.from('handshake bytes');
    const rec = encodePlaintext({ type: CONTENT_TYPE.HANDSHAKE, epoch: 0, sequenceNumber: 42, fragment: frag });
    const out = decodePlaintext(rec, 0);
    assert.equal(out.type, CONTENT_TYPE.HANDSHAKE);
    assert.equal(out.epoch, 0);
    assert.equal(out.sequenceNumber, 42);
    assert.deepEqual(out.fragment, frag);
    assert.equal(out.bytesConsumed, rec.length);
  });

  await r.test('uint48 sınır değerleri', () => {
    const b = Buffer.alloc(6);
    writeUInt48BE(b, 0xffffffffffff, 0);
    assert.equal(readUInt48BE(b, 0), 0xffffffffffff);
    writeUInt48BE(b, 0, 0);
    assert.equal(readUInt48BE(b, 0), 0);
    assert.throws(() => writeUInt48BE(b, 0x1000000000000, 0), RangeError);
  });

  await r.test('kesik kayıt hata verir', () => {
    const rec = encodePlaintext({ type: 22, epoch: 0, sequenceNumber: 1, fragment: Buffer.alloc(50) });
    assert.throws(() => decodePlaintext(rec.subarray(0, 30), 0), /truncated/);
  });

  // ======================================================================
  // Kayıt katmanı — DTLS 1.3 koruması
  // ======================================================================
  const suite13 = getSuite(0x1301);
  const k13 = { key: crypto.randomBytes(16), iv: crypto.randomBytes(12), sn: crypto.randomBytes(16) };

  await r.test('DTLS 1.3 protect/unprotect roundtrip', () => {
    const content = Buffer.from('gizli uygulama verisi');
    const rec = protectRecord({
      contentType: CONTENT_TYPE.APPLICATION_DATA, content, recordSeq: 7, epoch: 3,
      writeKey: k13.key, writeIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher,
    });
    const out = unprotectRecord({
      record: rec, offset: 0,
      readKey: k13.key, readIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher, lastSeq: 6, epoch: 3,
    });
    assert.equal(out.contentType, CONTENT_TYPE.APPLICATION_DATA);
    assert.deepEqual(out.content, content);
    assert.equal(out.fullSeq, 7);
    assert.equal(out.bytesConsumed, rec.length);
  });

  await r.test('DTLS 1.3: sequence number şifreli, uzunluk açık', () => {
    // §4.2.3 — seq maskelenir, length alanı maskelenmez.
    const rec = protectRecord({
      contentType: 23, content: Buffer.alloc(100, 7), recordSeq: 0x1234, epoch: 3,
      writeKey: k13.key, writeIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher,
    });
    assert.notEqual(rec.readUInt16BE(1), 0x1234, 'seq düz metin kalmamalı');
    assert.equal(rec.readUInt16BE(3), rec.length - 5, 'length alanı gerçek uzunluk olmalı');
  });

  await r.test('DTLS 1.3: tek bit bozulması AEAD ile yakalanır', () => {
    const rec = protectRecord({
      contentType: 23, content: Buffer.from('abc'), recordSeq: 1, epoch: 3,
      writeKey: k13.key, writeIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher,
    });
    rec[rec.length - 1] ^= 0x01;
    assert.throws(() => unprotectRecord({
      record: rec, readKey: k13.key, readIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher, lastSeq: 0, epoch: 3,
    }), /AEAD authentication failed/);
  });

  await r.test('DTLS 1.3: birden çok kayıt tek datagramda', () => {
    const mk = (seq, txt) => protectRecord({
      contentType: 23, content: Buffer.from(txt), recordSeq: seq, epoch: 3,
      writeKey: k13.key, writeIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher,
    });
    const dg = Buffer.concat([mk(0, 'bir'), mk(1, 'iki')]);
    const a = unprotectRecord({ record: dg, offset: 0, readKey: k13.key, readIv: k13.iv, snKey: k13.sn,
      aeadAlg: suite13.aead, snCipher: suite13.sn_cipher, lastSeq: 0, epoch: 3 });
    const b = unprotectRecord({ record: dg, offset: a.bytesConsumed, readKey: k13.key, readIv: k13.iv,
      snKey: k13.sn, aeadAlg: suite13.aead, snCipher: suite13.sn_cipher, lastSeq: 0, epoch: 3 });
    assert.equal(a.content.toString(), 'bir');
    assert.equal(b.content.toString(), 'iki');
  });

  for (const id of [0x1301, 0x1302, 0x1303]) {
    const s = getSuite(id);
    await r.test(`DTLS 1.3 roundtrip: ${s.name}`, () => {
      const keys = {
        key: crypto.randomBytes(s.keyLen), iv: crypto.randomBytes(s.ivLen),
        sn: crypto.randomBytes(s.sn_keyLen),
      };
      const content = crypto.randomBytes(200);
      const rec = protectRecord({
        contentType: 23, content, recordSeq: 5, epoch: 3,
        writeKey: keys.key, writeIv: keys.iv, snKey: keys.sn,
        aeadAlg: s.aead, snCipher: s.sn_cipher,
      });
      const out = unprotectRecord({
        record: rec, readKey: keys.key, readIv: keys.iv, snKey: keys.sn,
        aeadAlg: s.aead, snCipher: s.sn_cipher, lastSeq: 4, epoch: 3,
      });
      assert.deepEqual(out.content, content);
    });
  }

  // ======================================================================
  // Kayıt katmanı — DTLS 1.2 koruması
  // ======================================================================
  for (const id of [0xc02b, 0xc02c, 0xcca9]) {
    const s = getSuite(id);
    await r.test(`DTLS 1.2 roundtrip: ${s.name}`, () => {
      const key = crypto.randomBytes(s.keyLen);
      const salt = crypto.randomBytes(s.saltLen);
      const content = crypto.randomBytes(300);
      const rec = protectRecord12({
        contentType: 23, content, epoch: 1, recordSeq: 9, suite: s, key, salt,
      });
      const parsed = decodePlaintext(rec, 0);
      assert.equal(parsed.epoch, 1);
      assert.equal(parsed.sequenceNumber, 9);
      const out = unprotectRecord12({ record: parsed, suite: s, key, salt });
      assert.equal(out.contentType, 23);
      assert.deepEqual(out.content, content);
    });
  }

  await r.test('DTLS 1.2: bozulmuş kayıt reddedilir', () => {
    const s = getSuite(0xc02b);
    const key = crypto.randomBytes(16);
    const salt = crypto.randomBytes(4);
    const rec = protectRecord12({
      contentType: 23, content: Buffer.from('veri'), epoch: 1, recordSeq: 1, suite: s, key, salt,
    });
    rec[rec.length - 2] ^= 0xff;
    assert.throws(() => unprotectRecord12({ record: decodePlaintext(rec, 0), suite: s, key, salt }));
  });

  await r.test('DTLS 1.2: AAD sequence number\'a bağlı', () => {
    const s = getSuite(0xc02b);
    const key = crypto.randomBytes(16);
    const salt = crypto.randomBytes(4);
    const rec = protectRecord12({
      contentType: 23, content: Buffer.from('veri'), epoch: 1, recordSeq: 5, suite: s, key, salt,
    });
    const parsed = decodePlaintext(rec, 0);
    parsed.sequenceNumber = 6; // saldırgan seq'i değiştirdi
    assert.throws(() => unprotectRecord12({ record: parsed, suite: s, key, salt }));
  });

  // ======================================================================
  // Replay penceresi
  // ======================================================================
  await r.test('replay: yeni seq kabul, tekrar reddedilir', () => {
    const w = new ReplayWindow(64);
    assert.equal(w.accept(1), true);
    assert.equal(w.accept(1), false);
    assert.equal(w.accept(2), true);
    assert.equal(w.accept(0), true);
    assert.equal(w.accept(0), false);
  });

  await r.test('replay: pencere dışı eski paket reddedilir', () => {
    const w = new ReplayWindow(64);
    w.accept(500);
    assert.equal(w.accept(400), false);
    assert.equal(w.accept(450), true);
  });

  await r.test('replay: sırasız gelen paketler kabul edilir', () => {
    const w = new ReplayWindow(64);
    for (const s of [10, 5, 8, 3, 12, 1]) assert.equal(w.accept(s), true, `seq ${s}`);
    for (const s of [10, 5, 8, 3, 12, 1]) assert.equal(w.accept(s), false, `tekrar ${s}`);
  });

  // ======================================================================
  // ACK
  // ======================================================================
  await r.test('ACK encode/decode', () => {
    const nums = [{ epoch: 2, seq: 0 }, { epoch: 2, seq: 1 }, { epoch: 3, seq: 9 }];
    assert.deepEqual(parseAck(buildAck(nums)), nums);
  });

  // ======================================================================
  // AEAD ilkelleri
  // ======================================================================
  await r.test('AEAD nonce: seq XOR iv', () => {
    const iv = Buffer.alloc(12, 0);
    assert.deepEqual(buildAeadNonce(iv, 0), iv);
    assert.equal(buildAeadNonce(iv, 1)[11], 1);
    assert.equal(buildAeadNonce(iv, 0x0102030405).subarray(7).toString('hex'), '0102030405');
  });

  await r.test('AEAD nonce: BigInt ve Number aynı sonucu verir', () => {
    const iv = crypto.randomBytes(12);
    assert.deepEqual(buildAeadNonce(iv, 12345), buildAeadNonce(iv, 12345n));
  });

  await r.test('inner plaintext: content type + padding', () => {
    const inner = buildInnerPlaintext(22, Buffer.from('abc'), 5);
    assert.equal(inner.length, 3 + 1 + 5);
    const out = parseInnerPlaintext(inner);
    assert.equal(out.contentType, 22);
    assert.equal(out.content.toString(), 'abc');
  });

  await r.test('inner plaintext: tamamen sıfır reddedilir', () => {
    assert.throws(() => parseInnerPlaintext(Buffer.alloc(8, 0)), /sıfır/);
  });

  await r.test('sn mask: 16 baytın altındaki ciphertext sıfırla doldurulur', () => {
    const key = crypto.randomBytes(16);
    const short = Buffer.from([1, 2, 3]);
    const padded = Buffer.concat([short, Buffer.alloc(13, 0)]);
    assert.deepEqual(snMask('aes-128-ecb', key, short), snMask('aes-128-ecb', key, padded));
  });

  await r.test('sn mask: chacha20 varyantı deterministik', () => {
    const key = crypto.randomBytes(32);
    const ct = crypto.randomBytes(64);
    assert.deepEqual(snMask('chacha20', key, ct), snMask('chacha20', key, ct));
  });

  await r.test('reconstructSeq: sarmalama', () => {
    assert.equal(reconstructSeq(0, 5, 16), 5);
    assert.equal(reconstructSeq(65530, 3, 16), 65539);      // ileri sarmal
    assert.equal(reconstructSeq(65540, 65535, 16), 65535);  // geri kalmış paket
    assert.equal(reconstructSeq(100, 101, 8), 101);
  });

  // ======================================================================
  // TLS 1.2 PRF — RFC 5246 §5 (IETF test vektörü)
  // ======================================================================
  await r.test('TLS 1.2 PRF (SHA-256) bilinen vektör', () => {
    const secret = Buffer.from('9bbe436ba940f017b17652849a71db35', 'hex');
    const seed = Buffer.from('a0ba9f936cda311827a6f796ffd5198c', 'hex');
    const out = prf12('sha256', secret, 'test label', seed, 100);
    assert.equal(out.toString('hex'),
      'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a' +
      '6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab' +
      '4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701' +
      '87347b66');
  });

  await r.test('TLS 1.2 PRF keyfi uzunluk üretir', () => {
    assert.equal(prf12('sha384', Buffer.alloc(48, 1), 'x', Buffer.alloc(16, 2), 200).length, 200);
  });

  // ======================================================================
  // Cipher suite tablosu
  // ======================================================================
  await r.test('suite seçimi 1.3/1.2 ayrımı yapar', () => {
    const offers = [0x1301, 0xc02b];
    assert.equal(selectSuite(offers, [0x1301, 0x1302], { tls13: true }).id, 0x1301);
    assert.equal(selectSuite(offers, [0xc02b, 0xc02f], { tls13: false, auth: 'ec' }).id, 0xc02b);
    assert.equal(selectSuite(offers, [0xc02f], { tls13: false, auth: 'rsa' }), null);
  });

  await r.test('suite seçimi anahtar tipini zorlar', () => {
    assert.equal(selectSuite([0xc02f], [0xc02f], { tls13: false, auth: 'ec' }), null);
  });

  await r.test('resolveSuiteId isim ve sayı kabul eder', () => {
    assert.equal(resolveSuiteId('TLS_AES_128_GCM_SHA256'), 0x1301);
    assert.equal(resolveSuiteId(0x1301), 0x1301);
    assert.throws(() => resolveSuiteId('YOK'));
  });

  // ======================================================================
  // ECDHE
  // ======================================================================
  for (const [name, g] of [['X25519', NAMED_GROUP.X25519], ['P-256', NAMED_GROUP.SECP256R1]]) {
    await r.test(`ECDHE ${name}: iki taraf aynı sırrı üretir`, () => {
      const a = ecdhe.generateKeyPair(g);
      const b = ecdhe.generateKeyPair(g);
      const sa = ecdhe.computeSharedSecret(a.privateKey, ecdhe.importPeerPublic(g, b.publicRaw));
      const sb = ecdhe.computeSharedSecret(b.privateKey, ecdhe.importPeerPublic(g, a.publicRaw));
      assert.deepEqual(sa, sb);
      assert.equal(sa.length, 32);
    });
  }

  await r.test('ECDHE geçersiz public key reddedilir', () => {
    assert.throws(() => ecdhe.importPeerPublic(NAMED_GROUP.X25519, Buffer.alloc(31)));
    assert.throws(() => ecdhe.importPeerPublic(NAMED_GROUP.SECP256R1, Buffer.alloc(65)));
  });

  // ======================================================================
  // Handshake çerçeveleme
  // ======================================================================
  await r.test('ClientHello roundtrip (1.3 uzantılarıyla)', () => {
    const kp = ecdhe.generateKeyPair(NAMED_GROUP.X25519);
    const body = buildClientHello({
      cipherSuites: [0x1301, 0xc02b],
      extensions: [
        ext.ext_serverName('example.com'),
        ext.ext_supportedVersionsClient([VERSION.DTLS_1_3, VERSION.DTLS_1_2]),
        ext.ext_supportedGroups([NAMED_GROUP.X25519]),
        ext.ext_keyShareClient([{ group: NAMED_GROUP.X25519, keyExchange: kp.publicRaw }]),
        ext.ext_useSrtp([SRTP_PROFILE.SRTP_AEAD_AES_128_GCM]),
        ext.ext_alpn(['h3', 'echo']),
      ],
    });
    const ch = parseClientHello(body);
    assert.equal(ch.legacyVersion, VERSION.DTLS_1_2);
    assert.deepEqual(ch.cipherSuites.map((c) => c.value), [0x1301, 0xc02b]);
    assert.equal(ext.sniHostname(ch.extensions), 'example.com');
    assert.deepEqual(
      ext.parse_supportedVersionsClient(ext.findExt(ch.extensions, EXT_TYPE.SUPPORTED_VERSIONS).data),
      [VERSION.DTLS_1_3, VERSION.DTLS_1_2]);
    assert.deepEqual(ext.parse_alpn(ext.findExt(ch.extensions, EXT_TYPE.ALPN).data), ['h3', 'echo']);
    assert.deepEqual(ext.parse_useSrtp(ext.findExt(ch.extensions, EXT_TYPE.USE_SRTP).data).profiles,
                     [SRTP_PROFILE.SRTP_AEAD_AES_128_GCM]);
  });

  await r.test('ClientHello legacy_cookie (DTLS 1.2) taşınır', () => {
    const cookie = crypto.randomBytes(32);
    const body = buildClientHello({ legacyCookie: cookie, extensions: [ext.ext_supportedGroups()] });
    assert.deepEqual(Buffer.from(parseClientHello(body).legacyCookie), cookie);
  });

  await r.test('ServerHello ve HelloRetryRequest ayırt edilir', () => {
    assert.equal(parseServerHello(buildServerHello({ cipherSuite: 0x1301, extensions: [] })).isHRR, false);
    assert.equal(parseServerHello(
      buildServerHello({ cipherSuite: 0x1301, extensions: [], isHRR: true })).isHRR, true);
  });

  await r.test('handshake başlığı roundtrip', () => {
    const body = crypto.randomBytes(100);
    const hs = decodeHandshake(encodeHandshake({ msgType: HS_TYPE.CERTIFICATE, messageSeq: 3, body }), 0);
    assert.equal(hs.msgType, HS_TYPE.CERTIFICATE);
    assert.equal(hs.messageSeq, 3);
    assert.equal(hs.length, 100);
    assert.equal(hs.isComplete, true);
    assert.deepEqual(hs.body, body);
  });

  await r.test('uzantı listesi bozuksa hata verir', () => {
    assert.throws(() => ext.decodeExtensions(Buffer.from([0x00, 0x10, 0x00, 0x0d]), 0), /truncated/);
  });

  await r.test('use_srtp bozuk gövdesi reddedilir', () => {
    assert.throws(() => ext.parse_useSrtp(Buffer.from([0x00])), /truncated/);
    assert.throws(() => ext.parse_useSrtp(Buffer.from([0x00, 0x03, 0x00, 0x01, 0x00])), /malformed/);
  });

  // ======================================================================
  // Fragment birleştirme
  // ======================================================================
  await r.test('reassembler: sırasız parçaları birleştirir', () => {
    const body = crypto.randomBytes(300);
    const asm = new HsReassembler();
    const frag = (off, len) => ({
      msgType: 11, length: 300, messageSeq: 0,
      fragmentOffset: off, fragmentLength: len, body: body.subarray(off, off + len),
    });
    assert.equal(asm.add(frag(200, 100)).complete, false);
    assert.equal(asm.add(frag(0, 100)).complete, false);
    const done = asm.add(frag(100, 100));
    assert.equal(done.complete, true);
    assert.deepEqual(done.body, body);
  });

  await r.test('reassembler: çakışan parçalar sorun çıkarmaz', () => {
    const body = crypto.randomBytes(100);
    const asm = new HsReassembler();
    const frag = (off, len) => ({
      msgType: 11, length: 100, messageSeq: 0,
      fragmentOffset: off, fragmentLength: len, body: body.subarray(off, off + len),
    });
    asm.add(frag(0, 60));
    asm.add(frag(40, 60));
    const done = asm.add(frag(0, 100));
    assert.equal(done.complete, true);
    assert.deepEqual(done.body, body);
  });

  await r.test('reassembler: taşan parça reddedilir', () => {
    const asm = new HsReassembler();
    assert.throws(() => asm.add({
      msgType: 11, length: 10, messageSeq: 0,
      fragmentOffset: 5, fragmentLength: 10, body: Buffer.alloc(10),
    }), /overflow/);
  });

  // ======================================================================
  // Cookie
  // ======================================================================
  await r.test('cookie: üret + doğrula', () => {
    const cm = new CookieMinter();
    const peer = { address: '1.2.3.4', port: 5000 };
    const hash = crypto.randomBytes(32);
    assert.equal(cm.verify(cm.mint(peer, hash), peer, hash).ok, true);
  });

  await r.test('cookie: farklı peer/hash/MAC reddedilir', () => {
    const cm = new CookieMinter();
    const peer = { address: '1.2.3.4', port: 5000 };
    const hash = crypto.randomBytes(32);
    const c = cm.mint(peer, hash);
    assert.equal(cm.verify(c, { address: '1.2.3.5', port: 5000 }, hash).ok, false);
    assert.equal(cm.verify(c, { address: '1.2.3.4', port: 5001 }, hash).ok, false);
    assert.equal(cm.verify(c, peer, crypto.randomBytes(32)).ok, false);
    const bad = Buffer.from(c); bad[20] ^= 0xff;
    assert.equal(cm.verify(bad, peer, hash).ok, false);
  });

  await r.test('cookie: süresi dolmuş reddedilir', () => {
    const cm = new CookieMinter({ ttlMs: 1000 });
    const peer = { address: '1.2.3.4', port: 1 };
    const hash = crypto.randomBytes(32);
    const now = Date.now();
    assert.equal(cm.verify(cm.mint(peer, hash, now), peer, hash, now + 2000).reason, 'expired');
  });

  // ======================================================================
  // Transcript
  // ======================================================================
  await r.test('Transcript (1.3): DTLS başlığını TLS başlığına indirger', () => {
    const body = Buffer.from('gövde');
    const dtlsWire = encodeHandshake({ msgType: 1, messageSeq: 7, body });
    const t = new Transcript('sha256').appendDtls(dtlsWire);
    const tlsForm = Buffer.concat([Buffer.from([1, 0, 0, body.length]), body]);
    assert.equal(t.digest().toString('hex'),
                 crypto.createHash('sha256').update(tlsForm).digest('hex'));
  });

  await r.test('Transcript (1.2): DTLS başlığını KORUR', () => {
    const body = Buffer.from('gövde');
    const dtlsWire = encodeHandshake({ msgType: 1, messageSeq: 7, body });
    const t = new Transcript12('sha256').append(dtlsWire);
    assert.equal(t.digest().toString('hex'),
                 crypto.createHash('sha256').update(dtlsWire).digest('hex'));
    assert.deepEqual(t.rawBytes(), dtlsWire);
  });

  await r.test('Transcript: message_hash dönüşümü (HRR)', () => {
    const body = crypto.randomBytes(50);
    const ch1 = encodeHandshake({ msgType: 1, messageSeq: 0, body });
    const t = new Transcript('sha256').replaceWithMessageHash(ch1);
    const tlsForm = Buffer.concat([Buffer.from([1, 0, 0, 50]), body]);
    const ch1Hash = crypto.createHash('sha256').update(tlsForm).digest();
    const expected = crypto.createHash('sha256')
      .update(Buffer.from([254, 0, 0, 32])).update(ch1Hash).digest();
    assert.equal(t.digest().toString('hex'), expected.toString('hex'));
  });

  // ======================================================================
  // DTLS 1.2 mesajları
  // ======================================================================
  await r.test('HelloVerifyRequest roundtrip', () => {
    const cookie = crypto.randomBytes(20);
    const out = m12.parseHelloVerifyRequest(m12.buildHelloVerifyRequest(cookie));
    assert.deepEqual(Buffer.from(out.cookie), cookie);
    assert.equal(out.serverVersion, VERSION.DTLS_1_0);
  });

  await r.test('ServerKeyExchange imzala + doğrula', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const kp = ecdhe.generateKeyPair(NAMED_GROUP.X25519);
    const clientRandom = crypto.randomBytes(32);
    const serverRandom = crypto.randomBytes(32);
    const ske = m12.parseServerKeyExchange(m12.buildServerKeyExchange({
      group: NAMED_GROUP.X25519, publicRaw: kp.publicRaw,
      sigScheme: 0x0403, privateKey, clientRandom, serverRandom,
    }));
    assert.equal(ske.group, NAMED_GROUP.X25519);
    assert.deepEqual(Buffer.from(ske.publicRaw), kp.publicRaw);
    assert.equal(m12.verifyServerKeyExchange({
      publicKey, clientRandom, serverRandom,
      params: ske.params, sigScheme: ske.sigScheme, signature: ske.signature,
    }), true);
    assert.equal(m12.verifyServerKeyExchange({
      publicKey, clientRandom: crypto.randomBytes(32), serverRandom,
      params: ske.params, sigScheme: ske.sigScheme, signature: ske.signature,
    }), false, 'random değişirse imza tutmamalı');
  });

  await r.test('Certificate (1.2) zincir roundtrip', () => {
    const a = crypto.randomBytes(120), b = crypto.randomBytes(80);
    const { entries } = m12.parseCertificate12(m12.buildCertificate12([a, b]));
    assert.equal(entries.length, 2);
    assert.deepEqual(Buffer.from(entries[0].cert), a);
    assert.deepEqual(Buffer.from(entries[1].cert), b);
  });

  await r.test('ClientKeyExchange roundtrip', () => {
    const pub = crypto.randomBytes(32);
    assert.deepEqual(
      Buffer.from(m12.parseClientKeyExchange(m12.buildClientKeyExchange(pub)).publicRaw), pub);
  });

  await r.test('imza şeması seçimi anahtar tipine uyar', () => {
    assert.equal(m12.chooseSigScheme12('ec', [0x0403, 0x0401]), 0x0403);
    assert.equal(m12.chooseSigScheme12('rsa', [0x0401]), 0x0401);
    assert.equal(m12.chooseSigScheme12('ed25519', []), 0x0807);
    assert.throws(() => m12.chooseSigScheme12('dsa', []));
  });

  // ======================================================================
  // SRTP / SRTCP
  // ======================================================================
  await r.test('RTP başlık uzunluğu: CSRC ve uzantı', () => {
    const base = Buffer.alloc(12); base[0] = 0x80;
    assert.equal(rtpHeaderLength(base), 12);
    const withCsrc = Buffer.alloc(20); withCsrc[0] = 0x82; // CC=2
    assert.equal(rtpHeaderLength(withCsrc), 20);
    const withExt = Buffer.alloc(24); withExt[0] = 0x90;   // X=1
    withExt.writeUInt16BE(2, 14);
    assert.equal(rtpHeaderLength(withExt), 24);
    assert.equal(rtpHeaderLength(Buffer.alloc(4)), -1);
  });

  await r.test('RFC 7983 demux', () => {
    assert.equal(demuxPacket(Buffer.from([0x00])), 'stun');
    assert.equal(demuxPacket(Buffer.from([0x16, 0xfe, 0xfd])), 'dtls');
    assert.equal(demuxPacket(Buffer.from([0x80, 96])), 'rtp');
    assert.equal(demuxPacket(Buffer.from([0x80, 200])), 'rtcp');
    assert.equal(demuxPacket(Buffer.from([0x40])), 'turn'); // TURN kanalı 64..79
    assert.equal(demuxPacket(Buffer.from([0x50])), 'unknown');
  });

  for (const [name, profile] of Object.entries({
    CM_80: SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80,
    CM_32: SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_32,
    GCM128: SRTP_PROFILE.SRTP_AEAD_AES_128_GCM,
    GCM256: SRTP_PROFILE.SRTP_AEAD_AES_256_GCM,
  })) {
    const params = SRTP_PROFILE_PARAMS[profile];
    const mk = () => new SrtpContext({
      profile,
      masterKey: Buffer.alloc(params.keyLen, 0xa5),
      masterSalt: Buffer.alloc(params.saltLen, 0x5a),
    });

    await r.test(`SRTP ${name}: protect/unprotect roundtrip`, () => {
      const tx = mk(), rx = mk();
      const pkt = makeRtp(1000, 0x11223344, Buffer.from('medya yükü'));
      const wire = tx.protectRtp(pkt);
      assert.notDeepEqual(wire.subarray(12, 12 + 10), pkt.subarray(12, 22), 'yük şifreli olmalı');
      assert.deepEqual(rx.unprotectRtp(wire), pkt);
    });

    await r.test(`SRTP ${name}: bozulmuş paket reddedilir`, () => {
      const tx = mk(), rx = mk();
      const p = tx.protectRtp(makeRtp(1, 1, Buffer.from('xyz')));
      p[p.length - 1] ^= 0xff;
      assert.throws(() => rx.unprotectRtp(p), /doğrulama/);
    });

    await r.test(`SRTP ${name}: replay reddedilir`, () => {
      const tx = mk(), rx = mk();
      const p = tx.protectRtp(makeRtp(7, 1, Buffer.from('x')));
      rx.unprotectRtp(p);
      assert.throws(() => rx.unprotectRtp(p), /replay/);
    });

    await r.test(`SRTCP ${name}: protect/unprotect roundtrip`, () => {
      const tx = mk(), rx = mk();
      const rtcp = Buffer.alloc(28); rtcp[0] = 0x80; rtcp[1] = 200;
      rtcp.writeUInt16BE(6, 2); rtcp.writeUInt32BE(0x11223344, 4);
      rtcp.write('RAPOR', 8);
      assert.deepEqual(rx.unprotectRtcp(tx.protectRtcp(rtcp)), rtcp);
    });

    await r.test(`SRTP ${name}: yanlış anahtar reddedilir`, () => {
      const tx = mk();
      const rx = new SrtpContext({
        profile,
        masterKey: Buffer.alloc(params.keyLen, 0x11),
        masterSalt: Buffer.alloc(params.saltLen, 0x22),
      });
      assert.throws(() => rx.unprotectRtp(tx.protectRtp(makeRtp(1, 1, Buffer.from('x')))));
    });
  }

  await r.test('SRTP: sequence sarmalında ROC ilerler', () => {
    const p = SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80;
    const mk = () => new SrtpContext({
      profile: p, masterKey: Buffer.alloc(16, 3), masterSalt: Buffer.alloc(14, 4),
    });
    const tx = mk(), rx = mk();
    for (const seq of [65530, 65535, 0, 1]) {
      const pkt = makeRtp(seq, 0xabcdef01, Buffer.from(`s${seq}`));
      assert.deepEqual(rx.unprotectRtp(tx.protectRtp(pkt)), pkt, `seq=${seq}`);
    }
    assert.equal(tx.streams.get(0xabcdef01).roc, 1);
    assert.equal(rx.streams.get(0xabcdef01).roc, 1);
  });

  await r.test('SRTP: farklı SSRC\'ler bağımsız durum tutar', () => {
    const p = SRTP_PROFILE.SRTP_AEAD_AES_128_GCM;
    const mk = () => new SrtpContext({
      profile: p, masterKey: Buffer.alloc(16, 9), masterSalt: Buffer.alloc(12, 8),
    });
    const tx = mk(), rx = mk();
    const a = makeRtp(5, 0xaaaa, Buffer.from('A'));
    const b = makeRtp(5, 0xbbbb, Buffer.from('B'));
    assert.deepEqual(rx.unprotectRtp(tx.protectRtp(a)), a);
    assert.deepEqual(rx.unprotectRtp(tx.protectRtp(b)), b);
  });

  await r.test('SRTP: yanlış boyutlu anahtar reddedilir', () => {
    assert.throws(() => new SrtpContext({
      profile: SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80,
      masterKey: Buffer.alloc(8), masterSalt: Buffer.alloc(14),
    }), /master key/);
  });

  await r.test('SRTP index kestirimi (RFC 3711 Ek A)', () => {
    assert.equal(estimateIndex({ roc: 0, sl: 65000, started: true }, 65100).index, 65100);
    assert.equal(estimateIndex({ roc: 0, sl: 65000, started: true }, 10).index, 65546);
    assert.equal(estimateIndex({ roc: 1, sl: 100, started: true }, 65500).index, 65500);
  });

  // ======================================================================
  // Güvenilir kanal
  // ======================================================================
  await r.test('reliable: mesaj parçalanır ve birleşir', async () => {
    // İki kanalı karşılıklı bağla: ACK'ler akmadan tıkanıklık penceresi
    // (RFC 9002 §7.2: 10 paket) açılmaz ve büyük mesaj tek turda bitmez.
    let a, b;
    a = new ReliableChannel({ mtu: 64, ackDelay: 1, send: (x) => setImmediate(() => b.onData(x)) });
    b = new ReliableChannel({ mtu: 64, ackDelay: 1, send: (x) => setImmediate(() => a.onData(x)) });
    const payload = crypto.randomBytes(500);
    const got = new Promise((res) => b.on('message', res));
    await a.sendMessage(payload);
    assert.deepEqual(await got, payload);
    assert.equal(a.inFlight, 0, 'her parça teyitlenmiş olmalı');
  });

  await r.test('reliable: tıkanıklık penceresi ilk turu sınırlar (RFC 9002 §7.2)', () => {
    const wire = [];
    const a = new ReliableChannel({ mtu: 64, send: (x) => wire.push(x) });
    a.sendMessage(crypto.randomBytes(2000));       // ~44 parça
    // kInitialWindow = min(10·mtu, max(14720, 2·mtu)) = 640 bayt = 10 paket
    assert.equal(wire.length, 10, 'ilk uçuşta yalnızca pencere kadar paket çıkmalı');
    assert.ok(a.recovery.bytesInFlight <= a.recovery.congestionWindow);
  });

  await r.test('reliable: yeniden gönderim YENİ paket numarası alır', () => {
    const wire = [];
    const a = new ReliableChannel({ mtu: 200, send: (x) => wire.push(x) });
    a.sendMessage(Buffer.from('tekrar'));
    const firstPn = wire[0].readUIntBE(2, 6);
    // PTO sondasını elle tetikle
    a.recovery.ptoCount = 0;
    a._sendProbes(1);
    assert.equal(wire.length, 2);
    const secondPn = wire[1].readUIntBE(2, 6);
    assert.ok(secondPn > firstPn, 'sonda yeni pn kullanmalı (RTT belirsizliği olmasın)');
    // Veri kimliği (streamId, msgId, idx) DEĞİŞMEZ — alıcı yinelemeyi ondan eler.
    assert.deepEqual(wire[0].subarray(8, 18), wire[1].subarray(8, 18));
  });

  await r.test('reliable: ACK outstanding\'i temizler', async () => {
    const toB = [], toA = [];
    const a = new ReliableChannel({ mtu: 200, ackDelay: 1, send: (x) => toB.push(x) });
    const b = new ReliableChannel({ mtu: 200, ackDelay: 1, send: (x) => toA.push(x) });
    const done = a.sendMessage(Buffer.from('merhaba'));
    for (const x of toB) b.onData(x);
    await new Promise((res) => setTimeout(res, 20));
    for (const x of toA) a.onData(x);
    await done;
    assert.equal(a.inFlight, 0);
    assert.equal(a.stats.acked, 1);
  });

  await r.test('reliable: yinelenen paket iki kez teslim edilmez', () => {
    const b = new ReliableChannel({ send: () => {} });
    let count = 0;
    b.on('message', () => count++);
    const a = new ReliableChannel({ send: (buf) => { b.onData(buf); b.onData(buf); } });
    a.sendMessage(Buffer.from('tek'));
    assert.equal(count, 1);
    assert.equal(b.stats.duplicates, 1);
  });

  await r.test('reliable: RAW çerçevesi ayrı olayla gelir', () => {
    const b = new ReliableChannel({ send: () => {} });
    let raw = null;
    b.on('unreliable', (d) => { raw = d; });
    const a = new ReliableChannel({ send: (buf) => b.onData(buf) });
    a.sendUnreliable(Buffer.from('kayipolabilir'));
    assert.equal(raw.toString(), 'kayipolabilir');
  });

  await r.test('reliable: sırasız modda geç gelen mesaj beklenmez', () => {
    const order = [];
    const b = new ReliableChannel({ send: () => {}, ordered: false });
    b.on('message', (d) => order.push(d.toString()));
    const held = [];
    const a = new ReliableChannel({ mtu: 200, ordered: false, send: (buf) => held.push(buf) });
    a.sendMessage(Buffer.from('BIR'));
    a.sendMessage(Buffer.from('IKI'));
    b.onData(held[1]);
    b.onData(held[0]);
    assert.deepEqual(order, ['IKI', 'BIR']);
  });

  await r.test('reliable: parça yinelemesi paket numarasından bağımsız elenir', () => {
    const order = [];
    const b = new ReliableChannel({ send: () => {} });
    b.on('message', (d) => order.push(d.toString()));
    const held = [];
    const a = new ReliableChannel({ mtu: 200, send: (buf) => held.push(buf) });
    a.sendMessage(Buffer.from('BIR'));
    a._sendProbes(1);                    // aynı veri, farklı pn
    assert.equal(held.length, 2);
    assert.notDeepEqual(held[0].subarray(2, 8), held[1].subarray(2, 8), 'pn farklı olmalı');
    b.onData(held[0]);
    b.onData(held[1]);
    assert.deepEqual(order, ['BIR'], 'veri kimliği aynı olduğu için bir kez teslim edilmeli');
    assert.equal(b.stats.duplicates, 1);
  });

  await r.test('reliable: sıralı modda sıra korunur', () => {
    const order = [];
    const b = new ReliableChannel({ send: () => {}, ordered: true });
    b.on('message', (d) => order.push(d.toString()));
    const held = [];
    const a = new ReliableChannel({ mtu: 200, ordered: true, send: (buf) => held.push(buf) });
    a.sendMessage(Buffer.from('BIR'));
    a.sendMessage(Buffer.from('IKI'));
    b.onData(held[1]);
    assert.deepEqual(order, [], 'birinci gelmeden teslim olmamalı');
    b.onData(held[0]);
    assert.deepEqual(order, ['BIR', 'IKI']);
  });

  await r.test('reliable: PING/PONG', async () => {
    const a = new ReliableChannel({ send: (buf) => b.onData(buf) });
    const b = new ReliableChannel({ send: (buf) => a.onData(buf) });
    const pong = new Promise((res) => a.on('pong', res));
    a.ping(0x1234);
    assert.equal(await pong, 0x1234);
  });

  await r.test('reliable: kapanış bekleyen gönderimleri reddeder', async () => {
    const a = new ReliableChannel({ send: () => {} });
    const p = a.sendMessage(Buffer.from('x'));
    a.close();
    await assert.rejects(p, /kapandı/);
  });

  // ======================================================================
  // PKI (sertifika gerektirir)
  // ======================================================================
  if (HAVE_CERTS) {
    await r.test('PEM/DER dönüşümü', () => {
      const list = pki.toDerList(readCert('server.crt'));
      assert.equal(list.length, 1);
      assert.deepEqual(pki.toDerList(Buffer.from(pki.derToPem(list[0])))[0], list[0]);
    });

    await r.test('zincir doğrulama: doğru CA kabul, yanlış CA red', () => {
      const leaf = new crypto.X509Certificate(readCert('server.crt'));
      const ca = new crypto.X509Certificate(readCert('ca.crt'));
      const other = new crypto.X509Certificate(readCert('client.crt'));
      assert.equal(pki.verifyCertificateChain({ chain: [leaf], ca: [ca] }).authorized, true);
      assert.equal(pki.verifyCertificateChain({ chain: [leaf], ca: [other] }).authorized, false);
      assert.equal(pki.verifyCertificateChain({ chain: [leaf], ca: [ca], hostname: 'localhost' }).authorized, true);
      assert.equal(pki.verifyCertificateChain({ chain: [leaf], ca: [ca], hostname: 'evil.com' }).error,
                   'HOSTNAME_MISMATCH');
      assert.equal(pki.verifyCertificateChain({ chain: [leaf], ca: [ca], hostname: '127.0.0.1' }).authorized, true);
    });

    await r.test('kendinden imzalı: CA yoksa reddedilir, allowSelfSigned ile kabul', () => {
      const self = new crypto.X509Certificate(readCert('server.pem'));
      assert.equal(pki.verifyCertificateChain({ chain: [self], ca: [] }).authorized, false);
      assert.equal(pki.verifyCertificateChain({ chain: [self], ca: [], allowSelfSigned: true }).authorized, true);
    });

    await r.test('parmak izi eşleştirme', () => {
      const c = new crypto.X509Certificate(readCert('server.crt'));
      assert.equal(pki.matchFingerprint(c, c.fingerprint256, 'sha-256'), true);
      assert.equal(pki.matchFingerprint(c, c.fingerprint256.replace(/:/g, '').toLowerCase()), true);
      assert.equal(pki.matchFingerprint(c, 'AA'.repeat(32)), false);
    });

    await r.test('cert/key uyuşmazlığı erken yakalanır', () => {
      assert.throws(() => createSecureContext({
        cert: readCert('server.crt'), key: readCert('client.key'),
      }), /eşleşmiyor/);
    });
  }

  // ======================================================================
  // Seçenek doğrulama
  // ======================================================================
  await r.test('options: geçersiz sürüm reddedilir', () => {
    assert.throws(() => normalizeOptions('client', { minVersion: 'TLSv1.3' }), /geçersiz/);
    assert.throws(() => normalizeOptions('client', {
      minVersion: 'DTLSv1.3', maxVersion: 'DTLSv1.2',
    }), /büyük olamaz/);
  });

  await r.test('options: sunucu sertifikasız kurulamaz', () => {
    assert.throws(() => normalizeOptions('server', {}), /cert ve key zorunlu/);
  });

  await r.test('options: doğrulama dayanağı olmadan rejectUnauthorized reddedilir', () => {
    assert.throws(() => normalizeOptions('client', {}), /dayanak yok/);
    assert.ok(normalizeOptions('client', { rejectUnauthorized: false }));
    assert.ok(normalizeOptions('client', { allowSelfSigned: true }));
  });

  await r.test('options: srtp + reliable birlikte reddedilir', () => {
    assert.throws(() => normalizeOptions('client', {
      rejectUnauthorized: false, srtp: true, reliable: true,
    }), /aynı anda kullanılamaz/);
  });

  await r.test('options: alıcı bellek tavanları kanala ULAŞIR', () => {
    // Gerileme testi: normalizeReliable bir beyaz liste üretiyor, bu iki alan
    // listede yoktu ve sessizce düşüyordu. Tünel 1/8 MiB istiyor, kanal 16/64
    // MiB varsayılanıyla çalışıyordu — yapılandırma korunduğunu söylerken.
    const o = normalizeOptions('client', {
      rejectUnauthorized: false,
      reliable: { maxMessageBytes: 1024 * 1024, maxReassemblyBytes: 8 * 1024 * 1024 },
    });
    assert.equal(o.reliable.maxMessageBytes, 1024 * 1024);
    assert.equal(o.reliable.maxReassemblyBytes, 8 * 1024 * 1024);

    // Verilmediğinde undefined kalmalı: kanal açık `undefined` değerleri
    // atlayıp kendi varsayılanını koruyor, bu yüzden burada bir sayı
    // uydurmak varsayılanı iki yere kopyalamak olurdu.
    const bare = normalizeOptions('client', { rejectUnauthorized: false, reliable: true });
    assert.equal(bare.reliable.maxMessageBytes, undefined);

    const ch = new ReliableChannel({ send() {}, ...bare.reliable });
    assert.equal(ch.opts.maxMessageBytes, DEFAULTS.maxMessageBytes);

    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => normalizeOptions('client', {
        rejectUnauthorized: false, reliable: { maxMessageBytes: bad },
      }), /pozitif bir bayt sayısı/);
    }
  });

  await r.test('options: srtp profil isimleri çözülür', () => {
    const o = normalizeOptions('client', {
      rejectUnauthorized: false, srtp: { profiles: ['SRTP_AEAD_AES_128_GCM'] },
    });
    assert.deepEqual(o.srtp.profiles, [SRTP_PROFILE.SRTP_AEAD_AES_128_GCM]);
    assert.throws(() => normalizeOptions('client', {
      rejectUnauthorized: false, srtp: { profiles: ['YOK'] },
    }), /bilinmeyen SRTP/);
  });

  await r.test('options: sürüm listesi doğru sırada', () => {
    const both = normalizeOptions('client', { rejectUnauthorized: false });
    assert.deepEqual(both.versions, [VERSION.DTLS_1_3, VERSION.DTLS_1_2]);
    const only12 = normalizeOptions('client', { rejectUnauthorized: false, maxVersion: 'DTLSv1.2' });
    assert.deepEqual(only12.versions, [VERSION.DTLS_1_2]);
    assert.equal(only12.allow13, false);
  });

  // ---- şifreleme paketi seçimi ------------------------------------------
  await r.test('cipher: politika adı hem 1.3 hem 1.2 listesini kurar', () => {
    const o = normalizeOptions('client', { rejectUnauthorized: false, cipherSuites: 'chacha20' });
    assert.deepEqual(o.cipherSuites13, [CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256]);
    // Politika, sürüme göre ELLE eşlenmeye bırakılmamalı: 1.2 karşılıkları da
    // gelmezse istemci DTLS 1.2'ye düştüğünde el sıkışma sessizce başarısız olur.
    assert.deepEqual(o.cipherSuites12, [
      CIPHER_SUITE.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      CIPHER_SUITE.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]);
  });

  await r.test('cipher: `cipher` kısa adı `cipherSuites` ile eşdeğer', () => {
    const a = normalizeOptions('client', { rejectUnauthorized: false, cipher: 'aes256' });
    const b = normalizeOptions('client', { rejectUnauthorized: false, cipherSuites: 'aes256' });
    assert.deepEqual(a.cipherSuites13, b.cipherSuites13);
    assert.deepEqual(a.cipherSuites13, [CIPHER_SUITE.TLS_AES_256_GCM_SHA384]);
  });

  await r.test('cipher: açık suite listesi ve takma adlar', () => {
    const byName = normalizeOptions('client', {
      rejectUnauthorized: false, cipherSuites: ['TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'],
    });
    assert.deepEqual(byName.cipherSuites13, [
      CIPHER_SUITE.TLS_AES_256_GCM_SHA384, CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    ], 'verilen SIRA korunmalı — sunucu bunu tercih sırası olarak kullanıyor');

    // Takma adlar ve karışık liste.
    const mixed = normalizeOptions('client', {
      rejectUnauthorized: false, cipherSuites: ['chacha', 'aes-128'],
    });
    assert.equal(mixed.cipherSuites13[0], CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256);
    assert.ok(mixed.cipherSuites13.includes(CIPHER_SUITE.TLS_AES_128_GCM_SHA256));
  });

  await r.test('cipher: bilinmeyen ad politika listesiyle birlikte reddedilir', () => {
    assert.throws(
      () => normalizeOptions('client', { rejectUnauthorized: false, cipherSuites: 'des' }),
      /politikalar:/,
    );
  });

  await r.test('cipher: mobile politikası ChaCha20\'yi öne alır', () => {
    // ARM/gömülü uçlarda AES yazılımda çalışır ve ChaCha20'den kat kat yavaştır.
    const o = normalizeOptions('client', { rejectUnauthorized: false, cipherSuites: 'mobile' });
    assert.equal(o.cipherSuites13[0], CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256);
    assert.ok(o.cipherSuites13.includes(CIPHER_SUITE.TLS_AES_128_GCM_SHA256), 'AES yedek kalmalı');
  });

  // ---- tıkanıklık denetimi seçimi ---------------------------------------
  await r.test('reliable: tıkanıklık denetleyicisi seçilebilir', () => {
    const bbr = normalizeOptions('client', { rejectUnauthorized: false, reliable: true });
    assert.equal(bbr.reliable.congestionControl, undefined, 'verilmezse kanal varsayılanı geçerli');

    const reno = normalizeOptions('client', {
      rejectUnauthorized: false, reliable: { congestionControl: 'newreno' },
    });
    assert.equal(reno.reliable.congestionControl, 'newreno');

    // Takma adlar tek kanonik ada iner.
    const alias = normalizeOptions('client', {
      rejectUnauthorized: false, reliable: { cc: 'bbr' },
    });
    assert.equal(alias.reliable.congestionControl, 'bbr3');

    assert.throws(() => normalizeOptions('client', {
      rejectUnauthorized: false, reliable: { congestionControl: 'cubic' },
    }), /bilinmeyen denetleyici/);
  });

  // ======================================================================
  // DER / X.509 ilkelleri
  // ======================================================================
  await r.test('DER: OID gidiş-dönüş (çok baytlı ilk alt-tanımlayıcı dahil)', () => {
    // İlk İKİ bileşen tek bir alt-tanımlayıcıya sıkışır (40·X + Y) ve bu değer
    // tek bayta sığmayabilir — 2.999.1 → 1079. Tek bayt varsayan bir çözücü
    // bunu SESSİZCE '1.15.1' diye okur.
    for (const oid of [
      '1.2.840.113549.1.1.11', '2.5.29.19', '1.3.6.1.5.5.7.48.1.1',
      '1.3.6.1.4.1.65133.1.1', '0.0', '1.39', '0.39', '2.100.3', '2.999.1',
      '2.16.840.1.101.3.4.2.1',
    ]) {
      assert.equal(der.oidToString(der.oidToDer(oid)), oid, oid);
    }
    assert.throws(() => der.oidToDer('3.1.1'), /kök bileşeni/);
    assert.throws(() => der.oidToDer('1.40.1'), /39/);
    assert.throws(() => der.oidToDer('1'), /en az iki/);
    assert.throws(() => der.oidToDer('1.a'), /geçersiz/);
  });

  await r.test('DER: bozuk kodlamalar reddedilir', () => {
    const malformed = [
      Buffer.alloc(0),
      Buffer.from([0x30]),
      Buffer.from([0x30, 0x80]),                         // belirsiz uzunluk (BER)
      Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), // devasa uzunluk
      Buffer.from([0x1f, 0x01, 0x00]),                   // çok baytlı etiket
      Buffer.from([0x30, 0x05, 0x02, 0x03, 0x01]),       // kesik içerik
    ];
    for (const e of malformed) {
      assert.throws(() => der.readTLV(e, 0), Error, `girdi: ${e.toString('hex')}`);
    }
  });

  await r.test('DER: rastgele girdi ayrıştırıcıyı çökertmez', () => {
    // Rastgele baytlar GEÇERLİ bir TLV olabilir — burada aranan "her zaman hata"
    // değil, "asla kontrolsüz çökme". Üst seviye ayrıştırıcılar ise anlamsız
    // yapıyı DAİMA reddetmelidir (ağdan gelen OCSP/CRL yükleri buradan geçer).
    for (let i = 0; i < 500; i++) {
      const fuzz = crypto.randomBytes(1 + (i % 96));
      try {
        const node = der.readTLV(fuzz, 0);
        assert.ok(node.contentOff + node.len <= fuzz.length, 'sınır dışına taşmamalı');
      } catch (e) {
        assert.ok(e instanceof Error);
      }
      for (const parse of [revocationMod.parseOcspResponse, x509mod.parseCrl, x509mod.parseCertificate]) {
        try { parse(fuzz); } catch (e) { assert.ok(e instanceof Error); }
      }
    }
  });

  await r.test('DER: UTCTime yüzyıl kuralı (RFC 5280 §4.1.2.5.1)', () => {
    const at = (s) => new Date(der.timeToMs({ tag: der.TAG.UTC_TIME, content: Buffer.from(s) }));
    assert.equal(at('490101000000Z').getUTCFullYear(), 2049);
    assert.equal(at('500101000000Z').getUTCFullYear(), 1950);
    const gen = new Date(der.timeToMs({
      tag: der.TAG.GENERALIZED_TIME, content: Buffer.from('20491231235959Z'),
    }));
    assert.equal(gen.getUTCFullYear(), 2049);
  });

  if (HAVE_CERTS) {
    await r.test('X.509: tbsDer imzalanan baytları birebir verir', () => {
      // Regresyon: tbs dilimi bir ara ayrıştırma tamponuna göre hesaplanırsa
      // üst başlığın uzunluğu kadar kayar ve HER imza doğrulaması sessizce
      // başarısız olur — OCSP delege responder'ları da dahil.
      const ca = new crypto.X509Certificate(readCert('ca.crt'));
      const leaf = new crypto.X509Certificate(readCert('client.crt'));
      const info = x509mod.parseCertificate(leaf.raw);
      assert.equal(x509mod.verifySignature({
        tbs: info.tbsDer, sigAlgOid: info.sigAlgOid, sigAlgParams: info.sigAlgParams,
        signature: info.signature, publicKey: ca.publicKey,
      }), true, 'doğru CA anahtarıyla doğrulanmalı');
      assert.equal(x509mod.verifySignature({
        tbs: info.tbsDer, sigAlgOid: info.sigAlgOid, sigAlgParams: info.sigAlgParams,
        signature: info.signature, publicKey: leaf.publicKey,
      }), false, 'yanlış anahtarla doğrulanmamalı');
    });

    await r.test('X.509: uzantılar okunur (BC, KU, EKU, AIA, CDP)', () => {
      const client = x509mod.parseCertificate(new crypto.X509Certificate(readCert('client.crt')).raw);
      assert.deepEqual(x509mod.extKeyUsage(client), [x509mod.OID.kpClientAuth]);
      assert.equal(x509mod.keyUsage(client).digitalSignature, true);
      assert.equal(x509mod.keyUsage(client).keyCertSign, false);
      assert.equal(x509mod.basicConstraints(client).isCA, false);
      assert.ok(x509mod.authorityInfoAccess(client).ocsp.length > 0, 'AIA OCSP URL\'i olmalı');
      assert.ok(x509mod.crlDistributionPoints(client).length > 0, 'CDP olmalı');

      const inter = x509mod.parseCertificate(new crypto.X509Certificate(readCert('inter.crt')).raw);
      const bc = x509mod.basicConstraints(inter);
      assert.equal(bc.isCA, true);
      assert.equal(bc.pathLen, 0, 'ara CA pathlen:0 taşımalı');
      assert.equal(x509mod.keyUsage(inter).keyCertSign, true);
    });

    await r.test('PKI: karışık sıralı demet leaf\'i başa alır', () => {
      const leaf = readCert('inter-leaf.crt');
      const inter = readCert('inter.crt');
      const { x509: ordered, reordered } = pki.loadCertChain(Buffer.concat([inter, leaf]));
      assert.equal(reordered, true, 'sıra düzeltilmiş olmalı');
      assert.match(ordered[0].subject, /localhost/, 'leaf başta olmalı');
      assert.match(ordered[1].subject, /Intermediate/);
    });

    await r.test('PKI: pathLen kısıtı ve amaç (EKU) doğrulanır', () => {
      const ca = new crypto.X509Certificate(readCert('ca.crt'));
      const inter = new crypto.X509Certificate(readCert('inter.crt'));
      const leaf = new crypto.X509Certificate(readCert('inter-leaf.crt'));

      const ok = pki.verifyCertificateChain({ chain: [leaf, inter], ca: [ca] });
      assert.equal(ok.authorized, true, ok.error || '');
      assert.equal(ok.path.length, 3, 'yol leaf → ara CA → kök olmalı');

      // Ara CA gönderilmezse zincir kurulamaz.
      assert.equal(pki.verifyCertificateChain({ chain: [leaf], ca: [ca] }).authorized, false);

      // Ara CA'nın kendisi güven çıpası olarak verilebilir.
      const pinned = pki.verifyCertificateChain({ chain: [leaf], ca: [inter] });
      assert.equal(pinned.authorized, true, pinned.error || '');
      assert.equal(pinned.path.length, 2);

      // Sunucu sertifikası istemci amacına uygun değildir (EKU: serverAuth).
      const server = new crypto.X509Certificate(readCert('server.crt'));
      const wrongPurpose = pki.verifyCertificateChain({ chain: [server], ca: [ca], purpose: 'client' });
      assert.equal(wrongPurpose.authorized, false);
      assert.match(wrongPurpose.error, /INVALID_PURPOSE/);
    });

    await r.test('PKI: zincirdeki kök güven üretmez', () => {
      const ca = new crypto.X509Certificate(readCert('ca.crt'));
      const inter = new crypto.X509Certificate(readCert('inter.crt'));
      const leaf = new crypto.X509Certificate(readCert('inter-leaf.crt'));
      const other = new crypto.X509Certificate(readCert('server.pem'));
      // Kök zincirin İÇİNDE ama güven deposunda değil → reddedilmeli.
      const res = pki.verifyCertificateChain({ chain: [leaf, inter, ca], ca: [other] });
      assert.equal(res.authorized, false);
      assert.match(res.error, /SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_GET_ISSUER_CERT/);
    });
  }

  r.exit();
})();
