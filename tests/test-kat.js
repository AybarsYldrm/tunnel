'use strict';
// Known-answer tests — HKDF (RFC 5869) + TLS 1.3 Key Schedule (RFC 8448 §3).
//
// RFC 8448 TLS 1.3'ün resmi test vektörleridir. Şemada TLS/DTLS arasında key schedule
// semantik fark yok (RFC 9147 §5.9), yani bu vektörler bizim HKDF + key-schedule
// modüllerinin doğruluğunu bire-bir kanıtlar.
//
// Başarı kriteri: her "expect" eşittir dönmeli, aksi halde exit code 1.

const assert = require('node:assert/strict');
const {
  hkdfExtract, hkdfExpand, hkdfExpandLabel, deriveSecret,
  hashLen, hashEmpty, transcriptHash,
} = require('../src/crypto/hkdf.js');
const {
  earlySecret, derivedFromEarly,
  handshakeSecret, derivedFromHandshake,
  masterSecret,
  clientHandshakeTrafficSecret, serverHandshakeTrafficSecret,
  clientApplicationTrafficSecret, serverApplicationTrafficSecret,
  trafficKeyIv, finishedKey,
} = require('../src/crypto/key-schedule.js');

let failed = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.error(`  ✗ ${name}\n    ${e.message}`); }
}

const h = (s) => Buffer.from(s.replace(/\s+/g, ''), 'hex');

// ============================================================================
// RFC 5869 — HKDF KAT
// ============================================================================
console.log('\n[RFC 5869] HKDF test vectors');

// A.1: SHA-256, basic
t('A.1 Extract(SHA-256)', () => {
  const IKM  = h('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const salt = h('000102030405060708090a0b0c');
  const prk  = hkdfExtract('sha256', salt, IKM);
  assert.equal(prk.toString('hex'),
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
});

t('A.1 Expand(SHA-256, L=42)', () => {
  const PRK  = h('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  const info = h('f0f1f2f3f4f5f6f7f8f9');
  const out  = hkdfExpand('sha256', PRK, info, 42);
  assert.equal(out.toString('hex'),
    '3cb25f25faacd57a90434f64d0362f2a' +
    '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
    '34007208d5b887185865');
});

// A.2: SHA-256, longer inputs
t('A.2 Extract(SHA-256, long)', () => {
  const IKM = h(
    '000102030405060708090a0b0c0d0e0f' +
    '101112131415161718191a1b1c1d1e1f' +
    '202122232425262728292a2b2c2d2e2f' +
    '303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f'
  );
  const salt = h(
    '606162636465666768696a6b6c6d6e6f' +
    '707172737475767778797a7b7c7d7e7f' +
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f' +
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
  );
  const prk = hkdfExtract('sha256', salt, IKM);
  assert.equal(prk.toString('hex'),
    '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244');
});

// A.3: SHA-256, zero-length salt and info
t('A.3 Extract(SHA-256, empty salt)', () => {
  const IKM = h('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const prk = hkdfExtract('sha256', Buffer.alloc(0), IKM);
  assert.equal(prk.toString('hex'),
    '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
});

t('A.3 Expand(SHA-256, empty info, L=42)', () => {
  const PRK = h('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
  const out = hkdfExpand('sha256', PRK, Buffer.alloc(0), 42);
  assert.equal(out.toString('hex'),
    '8da4e775a563c18f715f802a063c5a31' +
    'b8a11f5c5ee1879ec3454e5f3c738d2d' +
    '9d201395faa4b61a96c8');
});

// ============================================================================
// RFC 8448 §3 — "Simple 1-RTT Handshake" key schedule KAT
//
// Suite: TLS_AES_128_GCM_SHA256 (hash=SHA-256, keyLen=16, ivLen=12)
// ============================================================================
console.log('\n[RFC 8448 §3] TLS 1.3 key schedule — 1-RTT handshake');

const shared = h('8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d');

// RFC 8448'deki ClientHello'nun hash'ini (transcript CH'den sonra) üretmek için
// RFC direkt ClientHello bytes veriyor. Biz hash'i doğrudan veriyoruz (RFC 8448'de açık):
// transcript_hash(CH) = SHA-256(ClientHello) — RFC 8448 "hash" satırı.
// CH||SH transcript hash'i ve CH..SF transcript hash'i de verilmiş; doğrudan kullanıyoruz.

// RFC 8448 §3 vektörleri:
const TH_CH_SH = h('860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8');
const TH_CH_SF = h('9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13');

// Early Secret (SHA-256)
const expectedEarly = h('33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a');
t('RFC 8448: Early Secret', () => {
  const es = earlySecret('sha256');
  assert.equal(es.toString('hex'), expectedEarly.toString('hex'));
});

// Derived from Early
const expectedDerivedEarly = h('6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba');
t('RFC 8448: Derive-Secret(Early, "derived", "")', () => {
  const es = earlySecret('sha256');
  const de = derivedFromEarly('sha256', es);
  assert.equal(de.toString('hex'), expectedDerivedEarly.toString('hex'));
});

// Handshake Secret
const expectedHS = h('1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac');
t('RFC 8448: Handshake Secret', () => {
  const es = earlySecret('sha256');
  const hs = handshakeSecret('sha256', es, shared);
  assert.equal(hs.toString('hex'), expectedHS.toString('hex'));
});

// c_hs_traffic secret
const expected_cHS = h('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');
t('RFC 8448: client_handshake_traffic_secret', () => {
  const cHS = clientHandshakeTrafficSecret('sha256', expectedHS, TH_CH_SH);
  assert.equal(cHS.toString('hex'), expected_cHS.toString('hex'));
});

// s_hs_traffic secret
const expected_sHS = h('b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38');
t('RFC 8448: server_handshake_traffic_secret', () => {
  const sHS = serverHandshakeTrafficSecret('sha256', expectedHS, TH_CH_SH);
  assert.equal(sHS.toString('hex'), expected_sHS.toString('hex'));
});

// client handshake key + iv (AES-128-GCM)
t('RFC 8448: client handshake key', () => {
  const { key } = trafficKeyIv('sha256', expected_cHS, { keyLen: 16, ivLen: 12 });
  assert.equal(key.toString('hex'), 'dbfaa693d1762c5b666af5d950258d01');
});
t('RFC 8448: client handshake iv', () => {
  const { iv } = trafficKeyIv('sha256', expected_cHS, { keyLen: 16, ivLen: 12 });
  assert.equal(iv.toString('hex'), '5bd3c71b836e0b76bb73265f');
});

// server handshake key + iv
t('RFC 8448: server handshake key', () => {
  const { key } = trafficKeyIv('sha256', expected_sHS, { keyLen: 16, ivLen: 12 });
  assert.equal(key.toString('hex'), '3fce516009c21727d0f2e4e86ee403bc');
});
t('RFC 8448: server handshake iv', () => {
  const { iv } = trafficKeyIv('sha256', expected_sHS, { keyLen: 16, ivLen: 12 });
  assert.equal(iv.toString('hex'), '5d313eb2671276ee13000b30');
});

// Master Secret (derived from Handshake Secret)
const expectedMaster = h('18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919');
t('RFC 8448: Master Secret', () => {
  const ms = masterSecret('sha256', expectedHS);
  assert.equal(ms.toString('hex'), expectedMaster.toString('hex'));
});

// c_ap_traffic secret_0
const expected_cAP = h('9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5');
t('RFC 8448: client_application_traffic_secret_0', () => {
  const cAP = clientApplicationTrafficSecret('sha256', expectedMaster, TH_CH_SF);
  assert.equal(cAP.toString('hex'), expected_cAP.toString('hex'));
});

// s_ap_traffic secret_0
const expected_sAP = h('a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643');
t('RFC 8448: server_application_traffic_secret_0', () => {
  const sAP = serverApplicationTrafficSecret('sha256', expectedMaster, TH_CH_SF);
  assert.equal(sAP.toString('hex'), expected_sAP.toString('hex'));
});

// server application key/iv (AES-128-GCM)
t('RFC 8448: server application key', () => {
  const { key } = trafficKeyIv('sha256', expected_sAP, { keyLen: 16, ivLen: 12 });
  assert.equal(key.toString('hex'), '9f02283b6c9c07efc26bb9f2ac92e356');
});
t('RFC 8448: server application iv', () => {
  const { iv } = trafficKeyIv('sha256', expected_sAP, { keyLen: 16, ivLen: 12 });
  assert.equal(iv.toString('hex'), 'cf782b88dd83549aadf1e984');
});

// Finished key (server) — finished_key = HKDF-Expand-Label(s_hs_traffic_secret, "finished", "", Hash.length)
// RFC 8448'de server Finished içeriği verifiable değil ama finished_key türetimi bellidir.
// Test: finished_key 32 byte (SHA-256 hashLen) ve deterministik
t('RFC 8448: server finished_key length', () => {
  const fk = finishedKey('sha256', expected_sHS, 32);
  assert.equal(fk.length, 32);
});

// Ayrıca client Finished doğrulaması için ek KAT:
// RFC 8448 §3'te server Finished verify_data = a77a:
//   finished_key = HKDF-Expand-Label(s_hs_traffic, "finished", "", 32)
//   verify_data  = HMAC-SHA256(finished_key, transcript_hash_up_to_CertVerify)
// Biz transcript'in Finished'den önceki halini bilmiyoruz (RFC ara hash da veriyor ama bu
// test kapsamını şişirir). Üstteki vektörler key-schedule'un doğruluğu için yeterli.

console.log('\n[HKDF-Expand-Label sanity]');
t('expand_label: deterministic + non-empty', () => {
  const out = hkdfExpandLabel('sha256', expectedHS, 'test', Buffer.alloc(0), 16);
  assert.equal(out.length, 16);
  const out2 = hkdfExpandLabel('sha256', expectedHS, 'test', Buffer.alloc(0), 16);
  assert.deepEqual(out, out2);
});

console.log('\n[hashEmpty]');
t('SHA-256 empty', () => {
  assert.equal(hashEmpty('sha256').toString('hex'),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
t('SHA-384 empty', () => {
  assert.equal(hashEmpty('sha384').toString('hex'),
    '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b');
});

// ============================================================================
console.log(`\nResult: ${failed === 0 ? 'ALL PASS' : `${failed} FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
