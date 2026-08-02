'use strict';
// DTLS-SRTP uçtan uca testleri — use_srtp müzakeresi, anahtar dışa aktarımı,
// medya koruması ve "srtp kapalıyken düz DTLS bozulmuyor" güvencesi.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Runner, loadCerts, pair, once, sleep } = require('./helpers.js');
const { SRTP_PROFILE, NAMES } = require('../src/constants.js');
const { exportSrtpKeyingMaterial } = require('../src/crypto/exporter.js');

const c = loadCerts();
const r = new Runner('DTLS-SRTP');

function makeRtp(seq, ssrc, payload) {
  const p = Buffer.alloc(12 + payload.length);
  p[0] = 0x80; p[1] = 96;
  p.writeUInt16BE(seq & 0xffff, 2);
  p.writeUInt32BE((seq * 960) >>> 0, 4);
  p.writeUInt32BE(ssrc >>> 0, 8);
  payload.copy(p, 12);
  return p;
}

function makeRtcp(ssrc) {
  const p = Buffer.alloc(28);
  p[0] = 0x80; p[1] = 200;
  p.writeUInt16BE(6, 2);
  p.writeUInt32BE(ssrc >>> 0, 4);
  p.write('SENDER-REPORT-BODY!!', 8);
  return p;
}

const PROFILES = [
  SRTP_PROFILE.SRTP_AEAD_AES_128_GCM,
  SRTP_PROFILE.SRTP_AEAD_AES_256_GCM,
  SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80,
  SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_32,
];

(async () => {
  for (const version of ['DTLSv1.3', 'DTLSv1.2']) {
    const V = { minVersion: version, maxVersion: version };
    const SRV = { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...V };
    const CLI = { ca: c.ca, servername: 'localhost', ...V };

    for (const profile of PROFILES) {
      const pname = NAMES.SRTP_PROFILE[profile];
      await r.test(`[${version}] ${pname}: müzakere + RTP/RTCP çift yönlü`, async () => {
        const srtp = { profiles: [profile] };
        const p = await pair({ ...SRV, srtp }, { ...CLI, srtp }, { echo: false });
        const s = await p.waitConnected();
        await sleep(30);

        assert.equal(p.client.srtpProfile, pname);
        assert.equal(s.srtpProfile, pname);
        assert.equal(p.client.negotiatedSrtpProfile, profile);

        // İstemci → sunucu RTP
        const up = makeRtp(1000, 0xdeadbeef, Buffer.from('video-karesi'));
        const gotUp = once(s, 'media');
        p.client.sendMedia(up);
        assert.deepEqual(await gotUp, up);

        // Sunucu → istemci RTP
        const down = makeRtp(500, 0xcafebabe, Buffer.from('ses-karesi'));
        const gotDown = once(p.client, 'media');
        s.sendMedia(down);
        assert.deepEqual(await gotDown, down);

        // RTCP
        const rc = makeRtcp(0xdeadbeef);
        const gotRtcp = once(s, 'rtcp');
        p.client.sendRtcp(rc);
        assert.deepEqual(await gotRtcp, rc);

        await p.close();
      });
    }

    await r.test(`[${version}] iki taraf aynı SRTP anahtar materyalini türetir`, async () => {
      const srtp = { profiles: [SRTP_PROFILE.SRTP_AEAD_AES_128_GCM] };
      const p = await pair({ ...SRV, srtp }, { ...CLI, srtp });
      const s = await p.waitConnected();
      const kmA = exportSrtpKeyingMaterial(p.client._exportContext(), p.client.negotiatedSrtpProfile);
      const kmB = exportSrtpKeyingMaterial(s._exportContext(), s.negotiatedSrtpProfile);
      assert.deepEqual(kmA.clientMasterKey, kmB.clientMasterKey);
      assert.deepEqual(kmA.serverMasterKey, kmB.serverMasterKey);
      assert.deepEqual(kmA.clientMasterSalt, kmB.clientMasterSalt);
      assert.notDeepEqual(kmA.clientMasterKey, kmA.serverMasterKey);
      await p.close();
    });

    await r.test(`[${version}] profil önceliği sunucuda belirlenir`, async () => {
      const p = await pair(
        { ...SRV, srtp: { profiles: ['SRTP_AES128_CM_HMAC_SHA1_80', 'SRTP_AEAD_AES_128_GCM'] } },
        { ...CLI, srtp: { profiles: ['SRTP_AEAD_AES_128_GCM', 'SRTP_AES128_CM_HMAC_SHA1_80'] } });
      await p.waitConnected();
      assert.equal(p.client.srtpProfile, 'SRTP_AES128_CM_HMAC_SHA1_80');
      await p.close();
    });

    await r.test(`[${version}] ortak profil yoksa handshake reddedilir`, async () => {
      await assert.rejects(pair(
        { ...SRV, srtp: { profiles: ['SRTP_AEAD_AES_256_GCM'] } },
        { ...CLI, srtp: { profiles: ['SRTP_AES128_CM_HMAC_SHA1_32'] } }));
    });

    await r.test(`[${version}] srtp:false düz DTLS'i bozmaz`, async () => {
      const p = await pair(SRV, CLI);
      await p.waitConnected();
      assert.equal(p.client.srtpProfile, null);
      assert.equal(p.client.srtp, null);
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('duz'));
      assert.equal((await got).toString(), 'echo:duz');
      assert.throws(() => p.client.sendMedia(makeRtp(1, 1, Buffer.from('x'))), /müzakere edilmedi/);
      await p.close();
    });

    await r.test(`[${version}] SRTP açıkken uygulama verisi de akar`, async () => {
      const srtp = { profiles: [SRTP_PROFILE.SRTP_AEAD_AES_128_GCM] };
      const p = await pair({ ...SRV, srtp }, { ...CLI, srtp });
      await p.waitConnected();
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('kontrol-kanali'));
      assert.equal((await got).toString(), 'echo:kontrol-kanali');
      await p.close();
    });

    await r.test(`[${version}] sadece bir taraf SRTP isterse düz DTLS'e düşülür`, async () => {
      const p = await pair(SRV, { ...CLI, srtp: true });
      await p.waitConnected();
      assert.equal(p.client.srtpProfile, null, 'sunucu istemedi → SRTP yok');
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('yine-calisir'));
      assert.equal((await got).toString(), 'echo:yine-calisir');
      await p.close();
    });

    await r.test(`[${version}] bozuk medya paketi oturumu düşürmez`, async () => {
      const srtp = { profiles: [SRTP_PROFILE.SRTP_AEAD_AES_128_GCM] };
      const p = await pair({ ...SRV, srtp }, { ...CLI, srtp }, { echo: false });
      const s = await p.waitConnected();
      await sleep(30);

      // Geçerli görünen ama şifresi tutmayan bir RTP paketi enjekte et
      const bogus = makeRtp(9, 0x12345678, crypto.randomBytes(40));
      await p.client._sendRaw(bogus);
      await sleep(60);
      assert.equal(s.closed, false, 'oturum ayakta kalmalı');

      // Ardından geçerli medya hâlâ geçmeli
      const good = makeRtp(10, 0x12345678, Buffer.from('gecerli'));
      const got = once(s, 'media');
      p.client.sendMedia(good);
      assert.deepEqual(await got, good);
      await p.close();
    });

    await r.test(`[${version}] medya replay ikinci kez teslim edilmez`, async () => {
      const srtp = { profiles: [SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80] };
      const p = await pair({ ...SRV, srtp }, { ...CLI, srtp }, { echo: false });
      const s = await p.waitConnected();
      await sleep(30);

      let count = 0;
      s.on('media', () => count++);
      const wire = p.client.srtp.write.protectRtp(makeRtp(77, 0xabc, Buffer.from('tek')));
      await p.client._sendRaw(wire);
      await p.client._sendRaw(wire); // aynı paketi tekrar yolla
      await sleep(120);
      assert.equal(count, 1, 'replay reddedilmeli');
      await p.close();
    });
  }

  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
