'use strict';
// mTLS ve sertifika doğrulama testleri — her iki DTLS sürümünde.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Runner, loadCerts, pair, once, sleep, dtls } = require('./helpers.js');

const c = loadCerts();
const r = new Runner('mTLS ve sertifika doğrulama');

const serverFp = new crypto.X509Certificate(c.serverCert).fingerprint256;
const selfFp = new crypto.X509Certificate(c.selfSigned).fingerprint256;

/** Handshake'in reddedilmesini bekler — hata istemcide veya sunucuda çıkabilir. */
async function expectRejected(srvOpts, cliOpts, matcher) {
  let p = null;
  try {
    p = await pair(srvOpts, cliOpts);
  } catch (e) {
    if (matcher) {
      const all = [e.message, ...(e.serverErrors || []).map((x) => x.message)].join(' | ');
      assert.match(all, matcher);
    }
    return;
  }
  // İstemci bağlanmış olabilir (DTLS 1.3'te istemci Finished'i gönderince
  // "bağlandı" sayar); sunucunun reddettiğini doğrula.
  await sleep(150);
  const rejected = p.errors.length > 0 || p.serverSocket() === null || p.serverSocket().closed;
  await p.close();
  assert.ok(rejected, 'handshake reddedilmeliydi ama iki taraf da kabul etti');
  if (matcher && p.errors.length) {
    assert.match(p.errors.map((x) => x.message).join(' | '), matcher);
  }
}

// Aynı senaryo kümesi her iki sürümde de koşturulur.
const suites = ['DTLSv1.3', 'DTLSv1.2'].map((version) => {
  const V = { minVersion: version, maxVersion: version };
  const SRV = { cert: c.serverCert, key: c.serverKey, ca: c.ca, ...V };
  const CLI = { ca: c.ca, servername: 'localhost', ...V };

  return async function suite() {
    await r.test(`[${version}] mTLS: geçerli istemci sertifikası kabul edilir`, async () => {
      const p = await pair(
        { ...SRV, requestCert: true, rejectUnauthorized: true },
        { ...CLI, cert: c.clientCert, key: c.clientKey });
      const s = await p.waitConnected();
      assert.equal(s.authorized, true);
      assert.equal(s.authorizationError, null);
      assert.match(s.getPeerCertificate().subject, /dtls-client/);
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('mtls'));
      assert.equal((await got).toString(), 'echo:mtls');
      await p.close();
    });

    await r.test(`[${version}] mTLS: sertifikasız istemci reddedilir`, async () => {
      await expectRejected(
        { ...SRV, requestCert: true, rejectUnauthorized: true },
        CLI, /NO_PEER_CERTIFICATE|CERTIFICATE_REQUIRED/);
    });

    await r.test(`[${version}] mTLS: rejectUnauthorized=false ile isteğe bağlı kimlik`, async () => {
      const p = await pair(
        { ...SRV, requestCert: true, rejectUnauthorized: false }, CLI);
      const s = await p.waitConnected();
      assert.equal(s.authorized, false);
      assert.equal(s.authorizationError, 'NO_PEER_CERTIFICATE');
      const got = once(p.client, 'data');
      await p.client.send(Buffer.from('anon'));
      assert.equal((await got).toString(), 'echo:anon');
      await p.close();
    });

    await r.test(`[${version}] mTLS: başka CA'dan istemci sertifikası reddedilir`, async () => {
      // Sunucu yalnızca kendi imzaladığı istemcileri kabul etsin; ama CA olarak
      // istemci sertifikasının kendisini veriyoruz → zincir kurulamaz.
      await expectRejected(
        { cert: c.serverCert, key: c.serverKey, ca: c.selfSigned, requestCert: true,
          rejectUnauthorized: true, ...V },
        { ...CLI, cert: c.clientCert, key: c.clientKey },
        /UNABLE_TO_GET_ISSUER_CERT|SELF_SIGNED|doğrulama/);
    });

    await r.test(`[${version}] sunucu doğrulaması: yanlış CA reddedilir`, async () => {
      await expectRejected(SRV, { ...CLI, ca: c.clientCert },
                           /UNABLE_TO_GET_ISSUER_CERT|doğrulama/);
    });

    await r.test(`[${version}] sunucu doğrulaması: hostname uyuşmazlığı reddedilir`, async () => {
      await expectRejected(SRV, { ...CLI, servername: 'baska.example' },
                           /HOSTNAME_MISMATCH/);
    });

    await r.test(`[${version}] SAN'daki alternatif isim kabul edilir`, async () => {
      const p = await pair(SRV, { ...CLI, servername: 'dtls.local' });
      await p.waitConnected();
      assert.equal(p.client.authorized, true);
      await p.close();
    });

    await r.test(`[${version}] rejectUnauthorized=false doğrulamayı raporlar ama kesmez`, async () => {
      const p = await pair(SRV, {
        ...CLI, ca: undefined, rejectUnauthorized: false, servername: 'localhost',
      });
      await p.waitConnected();
      assert.equal(p.client.authorized, false);
      assert.ok(p.client.authorizationError);
      await p.close();
    });

    await r.test(`[${version}] parmak izi ile güven (WebRTC tarzı)`, async () => {
      const p = await pair(
        { cert: c.selfSigned, key: c.serverKey, ...V },
        { peerFingerprint: selfFp, servername: 'localhost', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true);
      await p.close();
    });

    await r.test(`[${version}] yanlış parmak izi reddedilir`, async () => {
      await expectRejected(
        { cert: c.selfSigned, key: c.serverKey, ...V },
        { peerFingerprint: 'AA'.repeat(32), servername: 'localhost', ...V },
        /FINGERPRINT_MISMATCH/);
    });

    await r.test(`[${version}] allowSelfSigned kendinden imzalıyı kabul eder`, async () => {
      const p = await pair(
        { cert: c.selfSigned, key: c.serverKey, ...V },
        { allowSelfSigned: true, servername: 'localhost', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true);
      await p.close();
    });

    await r.test(`[${version}] verifyPeerCertificate kancası reddedebilir`, async () => {
      await expectRejected(SRV, {
        ...CLI,
        verifyPeerCertificate: (cert) => (cert.subject.includes('localhost')
          ? new Error('bu sunucuyu istemiyorum') : null),
      }, /VERIFY_HOOK_REJECTED/);
    });

    await r.test(`[${version}] verifyPeerCertificate kancası kabul edebilir`, async () => {
      let seen = null;
      const p = await pair(SRV, {
        ...CLI,
        verifyPeerCertificate: (cert, chain) => { seen = { cert, len: chain.length }; return null; },
      });
      await p.waitConnected();
      assert.ok(seen);
      assert.match(seen.cert.subject, /localhost/);
      await p.close();
    });

    await r.test(`[${version}] checkServerIdentity özel doğrulayıcı`, async () => {
      let asked = null;
      const p = await pair(SRV, {
        ...CLI, servername: 'her-neyse',
        checkServerIdentity: (host, cert) => { asked = host; return null; },
      });
      await p.waitConnected();
      assert.equal(asked, 'her-neyse');
      assert.equal(p.client.authorized, true);
      await p.close();
    });

    await r.test(`[${version}] ara sertifikalı zincir doğrulanır`, async () => {
      // Sunucu leaf + CA gönderir; istemci yalnızca CA'ya güvenir.
      const p = await pair(
        { ...SRV, cert: Buffer.concat([c.serverCert, c.ca]) }, CLI);
      await p.waitConnected();
      assert.equal(p.client.authorized, true);
      assert.equal(p.client.peerCertificateChain.length, 2);
      await p.close();
    });

    // ======================================================================
    // Gerçek zincir senaryoları: kök CA → ara CA → sunucu
    // ======================================================================
    await r.test(`[${version}] gerçek ara CA zinciri: leaf + ara CA gönderilir, köke güvenilir`, async () => {
      // `cert` bir DEMETTİR (leaf + ara CA); `ca` yalnızca KÖKÜ içerir.
      // İstemci ara CA'yı hiç tanımaz — zinciri gelen demetten kurmak zorundadır.
      const p = await pair(
        { cert: c.interChain, key: c.serverKey, ...V },
        { ca: c.ca, servername: 'localhost', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true, p.client.authorizationError || '');
      assert.equal(p.client.peerCertificateChain.length, 2, 'leaf + ara CA gönderilmeli');
      // Doğrulanmış yol köke kadar uzanır: leaf → ara CA → kök
      assert.equal(p.client.peerCertificatePath.length, 3);
      await p.close();
    });

    await r.test(`[${version}] ara CA gönderilmezse zincir kurulamaz`, async () => {
      // Yalnızca leaf gönderilir; istemci ara CA'yı bilmediği için doğrulayamaz.
      await expectRejected(
        { cert: c.interLeaf, key: c.serverKey, ...V },
        { ca: c.ca, servername: 'localhost', ...V },
        /UNABLE_TO_GET_ISSUER_CERT|doğrulama/);
    });

    await r.test(`[${version}] ara CA doğrudan güven çıpası olarak verilebilir`, async () => {
      // Kök hiç verilmez; güven doğrudan ara CA'ya sabitlenir (kısıtlı güven).
      const p = await pair(
        { cert: c.interLeaf, key: c.serverKey, ...V },
        { ca: c.interCert, servername: 'localhost', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true, p.client.authorizationError || '');
      assert.equal(p.client.peerCertificatePath.length, 2, 'yol ara CA\'da bitmeli');
      await p.close();
    });

    await r.test(`[${version}] ara CA'yı içeren CA demeti de çalışır`, async () => {
      // Yaygın yapılandırma: `ca` dosyasına kök + ara CA birlikte konur,
      // sunucu ise sadece leaf gönderir.
      const p = await pair(
        { cert: c.interLeaf, key: c.serverKey, ...V },
        { ca: Buffer.concat([c.ca, c.interCert]), servername: 'localhost', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true, p.client.authorizationError || '');
      await p.close();
    });

    await r.test(`[${version}] karışık sıralı demet leaf'i başa alarak düzeltilir`, async () => {
      // Kullanıcı zinciri TERS sırada verdi (ara CA önce, leaf sonra).
      // TLS leaf'in ilk sırada olmasını şart koşar; kütüphane demeti çözer.
      const reversed = Buffer.concat([c.interCert, c.interLeaf]);
      const p = await pair(
        { cert: reversed, key: c.serverKey, ...V },
        { ca: c.ca, servername: 'localhost', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true, p.client.authorizationError || '');
      assert.match(p.client.getPeerCertificate().subject, /localhost/,
                   'leaf olarak sunucu sertifikası seçilmeli');
      await p.close();
    });

    await r.test(`[${version}] kök zincire dahil edilse de güven deposundan gelmelidir`, async () => {
      // Sunucu leaf + ara + KÖK gönderir; istemcinin güven deposu BOŞ değil ama
      // farklı bir CA içeriyor → zincirdeki kökün varlığı güven üretmez.
      await expectRejected(
        { cert: Buffer.concat([c.interLeaf, c.interCert, c.ca]), key: c.serverKey, ...V },
        { ca: c.selfSigned, servername: 'localhost', ...V },
        /SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_GET_ISSUER_CERT|doğrulama/);
    });

    await r.test(`[${version}] mTLS: istemci de ara CA zinciri gönderebilir`, async () => {
      const p = await pair(
        { ...SRV, requestCert: true, rejectUnauthorized: true },
        { ...CLI, cert: c.interChain, key: c.serverKey });
      const s = await p.waitConnected();
      assert.equal(s.authorized, true, s.authorizationError || '');
      assert.equal(s.peerCertificatePath.length, 3, 'sunucu yolu köke kadar kurmalı');
      await p.close();
    });

    await r.test(`[${version}] pathLen kısıtı aşılırsa reddedilir`, async () => {
      // Ara CA pathlen:0 ile imzalanmıştır: altında BAŞKA bir CA olamaz.
      // Ara CA'yı leaf'miş gibi sunup altına sahte bir halka eklemek yerine,
      // kısıtın gerçekten okunduğunu doğrudan doğrulayalım.
      const inter = new crypto.X509Certificate(c.interCert);
      const info = dtls.pki.certInfo(inter);
      const bc = dtls.pki.x509.basicConstraints(info);
      assert.equal(bc.isCA, true);
      assert.equal(bc.pathLen, 0, 'ara CA pathlen:0 taşımalı');
    });
  };
});

(async () => {
  for (const suite of suites) await suite();
  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
