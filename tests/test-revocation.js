'use strict';
// Sertifika iptal denetimi — OCSP (RFC 6960) ve CRL (RFC 5280 §5).
//
// Testler gerçek bir HTTP OCSP responder'ı ve CRL dağıtım noktası ayağa
// kaldırır (tests/pki-server.js), sertifikalara AIA/CDP uzantılarını yeniden
// gömer ve DTLS handshake'inin bu uç noktalara gerçekten gittiğini doğrular.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { Runner, loadCerts, pair, once, sleep, dtls, CERT_DIR } = require('./helpers.js');
const { startPkiServer, buildOcspResponse, buildCrl, parseOcspRequest, serialHexOf } =
  require('./pki-server.js');
const revocationLib = require('../src/crypto/revocation.js');
const x509 = require('../src/crypto/x509.js');

const c = loadCerts();
const r = new Runner('iptal denetimi (OCSP / CRL)');

const caX509 = new crypto.X509Certificate(c.ca);
const caKey = crypto.createPrivateKey(c.caKey);

// ---------------------------------------------------------------------------
// AIA/CDP uzantıları çalışma anındaki port'a bağlıdır; sertifikaları test
// başlarken yeniden imzalarız (gen-certs.sh sabit bir port gömer).
// ---------------------------------------------------------------------------
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dtls-revoke-'));

function issueLeaf({ cn, ocspUrl, crlUrl, san = 'DNS:localhost, IP:127.0.0.1',
                     eku = 'serverAuth, clientAuth' }) {
  const keyPath = path.join(CERT_DIR, 'server.key');
  const csr = path.join(tmp, `${cn}.csr`);
  const extFile = path.join(tmp, `${cn}.ext`);
  const out = path.join(tmp, `${cn}.crt`);

  execFileSync('openssl', ['req', '-new', '-key', keyPath, '-out', csr,
                           '-subj', `/CN=${cn}/O=node-dtls`], { stdio: 'pipe' });
  const aia = ocspUrl ? `authorityInfoAccess = OCSP;URI:${ocspUrl}\n` : '';
  const cdp = crlUrl ? `crlDistributionPoints = URI:${crlUrl}\n` : '';
  fs.writeFileSync(extFile,
    'basicConstraints = critical,CA:FALSE\n' +
    'keyUsage = critical,digitalSignature,keyEncipherment\n' +
    `extendedKeyUsage = ${eku}\n` +
    `subjectAltName = ${san}\n` +
    'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n' +
    aia + cdp);

  execFileSync('openssl', ['x509', '-req', '-in', csr, '-CA', path.join(CERT_DIR, 'ca.crt'),
                           '-CAkey', path.join(CERT_DIR, 'ca.key'), '-CAcreateserial',
                           '-out', out, '-days', '30', '-sha256', '-extfile', extFile], { stdio: 'pipe' });
  const pem = fs.readFileSync(out);
  return { pem, x509: new crypto.X509Certificate(pem), serial: serialHexOf(new crypto.X509Certificate(pem)) };
}


/**
 * Handshake'in reddedilmesini bekler. Reddin nerede görüneceği SÜRÜME bağlıdır:
 * DTLS 1.3'te istemci kendi Finished'ini gönderip "bağlandım" der, sunucu ise
 * sonradan reddeder (hata `sessionError` olarak görünür); DTLS 1.2'de istemci
 * sunucunun Finished'ini beklediği için reddi ALARM olarak alır ve `connect()`
 * reject eder. İki yolu da kabul ediyoruz.
 */
async function expectRejected(srvOpts, cliOpts, matcher) {
  let p = null;
  try {
    p = await pair(srvOpts, cliOpts);
  } catch (e) {
    const all = [e.message, ...(e.serverErrors || []).map((x) => x.message)].join(' | ');
    if (matcher) assert.match(all, matcher);
    return all;
  }
  await sleep(300);
  const rejected = p.errors.length > 0 || p.serverSocket() === null || p.serverSocket().closed;
  const msgs = p.errors.map((x) => x.message).join(' | ');
  await p.close();
  assert.ok(rejected, 'handshake reddedilmeliydi ama iki taraf da kabul etti');
  if (matcher && msgs) assert.match(msgs, matcher);
  return msgs;
}

(async () => {
  // =========================================================================
  // Birim düzeyi: DER / OCSP / CRL yapıları
  // =========================================================================
  await r.test('OCSP isteği RFC 6960 §4.1.1 yapısına uyar', () => {
    const leafInfo = x509.parseCertificate(new crypto.X509Certificate(c.clientCert).raw);
    const issuerInfo = x509.parseCertificate(caX509.raw);
    const req = revocationLib.buildOcspRequest(leafInfo, issuerInfo, { hashAlgorithm: 'sha256' });

    const parsed = parseOcspRequest(req.der);
    assert.equal(parsed.requests.length, 1);
    assert.equal(parsed.requests[0].hashAlgOid, x509.OID.sha256);
    assert.deepEqual(parsed.requests[0].serialNumber, leafInfo.serialNumber);
    assert.ok(req.nonce && req.nonce.length === 16, 'nonce üretilmeli');
    assert.deepEqual(parsed.nonce, req.nonce, 'nonce isteğe gömülmeli');

    // issuerNameHash / issuerKeyHash gerçekten CA'nın alanlarından türemeli
    assert.deepEqual(parsed.requests[0].issuerNameHash,
                     crypto.createHash('sha256').update(issuerInfo.subjectDer).digest());
    assert.deepEqual(parsed.requests[0].issuerKeyHash,
                     crypto.createHash('sha256').update(issuerInfo.spkiKeyBits).digest());
  });

  await r.test('AIA ve CDP uzantıları okunur', async () => {
    const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
    const leaf = issueLeaf({ cn: 'aia-test', ocspUrl: srv.ocspUrl, crlUrl: srv.crlUrl });
    const info = x509.parseCertificate(leaf.x509.raw);
    assert.deepEqual(x509.authorityInfoAccess(info).ocsp, [srv.ocspUrl]);
    assert.deepEqual(x509.crlDistributionPoints(info), [srv.crlUrl]);
    await srv.close();
  });

  await r.test('CRL çözümlenir ve imzası doğrulanır', () => {
    const leaf = new crypto.X509Certificate(c.clientCert);
    const serial = serialHexOf(leaf);
    const crlDer = buildCrl({
      issuerCert: caX509, issuerKey: caKey,
      revoked: [{ serial, reason: 1 }],
    });
    const parsed = x509.parseCrl(crlDer);
    assert.equal(parsed.isDelta, false);
    assert.ok(parsed.revoked.has(serial.replace(/^0+/, '') || serial) || parsed.revoked.has(serial));

    const res = revocationLib.verifyCrl({
      crlDer,
      subject: x509.parseCertificate(leaf.raw),
      issuer: x509.parseCertificate(caX509.raw),
      issuerPublicKey: caX509.publicKey,
    });
    assert.equal(res.status, 'revoked');
    assert.equal(res.reason, 'keyCompromise');
  });

  await r.test('yanlış anahtarla imzalanmış CRL reddedilir', () => {
    const wrongKey = crypto.createPrivateKey(c.interKey);
    const crlDer = buildCrl({ issuerCert: caX509, issuerKey: wrongKey, revoked: [] });
    const res = revocationLib.verifyCrl({
      crlDer,
      subject: x509.parseCertificate(new crypto.X509Certificate(c.clientCert).raw),
      issuer: x509.parseCertificate(caX509.raw),
      issuerPublicKey: caX509.publicKey,
    });
    assert.equal(res.status, 'unknown');
    assert.equal(res.error, 'CRL_BAD_SIGNATURE');
  });

  await r.test('süresi geçmiş CRL kabul edilmez', () => {
    const crlDer = buildCrl({
      issuerCert: caX509, issuerKey: caKey, revoked: [],
      thisUpdate: Date.now() - 30 * 86400_000, nextUpdateMs: 7 * 86400_000,
    });
    const res = revocationLib.verifyCrl({
      crlDer,
      subject: x509.parseCertificate(new crypto.X509Certificate(c.clientCert).raw),
      issuer: x509.parseCertificate(caX509.raw),
      issuerPublicKey: caX509.publicKey,
    });
    assert.equal(res.error, 'CRL_EXPIRED');
  });

  await r.test('OCSP yanıtı doğrulanır (good / revoked / unknown)', () => {
    const leaf = new crypto.X509Certificate(c.clientCert);
    const subject = x509.parseCertificate(leaf.raw);
    const issuer = x509.parseCertificate(caX509.raw);
    const serial = serialHexOf(leaf);

    for (const [status, expected] of [['good', 'good'], ['revoked', 'revoked'], ['unknown', 'unknown']]) {
      const reqObj = revocationLib.buildOcspRequest(subject, issuer);
      const respDer = buildOcspResponse({
        request: parseOcspRequest(reqObj.der),
        issuerCert: caX509, responderKey: caKey,
        statusMap: new Map([[serial, { status, reason: status === 'revoked' ? 4 : undefined }]]),
      });
      const parsed = revocationLib.parseOcspResponse(respDer);
      assert.equal(parsed.status, 'successful');
      const res = revocationLib.verifyOcspResponse({
        basic: parsed.basic, subject, issuer,
        issuerPublicKey: caX509.publicKey, nonce: reqObj.nonce,
      });
      assert.equal(res.status, expected, `status=${status}`);
      if (status === 'revoked') assert.equal(res.reason, 'superseded');
    }
  });

  await r.test('OCSP nonce uyuşmazlığı reddedilir (tekrar oynatma)', () => {
    const leaf = new crypto.X509Certificate(c.clientCert);
    const subject = x509.parseCertificate(leaf.raw);
    const issuer = x509.parseCertificate(caX509.raw);

    const reqObj = revocationLib.buildOcspRequest(subject, issuer);
    // Responder BAŞKA bir nonce yansıtıyor → yanıt bu isteğe ait değil.
    const respDer = buildOcspResponse({
      request: { ...parseOcspRequest(reqObj.der), nonce: crypto.randomBytes(16) },
      issuerCert: caX509, responderKey: caKey,
      statusMap: new Map([[serialHexOf(leaf), { status: 'good' }]]),
    });
    const res = revocationLib.verifyOcspResponse({
      basic: revocationLib.parseOcspResponse(respDer).basic,
      subject, issuer, issuerPublicKey: caX509.publicKey, nonce: reqObj.nonce,
    });
    assert.equal(res.error, 'OCSP_NONCE_MISMATCH');
  });

  await r.test('yetkisiz imzalayan OCSP yanıtı reddedilir', () => {
    const leaf = new crypto.X509Certificate(c.clientCert);
    const subject = x509.parseCertificate(leaf.raw);
    const issuer = x509.parseCertificate(caX509.raw);
    const interX = new crypto.X509Certificate(c.interCert);

    // Ara CA, CA tarafından imzalıdır ama OCSPSigning EKU'su YOKTUR:
    // bu yüzden bu CA adına iptal durumu bildiremez (RFC 6960 §4.2.2.2).
    const reqObj = revocationLib.buildOcspRequest(subject, issuer);
    const respDer = buildOcspResponse({
      request: parseOcspRequest(reqObj.der),
      issuerCert: caX509,
      responderKey: crypto.createPrivateKey(c.interKey),
      responderCertDer: interX.raw,
      responderIdType: 'byName',
      statusMap: new Map([[serialHexOf(leaf), { status: 'good' }]]),
    });
    const res = revocationLib.verifyOcspResponse({
      basic: revocationLib.parseOcspResponse(respDer).basic,
      subject, issuer, issuerPublicKey: caX509.publicKey, nonce: reqObj.nonce,
    });
    assert.equal(res.status, 'unknown');
    assert.equal(res.error, 'OCSP_RESPONDER_NOT_AUTHORIZED');
  });

  await r.test('süresi geçmiş OCSP yanıtı reddedilir', () => {
    const leaf = new crypto.X509Certificate(c.clientCert);
    const subject = x509.parseCertificate(leaf.raw);
    const issuer = x509.parseCertificate(caX509.raw);
    const reqObj = revocationLib.buildOcspRequest(subject, issuer);
    const respDer = buildOcspResponse({
      request: parseOcspRequest(reqObj.der),
      issuerCert: caX509, responderKey: caKey,
      statusMap: new Map([[serialHexOf(leaf), { status: 'good' }]]),
      thisUpdate: Date.now() - 30 * 86400_000, nextUpdateMs: 86400_000,
    });
    const res = revocationLib.verifyOcspResponse({
      basic: revocationLib.parseOcspResponse(respDer).basic,
      subject, issuer, issuerPublicKey: caX509.publicKey, nonce: reqObj.nonce,
    });
    assert.equal(res.error, 'OCSP_RESPONSE_EXPIRED');
  });

  // =========================================================================
  // Uçtan uca: gerçek handshake + gerçek HTTP responder
  // =========================================================================
  for (const version of ['DTLSv1.3', 'DTLSv1.2']) {
    const V = { minVersion: version, maxVersion: version };

    await r.test(`[${version}] mTLS: OCSP 'good' ile istemci kabul edilir`, async () => {
      const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const leaf = issueLeaf({ cn: 'ocsp-good-client', ocspUrl: srv.ocspUrl, san: 'DNS:dtls-client' });
      srv.setStatus(leaf.serial, { status: 'good' });

      const p = await pair(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: 'hard-fail', ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V });
      const s = await p.waitConnected();
      assert.equal(s.authorized, true, s.authorizationError || '');
      assert.ok(srv.stats.ocsp > 0, 'OCSP responder gerçekten sorgulanmalıydı');
      assert.equal(s.peerRevocation.results[0].status, 'good');
      assert.equal(s.peerRevocation.results[0].method, 'ocsp');
      await p.close();
      await srv.close();
    });

    await r.test(`[${version}] mTLS: OCSP 'revoked' istemciyi reddeder`, async () => {
      const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const leaf = issueLeaf({ cn: 'ocsp-revoked-client', ocspUrl: srv.ocspUrl, san: 'DNS:dtls-client' });
      srv.setStatus(leaf.serial, { status: 'revoked', reason: 1 });

      await expectRejected(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: 'hard-fail', ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V },
        /CERT_REVOKED|keyCompromise/);
      await srv.close();
    });

    await r.test(`[${version}] CRL: iptal edilmiş istemci reddedilir (AIA yok)`, async () => {
      const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const leaf = issueLeaf({ cn: 'crl-revoked-client', crlUrl: srv.crlUrl, san: 'DNS:dtls-client' });
      srv.setRevoked([{ serial: leaf.serial, reason: 4 }]);

      await expectRejected(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: 'hard-fail', ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V },
        /CERT_REVOKED|superseded/);
      assert.ok(srv.stats.crl > 0, 'CRL indirilmeliydi');
      await srv.close();
    });

    await r.test(`[${version}] CRL: listede olmayan istemci kabul edilir`, async () => {
      const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const leaf = issueLeaf({ cn: 'crl-good-client', crlUrl: srv.crlUrl, san: 'DNS:dtls-client' });
      srv.setRevoked([{ serial: 'deadbeef', reason: 1 }]);

      const p = await pair(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: 'hard-fail', ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V });
      const s = await p.waitConnected();
      assert.equal(s.authorized, true, s.authorizationError || '');
      assert.equal(s.peerRevocation.results[0].method, 'crl');
      await p.close();
      await srv.close();
    });

    await r.test(`[${version}] responder ulaşılamazsa: soft-fail geçer, hard-fail keser`, async () => {
      // Kapalı bir port: bağlantı ANINDA reddedilir, testi bekletmez.
      const dead = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const ocspUrl = dead.ocspUrl;
      await dead.close();
      const leaf = issueLeaf({ cn: 'unreachable-client', ocspUrl, san: 'DNS:dtls-client' });

      // soft-fail: ulaşılamayan responder bağlantıyı kesmez
      const soft = await pair(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: { mode: 'soft-fail', timeoutMs: 1000 }, ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V });
      const ss = await soft.waitConnected();
      assert.equal(ss.authorized, true, 'soft-fail bağlantıyı kesmemeli');
      assert.equal(ss.peerRevocation.results[0].status, 'unknown');
      await soft.close();

      // hard-fail: aynı durumda handshake reddedilir
      await expectRejected(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: { mode: 'hard-fail', timeoutMs: 1000 }, ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V },
        /REVOCATION_CHECK_FAILED|REVOCATION_UNAVAILABLE/);
    });

    await r.test(`[${version}] AIA/CDP taşımayan sertifika: hard-fail reddeder`, async () => {
      // client.crt gen-certs'in sabit (dinlenmeyen) adreslerini taşır; burada
      // hiç uzantısı olmayan bir sertifika kullanıyoruz.
      const leaf = issueLeaf({ cn: 'no-aia-client', san: 'DNS:dtls-client' });
      await expectRejected(
        { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
          rejectUnauthorized: true, revocation: 'hard-fail', ...V },
        { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey, ...V },
        /REVOCATION_NO_DISTRIBUTION_POINT|REVOCATION_CHECK_FAILED/);
    });

    await r.test(`[${version}] OCSP zımbalama: sunucu yanıtı taşır, istemci ağa çıkmaz`, async () => {
      const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const leaf = issueLeaf({ cn: 'stapled-server', ocspUrl: srv.ocspUrl });
      srv.setStatus(leaf.serial, { status: 'good' });

      // Sunucu, kendi sertifikası için OCSP yanıtını önceden hazırlar.
      const subject = x509.parseCertificate(leaf.x509.raw);
      const issuer = x509.parseCertificate(caX509.raw);
      const reqObj = revocationLib.buildOcspRequest(subject, issuer, { nonce: false });
      const stapled = buildOcspResponse({
        request: parseOcspRequest(reqObj.der),
        issuerCert: caX509, responderKey: caKey,
        statusMap: new Map([[leaf.serial, { status: 'good' }]]),
      });

      const before = srv.stats.ocsp;
      const p = await pair(
        { cert: leaf.pem, key: c.serverKey, ocspResponse: stapled, ...V },
        { ca: c.ca, servername: 'localhost', revocation: 'hard-fail', ...V });
      await p.waitConnected();
      assert.equal(p.client.authorized, true, p.client.authorizationError || '');
      assert.ok(p.client.peerOcspStaple, 'istemci zımbalanmış yanıtı almalı');
      assert.equal(p.client.peerRevocation.results[0].method, 'ocsp-stapled');
      assert.equal(srv.stats.ocsp, before, 'zımbalama varken responder\'a HİÇ gidilmemeli');
      await p.close();
      await srv.close();
    });

    await r.test(`[${version}] zımbalanmış 'revoked' yanıt bağlantıyı keser`, async () => {
      const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
      const leaf = issueLeaf({ cn: 'stapled-revoked-server', ocspUrl: srv.ocspUrl });

      const subject = x509.parseCertificate(leaf.x509.raw);
      const issuer = x509.parseCertificate(caX509.raw);
      const reqObj = revocationLib.buildOcspRequest(subject, issuer, { nonce: false });
      const stapled = buildOcspResponse({
        request: parseOcspRequest(reqObj.der),
        issuerCert: caX509, responderKey: caKey,
        statusMap: new Map([[leaf.serial, { status: 'revoked', reason: 1 }]]),
      });

      await assert.rejects(
        pair({ cert: leaf.pem, key: c.serverKey, ocspResponse: stapled, ...V },
             { ca: c.ca, servername: 'localhost', revocation: 'soft-fail', ...V }),
        /CERT_REVOKED|keyCompromise/);
      await srv.close();
    });
  }

  // =========================================================================
  // Politika ve önbellek
  // =========================================================================
  await r.test('revocation:"off" hiçbir ağ isteği yapmaz', async () => {
    const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
    const leaf = issueLeaf({ cn: 'off-policy-client', ocspUrl: srv.ocspUrl, san: 'DNS:dtls-client' });
    srv.setStatus(leaf.serial, { status: 'revoked', reason: 1 });

    const p = await pair(
      { cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
        rejectUnauthorized: true, revocation: 'off' },
      { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey });
    const s = await p.waitConnected();
    assert.equal(s.authorized, true, 'iptal denetimi kapalıyken sertifika kabul edilir');
    assert.equal(srv.stats.ocsp, 0, 'kapalıyken hiç istek gitmemeli');
    assert.equal(s.peerRevocation, null);
    await p.close();
    await srv.close();
  });

  await r.test('sonuç önbelleğe alınır — ikinci handshake ağa çıkmaz', async () => {
    const srv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
    const leaf = issueLeaf({ cn: 'cache-client', ocspUrl: srv.ocspUrl, san: 'DNS:dtls-client' });
    srv.setStatus(leaf.serial, { status: 'good' });

    const serverOpts = {
      cert: c.serverCert, key: c.serverKey, ca: c.ca, requestCert: true,
      rejectUnauthorized: true, revocation: 'hard-fail',
    };
    const clientOpts = { ca: c.ca, servername: 'localhost', cert: leaf.pem, key: c.serverKey };

    // Aynı sunucu nesnesi (dolayısıyla aynı önbellek) iki istemciye hizmet eder.
    const server = dtls.createServer(serverOpts);
    const conns = [];
    server.on('secureConnection', (s) => conns.push(s));
    const addr = await server.listen(0, '127.0.0.1');

    const c1 = await dtls.connect({ host: '127.0.0.1', port: addr.port, ...clientOpts });
    await sleep(150);
    const afterFirst = srv.stats.ocsp;
    assert.ok(afterFirst > 0, 'ilk handshake responder\'a gitmeli');

    const c2 = await dtls.connect({ host: '127.0.0.1', port: addr.port, ...clientOpts });
    await sleep(150);
    assert.equal(srv.stats.ocsp, afterFirst, 'ikinci handshake önbellekten karşılanmalı');
    assert.equal(conns.length, 2);
    assert.ok(conns[1].peerRevocation.results[0].cached, 'sonuç önbellekten gelmeli');

    await c1.close(); await c2.close(); await server.close();
    await srv.close();
  });

  await r.test('eş zamanlı sorgular tek isteğe birleşir (ölçeklenme)', async () => {
    // Bir sunucuya aynı anda N istemci bağlandığında önbellek henüz dolmamıştır;
    // birleştirme olmadan N ayrı OCSP isteği çıkar ve responder DoS'lanır.
    let calls = 0;
    const checker = new revocationLib.RevocationChecker({
      mode: 'soft-fail', ocsp: true, crl: false,
      fetch: async () => {
        calls++;
        await sleep(40);
        throw new Error('offline');
      },
    });
    const leaf = new crypto.X509Certificate(c.clientCert);
    const results = await Promise.all(
      Array.from({ length: 50 }, () => checker.checkChain([leaf, caX509])));

    assert.equal(calls, 1, `50 eş zamanlı denetim tek istek yapmalı (yapılan: ${calls})`);
    assert.equal(checker.snapshot().coalesced, 49);
    assert.ok(results.every((x) => x.ok), 'soft-fail hepsini geçirmeli');
  });

  await r.test('kök sertifika sorgulanmaz (RFC 5280 §6.1)', async () => {
    const checker = new revocationLib.RevocationChecker({
      mode: 'soft-fail', ocsp: true, crl: true,
      fetch: async () => { throw new Error('ağa çıkılmamalıydı'); },
    });
    // Yalnızca kökten oluşan bir "yol": sorgulanacak bağ yok.
    const res = await checker.checkChain([caX509]);
    assert.equal(res.ok, true);
    assert.equal(res.results.length, 0);
  });

  await r.test('zincirdeki ara CA da denetlenir', async () => {
    const queried = [];
    const checker = new revocationLib.RevocationChecker({
      mode: 'soft-fail', ocsp: true, crl: true,
      fetch: async (url) => { queried.push(url); throw new Error('offline'); },
    });
    const leaf = new crypto.X509Certificate(c.interLeaf);
    const inter = new crypto.X509Certificate(c.interCert);
    const res = await checker.checkChain([leaf, inter, caX509]);
    // leaf ve ara CA denetlenir; KÖK denetlenmez → 2 sonuç
    assert.equal(res.results.length, 2);
    assert.equal(res.ok, true, 'soft-fail modunda bağlantı kesilmez');
  });

  await r.test('geçersiz revocation.mode erken hata verir', () => {
    assert.throws(() => dtls.normalizeOptions('client', {
      ca: c.ca, revocation: 'belki',
    }), /revocation\.mode geçersiz/);
    assert.throws(() => dtls.normalizeOptions('server', {
      cert: c.serverCert, key: c.serverKey, ca: c.ca, revocation: true,
    }), /requestCert kapalı/);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  r.exit();
})().catch((e) => { console.error('test çöktü:', e); process.exit(1); });
