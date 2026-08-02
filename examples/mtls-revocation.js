#!/usr/bin/env node
'use strict';
/**
 * mTLS + iptal denetimi (OCSP / CRL) — uçtan uca çalışan örnek.
 *
 *   node examples/mtls-revocation.js
 *   node examples/mtls-revocation.js --revoke      # istemciyi iptal listesine al
 *   node examples/mtls-revocation.js --crl         # OCSP yerine CRL kullan
 *   node examples/mtls-revocation.js --staple      # sunucu kendi yanıtını zımbalasın
 *
 * Örnek üç şeyi tek süreçte ayağa kaldırır:
 *   1. `node:http` üzerinde bir OCSP responder + CRL dağıtım noktası
 *   2. `requestCert` + `revocation: 'hard-fail'` ile bir DTLS sunucusu
 *   3. Sertifikası az önce imzalanmış bir DTLS istemcisi
 *
 * Böylece "sertifika geçerli ama İPTAL EDİLMİŞ" durumunun handshake'i gerçekten
 * kestiği görülebilir — normal bir zincir doğrulaması bunu YAKALAYAMAZ.
 *
 * Önce: npm run certs
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const dtls = require('..');
const { startPkiServer, buildOcspResponse, parseOcspRequest, serialHexOf } =
  require('../tests/pki-server.js');

const CERT_DIR = path.join(__dirname, '..', 'certs');
const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);

const USE_CRL = has('--crl');
const REVOKE = has('--revoke');
const STAPLE = has('--staple');

function need(file) {
  const p = path.join(CERT_DIR, file);
  if (!fs.existsSync(p)) {
    console.error(`\n  ${file} yok. Önce çalıştırın:  npm run certs\n`);
    process.exit(1);
  }
  return fs.readFileSync(p);
}

const caPem = need('ca.crt');
const caKeyPem = need('ca.key');
const serverCert = need('server.crt');
const serverKey = need('server.key');

const caX509 = new crypto.X509Certificate(caPem);
const caKey = crypto.createPrivateKey(caKeyPem);

/** AIA/CDP uzantıları çalışma anındaki port'a bağlı olduğu için taze imzalarız. */
function issueClientCert({ cn, ocspUrl, crlUrl, tmpDir }) {
  const csr = path.join(tmpDir, 'c.csr');
  const ext = path.join(tmpDir, 'c.ext');
  const out = path.join(tmpDir, 'c.crt');

  execFileSync('openssl', ['req', '-new', '-key', path.join(CERT_DIR, 'server.key'),
                           '-out', csr, '-subj', `/CN=${cn}/O=node-dtls`], { stdio: 'pipe' });
  fs.writeFileSync(ext,
    'basicConstraints = critical,CA:FALSE\n' +
    'keyUsage = critical,digitalSignature\n' +
    'extendedKeyUsage = clientAuth\n' +
    `subjectAltName = DNS:${cn}\n` +
    'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n' +
    (ocspUrl ? `authorityInfoAccess = OCSP;URI:${ocspUrl}\n` : '') +
    (crlUrl ? `crlDistributionPoints = URI:${crlUrl}\n` : ''));
  execFileSync('openssl', ['x509', '-req', '-in', csr, '-CA', path.join(CERT_DIR, 'ca.crt'),
                           '-CAkey', path.join(CERT_DIR, 'ca.key'), '-CAcreateserial',
                           '-out', out, '-days', '30', '-sha256', '-extfile', ext], { stdio: 'pipe' });
  const pem = fs.readFileSync(out);
  const x = new crypto.X509Certificate(pem);
  return { pem, x509: x, serial: serialHexOf(x) };
}

(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dtls-example-'));

  // ---------------------------------------------------------------- 1) PKI servisi
  const pkiSrv = await startPkiServer({ issuerCert: caX509, issuerKey: caKey });
  console.log(`OCSP responder : ${pkiSrv.ocspUrl}`);
  console.log(`CRL dağıtımı   : ${pkiSrv.crlUrl}`);

  const client = issueClientCert({
    cn: 'dtls-demo-client', tmpDir,
    ocspUrl: USE_CRL ? null : pkiSrv.ocspUrl,
    crlUrl: USE_CRL ? pkiSrv.crlUrl : null,
  });
  console.log(`İstemci sertifikası: CN=dtls-demo-client, seri=${client.serial}`);

  if (REVOKE) {
    if (USE_CRL) pkiSrv.setRevoked([{ serial: client.serial, reason: 1 /* keyCompromise */ }]);
    else pkiSrv.setStatus(client.serial, { status: 'revoked', reason: 1 });
    console.log('DURUM          : İPTAL EDİLDİ (keyCompromise)');
  } else {
    if (!USE_CRL) pkiSrv.setStatus(client.serial, { status: 'good' });
    console.log('DURUM          : geçerli');
  }

  // -------------------------------------------- sunucu için zımbalanacak yanıt
  let ocspResponse = null;
  if (STAPLE) {
    const subject = dtls.x509.parseCertificate(new crypto.X509Certificate(serverCert).raw);
    const issuer = dtls.x509.parseCertificate(caX509.raw);
    const req = dtls.revocation.buildOcspRequest(subject, issuer, { nonce: false });
    ocspResponse = buildOcspResponse({
      request: parseOcspRequest(req.der),
      issuerCert: caX509, responderKey: caKey,
      statusMap: new Map([[serialHexOf(new crypto.X509Certificate(serverCert)), { status: 'good' }]]),
    });
    console.log('Zımbalama      : açık (sunucu kendi OCSP yanıtını taşıyor)');
  }

  // ---------------------------------------------------------------- 2) DTLS sunucusu
  const server = dtls.createServer({
    cert: serverCert,
    key: serverKey,
    ca: caPem,
    requestCert: true,
    rejectUnauthorized: true,
    revocation: 'hard-fail',       // durum öğrenilemezse de reddet
    ocspResponse,
  });

  server.on('secureConnection', (sock) => {
    console.log('\n✓ İstemci KABUL edildi');
    console.log(`  konu    : ${sock.getPeerCertificate().subject.replace(/\n/g, ', ')}`);
    console.log(`  yol     : ${sock.peerCertificatePath.map((c) => c.subject.split('\n')[0]).join(' → ')}`);
    for (const res of sock.peerRevocation.results) {
      console.log(`  iptal   : ${res.subject} → ${res.status} (${res.method}${res.cached ? ', önbellek' : ''})`);
    }
    sock.on('data', (b) => sock.send(Buffer.concat([Buffer.from('echo:'), b])).catch(() => {}));
  });

  server.on('sessionError', (e) => {
    console.log('\n✗ İstemci REDDEDİLDİ');
    console.log(`  sebep   : ${e.message}`);
  });

  const addr = await server.listen(0, '127.0.0.1');

  // ---------------------------------------------------------------- 3) DTLS istemcisi
  try {
    const sock = await dtls.connect({
      host: '127.0.0.1', port: addr.port, servername: 'localhost',
      ca: caPem, cert: client.pem, key: serverKey,
      revocation: 'soft-fail',      // istemci de sunucuyu denetler
    });
    console.log(`\nBağlandı: ${sock.protocol} / ${sock.cipher}`);
    if (sock.peerOcspStaple) {
      console.log(`Sunucu yanıtı zımbaladı (${sock.peerOcspStaple.length} bayt) — ağ turu yok`);
    }
    if (sock.peerRevocation) {
      for (const res of sock.peerRevocation.results) {
        console.log(`Sunucu iptal durumu: ${res.status} (${res.method})`);
      }
    }

    const reply = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('yanıt gelmedi')), 3000);
      sock.once('data', (b) => { clearTimeout(t); resolve(b); });
      sock.send(Buffer.from('merhaba')).catch(reject);
    });
    console.log(`Yanıt: ${reply}`);
    await sock.close();
  } catch (e) {
    console.log(`\nİstemci bağlanamadı: ${e.message}`);
  }

  await new Promise((r) => setTimeout(r, 200));
  console.log(`\nResponder istatistiği: ${pkiSrv.stats.ocsp} OCSP, ${pkiSrv.stats.crl} CRL isteği`);

  await server.close();
  await pkiSrv.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
})().catch((e) => { console.error('örnek çöktü:', e); process.exit(1); });
