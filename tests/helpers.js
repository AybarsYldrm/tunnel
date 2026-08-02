'use strict';
// Testler için ortak yardımcılar: minik koşucu + sertifika yükleme + uç nokta kurulumu.

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');

const CERT_DIR = path.join(__dirname, '..', 'certs');

const REQUIRED_CERTS = [
  'ca.crt', 'ca.key', 'inter.crt', 'inter.key', 'inter-leaf.crt', 'inter-chain.pem',
  'server.crt', 'server.key', 'client.crt', 'client.key',
  'revoked.crt', 'revoked.key', 'server.pem',
];

function certsAvailable() {
  return REQUIRED_CERTS.every((f) => fs.existsSync(path.join(CERT_DIR, f)));
}

function readCert(name) {
  return fs.readFileSync(path.join(CERT_DIR, name));
}

/**
 * Test PKI'sını yükler ve TUTARLILIĞINI doğrular.
 *
 * Neden burada da kontrol ediliyor? Çünkü tutarsız bir certs/ dizini, testleri
 * "sunucu doğrulaması başarısız" / "HOSTNAME_MISMATCH" gibi KOD HATASI gibi
 * görünen mesajlarla düşürür. Sebebi burada söylemek, saatlerce yanlış yerde
 * hata aramayı önler.
 */
function loadCerts() {
  if (!certsAvailable()) {
    const missing = REQUIRED_CERTS.filter((f) => !fs.existsSync(path.join(CERT_DIR, f)));
    console.error(`\n  Test sertifikaları eksik (${missing.join(', ')}).` +
                  '\n  Çalıştırın:  npm run certs\n');
    process.exit(1);
  }

  const c = {
    ca: readCert('ca.crt'),
    caKey: readCert('ca.key'),
    interCert: readCert('inter.crt'),
    interKey: readCert('inter.key'),
    interLeaf: readCert('inter-leaf.crt'),
    interChain: readCert('inter-chain.pem'),
    serverCert: readCert('server.crt'),
    serverKey: readCert('server.key'),
    clientCert: readCert('client.crt'),
    clientKey: readCert('client.key'),
    revokedCert: readCert('revoked.crt'),
    revokedKey: readCert('revoked.key'),
    selfSigned: readCert('server.pem'),
  };

  const problems = [];
  const x = (pem) => new crypto.X509Certificate(pem);
  try {
    const ca = x(c.ca);
    for (const [name, pem] of [['server.crt', c.serverCert], ['client.crt', c.clientCert]]) {
      const leaf = x(pem);
      if (!leaf.checkIssued(ca) || !leaf.verify(ca.publicKey)) {
        problems.push(`${name} kök CA (ca.crt) tarafından imzalanmamış`);
      }
    }
    if (!x(c.serverCert).checkPrivateKey(crypto.createPrivateKey(c.serverKey))) {
      problems.push('server.key ↔ server.crt uyuşmuyor');
    }
    if (!x(c.serverCert).checkHost('dtls.local')) {
      problems.push("server.crt 'dtls.local' SAN'ını taşımıyor");
    }
    if (!/dtls-client/.test(x(c.clientCert).subject)) {
      problems.push("client.crt CN'i 'dtls-client' değil");
    }
  } catch (e) {
    problems.push(`sertifikalar okunamadı: ${e.message}`);
  }

  if (problems.length) {
    console.error('\n  certs/ dizinindeki test PKI\'sı TUTARSIZ:\n' +
                  problems.map((p) => `    • ${p}`).join('\n') +
                  '\n\n  Bu, kodda değil sertifikalarda bir sorundur. Çalıştırın:' +
                  '\n    npm run certs -- --force\n');
    process.exit(1);
  }
  return c;
}

// ---------------------------------------------------------------- koşucu
class Runner {
  constructor(title) {
    this.title = title;
    this.passed = 0;
    this.failed = 0;
    this.failures = [];
    console.log(`\n=== ${title} ===`);
  }

  async test(name, fn) {
    // Kütüphanenin İÇ zamanlayıcıları bilinçli olarak unref'lidir: bir DTLS
    // oturumu tek başına Node sürecini ayakta tutmamalıdır. Ama bu, soket
    // kullanmayan bir birim testinde event loop'un test ortasında boşalıp
    // sürecin SESSİZCE (exit 0) sonlanmasına yol açar — testin geri kalanı hiç
    // çalışmaz ve çıktı yarıda kesilir. Test süresince ref'li bir kalp atışı
    // tutarak loop'u açık tutuyoruz.
    const heartbeat = setInterval(() => {}, 1000);
    try {
      await fn();
      this.passed++;
      console.log(`  ✓ ${name}`);
    } catch (e) {
      this.failed++;
      this.failures.push({ name, error: e });
      console.error(`  ✗ ${name}\n      ${e.message}`);
    } finally {
      clearInterval(heartbeat);
    }
  }

  finish() {
    const total = this.passed + this.failed;
    console.log(`\n${this.title}: ${this.passed}/${total} geçti` +
                (this.failed ? ` — ${this.failed} BAŞARISIZ` : ' ✓'));
    return this.failed === 0;
  }

  /**
   * Sonucu bildirir ve süreci sonlandırır.
   *
   * `process.exit()` KULLANILMAZ: çıktı bir boruya (pipe) yazılıyorsa
   * tamponlanmış satırlar kaybolur — testler "geçti" derken çıktının yarısı
   * yok olur. Bunun yerine exitCode ayarlanır ve açık kalan zamanlayıcılar
   * unref edilerek event loop'un kendiliğinden boşalması sağlanır.
   */
  exit() {
    process.exitCode = this.finish() ? 0 : 1;
    // Testler soket/zamanlayıcı sızdırdıysa süreç asılı kalmasın.
    const guard = setTimeout(() => process.exit(process.exitCode), 2000);
    if (guard.unref) guard.unref();
  }
}

// ---------------------------------------------------------------- ağ kurulumu
const dtls = require('..');

/**
 * Bir sunucu + bağlı bir istemci kurar ve ikisini de döner.
 * `onData` verilirse sunucu tarafında veri geldiğinde çağrılır.
 */
async function pair(serverOptions = {}, clientOptions = {}, { echo = true } = {}) {
  const server = dtls.createServer(serverOptions);
  const errors = [];
  server.on('sessionError', (e) => errors.push(e));
  server.on('error', (e) => errors.push(e));

  let serverSocket = null;
  // Sunucu tarafı bağlantı, ZAMAN AŞIMLI beklenir. DTLS 1.3'te istemci kendi
  // Finished'ini gönderdiği anda "bağlandım" sayar; sunucu o sertifikayı
  // reddederse `pair()` başarıyla döner ama sunucu soketi HİÇ oluşmaz.
  // Zaman aşımı olmadan böyle bir test sonsuza kadar asılı kalır.
  let resolveConnected;
  let rejectConnected;
  const connectedPromise = new Promise((res, rej) => { resolveConnected = res; rejectConnected = rej; });
  connectedPromise.catch(() => {});   // beklemeyen çağıran varsa 'unhandled rejection' olmasın
  server.on('secureConnection', (s) => {
    serverSocket = s;
    if (echo) s.on('data', (b) => { s.send(Buffer.concat([Buffer.from('echo:'), b])).catch(() => {}); });
    resolveConnected(s);
  });

  const addr = await server.listen(0, '127.0.0.1');
  let client;
  try {
    client = await dtls.connect({ host: '127.0.0.1', port: addr.port, ...clientOptions });
  } catch (e) {
    await server.close();
    e.serverErrors = errors;
    throw e;
  }

  return {
    server,
    client,
    addr,
    errors,
    serverSocket: () => serverSocket,
    waitConnected: (timeoutMs = 5000) => Promise.race([
      connectedPromise,
      new Promise((_, rej) => {
        const t = setTimeout(() => rej(new Error(
          `sunucu 'secureConnection' ${timeoutMs}ms içinde gelmedi` +
          (errors.length ? ` — sunucu hataları: ${errors.map((e) => e.message).join(' | ')}` : ''),
        )), timeoutMs);
        if (t.unref) t.unref();
        connectedPromise.then(() => clearTimeout(t), () => {});
      }),
    ]),
    async close() {
      try { await client.close(); } catch { /* yoksay */ }
      await server.close();
      // Kapanıştan sonra hâlâ bekleyen varsa sonsuza kadar asılı kalmasın.
      rejectConnected(new Error('sunucu bağlantı beklenirken kapatıldı'));
    },
  };
}

/** Bir olayın İLK argümanını zaman aşımıyla bekler. */
function once(emitter, event, timeoutMs = 4000) {
  return onceArgs(emitter, event, timeoutMs).then((args) => args[0]);
}

/** Bir olayın tüm argümanlarını dizi olarak bekler. */
function onceArgs(emitter, event, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const onEvent = (...args) => { clearTimeout(timer); resolve(args); };
    const timer = setTimeout(() => {
      emitter.removeListener(event, onEvent);
      reject(new Error(`'${event}' olayı ${timeoutMs}ms içinde gelmedi`));
    }, timeoutMs);
    emitter.once(event, onEvent);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Bir soketin _sendRaw'ını sararak paket kaybı simüle eder. */
function injectLoss(socket, predicate) {
  const orig = socket._sendRaw.bind(socket);
  let n = 0;
  socket._sendRaw = (buf) => (predicate(n++, buf) ? Promise.resolve(0) : orig(buf));
  return () => { socket._sendRaw = orig; };
}

module.exports = {
  Runner, loadCerts, readCert, certsAvailable, pair,
  once, onceArgs, sleep, injectLoss, dtls, CERT_DIR,
};
