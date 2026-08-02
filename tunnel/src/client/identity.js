'use strict';
// İstemci kimliği: cihaz kodu ile giriş → CSR → mTLS sertifikası.
//
// Tünel istemcisi bir tarayıcı barındırmaz ve çoğu zaman bir SSH oturumunda
// ya da bir servis olarak çalışır. RFC 8628 (Device Authorization Grant) tam
// olarak bu durum için var: istemci bir kod gösterir, kullanıcı BAŞKA bir
// cihazda tarayıcıyla onaylar, istemci arka planda bekler.
//
//   1. POST /oauth/device/code      -> user_code + verification_uri
//   2. kullanıcı tarayıcıda onaylar
//   3. POST /oauth/token (poll)     -> access_token
//   4. yerel P-256 anahtar çifti + PKCS#10 CSR
//   5. POST /device/certificate     -> imzalanmış istemci sertifikası
//
// ÖZEL ANAHTAR HİÇBİR ZAMAN AĞA ÇIKMAZ. CSR yalnızca açık anahtarı ve onunla
// atılmış bir imzayı taşır; imza, isteği yapanın gerçekten o özel anahtara
// sahip olduğunun kanıtıdır (proof of possession). Sunucudan anahtar istemek
// (bazı sistemlerin yaptığı gibi) kimliğin kopyasını sunucuda bırakırdı.
//
// Yenileme her seferinde YENİ anahtar üretir: aynı anahtarı yeniden
// sertifikalandırmak, geçmişte olmuş olabilecek bir sızıntıyı bir ömür daha
// ileri taşımaktır.

const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fsp = require('node:fs/promises');
const path = require('node:path');

const { createCsr, generateKeyPair, OID } = require('./csr.js');

const IDENTITY_FILE = 'client-identity.json';

function request(method, url, {
  body = null, headers = {}, timeoutMs = 20_000, form = false,
} = {}) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(url); } catch { reject(new Error(`geçersiz URL: ${url}`)); return; }
    const lib = target.protocol === 'https:' ? https : http;

    let payload = null;
    const outHeaders = { accept: 'application/json', ...headers };
    if (body) {
      if (form) {
        payload = Buffer.from(new URLSearchParams(body).toString());
        outHeaders['content-type'] = 'application/x-www-form-urlencoded';
      } else {
        payload = Buffer.from(JSON.stringify(body));
        outHeaders['content-type'] = 'application/json';
      }
      outHeaders['content-length'] = payload.length;
    }

    const req = lib.request(target, { method, headers: outHeaders, timeout: timeoutMs }, (res) => {
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > 1024 * 1024) { req.destroy(new Error('yanıt çok büyük')); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* JSON olmayabilir */ }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${url} zaman aşımı`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * RFC 8628 cihaz yetkilendirme akışı.
 * @returns {Promise<{accessToken: string, refreshToken?: string, expiresIn: number}>}
 */
async function deviceLogin({
  idpUrl, clientId, scope, onPrompt, timeoutMs, log,
}) {
  const start = await request('POST', `${idpUrl}/oauth/device/code`, {
    body: { client_id: clientId, scope },
  });
  if (start.status !== 200 || !start.json?.device_code) {
    throw new Error(`cihaz kodu alınamadı: HTTP ${start.status} ${start.json?.error_description || start.text.slice(0, 200)}`);
  }

  const {
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: verificationUri,
    verification_uri_complete: verificationUriComplete,
    expires_in: expiresIn,
    interval,
  } = start.json;

  const prompt = {
    userCode, verificationUri, verificationUriComplete, expiresIn,
  };
  if (onPrompt) onPrompt(prompt);
  else {
    log?.info('tarayıcıda oturum açın', {
      adres: verificationUriComplete || verificationUri, kod: userCode,
    });
  }

  const deadline = Date.now() + (timeoutMs || expiresIn * 1000);
  let pollMs = (interval || 5) * 1000;

  for (;;) {
    if (Date.now() > deadline) throw new Error('cihaz onayı zaman aşımına uğradı');
    // eslint-disable-next-line no-await-in-loop
    await sleep(pollMs);
    // eslint-disable-next-line no-await-in-loop
    const res = await request('POST', `${idpUrl}/oauth/token`, {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: clientId,
      },
    });
    if (res.status === 200 && res.json?.access_token) {
      return {
        accessToken: res.json.access_token,
        refreshToken: res.json.refresh_token,
        expiresIn: res.json.expires_in,
      };
    }
    const code = res.json?.error;
    if (code === 'authorization_pending') continue;
    // RFC 8628 §3.5: sunucu yavaşlamamızı istiyorsa aralığı BÜYÜTMEK zorundayız;
    // yok saymak, sunucunun bizi tamamen reddetmesiyle sonuçlanır.
    if (code === 'slow_down') { pollMs += 5000; continue; }
    const err = new Error(`cihaz kodu değişimi başarısız: ${res.json?.error_description || code || `HTTP ${res.status}`}`);
    err.code = code;
    throw err;
  }
}

/** Sertifikanın yenilenme zamanı: ömrünün 2/3'ü. */
function renewAfterFor(certPem) {
  const cert = new crypto.X509Certificate(certPem);
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  if (!Number.isFinite(from) || !Number.isFinite(to)) return 0;
  return from + Math.floor((to - from) * (2 / 3));
}

async function loadIdentity(dir, log) {
  try {
    const raw = JSON.parse(await fsp.readFile(path.join(dir, IDENTITY_FILE), 'utf8'));
    if (!raw.certPem || !raw.privateKeyPem) return null;
    const cert = new crypto.X509Certificate(raw.certPem);
    const notAfter = Date.parse(cert.validTo);
    if (!Number.isFinite(notAfter) || notAfter < Date.now() + 60_000) {
      log?.info('kayıtlı sertifikanın süresi dolmuş, yenisi alınacak');
      return null;
    }
    return {
      ...raw,
      subject: cert.subject,
      notAfter,
      renewAfter: raw.renewAfter || renewAfterFor(raw.certPem),
      fingerprint256: String(cert.fingerprint256).replace(/:/g, '').toLowerCase(),
    };
  } catch {
    return null;
  }
}

async function saveIdentity(dir, identity) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, IDENTITY_FILE);
  const tmp = `${file}.tmp`;
  // 0600 ve temp+rename: özel anahtar içeren bir dosya, yazma yarıda kalırsa
  // "var ama bozuk" olmamalı ve asla dünya-okunur oluşturulmamalı.
  await fsp.writeFile(tmp, JSON.stringify(identity, null, 2), { mode: 0o600 });
  await fsp.rename(tmp, file);
}

/**
 * Kimlik edinir: diskte geçerli bir sertifika varsa onu döner, yoksa cihaz
 * kodu akışını çalıştırıp yeni bir tane alır.
 *
 * @param {object} o
 * @param {string} o.idpUrl        https://session.fitfak.net
 * @param {string} o.trustUrl      https://trust.fitfak.net
 * @param {string} o.oauthClientId
 * @param {string} o.dataDir
 * @param {string} [o.commonName]  sunucuda kullanıcı adıyla ezilir
 * @param {boolean} [o.force]      geçerli sertifika olsa bile yenile
 */
async function ensureIdentity({
  idpUrl, trustUrl, oauthClientId, dataDir, commonName, altNames = [],
  scope = 'openid profile', profile = 'client-auth', force = false,
  onPrompt, log, accessToken: providedToken,
}) {
  const existing = force ? null : await loadIdentity(dataDir, log);
  if (existing && Date.now() < existing.renewAfter) {
    log?.info('kayıtlı istemci sertifikası kullanılıyor', {
      subject: existing.subject,
      gecerlilikSonu: new Date(existing.notAfter).toISOString(),
    });
    return existing;
  }
  if (existing) {
    log?.info('sertifika yenileme zamanı geldi', {
      gecerlilikSonu: new Date(existing.notAfter).toISOString(),
    });
  }

  let accessToken = providedToken;
  if (!accessToken) {
    if (!oauthClientId) throw new Error('cihaz kodu girişi için OAuth client_id gerekli');
    const tokens = await deviceLogin({
      idpUrl, clientId: oauthClientId, scope, onPrompt, log,
    });
    accessToken = tokens.accessToken;
    log?.info('kimlik doğrulandı, sertifika isteniyor');
  }

  const { privateKey, publicKey } = generateKeyPair();
  const subjectCn = commonName || `tunnel-${crypto.randomBytes(4).toString('hex')}`;
  const { csrPem } = createCsr({
    privateKey,
    publicKey,
    subject: { commonName: subjectCn, organizationalUnit: 'fitfak-tunnel' },
    altNames: [subjectCn, ...altNames],
    extendedKeyUsage: [OID.CLIENT_AUTH],
  });

  const res = await request('POST', `${trustUrl}/device/certificate`, {
    body: { csrPem, profile },
    // Bearer ile geliyoruz: bu istek tarayıcıdan gelmiyor ve CSRF'e yapısal
    // olarak kapalı (bkz. fitfak-idp core/same-origin.js'teki kapsam notu).
    headers: { authorization: `Bearer ${accessToken}` },
  });

  if (res.status !== 200 || !res.json?.certPem) {
    const detail = res.json?.error_description || res.json?.error || res.text.slice(0, 300);
    throw new Error(`sertifika alınamadı: HTTP ${res.status} — ${detail}`);
  }

  const identity = {
    certPem: res.json.certPem,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    serialNumberHex: res.json.serialNumberHex,
    notBefore: res.json.notBefore,
    notAfter: Date.parse(res.json.notAfter) || 0,
    renewAfter: renewAfterFor(res.json.certPem),
    profile,
    commonName: subjectCn,
    issuedAt: Date.now(),
  };
  await saveIdentity(dataDir, identity);

  const cert = new crypto.X509Certificate(identity.certPem);
  log?.info('istemci sertifikası alındı', {
    subject: cert.subject,
    serial: identity.serialNumberHex,
    gecerlilikSonu: new Date(identity.notAfter).toISOString(),
    yenilemeZamani: new Date(identity.renewAfter).toISOString(),
  });

  return {
    ...identity,
    subject: cert.subject,
    fingerprint256: String(cert.fingerprint256).replace(/:/g, '').toLowerCase(),
  };
}

module.exports = {
  ensureIdentity, deviceLogin, loadIdentity, saveIdentity, request, IDENTITY_FILE,
};
