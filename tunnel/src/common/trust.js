'use strict';
// Kök sertifikanın alınması: http://status.trust.fitfak.net/root.crt
//
// Neden DÜZ HTTP? Çünkü aksi bir döngüdür: bir sertifikayı doğrulamak için
// gereken kökü HTTPS ile indirmek, o indirmeyi doğrulamak için başka bir köke
// ihtiyaç duymak demektir. RFC 5280 bu yüzden AIA/CDP uçlarını düz HTTP olarak
// tanımlar. Taşıma katmanına güvenmiyoruz; İÇERİĞE güveniyoruz.
//
// Peki içeriğe nasıl güveniyoruz? İki yoldan biriyle, ve en az biri ŞART:
//
//   1. parmak izi sabitleme (`expectedFingerprint`) — tercih edilen. Kök
//      sertifikanın SHA-256'sı istemciye elle/dağıtımla verilir; indirilen
//      şey ona uymuyorsa reddedilir.
//   2. yerel dosya — kök zaten diskte, indirme hiç yapılmaz.
//
// Hiçbiri yoksa indirme "ilk kullanımda güven"dir: ilk bağlantı korunmasızdır,
// sonrası korunur. Bu bilinçli olarak AÇIKÇA istenmelidir (`allowUnpinned`) ve
// yüksek sesle loglanır — sessizce yapılan bir TOFU, kimsenin farkına varmadığı
// bir ortadaki adam penceresidir.

const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fsp = require('node:fs/promises');

const PEM_HEADER = '-----BEGIN CERTIFICATE-----';

function derToPem(der) {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `${PEM_HEADER}\n${b64}\n-----END CERTIFICATE-----\n`;
}

function normalizeFingerprint(value) {
  return String(value || '').replace(/[:\s]/g, '').toLowerCase();
}

function fetchBuffer(url, { timeoutMs = 10_000, maxBytes = 256 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(url); } catch (e) { reject(new Error(`geçersiz URL: ${url}`)); return; }
    const lib = target.protocol === 'https:' ? https : http;

    const req = lib.get(target, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`${url} → HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        // Kimlik doğrulaması olmayan bir uçtan sınırsız gövde kabul etmek,
        // bedava bellek tüketimidir.
        if (total > maxBytes) { req.destroy(); reject(new Error(`${url} yanıtı çok büyük`)); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`${url} zaman aşımı (${timeoutMs}ms)`)));
    req.on('error', reject);
  });
}

/**
 * @param {object} o
 * @param {string} [o.url] indirilecek adres
 * @param {string} [o.file] yerel dosya (verilirse indirme yapılmaz)
 * @param {string} [o.expectedFingerprint] SHA-256, iki nokta üst üste serbest
 * @param {boolean} [o.allowUnpinned] parmak izi olmadan indirmeye izin ver
 * @param {string} [o.cacheFile] indirilen kökün saklanacağı yol
 * @returns {Promise<{pem: string, fingerprint256: string, subject: string, source: string}>}
 */
async function loadTrustAnchor({
  url, file, expectedFingerprint, allowUnpinned = false, cacheFile, log, timeoutMs = 10_000,
}) {
  let raw = null;
  let source = null;

  if (file) {
    raw = await fsp.readFile(file);
    source = `file:${file}`;
  } else {
    if (!url) throw new Error('kök sertifika için ya `file` ya `url` gerekli');
    const pinned = normalizeFingerprint(expectedFingerprint);
    if (!pinned && !allowUnpinned) {
      throw new Error(
        `${url} adresinden kök sertifika indirilecek ama parmak izi verilmedi.\n`
        + '  Sabitleme olmadan indirmek, ilk bağlantıyı doğrulanmamış bırakır.\n'
        + '  Ya beklenen SHA-256 parmak izini verin ya da açıkça izin verin.',
      );
    }
    raw = await fetchBuffer(url, { timeoutMs });
    source = `url:${url}`;
  }

  const text = raw.toString('utf8');
  const pem = text.includes(PEM_HEADER) ? text : derToPem(raw);

  let cert;
  try { cert = new crypto.X509Certificate(pem); } catch (err) {
    throw new Error(`kök sertifika çözümlenemedi (${source}): ${err.message}`);
  }

  const fingerprint256 = normalizeFingerprint(cert.fingerprint256);
  const pinned = normalizeFingerprint(expectedFingerprint);
  if (pinned && pinned !== fingerprint256) {
    throw new Error(
      `kök sertifika parmak izi UYUŞMUYOR (${source})\n`
      + `  beklenen: ${pinned}\n  gelen   : ${fingerprint256}`,
    );
  }

  if (!pinned && !file) {
    log?.warn('kök sertifika sabitlenmeden kabul edildi (ilk kullanımda güven)', {
      url, fingerprint256, subject: cert.subject,
      oneri: 'bu parmak izini yapılandırmaya yazın; sonraki çalıştırmalar doğrulanmış olur',
    });
  }

  if (cacheFile) {
    try {
      await fsp.mkdir(require('node:path').dirname(cacheFile), { recursive: true });
      await fsp.writeFile(cacheFile, pem);
    } catch (err) {
      log?.debug('kök sertifika önbelleğe yazılamadı', { err: err.message });
    }
  }

  return {
    pem, fingerprint256, subject: cert.subject, issuer: cert.issuer, source,
  };
}

module.exports = {
  loadTrustAnchor, fetchBuffer, derToPem, normalizeFingerprint,
};
