'use strict';
// Tünelin tamamı node-dtls'in kendi logger'ını kullanır (src/logger.js): aynı
// süreçte iki farklı log biçimi olması, bir handshake hatasıyla onu tetikleyen
// tünel olayını yan yana okumayı imkânsız kılardı.
//
// Seviye FITFAK_TUNNEL_LOG_LEVEL ile ayarlanır; verilmezse DTLS_LOG_LEVEL'e,
// o da yoksa kütüphanenin varsayılanına (WARN) düşer. Bir SUNUCU olarak
// varsayılanımız INFO: kütüphane sessiz olmalıdır, çalışan bir servis değil.

const { mk, setLevel, hexDump } = require('../../../src/logger.js');

const envLevel = process.env.FITFAK_TUNNEL_LOG_LEVEL || process.env.DTLS_LOG_LEVEL;

let applied = false;
function applyLevel(fallback = 'INFO') {
  if (applied) return;
  applied = true;
  try { setLevel(envLevel || fallback); } catch { /* geçersiz isim: kütüphane varsayılanı kalsın */ }
}

/**
 * @param {string} component 'tunnel:server', 'tunnel:mux', ...
 */
function createLogger(component) {
  applyLevel();
  return mk(component);
}

/**
 * @fitfak/database ve benzeri modüller `info/warn/error` bekler; bizim
 * logger'ımız zaten o yüzeyi sağlıyor ama `child`/`timer` gibi çağrılar da
 * yapabiliyorlar. Eksik olanı burada tamamlıyoruz ki bir kütüphane çağrısı
 * loglama yüzünden çökmesin.
 */
function asPlainLogger(log) {
  return {
    trace: (m, x) => log.trace(m, x),
    debug: (m, x) => log.debug(m, x),
    info: (m, x) => log.info(m, x),
    warn: (m, x) => log.warn(m, x),
    error: (m, x) => log.error(m, x),
    child: (sub) => asPlainLogger(log.child(sub)),
    hex: (label, buf) => log.hex(label, buf),
    timer: () => {
      const started = Date.now();
      return { end: () => Date.now() - started };
    },
  };
}

module.exports = { createLogger, asPlainLogger, applyLevel, hexDump };
