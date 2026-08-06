'use strict';
// Bir "uygulama" (app): tünelin ucundaki tek bir yerel servisin dış dünyaya
// açılma kuralı.
//
//   yerel taraf   127.0.0.2:8080   istemcinin kendi ağında dinlenecek adres
//   genel taraf   :24913/tcp       bu sunucuda açılacak port (havuzdan rastgele)
//
// Kayıt hem yönetim panelinden hem de istemcinin kendi isteğinden (BIND_REQ)
// doğabilir; `source` hangisi olduğunu söyler. Yönetimden gelen kayıt kalıcıdır
// ve tünel her bağlandığında yeniden kurulur; istemciden gelen, o oturuma
// özgüdür.
//
// Hız sınırları BAYT/SANİYE tutulur, panelde Mbit/s gösterilir. Depolamada
// bit değil bayt kullanmak, her karşılaştırmada 8'e bölmeyi ve yuvarlama
// hatalarını ortadan kaldırıyor.

const crypto = require('node:crypto');

const {
  PROTO, PROTO_CODE, PROTO_NAME, DELIVERY, DELIVERY_NAME,
  QOS, QOS_NAME, QOS_CODE,
} = require('../protocol/constants.js');
const { TokenBucket, RateMeter } = require('../common/rate.js');

const DEFAULT_IDLE_MS = 300_000;

function newAppId() {
  return crypto.randomBytes(9).toString('base64url');
}

function toProto(value) {
  if (typeof value === 'number') return value === PROTO.UDP ? PROTO.UDP : PROTO.TCP;
  return PROTO_CODE[String(value || 'tcp').toLowerCase()] || PROTO.TCP;
}

function toDelivery(value, proto) {
  // TCP'de "kayıplı teslim" diye bir şey olamaz: TCP'nin sözleşmesi baytların
  // eksiksiz ve sırayla teslimidir. Panelden yanlışlıkla seçilse bile burada
  // düzeltiliyor — yanlış yapılandırmayı çalışma anında sessiz bozulmaya
  // çevirmek yerine, kabul ederken düzeltmek.
  if (proto === PROTO.TCP) return DELIVERY.RELIABLE;
  if (typeof value === 'number') return value === DELIVERY.RELIABLE ? DELIVERY.RELIABLE : DELIVERY.UNRELIABLE;
  return String(value || 'unreliable').toLowerCase() === 'reliable' ? DELIVERY.RELIABLE : DELIVERY.UNRELIABLE;
}

/**
 * Hizmet sınıfı. Verilmezse uygulamanın DOĞASINDAN çıkarılır:
 *
 *   UDP + kayıp toleranslı  → gerçek zamanlı. Bu kombinasyon zaten "geciken
 *                             paket, düşen paketten kötü" demektir; oyun, ses
 *                             ve görüntü tam olarak buradadır.
 *   diğer her şey           → etkileşimli.
 *
 * Tahmin, kullanıcıyı doğru varsayılana yaklaştırır ama karar onundur: panelden
 * her uygulama açıkça bir sınıfa atanabilir.
 */
function toQos(value, proto, delivery) {
  if (value !== undefined && value !== null && value !== '') {
    const n = typeof value === 'number' ? value : QOS_CODE[String(value).toLowerCase()];
    if (Number.isInteger(n) && n >= QOS.REALTIME && n <= QOS.BULK) return n;
  }
  if (proto === PROTO.UDP && delivery === DELIVERY.UNRELIABLE) return QOS.REALTIME;
  return QOS.INTERACTIVE;
}

function toPort(value, { allowZero = true } = {}) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 65535) return allowZero ? 0 : -1;
  return n;
}

function toRate(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

/** Bir yerel hedef adresinin makul olup olmadığı. Hostname'e izin verilir. */
function sanitizeHost(value, fallback = '127.0.0.1') {
  const s = String(value || '').trim();
  if (!s) return fallback;
  if (s.length > 253) return fallback;
  if (!/^[A-Za-z0-9._:\-[\]%]+$/.test(s)) return fallback;
  return s;
}

/** Girdi hatası bir sunucu arızası değildir — çağıranın düzeltebileceği bir şey. */
function invalid(message) {
  return Object.assign(new Error(message), { status: 400, code: 'invalid_request' });
}

/**
 * Dışarıdan gelen (panel, DB, BIND_REQ) ham bir kaydı kanonik biçime çevirir.
 * Doğrulama TEK bir yerde: üç ayrı giriş yolunun üç ayrı yorumu olmasın.
 */
function normalizeApp(raw = {}, { source = 'admin', clientId = null } = {}) {
  const proto = toProto(raw.proto ?? raw.protocol);
  const localPort = toPort(raw.localPort, { allowZero: false });
  if (localPort < 1) throw invalid('localPort 1-65535 aralığında olmalı');
  const delivery = toDelivery(raw.delivery, proto);

  return {
    appId: raw.appId || newAppId(),
    clientId: raw.clientId || clientId || '',
    name: String(raw.name || '').slice(0, 64) || `${PROTO_NAME[proto]}-${localPort}`,
    proto,
    delivery,
    /**
     * Hizmet sınıfı — çoklayıcının hangi bantta sıraya koyacağı.
     * Bant genişliği payı DEĞİLDİR: sınıf "kim önce" sorusunu yanıtlar.
     */
    qos: toQos(raw.qos ?? raw.priority, proto, delivery),
    ordered: raw.ordered === undefined ? true : !!raw.ordered,
    localHost: sanitizeHost(raw.localHost),
    localPort,
    /** 0 → havuzdan rastgele. Sabit bir değer verilirse havuz içinde olmalı. */
    publicPort: toPort(raw.publicPort),
    /** true → aynı port tünel gitse de bu uygulamaya ayrılmış kalır. */
    sticky: !!raw.sticky,
    enabled: raw.enabled === undefined ? true : !!raw.enabled,
    /** genel → tünel yönü (yükleme) */
    rateInBps: toRate(raw.rateInBps),
    /** tünel → genel yönü (indirme) */
    rateOutBps: toRate(raw.rateOutBps),
    maxConns: Math.max(0, Number(raw.maxConns) || 0),
    idleMs: Math.max(0, Number(raw.idleMs) || DEFAULT_IDLE_MS),
    source: raw.source || source,
    createdBy: String(raw.createdBy || '').slice(0, 128),
    createdAt: Number(raw.createdAt) || Date.now(),
    updatedAt: Date.now(),
  };
}

/** Çalışma zamanı durumu — kalıcı kayda YAZILMAZ. */
function attachRuntime(app) {
  app.appIdx = 0;
  app.endpoint = null;
  app.activeConnections = 0;
  app.totalConnections = 0;
  app.refusedConnections = 0;
  app.meterIn = new RateMeter();
  app.meterOut = new RateMeter();
  app.bucketIn = new TokenBucket({ ratePerSec: app.rateInBps });
  app.bucketOut = new TokenBucket({ ratePerSec: app.rateOutBps });
  app.boundPort = 0;
  app.lastError = null;
  return app;
}

function applyRates(app) {
  app.bucketIn.setRate(app.rateInBps);
  app.bucketOut.setRate(app.rateOutBps);
}

/** İstemciye APP_SYNC ile gönderilen biçim. */
function appToWire(app) {
  return {
    appId: app.appId,
    appIdx: app.appIdx,
    name: app.name,
    proto: app.proto,
    delivery: app.delivery,
    // İstemci de sıralama yapar (yükleme yönü ONUN darboğazından geçer),
    // bu yüzden sınıfı bilmesi gerekiyor.
    qos: app.qos,
    ordered: app.ordered,
    localHost: app.localHost,
    localPort: app.localPort,
    publicPort: app.boundPort || app.publicPort,
    enabled: app.enabled,
    idleMs: app.idleMs,
  };
}

/** Yönetim API'sinin döndürdüğü biçim — insan okur, birimler dönüştürülmüş. */
function appToPublic(app, { publicHost = '' } = {}) {
  return {
    appId: app.appId,
    clientId: app.clientId,
    name: app.name,
    protocol: PROTO_NAME[app.proto],
    delivery: DELIVERY_NAME[app.delivery],
    qos: QOS_NAME[app.qos] || 'interactive',
    qosCode: app.qos,
    ordered: app.ordered,
    local: `${app.localHost}:${app.localPort}`,
    localHost: app.localHost,
    localPort: app.localPort,
    publicHost,
    publicPort: app.boundPort || app.publicPort || null,
    requestedPublicPort: app.publicPort || null,
    sticky: app.sticky,
    enabled: app.enabled,
    rateInBps: app.rateInBps,
    rateOutBps: app.rateOutBps,
    maxConns: app.maxConns,
    idleMs: app.idleMs,
    source: app.source,
    createdBy: app.createdBy,
    createdAt: app.createdAt,
    updatedAt: app.updatedAt,
    live: app.endpoint ? {
      bound: !!app.boundPort,
      activeConnections: app.activeConnections,
      totalConnections: app.totalConnections,
      refusedConnections: app.refusedConnections,
      bytesIn: app.meterIn.total,
      bytesOut: app.meterOut.total,
      rateIn: Math.round(app.meterIn.sample()),
      rateOut: Math.round(app.meterOut.sample()),
    } : null,
    lastError: app.lastError,
  };
}

/** DB'ye yazılan biçim — çalışma zamanı alanları yok, int64'ler BigInt. */
function appToRecord(app) {
  return {
    appId: app.appId,
    clientId: app.clientId,
    name: app.name,
    proto: app.proto,
    delivery: app.delivery,
    qos: app.qos,
    ordered: app.ordered,
    localHost: app.localHost,
    localPort: app.localPort,
    publicPort: app.publicPort,
    sticky: app.sticky,
    enabled: app.enabled,
    rateInBps: app.rateInBps,
    rateOutBps: app.rateOutBps,
    maxConns: app.maxConns,
    idleMs: app.idleMs,
    source: app.source,
    createdBy: app.createdBy,
    createdAt: app.createdAt,
    updatedAt: app.updatedAt,
  };
}

module.exports = {
  normalizeApp, attachRuntime, applyRates, invalid,
  appToWire, appToPublic, appToRecord,
  newAppId, toProto, toDelivery, toQos, sanitizeHost, DEFAULT_IDLE_MS,
};
