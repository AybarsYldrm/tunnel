'use strict';
// Kalıcılık: @fitfak/database'e mTLS + gRPC üzerinden.
//
// Yumurta-tavuk sorunu burada da var ve çözümü fitfak-idp'dekiyle aynı:
// veri düzlemi yalnızca mTLS kabul ediyor, ama tünel sunucusunun ilk
// çalıştırmada bir istemci sertifikası yok. Sıra şu (RFC 7030 / EST
// semantiği):
//
//   1. bootstrap TLS   sunucu kimliğini kanıtlar, biz kanıtlamayız
//   2. güven çıpaları  CA bundle çekilir (açık veri, sır taşımaz)
//   3. enrolment       paylaşılan tek kullanımlık sırla HMAC + CSR
//   4. mTLS'e yükselme aynı hedefe, artık karşılıklı doğrulamalı
//   5. yenileme        mTLS üzerinden, sır bir daha kullanılmaz
//
// Kimlik ve veritabanı tutamağı diske 0600 ile yazılır: `clientSecret`
// SUNUCUDA SAKLANMAZ, oluşturma anında bir kez döner. Kaybedilirse veri
// kalıcı olarak erişilemez hâle gelir.
//
// Veritabanı yapılandırılmamışsa bellek-içi bir uygulama kullanılır. Bu bir
// "test modu" değil, bilinçli bir çalıştırma biçimi: tek makinelik bir kurulum
// için veritabanı zorunlu olmamalı. Ama kalıcılık YOKTUR ve açılışta bunu
// yüksek sesle söyleriz — sessizce belleğe yazan bir sistem, ilk yeniden
// başlatmada bütün yapılandırmasını kaybettiğini kimseye haber vermez.

const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const schema = require('./schema.js');

const IDENTITY_FILE = 'identity.json';
const HANDLE_FILE = 'database.json';

function num(value, fallback = 0) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'bigint') return Number(value);
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function big(value) { return BigInt(Math.max(0, Math.floor(Number(value) || 0))); }

function newId() { return crypto.randomBytes(9).toString('base64url'); }

// ===========================================================================
// Bellek-içi uygulama
// ===========================================================================

class MemoryStore {
  constructor(log) {
    this.log = log;
    this.mode = 'memory';
    this.clients = new Map();
    this.apps = new Map();
    this.sessions = new Map();
    this.reservations = new Map();
    this.blocklist = new Map();
    this.events = [];
    this.metrics = [];
  }

  async init() { return this; }

  async upsertClient(record) {
    const prev = this.clients.get(record.clientId) || {};
    const merged = { ...prev, ...record, firstSeenAt: prev.firstSeenAt || record.firstSeenAt || Date.now() };
    this.clients.set(record.clientId, merged);
    return merged;
  }

  async getClient(clientId) { return this.clients.get(clientId) || null; }
  async listClients() { return [...this.clients.values()]; }

  async saveApp(app) {
    this.apps.set(app.appId, { ...app });
    return app;
  }

  async deleteApp(appId) { return this.apps.delete(appId); }
  async getApp(appId) { return this.apps.get(appId) || null; }
  async listApps() { return [...this.apps.values()]; }
  async listAppsForClient(clientId) {
    return [...this.apps.values()].filter((a) => a.clientId === clientId);
  }

  async startSession(row) { this.sessions.set(row.tunnelId, { ...row }); return row; }
  async endSession(tunnelId, patch) {
    const row = this.sessions.get(tunnelId);
    if (row) Object.assign(row, patch);
  }

  async listSessions(limit = 100) {
    return [...this.sessions.values()].sort((a, b) => b.startedAt - a.startedAt).slice(0, limit);
  }

  async saveReservation(row) { this.reservations.set(row.key, { ...row }); }
  async listReservations() { return [...this.reservations.values()]; }

  async saveBlock(row) { this.blocklist.set(row.address, { ...row }); return row; }
  async deleteBlock(address) { return this.blocklist.delete(address); }
  async listBlocks() { return [...this.blocklist.values()]; }

  async recordEvent(row) {
    this.events.push(row);
    // Bellek modunda sınırsız büyüyen bir denetim kaydı, uzun çalışan bir
    // süreçte sessizce bellek sızıntısıdır.
    if (this.events.length > 5000) this.events.splice(0, this.events.length - 5000);
  }

  async listEvents(limit = 200) { return this.events.slice(-limit).reverse(); }

  async saveMetric(row) {
    this.metrics.push(row);
    if (this.metrics.length > 20_000) this.metrics.splice(0, this.metrics.length - 20_000);
  }

  async listMetrics({ clientId = null, appId = null, since = 0, limit = 500 } = {}) {
    return this.metrics
      .filter((m) => (!clientId || m.clientId === clientId)
        && (!appId || m.appId === appId)
        && m.at >= since)
      .slice(-limit);
  }

  async close() { /* tutulacak bir kaynak yok */ }
}

// ===========================================================================
// @fitfak/database uygulaması
// ===========================================================================

class DatabaseStore {
  constructor({ db, handle, identity, log }) {
    this.db = db;
    this.handle = handle;
    this.identity = identity;
    this.log = log;
    this.mode = 'database';
  }

  _c(name) { return this.db.collection(name); }

  /**
   * Çoklu eşleşme: motorun API'sinde indeksli `find` varsa o, yoksa `scan` +
   * elle süzme. İkisini tek yerde toplamak, koleksiyon başına farklı davranan
   * çağrı noktaları oluşmasını engelliyor.
   */
  async _findAll(name, field, value) {
    const col = this._c(name);
    if (typeof col.find === 'function') {
      try {
        const rows = await col.find(field, value);
        if (Array.isArray(rows)) return rows;
      } catch (err) {
        this.log.debug('indeksli find başarısız, taramaya düşülüyor', { name, field, err: err.message });
      }
    }
    const out = [];
    for await (const row of col.scan()) if (String(row[field]) === String(value)) out.push(row);
    return out;
  }

  async _scanAll(name, limit = 0) {
    const out = [];
    for await (const row of this._c(name).scan()) {
      out.push(row);
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  async _upsert(name, keyField, keyValue, record) {
    const existing = (await this._findAll(name, keyField, keyValue))[0];
    if (existing) {
      await this._c(name).update(existing._id, record);
      return { ...existing, ...record };
    }
    await this._c(name).insertUnique({ [keyField]: keyValue, ...record }, { unique: [keyField] });
    return { [keyField]: keyValue, ...record };
  }

  // ---- istemciler ---------------------------------------------------------
  async upsertClient(record) {
    const now = Date.now();
    const prev = await this.getClient(record.clientId);
    const row = {
      commonName: record.commonName || '',
      displayName: record.displayName || prev?.displayName || '',
      email: record.email || '',
      organization: record.organization || '',
      firstSeenAt: big(prev?.firstSeenAt || record.firstSeenAt || now),
      lastSeenAt: big(record.lastSeenAt || now),
      lastAddress: record.lastAddress || '',
      certSerial: record.certSerial || '',
      certNotAfter: big(record.certNotAfter || 0),
      note: record.note !== undefined ? record.note : (prev?.note || ''),
      blocked: record.blocked !== undefined ? !!record.blocked : !!prev?.blocked,
      ownerUserId: record.ownerUserId || prev?.ownerUserId || '',
    };
    await this._upsert('tunnel_clients', 'clientId', record.clientId, row);
    return { clientId: record.clientId, ...row };
  }

  async getClient(clientId) {
    const rows = await this._findAll('tunnel_clients', 'clientId', clientId);
    return rows[0] ? this._clientOut(rows[0]) : null;
  }

  async listClients() {
    return (await this._scanAll('tunnel_clients')).map((r) => this._clientOut(r));
  }

  _clientOut(r) {
    return {
      clientId: r.clientId,
      commonName: r.commonName,
      displayName: r.displayName,
      email: r.email,
      organization: r.organization,
      firstSeenAt: num(r.firstSeenAt),
      lastSeenAt: num(r.lastSeenAt),
      lastAddress: r.lastAddress,
      certSerial: r.certSerial,
      certNotAfter: num(r.certNotAfter),
      note: r.note,
      blocked: !!r.blocked,
      ownerUserId: r.ownerUserId,
    };
  }

  // ---- uygulamalar --------------------------------------------------------
  async saveApp(app) {
    const row = {
      clientId: app.clientId,
      name: app.name,
      proto: app.proto,
      delivery: app.delivery,
      qos: app.qos,
      ordered: !!app.ordered,
      localHost: app.localHost,
      localPort: app.localPort,
      publicPort: app.publicPort || 0,
      sticky: !!app.sticky,
      enabled: !!app.enabled,
      rateInBps: big(app.rateInBps),
      rateOutBps: big(app.rateOutBps),
      maxConns: app.maxConns || 0,
      idleMs: big(app.idleMs),
      source: app.source,
      createdBy: app.createdBy || '',
      createdAt: big(app.createdAt),
      updatedAt: big(Date.now()),
    };
    await this._upsert('tunnel_apps', 'appId', app.appId, row);
    return app;
  }

  async deleteApp(appId) {
    const rows = await this._findAll('tunnel_apps', 'appId', appId);
    for (const r of rows) await this._c('tunnel_apps').delete(r._id);
    return rows.length > 0;
  }

  async getApp(appId) {
    const rows = await this._findAll('tunnel_apps', 'appId', appId);
    return rows[0] ? this._appOut(rows[0]) : null;
  }

  async listApps() {
    return (await this._scanAll('tunnel_apps')).map((r) => this._appOut(r));
  }

  async listAppsForClient(clientId) {
    return (await this._findAll('tunnel_apps', 'clientId', clientId)).map((r) => this._appOut(r));
  }

  _appOut(r) {
    return {
      appId: r.appId,
      clientId: r.clientId,
      name: r.name,
      proto: num(r.proto, 1),
      delivery: num(r.delivery, 1),
      // 0 = kayıt QoS'tan önce yazılmış; normalizeApp uygulamanın doğasından
      // çıkarsın diye undefined bırakılıyor.
      qos: num(r.qos) || undefined,
      ordered: !!r.ordered,
      localHost: r.localHost,
      localPort: num(r.localPort),
      publicPort: num(r.publicPort),
      sticky: !!r.sticky,
      enabled: !!r.enabled,
      rateInBps: num(r.rateInBps),
      rateOutBps: num(r.rateOutBps),
      maxConns: num(r.maxConns),
      idleMs: num(r.idleMs),
      source: r.source,
      createdBy: r.createdBy,
      createdAt: num(r.createdAt),
      updatedAt: num(r.updatedAt),
    };
  }

  // ---- oturumlar ----------------------------------------------------------
  async startSession(row) {
    await this._c('tunnel_sessions').insertUnique({
      tunnelId: row.tunnelId,
      clientId: row.clientId,
      remoteAddress: row.remoteAddress || '',
      startedAt: big(row.startedAt),
      endedAt: 0n,
      bytesIn: 0n,
      bytesOut: 0n,
      protocol: row.protocol || '',
      cipher: row.cipher || '',
      certSerial: row.certSerial || '',
      closeReason: '',
      streamsOpened: 0n,
    }, { unique: ['tunnelId'] });
    return row;
  }

  async endSession(tunnelId, patch) {
    const rows = await this._findAll('tunnel_sessions', 'tunnelId', tunnelId);
    if (!rows[0]) return;
    await this._c('tunnel_sessions').update(rows[0]._id, {
      endedAt: big(patch.endedAt || Date.now()),
      bytesIn: big(patch.bytesIn),
      bytesOut: big(patch.bytesOut),
      closeReason: String(patch.closeReason || '').slice(0, 200),
      streamsOpened: big(patch.streamsOpened),
    });
  }

  async listSessions(limit = 100) {
    const rows = await this._scanAll('tunnel_sessions');
    return rows
      .map((r) => ({
        tunnelId: r.tunnelId,
        clientId: r.clientId,
        remoteAddress: r.remoteAddress,
        startedAt: num(r.startedAt),
        endedAt: num(r.endedAt),
        bytesIn: num(r.bytesIn),
        bytesOut: num(r.bytesOut),
        protocol: r.protocol,
        cipher: r.cipher,
        certSerial: r.certSerial,
        closeReason: r.closeReason,
        streamsOpened: num(r.streamsOpened),
      }))
      .sort((a, b) => b.startedAt - a.startedAt)
      .slice(0, limit);
  }

  // ---- rezervasyonlar -----------------------------------------------------
  async saveReservation(row) {
    await this._upsert('tunnel_reservations', 'key', row.key, {
      proto: row.proto,
      port: row.port,
      appId: row.appId || '',
      clientId: row.clientId || '',
      acquiredAt: big(row.acquiredAt || Date.now()),
      releasedAt: big(row.releasedAt || 0),
      state: row.state || 'active',
    });
  }

  async listReservations() {
    return (await this._scanAll('tunnel_reservations')).map((r) => ({
      key: r.key,
      proto: num(r.proto),
      port: num(r.port),
      appId: r.appId,
      clientId: r.clientId,
      acquiredAt: num(r.acquiredAt),
      releasedAt: num(r.releasedAt),
      state: r.state,
    }));
  }

  // ---- engel listesi ------------------------------------------------------
  async saveBlock(row) {
    await this._upsert('tunnel_blocklist', 'address', row.address, {
      reason: String(row.reason || '').slice(0, 200),
      actor: String(row.actor || '').slice(0, 128),
      at: big(row.at || Date.now()),
      expiresAt: big(row.expiresAt || 0),
    });
    return row;
  }

  async deleteBlock(address) {
    const rows = await this._findAll('tunnel_blocklist', 'address', address);
    for (const row of rows) await this._c('tunnel_blocklist').delete(row._id);
    return rows.length > 0;
  }

  async listBlocks() {
    return (await this._scanAll('tunnel_blocklist')).map((r) => ({
      address: r.address,
      reason: r.reason,
      actor: r.actor,
      at: num(r.at),
      expiresAt: num(r.expiresAt),
    }));
  }

  // ---- denetim kaydı ------------------------------------------------------
  async recordEvent(row) {
    await this._c('tunnel_events').insertUnique({
      eventId: row.eventId || newId(),
      kind: row.kind,
      actor: String(row.actor || '').slice(0, 128),
      subject: String(row.subject || '').slice(0, 128),
      detail: String(row.detail || '').slice(0, 1000),
      at: big(row.at || Date.now()),
    }, { unique: ['eventId'] });
  }

  async listEvents(limit = 200) {
    const rows = await this._scanAll('tunnel_events');
    return rows
      .map((r) => ({
        eventId: r.eventId, kind: r.kind, actor: r.actor, subject: r.subject, detail: r.detail, at: num(r.at),
      }))
      .sort((a, b) => b.at - a.at)
      .slice(0, limit);
  }

  // ---- ölçümler -----------------------------------------------------------
  async saveMetric(row) {
    await this._c('tunnel_metrics').insertUnique({
      sampleId: newId(),
      clientId: row.clientId || '',
      appId: row.appId || '',
      at: big(row.at || Date.now()),
      bytesIn: big(row.bytesIn),
      bytesOut: big(row.bytesOut),
      rateIn: big(row.rateIn),
      rateOut: big(row.rateOut),
      rttMs: Math.round(row.rttMs || 0),
      connections: Math.round(row.connections || 0),
      lossPpm: Math.round(row.lossPpm || 0),
    }, { unique: ['sampleId'] });
  }

  async listMetrics({ clientId = null, since = 0, limit = 500 } = {}) {
    const rows = clientId
      ? await this._findAll('tunnel_metrics', 'clientId', clientId)
      : await this._scanAll('tunnel_metrics', limit * 4);
    return rows
      .map((r) => ({
        clientId: r.clientId,
        appId: r.appId,
        at: num(r.at),
        bytesIn: num(r.bytesIn),
        bytesOut: num(r.bytesOut),
        rateIn: num(r.rateIn),
        rateOut: num(r.rateOut),
        rttMs: num(r.rttMs),
        connections: num(r.connections),
        lossPpm: num(r.lossPpm),
      }))
      .filter((m) => m.at >= since)
      .sort((a, b) => a.at - b.at)
      .slice(-limit);
  }

  async close() {
    try { if (this.identity) this.identity.stopAutoRenewal?.(); } catch { /* yoksay */ }
    try { await this.handle?.close?.(); } catch { /* yoksay */ }
  }
}

// ===========================================================================
// Kurulum
// ===========================================================================

async function writeSecretFile(dir, name, payload) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, name);
  const tmp = `${file}.tmp`;
  // Önce geçici dosya, sonra rename. Doğrudan yazmak, süreç yazarken ölürse
  // yarım bir dosya bırakır ve sonraki açılış onu "var ama bozuk" bulur.
  await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
  await fsp.rename(tmp, file);
}

async function readJsonFile(dir, name) {
  try { return JSON.parse(await fsp.readFile(path.join(dir, name), 'utf8')); } catch { return null; }
}

async function loadStoredIdentity(dir) {
  const stored = await readJsonFile(dir, IDENTITY_FILE);
  if (!stored?.certPem || !stored?.privateKeyPem) return null;
  try {
    const cert = new crypto.X509Certificate(stored.certPem);
    const notAfter = new Date(cert.validTo).getTime();
    // Süresi dolmuş bir sertifikayla bağlanmayı denemek, anlaşılması zor bir
    // TLS hatasıyla sonuçlanır. Burada fark edip yeniden enrolment'a gitmek
    // hem daha hızlı hem daha okunur.
    if (Number.isFinite(notAfter) && notAfter < Date.now() + 60_000) return null;
  } catch { return null; }
  return stored;
}

/**
 * @param {object} o
 * @param {object} o.config store yapılandırması (bkz. config.js)
 * @param {object} o.log
 * @returns {Promise<MemoryStore|DatabaseStore>}
 */
async function createStore({ config, log }) {
  if (!config.target) {
    log.warn('veritabanı yapılandırılmadı — bellek-içi kalıcılık kullanılıyor', {
      uyari: 'yeniden başlatmada uygulama tanımları, port rezervasyonları ve denetim kaydı KAYBOLUR',
      nasil: 'FITFAK_TUNNEL_DB_TARGET verin',
    });
    return new MemoryStore(log).init();
  }

  let dbModule;
  try {
    // eslint-disable-next-line global-require, import/no-unresolved
    dbModule = require('@fitfak/database');
  } catch (err) {
    throw new Error(
      `FITFAK_TUNNEL_DB_TARGET verildi ama @fitfak/database yüklü değil: ${err.message}\n`
      + '  npm install @fitfak/database',
    );
  }

  const {
    enroll, resume, connectDatabase, createFitfakSslCsrProvider,
  } = dbModule;

  const trust = {};
  if (config.caPath) trust.caPem = await fsp.readFile(config.caPath, 'utf8');
  else if (config.caFingerprint) trust.pinnedFingerprints = [config.caFingerprint];
  else {
    // Kimliğini doğrulayamadığın bir sunucuya enrolment kanıtı göndermek, o
    // kanıtı yolu dinleyen herkese vermektir.
    throw new Error(
      'Veritabanı sunucusunu doğrulayacak güven çıpası yok '
      + '(FITFAK_TUNNEL_DB_CA_FINGERPRINT ya da FITFAK_TUNNEL_DB_CA_PATH gerekli).',
    );
  }

  const csrProvider = createFitfakSslCsrProvider();
  const stored = await loadStoredIdentity(config.identityDir);

  const bridge = {
    info: (m) => log.info(`[db] ${m}`),
    warn: (m) => log.warn(`[db] ${m}`),
  };

  let identity;
  if (stored) {
    log.info('kayıtlı mTLS kimliği bulundu, enrolment atlanıyor');
    identity = await resume({
      target: config.target,
      certPem: stored.certPem,
      privateKeyPem: stored.privateKeyPem,
      chainPem: stored.chainPem,
      principal: stored.principal,
      roles: stored.roles,
      notAfter: stored.notAfter,
      renewAfter: stored.renewAfter,
      csrProvider,
      logger: bridge,
    });
  } else {
    if (!config.enrolmentSecret) {
      throw new Error(
        'mTLS kimliği yok ve FITFAK_TUNNEL_DB_ENROLMENT_SECRET verilmemiş.\n'
        + '  Veritabanı tarafında üretin (generateEnrolmentSecret) ve bu değişkende verin.',
      );
    }
    log.info('mTLS kimliği yok — enrolment yapılıyor (TLS → enrol → mTLS)');
    identity = await enroll({
      target: config.target,
      serviceName: config.serviceName,
      csrProvider,
      trust,
      bootstrap: { secret: Buffer.from(config.enrolmentSecret, 'base64') },
      altNames: [config.serviceName],
      logger: bridge,
    });
    await writeSecretFile(config.identityDir, IDENTITY_FILE, {
      certPem: identity.certPem,
      privateKeyPem: identity.privateKeyPem,
      chainPem: identity.chainPem,
      principal: identity.principal,
      roles: identity.roles,
      notAfter: identity.notAfter,
      renewAfter: identity.renewAfter,
    });
    log.warn('enrolment tamamlandı — paylaşılan sır TÜKENDİ, ortamdan kaldırabilirsiniz', {
      principal: identity.principal,
    });
  }

  // Yenileme ömrün ~2/3'ünde başlar: başarısız olursa tekrar denemeye yer kalır.
  identity.startAutoRenewal();
  identity.on('renewed', async (e) => {
    await writeSecretFile(config.identityDir, IDENTITY_FILE, {
      certPem: identity.certPem,
      privateKeyPem: identity.privateKeyPem,
      chainPem: identity.chainPem,
      principal: identity.principal,
      roles: identity.roles,
      notAfter: e.notAfter,
      renewAfter: e.renewAfter,
    });
    log.info('veritabanı sertifikası yenilendi', { notAfter: new Date(e.notAfter).toISOString() });
  });

  const handle = await connectDatabase({ target: config.target, identity, logger: bridge });

  const storedHandle = await readJsonFile(config.identityDir, HANDLE_FILE);
  let db;
  if (storedHandle?.dbId && storedHandle?.clientSecret) {
    db = await handle.openDatabase({ dbId: storedHandle.dbId, clientSecret: storedHandle.clientSecret });
    log.info('veritabanı açıldı', { dbId: storedHandle.dbId });
  } else if (config.dbId && config.clientSecret) {
    db = await handle.openDatabase({ dbId: config.dbId, clientSecret: config.clientSecret });
    await writeSecretFile(config.identityDir, HANDLE_FILE, {
      dbId: config.dbId, clientSecret: config.clientSecret,
    });
  } else {
    const created = await handle.createDatabase(config.databaseName || 'tunnel');
    // Sır ÖNCE saklanıyor, sonra kullanılıyor: aradaki bir çökme, bir daha
    // açılamayan bir veritabanı bırakırdı.
    await writeSecretFile(config.identityDir, HANDLE_FILE, {
      dbId: created.dbId, clientSecret: created.clientSecret,
    });
    log.warn('yeni veritabanı oluşturuldu — erişim sırrı diskte (0600), YEDEKLEYİN', {
      dbId: created.dbId,
      dosya: path.join(config.identityDir, HANDLE_FILE),
      uyari: 'bu dosya kaybolursa veritabanı bir daha AÇILAMAZ',
    });
    db = await handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
  }

  // Şemayı her açılışta uygula. Bu bir no-op değil: alan eklemek bir
  // migrasyondur, motor onu tespit edip indeksleri yeniden kurar; kırıcı bir
  // değişiklik AÇILIŞTA reddedilir, ilk yazma denemesinde değil.
  if (typeof db.applySchemaRegistry === 'function') {
    await db.applySchemaRegistry(schema);
  } else {
    for (const [name, def] of Object.entries(schema)) {
      // eslint-disable-next-line no-await-in-loop
      await db.defineCollection(name, def);
    }
  }

  return new DatabaseStore({ db, handle, identity, log });
}

module.exports = {
  createStore, MemoryStore, DatabaseStore, schema, num, big, newId,
};
