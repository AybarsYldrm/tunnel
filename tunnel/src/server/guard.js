'use strict';
// Genel yüzeyin koruması.
//
// Bu sunucunun dış dünyaya bakan tarafı, arkasındaki hiçbir şeyin kendini
// savunamadığı bir yer: tünelin ucundaki servis bir ev bilgisayarında çalışan
// küçük bir HTTP sunucusu olabilir. Dolayısıyla YÜK BURADA durdurulmalıdır,
// orada değil — bir DoS'un tüneli doldurup AYNI SUNUCUDAKİ DİĞER müşterilerin
// tünellerini de yavaşlatması, tek bir hedefe yapılan saldırıyı herkese
// yayılan bir kesintiye çevirir.
//
// Katmanlar ve her birinin kapattığı somut senaryo:
//
//   kabul hızı (IP)      : tek kaynaktan saniyede binlerce bağlantı açıp kapamak
//   kabul hızı (genel)   : dağıtık ama toplamda aynı etkiyi yapan sel
//   eşzamanlılık (IP)    : bağlantı açıp hiç kapatmayarak akış tablosunu doldurmak
//   eşzamanlılık (uygl.) : bir uygulamanın diğerlerinin akış bütçesini yemesi
//   ilk bayt süresi      : slowloris — bağlantıyı açıp hiçbir şey göndermemek
//   boşta kalma          : açık bırakılmış ama ölü bağlantılar
//   UDP paket/bayt hızı  : sahte kaynaklı UDP seli
//   yükseltme oranı      : küçük istekle büyük yanıt ürettirip başkasına yöneltmek
//   yasaklama            : yukarıdakileri tekrar tekrar tetikleyen kaynağı susturmak
//
// Yasaklama üstel: ilk ihlal kısa bir mola, ısrar eden için gittikçe uzuyor ve
// sessizce sönümleniyor. Sabit süreli yasak, saldırganın süreyi ölçüp tam
// dolduğunda geri gelmesine izin verir; sabit ve KALICI yasak ise NAT arkasındaki
// koca bir binayı tek bir kötü istemci yüzünden dışarıda bırakır.

const { KeyedCounter } = require('../common/rate.js');
const { canonicalIp, ipToBuffer } = require('../protocol/codec.js');

const DEFAULTS = Object.freeze({
  acceptPerIpPerSec: 30,
  acceptGlobalPerSec: 2000,
  maxConnectionsPerIp: 128,
  maxConnectionsPerApp: 2048,
  maxConnectionsGlobal: 20000,
  firstByteTimeoutMs: 15_000,
  idleTimeoutMs: 300_000,

  udpPacketsPerIpPerSec: 500,
  udpBytesPerIpPerSec: 2 * 1024 * 1024,
  udpMaxFlowsPerIp: 64,
  udpMaxFlowsGlobal: 20000,
  /** Akış "kurulmuş" sayılana kadar izin verilen yanıt/istek bayt oranı. */
  udpAmplificationRatio: 3,
  /** Bu kadar gelen paketten sonra akış kurulmuş sayılır. */
  udpEstablishAfterPackets: 2,

  banBaseMs: 10_000,
  banMaxMs: 30 * 60_000,
  /** Bu kadar ihlalden sonra yasaklanır. */
  banAfterViolations: 20,
  /** İhlal sayacı bu sürede sönümlenir. */
  violationDecayMs: 60_000,
  /**
   * Yasak BİTTİKTEN sonra kaç ihlal işlediğini bu süre boyunca hatırlarız.
   *
   * Unutulsaydı üstel yasak diye bir şey olmazdı: saldırgan ilk (kısa)
   * yasağın bitmesini bekler, aynı şeyi yapar, yine aynı kısa yasağı yer ve
   * ceza hiç büyümezdi. Hatırlama süresi azami yasaktan uzun olmalı.
   */
  offenceMemoryMs: 60 * 60_000,
  maxTrackedIps: 50_000,
});

const REASON = Object.freeze({
  OK: null,
  BLOCKED: 'blocked',
  BANNED: 'banned',
  ACCEPT_RATE_IP: 'accept-rate-ip',
  ACCEPT_RATE_GLOBAL: 'accept-rate-global',
  CONN_LIMIT_IP: 'conn-limit-ip',
  CONN_LIMIT_APP: 'conn-limit-app',
  CONN_LIMIT_GLOBAL: 'conn-limit-global',
  UDP_RATE: 'udp-rate',
  UDP_BYTES: 'udp-bytes',
  UDP_FLOW_LIMIT: 'udp-flow-limit',
  AMPLIFICATION: 'amplification',
});

class Guard {
  /**
   * DİKKAT: adres alan HER genel metot girdiyi `canonicalIp` ile normalize
   * eder. Normalizasyonu çağrı noktalarına bırakmak, tek bir yerde unutulduğu
   * anda engellerin ve sayaçların sessizce ikiye bölünmesi demek olurdu —
   * bkz. protocol/codec.js `canonicalIp`.
   */
  constructor(options = {}, log = null) {
    this.opt = { ...DEFAULTS, ...options };
    this.log = log;

    this.acceptPerIp = new KeyedCounter({
      windowMs: 1000, max: this.opt.acceptPerIpPerSec, maxKeys: this.opt.maxTrackedIps,
    });
    this.acceptGlobal = new KeyedCounter({ windowMs: 1000, max: this.opt.acceptGlobalPerSec, maxKeys: 4 });
    this.udpPackets = new KeyedCounter({
      windowMs: 1000, max: this.opt.udpPacketsPerIpPerSec, maxKeys: this.opt.maxTrackedIps,
    });
    this.udpBytes = new KeyedCounter({
      windowMs: 1000, max: this.opt.udpBytesPerIpPerSec, maxKeys: this.opt.maxTrackedIps,
    });

    /** ip -> sayı */
    this.connsByIp = new Map();
    /** appId -> sayı */
    this.connsByApp = new Map();
    this.connsGlobal = 0;

    /** ip -> { count, until } — OTOMATİK, üstel, kendiliğinden sönümlenen. */
    this.bans = new Map();
    /** ip -> { n, at } */
    this.violations = new Map();
    /**
     * ip -> { address, reason, actor, at, expiresAt }
     *
     * YÖNETİCİNİN elle koyduğu engel. Otomatik yasaktan ayrı tutulur ve
     * karıştırılmaz: otomatik yasak bir hız sınırı tepkisidir, süresi dolar ve
     * sönümlenir; elle konan engel bir KARARDIR ve yalnızca yine elle kalkar.
     * Aynı tabloda tutulsalardı, sweep() yöneticinin kararını sessizce silerdi.
     */
    this.blocks = new Map();

    this.udpFlowsByIp = new Map();
    this.udpFlowsGlobal = 0;

    this.stats = {
      accepted: 0, refused: 0, banned: 0,
      udpAccepted: 0, udpDropped: 0, amplificationBlocked: 0,
      slowlorisKilled: 0, idleKilled: 0,
      blockedRejections: 0,
    };
    for (const key of Object.values(REASON)) if (key) this.stats[`refused:${key}`] = 0;

    this._sweepTimer = setInterval(() => this.sweep(), 10_000);
    if (this._sweepTimer.unref) this._sweepTimer.unref();
  }

  // -------------------------------------------------------------------------
  /**
   * Kayıt, yasak bittiğinde SİLİNMEZ — `offence` sayacı üstel cezanın
   * hafızasıdır ve onu burada düşürmek cezayı sıfırlardı. Temizlik
   * `sweep()`te, hatırlama süresi dolunca yapılır.
   */
  isBanned(address, now = Date.now()) {
    const b = this.bans.get(canonicalIp(address));
    return !!b && b.until > now;
  }

  /** Bir sınırı tetikleyen kaynağı işaretler; ısrar ederse yasaklanır. */
  penalize(address, reason, now = Date.now()) {
    const ip = canonicalIp(address);
    let v = this.violations.get(ip);
    if (!v || now - v.at > this.opt.violationDecayMs) v = { n: 0, at: now };
    v.n += 1;
    v.at = now;
    if (this.violations.size >= this.opt.maxTrackedIps && !this.violations.has(ip)) this._evict(this.violations);
    this.violations.set(ip, v);

    if (v.n < this.opt.banAfterViolations) return false;

    const prior = this.bans.get(ip);
    const count = (prior?.count || 0) + 1;
    const duration = Math.min(this.opt.banBaseMs * (2 ** (count - 1)), this.opt.banMaxMs);
    this.bans.set(ip, { count, until: now + duration });
    this.violations.delete(ip);
    this.stats.banned++;
    this.log?.warn('kaynak yasaklandı', {
      ip, reason, violations: v.n, durationMs: duration, offence: count,
    });
    return true;
  }

  unban(address) {
    const ip = canonicalIp(address);
    this.bans.delete(ip);
    this.violations.delete(ip);
  }

  // -------------------------------------------------------------------------
  // Elle engelleme (yönetim panelinden)
  // -------------------------------------------------------------------------
  /**
   * @param {string} address
   * @param {object} [o]
   * @param {number} [o.ttlMs] 0 / verilmezse KALICI
   * @param {string} [o.reason]
   * @param {string} [o.actor] denetim kaydı için
   * @returns {object} kayıt
   */
  blockAddress(address, { ttlMs = 0, reason = '', actor = '', at = Date.now() } = {}) {
    const raw = String(address || '').trim();
    if (!raw) throw Object.assign(new Error('adres gerekli'), { status: 400, code: 'invalid_request' });
    // Geçerli bir IP olduğunu BURADA doğruluyoruz. Doğrulamasak, panele
    // yazılan bir yazım hatası ("203.0.113." gibi) hiçbir şeyi engellemeyen
    // ama engellenmiş görünen bir kayıt üretirdi — güvenlik arayüzlerinde en
    // kötü sonuç budur: yanlış bir güvende olma hissi.
    if (!ipToBuffer(raw)) {
      throw Object.assign(new Error(`geçersiz IP adresi: ${raw.slice(0, 64)}`), {
        status: 400, code: 'invalid_request',
      });
    }
    const ip = canonicalIp(raw);
    const record = {
      address: ip,
      reason: String(reason || '').slice(0, 200),
      actor: String(actor || '').slice(0, 128),
      at,
      expiresAt: ttlMs > 0 ? at + ttlMs : 0,
    };
    this.blocks.set(ip, record);
    this.log?.warn('adres engellendi', { ip, reason: record.reason, actor: record.actor, ttlMs });
    return record;
  }

  unblockAddress(address) { return this.blocks.delete(canonicalIp(address)); }

  isBlocked(address, now = Date.now()) {
    const ip = canonicalIp(address);
    const b = this.blocks.get(ip);
    if (!b) return false;
    if (b.expiresAt && b.expiresAt <= now) { this.blocks.delete(ip); return false; }
    return true;
  }

  listBlocks(now = Date.now()) {
    const out = [];
    for (const [ip, b] of this.blocks) {
      if (b.expiresAt && b.expiresAt <= now) { this.blocks.delete(ip); continue; }
      out.push({ ...b });
    }
    return out.sort((a, b) => b.at - a.at);
  }

  /** Kalıcılıktan geri yükleme — süresi geçmiş kayıtlar atlanır. */
  loadBlocks(rows = [], now = Date.now()) {
    for (const row of rows) {
      if (!row || !row.address) continue;
      if (row.expiresAt && row.expiresAt <= now) continue;
      // Eski kayıtlar normalize edilmemiş olabilir; yüklerken düzeltiyoruz.
      const ip = canonicalIp(row.address);
      this.blocks.set(ip, {
        address: ip,
        reason: row.reason || '',
        actor: row.actor || '',
        at: Number(row.at) || now,
        expiresAt: Number(row.expiresAt) || 0,
      });
    }
    return this.blocks.size;
  }

  // -------------------------------------------------------------------------
  // TCP
  // -------------------------------------------------------------------------

  /**
   * @returns {{ok: boolean, reason: string|null}}
   */
  checkAccept(address, appId, now = Date.now()) {
    const ip = canonicalIp(address);
    // Elle konan engel en başta denetlenir ve CEZALANDIRMAZ: karar zaten
    // verilmiş, ayrıca üstel yasak saymanın anlamı yok.
    if (this.isBlocked(ip, now)) {
      this.stats.blockedRejections++;
      return this._refuse(ip, REASON.BLOCKED, false);
    }
    if (this.isBanned(ip, now)) return this._refuse(ip, REASON.BANNED, false);

    if (this.connsGlobal >= this.opt.maxConnectionsGlobal) {
      return this._refuse(ip, REASON.CONN_LIMIT_GLOBAL, false);
    }
    if (!this.acceptGlobal.allow('*', now)) return this._refuse(ip, REASON.ACCEPT_RATE_GLOBAL, false);
    if (!this.acceptPerIp.allow(ip, now)) return this._refuse(ip, REASON.ACCEPT_RATE_IP, true);

    if ((this.connsByIp.get(ip) || 0) >= this.opt.maxConnectionsPerIp) {
      return this._refuse(ip, REASON.CONN_LIMIT_IP, true);
    }
    if (appId && (this.connsByApp.get(appId) || 0) >= this.opt.maxConnectionsPerApp) {
      return this._refuse(ip, REASON.CONN_LIMIT_APP, false);
    }
    return { ok: true, reason: null };
  }

  _refuse(ip, reason, penalize) {
    this.stats.refused++;
    this.stats[`refused:${reason}`] = (this.stats[`refused:${reason}`] || 0) + 1;
    if (penalize) this.penalize(ip, reason);
    return { ok: false, reason };
  }

  noteOpen(address, appId) {
    const ip = canonicalIp(address);
    this.stats.accepted++;
    this.connsGlobal++;
    this.connsByIp.set(ip, (this.connsByIp.get(ip) || 0) + 1);
    if (appId) this.connsByApp.set(appId, (this.connsByApp.get(appId) || 0) + 1);
  }

  noteClose(address, appId) {
    const ip = canonicalIp(address);
    this.connsGlobal = Math.max(0, this.connsGlobal - 1);
    const n = (this.connsByIp.get(ip) || 1) - 1;
    if (n <= 0) this.connsByIp.delete(ip); else this.connsByIp.set(ip, n);
    if (appId) {
      const m = (this.connsByApp.get(appId) || 1) - 1;
      if (m <= 0) this.connsByApp.delete(appId); else this.connsByApp.set(appId, m);
    }
  }

  /**
   * Slowloris: bağlantıyı açıp hiçbir şey göndermeyen istemci. Zamanlayıcı
   * ilk bayt gelince iptal edilir.
   */
  armFirstByte(socket, address) {
    const ip = canonicalIp(address);
    const timer = setTimeout(() => {
      this.stats.slowlorisKilled++;
      this.penalize(ip, 'slowloris');
      socket.destroy();
    }, this.opt.firstByteTimeoutMs);
    if (timer.unref) timer.unref();
    const cancel = () => clearTimeout(timer);
    socket.once('data', cancel);
    socket.once('close', cancel);
    return cancel;
  }

  // -------------------------------------------------------------------------
  // UDP
  // -------------------------------------------------------------------------

  /** @returns {{ok:boolean, reason:string|null}} */
  checkUdpInbound(address, bytes, isNewFlow, now = Date.now()) {
    const ip = canonicalIp(address);
    if (this.isBlocked(ip, now)) {
      this.stats.udpDropped++;
      this.stats.blockedRejections++;
      return { ok: false, reason: REASON.BLOCKED };
    }
    if (this.isBanned(ip, now)) { this.stats.udpDropped++; return { ok: false, reason: REASON.BANNED }; }
    if (!this.udpPackets.allow(ip, now)) {
      this.stats.udpDropped++;
      this.penalize(ip, REASON.UDP_RATE, now);
      return { ok: false, reason: REASON.UDP_RATE };
    }
    if (!this.udpBytes.allow(ip, now, bytes)) {
      this.stats.udpDropped++;
      this.penalize(ip, REASON.UDP_BYTES, now);
      return { ok: false, reason: REASON.UDP_BYTES };
    }
    if (isNewFlow) {
      if (this.udpFlowsGlobal >= this.opt.udpMaxFlowsGlobal) {
        this.stats.udpDropped++;
        return { ok: false, reason: REASON.UDP_FLOW_LIMIT };
      }
      if ((this.udpFlowsByIp.get(ip) || 0) >= this.opt.udpMaxFlowsPerIp) {
        this.stats.udpDropped++;
        this.penalize(ip, REASON.UDP_FLOW_LIMIT, now);
        return { ok: false, reason: REASON.UDP_FLOW_LIMIT };
      }
    }
    this.stats.udpAccepted++;
    return { ok: true, reason: null };
  }

  /**
   * Yükseltme (amplification) koruması.
   *
   * UDP'de kaynak adresi doğrulanmadan yanıt üretmek, sunucuyu bir saldırı
   * silahına çevirir: saldırgan kurbanın adresini kaynak yazar, biz kurbana
   * onun hiç istemediği kat kat büyük bir yanıt göndeririz. Akış "kurulmuş"
   * sayılana kadar (iki yönlü işaret: birden fazla gelen paket) çıkan bayt,
   * gelen baytın belirli bir katıyla sınırlanır.
   *
   * @returns {boolean} yanıt gönderilebilir mi
   */
  checkUdpOutbound(flow, bytes) {
    if (flow.established) return true;
    if (flow.packetsIn >= this.opt.udpEstablishAfterPackets) { flow.established = true; return true; }
    const allowance = flow.bytesIn * this.opt.udpAmplificationRatio;
    if (flow.bytesOut + bytes > allowance) {
      this.stats.amplificationBlocked++;
      return false;
    }
    return true;
  }

  noteUdpFlowOpen(address) {
    const ip = canonicalIp(address);
    this.udpFlowsGlobal++;
    this.udpFlowsByIp.set(ip, (this.udpFlowsByIp.get(ip) || 0) + 1);
  }

  noteUdpFlowClose(address) {
    const ip = canonicalIp(address);
    this.udpFlowsGlobal = Math.max(0, this.udpFlowsGlobal - 1);
    const n = (this.udpFlowsByIp.get(ip) || 1) - 1;
    if (n <= 0) this.udpFlowsByIp.delete(ip); else this.udpFlowsByIp.set(ip, n);
  }

  // -------------------------------------------------------------------------
  _evict(map) {
    const drop = Math.max(1, Math.floor(map.size / 4));
    let n = 0;
    for (const k of map.keys()) { map.delete(k); if (++n >= drop) break; }
  }

  sweep(now = Date.now()) {
    this.acceptPerIp.sweep(now);
    this.udpPackets.sweep(now);
    this.udpBytes.sweep(now);
    for (const [ip, b] of this.bans) {
      if (now - b.until > this.opt.offenceMemoryMs) this.bans.delete(ip);
    }
    for (const [ip, v] of this.violations) if (now - v.at > this.opt.violationDecayMs) this.violations.delete(ip);
    // Süreli engeller doldukça düşer; kalıcı olanlara (expiresAt = 0) dokunulmaz.
    for (const [ip, b] of this.blocks) if (b.expiresAt && b.expiresAt <= now) this.blocks.delete(ip);
  }

  snapshot(now = Date.now()) {
    let active = 0;
    for (const b of this.bans.values()) if (b.until > now) active++;
    return {
      ...this.stats,
      connectionsGlobal: this.connsGlobal,
      distinctSourceIps: this.connsByIp.size,
      udpFlows: this.udpFlowsGlobal,
      // Süresi dolmuş kayıtlar üstel ceza için tutuluyor; "yasaklı" sayısı
      // yalnızca HÂLÂ yürürlükte olanlardır.
      bannedIps: active,
      rememberedOffenders: this.bans.size,
      watchedIps: this.violations.size,
      blockedAddresses: this.blocks.size,
    };
  }

  listBans() {
    const now = Date.now();
    return [...this.bans.entries()]
      .filter(([, b]) => b.until > now)
      .map(([ip, b]) => ({ ip, until: b.until, offences: b.count, remainingMs: b.until - now }));
  }

  stop() {
    if (this._sweepTimer) clearInterval(this._sweepTimer);
    this._sweepTimer = null;
  }
}

module.exports = { Guard, GUARD_DEFAULTS: DEFAULTS, GUARD_REASON: REASON };
