'use strict';
// Yönetim yüzeyi — varsayılan olarak http://127.0.1.3:80
//
// Neden düz HTTP ve neden bir geri döngü adresi? Bu yüzey dış dünyaya açılmaz;
// tıpkı fitfak-idp'nin mantıksal host'ları gibi ADRES SEVİYESİNDE ayrılır.
// Ayrımı `Host` başlığıyla yapmak yanlış olurdu: `Host`, istemcinin yazdığı
// bir dizedir, soketin gerçekten hangi arayüze bağlandığının kanıtı değil.
// Dışarıdan erişim isteniyorsa önüne TLS sonlandıran bir ters proxy konur.
//
// Adresin geri döngü olması KİMLİK DOĞRULAMANIN YERİNE GEÇMEZ: aynı makinedeki
// her süreç buraya ulaşabilir. Yetki tek yerden gelir — IdP'de yönetici olmak.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const { createLogger } = require('../../common/log.js');
const { PROTO_CODE } = require('../../protocol/constants.js');
const { mbitToBytes } = require('../config.js');
const {
  AdminAuth, parseCookies, assertSameOrigin, PKCE_COOKIE,
} = require('./auth.js');

const PUBLIC_DIR = path.join(__dirname, 'public');
/** Aynı anda açık canlı akış (SSE) tavanı. */
const MAX_SSE_CLIENTS = 64;
const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
};

// ===========================================================================
// Güvenlik başlıkları
//
// Politika `default-src 'none'` ile başlar: hiçbir şeye izin yok, sonra tek tek
// açılıyor. Tersi ("her şeye izin ver, tehlikelileri kapat") yeni bir kaynak
// türü eklendiğinde sessizce açık kalır.
//
// Satır içi script ve stil YOK — ve bu, sayfanın gerçekten uyduğu bir kural
// (bkz. public/index.html ve public/tunnel-console.js). Uymasaydı
// `'unsafe-inline'` eklemek zorunda kalırdık ve o noktada script-src'nin XSS'e
// karşı hiçbir değeri kalmazdı.
//
// `require-trusted-types-for 'script'` bunu tarayıcı seviyesinde MÜHÜRLER:
// konsol innerHTML'e yazmayı denerse tarayıcı engeller. Sayfa zaten hiç
// kullanmadığı için bedava gelen, ama gelecekte birinin yanlışlıkla eklemesini
// imkânsız kılan bir kural.
//
// Üçüncü taraf betikler (ör. Cloudflare Web Analytics'in enjekte ettiği
// beacon.min.js) VARSAYILAN OLARAK ENGELLİ. Açmak isteyen `admin.csp` ile
// açıkça izin verir — çünkü bu bir güvenlik kararıdır ve sessiz bir varsayılan
// olarak verilmemelidir. Ayrıntı: _buildCsp().
// ===========================================================================

/** Cloudflare Web Analytics'in kullandığı kaynaklar (opsiyonel). */
const CLOUDFLARE_INSIGHTS = Object.freeze({
  script: 'https://static.cloudflareinsights.com',
  connect: 'https://cloudflareinsights.com',
});

const BASE_HEADERS = Object.freeze({
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  // Tarayıcıya "bu sayfa hiçbir güçlü özelliğe ihtiyaç duymuyor" demek: panelde
  // bir XSS bulunsa bile kamera/mikrofon/konum isteyemez.
  'permissions-policy':
    'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), '
    + 'fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), '
    + 'midi=(), payment=(), picture-in-picture=(), usb=(), xr-spatial-tracking=()',
  // Spectre sınıfı çapraz-köken sızıntılarına karşı yalıtım.
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'x-permitted-cross-domain-policies': 'none',
});

/**
 * CSP dizesini yapılandırmadan üretir.
 *
 * @param {object} [csp] admin.csp
 * @param {boolean} [csp.cloudflareInsights] Cloudflare beacon'ına izin ver
 * @param {string[]} [csp.scriptSrc]  ek script kaynakları
 * @param {string[]} [csp.connectSrc] ek bağlantı hedefleri
 * @param {string[]} [csp.imgSrc]     ek görsel kaynakları
 * @param {boolean}  [csp.trustedTypes] varsayılan açık
 * @param {string}   [csp.reportUri]  ihlal raporları için uç
 */
function buildCsp(csp = {}) {
  const list = (base, extra) => {
    const out = base.slice();
    for (const item of extra || []) {
      const value = String(item).trim();
      // 'unsafe-inline' ve 'unsafe-eval' YAPILANDIRMAYLA DA AÇILAMAZ. Bunlar
      // "biraz daha esnek" ayarlar değil, politikanın tamamını anlamsız kılan
      // anahtarlardır; bir yapılandırma hatasının onları açabilmesi, elimizdeki
      // tek gerçek XSS bariyerini bir yazım hatasına bağlamak olurdu.
      if (/^'unsafe-(inline|eval|hashes)'$/i.test(value)) continue;
      if (value && !out.includes(value)) out.push(value);
    }
    return out;
  };

  const scriptSrc = list(["'self'"], csp.scriptSrc);
  const connectSrc = list(["'self'"], csp.connectSrc);
  const imgSrc = list(["'self'", 'data:'], csp.imgSrc);

  if (csp.cloudflareInsights) {
    // Beacon, Cloudflare'in HTML'e enjekte ettiği harici bir `<script src>`tir;
    // nonce ile çözülemez (etiketi biz üretmiyoruz). Doğru çözüm, TEK bir
    // kaynağı ada göre listelemek — 'unsafe-inline' açmak değil.
    if (!scriptSrc.includes(CLOUDFLARE_INSIGHTS.script)) scriptSrc.push(CLOUDFLARE_INSIGHTS.script);
    if (!connectSrc.includes(CLOUDFLARE_INSIGHTS.connect)) connectSrc.push(CLOUDFLARE_INSIGHTS.connect);
  }

  const directives = [
    "default-src 'none'",
    `script-src ${scriptSrc.join(' ')}`,
    "style-src 'self'",
    `img-src ${imgSrc.join(' ')}`,
    `connect-src ${connectSrc.join(' ')}`,
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
  ];
  if (csp.trustedTypes !== false) directives.push("require-trusted-types-for 'script'");
  if (csp.reportUri) directives.push(`report-uri ${csp.reportUri}`);
  return directives.join('; ');
}

/** Yapılandırma verilmemiş kurulumlar için hazır politika. */
const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': buildCsp(),
  ...BASE_HEADERS,
});

class AdminServer {
  constructor({ server, config }) {
    this.tunnelServer = server;
    this.config = config;
    this.log = createLogger('tunnel:admin');
    this.auth = new AdminAuth({ config, log: this.log });
    this.http = null;
    this.origins = [];
    this._sseClients = new Set();
    // Politika süreç başında BİR KEZ kurulur: istek başına dize birleştirmek,
    // hem boşuna iş hem de yapılandırmanın çalışma anında değişebileceği
    // izlenimi verirdi.
    this.headers = Object.freeze({
      'content-security-policy': buildCsp(config.csp),
      ...BASE_HEADERS,
    });
  }

  async start() {
    this.origins = [
      `http://${this.config.host}:${this.config.port}`,
      `http://${this.config.host}`,
    ];

    this.http = http.createServer((req, res) => {
      this._handle(req, res).catch((err) => this._fail(res, err));
    });
    // Yavaş istemcinin başlıkları damla damla göndererek bağlantı tutmasını
    // engeller (slowloris'in HTTP hâli).
    this.http.headersTimeout = 15_000;
    this.http.requestTimeout = 60_000;

    await new Promise((resolve, reject) => {
      this.http.once('error', reject);
      this.http.listen(this.config.port, this.config.host, () => {
        this.http.removeListener('error', reject);
        resolve();
      });
    });

    this.log.info('yönetim yüzeyi dinliyor', {
      adres: `http://${this.config.host}:${this.config.port}`,
      kimlik: this.auth.enabled ? this.config.idpUrl : 'KAPALI (insecureNoAuth)',
    });
    if (!this.auth.enabled) {
      this.log.warn('KİMLİK DOĞRULAMASI KAPALI — bu makinedeki her süreç yönetici', {
        kapatmakIcin: 'FITFAK_TUNNEL_ADMIN_INSECURE_NO_AUTH ayarını kaldırın',
      });
    }

    this.tunnelServer.on('tunnel', (t) => {
      t.once('ready', () => this._broadcast('tunnel', { event: 'ready', tunnelId: t.tunnelId }));
    });
    this.tunnelServer.on('tunnelClosed', (t) => this._broadcast('tunnel', { event: 'closed', tunnelId: t.tunnelId }));
  }

  async stop() {
    this.auth.stop();
    for (const res of this._sseClients) { try { res.end(); } catch { /* kapanmış */ } }
    this._sseClients.clear();
    if (!this.http) return;
    await new Promise((resolve) => this.http.close(resolve));
  }

  // =========================================================================
  async _handle(req, res) {
    for (const [k, v] of Object.entries(this.headers)) res.setHeader(k, v);

    const url = new URL(req.url, `http://${this.config.host}`);
    const p = url.pathname.replace(/\/+$/, '') || '/';

    // ---- kimlik doğrulama uçları (oturum gerektirmez) ---------------------
    if (p === '/login' && req.method === 'GET') return this._login(req, res, url);
    if (p === '/oauth/callback' && req.method === 'GET') return this._callback(req, res, url);
    if (p === '/logout' && req.method === 'POST') return this._logout(req, res);
    if (p === '/healthz') return this._json(res, 200, { ok: true, uptimeMs: Date.now() - this.tunnelServer.startedAt });

    const session = this.auth.resolve(req);
    if (!session) {
      if (p.startsWith('/api/')) return this._json(res, 401, { error: 'unauthenticated' });
      return this._redirect(res, `/login?returnTo=${encodeURIComponent(url.pathname + url.search)}`);
    }

    // Durum değiştiren her istek köken kapısından geçer.
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      assertSameOrigin(req, this.origins);
    }

    if (p === '/' || p === '/index.html') return this._static(res, 'index.html');
    if (p === '/tunnel-ui.css') return this._static(res, 'tunnel-ui.css');
    if (p === '/tunnel-console.js') return this._static(res, 'tunnel-console.js');
    // Tarayıcı bunu istemeden edemez; sunmazsak her sayfa açılışında konsola
    // bir 404 düşer ve gerçek hataları gürültüye gömer.
    if (p === '/favicon.svg' || p === '/favicon.ico') return this._static(res, 'favicon.svg');

    if (p.startsWith('/api/')) return this._api(req, res, url, p, session);

    return this._json(res, 404, { error: 'not_found' });
  }

  // ---- kimlik ------------------------------------------------------------
  _login(req, res, url) {
    if (!this.auth.enabled) return this._redirect(res, '/');
    if (this.auth.resolve(req)) return this._redirect(res, '/');
    const { location, cookie } = this.auth.beginLogin({ returnTo: url.searchParams.get('returnTo') || '/' });
    res.setHeader('set-cookie', cookie);
    return this._redirect(res, location);
  }

  async _callback(req, res, url) {
    if (!this.auth.enabled) return this._redirect(res, '/');
    const cookieState = parseCookies(req)[PKCE_COOKIE];
    try {
      const { sid, returnTo } = await this.auth.completeLogin({
        code: url.searchParams.get('code'),
        state: url.searchParams.get('state'),
        cookieState,
      });
      res.setHeader('set-cookie', [
        this.auth.sessionCookie(sid),
        `${PKCE_COOKIE}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`,
      ]);
      return this._redirect(res, returnTo.startsWith('/') ? returnTo : '/');
    } catch (err) {
      this.log.warn('giriş başarısız', { err: err.message, user: err.user });
      res.setHeader('set-cookie', this.auth.clearCookies());
      const body = `<!doctype html><meta charset="utf-8"><title>Giriş başarısız</title>`
        + `<link rel="stylesheet" href="/tunnel-ui.css">`
        + `<main class="tn-center"><div class="tn-card"><h1>Giriş başarısız</h1>`
        + `<p class="tn-muted">${escapeHtml(err.message)}</p>`
        + `<p><a class="tn-btn tn-btn--primary" href="/login">Tekrar dene</a></p></div></main>`;
      res.writeHead(err.status === 403 ? 403 : 400, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(body);
    }
  }

  _logout(req, res) {
    this.auth.logout(req);
    res.setHeader('set-cookie', this.auth.clearCookies());
    return this._json(res, 200, { ok: true });
  }

  // ---- REST --------------------------------------------------------------
  async _api(req, res, url, p, session) {
    const actor = `${session.username}<${session.email}>`;
    const m = req.method;

    // -- genel bakış
    if (p === '/api/overview' && m === 'GET') {
      return this._json(res, 200, {
        ...this.tunnelServer.overview(),
        me: { username: session.username, email: session.email, role: session.role },
      });
    }

    // -- tüneller
    if (p === '/api/tunnels' && m === 'GET') {
      return this._json(res, 200, {
        tunnels: [...this.tunnelServer.tunnels.values()].map((t) => t.snapshot()),
      });
    }

    let match = /^\/api\/tunnels\/([A-Za-z0-9_-]+)$/.exec(p);
    if (match && m === 'GET') {
      const t = this.tunnelServer.getTunnel(match[1]);
      if (!t) return this._json(res, 404, { error: 'not_found' });
      return this._json(res, 200, t.snapshot());
    }

    match = /^\/api\/tunnels\/([A-Za-z0-9_-]+)\/disconnect$/.exec(p);
    if (match && m === 'POST') {
      const body = await readJson(req);
      return this._json(res, 200, await this.tunnelServer.disconnectTunnel(match[1], {
        actor, reason: body.reason || 'yönetici tarafından kapatıldı',
      }));
    }

    match = /^\/api\/tunnels\/([A-Za-z0-9_-]+)\/limits$/.exec(p);
    if (match && m === 'POST') {
      const t = this.tunnelServer.getTunnel(match[1]);
      if (!t) return this._json(res, 404, { error: 'not_found' });
      const body = await readJson(req);
      const egressBps = body.egressMbit !== undefined ? mbitToBytes(Number(body.egressMbit)) : Number(body.egressBps) || 0;
      t.applyConfig({ egressBps });
      await this.tunnelServer.store.recordEvent({
        kind: 'tunnel.limits', actor, subject: t.tunnelId, detail: JSON.stringify({ egressBps }), at: Date.now(),
      }).catch(() => {});
      return this._json(res, 200, { tunnelId: t.tunnelId, egressBps });
    }

    // -- istemciler
    if (p === '/api/clients' && m === 'GET') {
      const clients = await this.tunnelServer.store.listClients();
      const online = new Set(this.tunnelServer.byClient.keys());
      return this._json(res, 200, {
        clients: clients.map((c) => ({
          ...c,
          online: online.has(c.clientId),
          tunnelId: this.tunnelServer.byClient.get(c.clientId)?.tunnelId || null,
        })),
      });
    }

    match = /^\/api\/clients\/([a-f0-9]{16,128})\/block$/.exec(p);
    if (match && m === 'POST') {
      const body = await readJson(req);
      return this._json(res, 200, await this.tunnelServer.setClientBlocked(match[1], !!body.blocked, { actor }));
    }

    // -- ziyaretçiler (genel yüzeye dışarıdan bağlananlar)
    if (p === '/api/peers' && m === 'GET') {
      return this._json(res, 200, {
        peers: this.tunnelServer.peers.list({
          appId: url.searchParams.get('appId') || null,
          address: url.searchParams.get('address') || null,
          limit: Math.min(Number(url.searchParams.get('limit')) || 500, 2000),
        }),
        stats: {
          ...this.tunnelServer.peers.snapshot(),
          blockedRejections: this.tunnelServer.guard.stats.blockedRejections,
        },
      });
    }

    match = /^\/api\/peers\/([A-Za-z0-9_-]+)\/kick$/.exec(p);
    if (match && m === 'POST') {
      return this._json(res, 200, await this.tunnelServer.kickPeer(match[1], { actor }));
    }

    if (p === '/api/blocklist' && m === 'GET') {
      return this._json(res, 200, { blocklist: this.tunnelServer.guard.listBlocks() });
    }
    if (p === '/api/blocklist' && m === 'POST') {
      const body = await readJson(req);
      return this._json(res, 200, await this.tunnelServer.blockAddress(body.address, {
        ttlMs: Math.max(0, Number(body.ttlMs) || 0),
        reason: body.reason || '',
        actor,
      }));
    }
    match = /^\/api\/blocklist\/(.+)$/.exec(p);
    if (match && m === 'DELETE') {
      const address = decodeURIComponent(match[1]);
      return this._json(res, 200, await this.tunnelServer.unblockAddress(address, { actor }));
    }

    // -- uygulamalar
    if (p === '/api/apps' && m === 'GET') {
      return this._json(res, 200, { apps: await this.tunnelServer.listApps() });
    }
    if (p === '/api/apps' && m === 'POST') {
      const body = await readJson(req);
      return this._json(res, 201, await this.tunnelServer.createApp(normalizeInput(body), { actor }));
    }

    match = /^\/api\/apps\/([A-Za-z0-9_-]+)$/.exec(p);
    if (match && m === 'PATCH') {
      const body = await readJson(req);
      return this._json(res, 200, await this.tunnelServer.updateApp(match[1], normalizeInput(body), { actor }));
    }
    if (match && m === 'DELETE') {
      return this._json(res, 200, await this.tunnelServer.deleteApp(match[1], { actor }));
    }

    // -- portlar, olaylar, ölçümler, oturumlar
    if (p === '/api/ports' && m === 'GET') {
      return this._json(res, 200, {
        stats: this.tunnelServer.ports.stats(),
        reservations: this.tunnelServer.ports.list(),
      });
    }
    if (p === '/api/guard' && m === 'GET') {
      return this._json(res, 200, {
        stats: this.tunnelServer.guard.snapshot(),
        bans: this.tunnelServer.guard.listBans(),
        limits: this.tunnelServer.guard.opt,
      });
    }
    match = /^\/api\/guard\/bans\/(.+)$/.exec(p);
    if (match && m === 'DELETE') {
      const ip = decodeURIComponent(match[1]);
      this.tunnelServer.guard.unban(ip);
      await this.tunnelServer.store.recordEvent({
        kind: 'guard.unban', actor, subject: ip, detail: '', at: Date.now(),
      }).catch(() => {});
      return this._json(res, 200, { ip, banned: false });
    }
    if (p === '/api/events' && m === 'GET') {
      const limit = Math.min(Number(url.searchParams.get('limit')) || 100, 500);
      return this._json(res, 200, { events: await this.tunnelServer.store.listEvents(limit) });
    }
    if (p === '/api/sessions' && m === 'GET') {
      const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 200);
      return this._json(res, 200, { sessions: await this.tunnelServer.store.listSessions(limit) });
    }
    if (p === '/api/metrics' && m === 'GET') {
      const since = Number(url.searchParams.get('since')) || Date.now() - 3600_000;
      return this._json(res, 200, {
        metrics: await this.tunnelServer.store.listMetrics({
          clientId: url.searchParams.get('clientId') || null, since,
        }),
      });
    }
    if (p === '/api/stream' && m === 'GET') return this._sse(req, res);

    return this._json(res, 404, { error: 'not_found' });
  }

  // ---- canlı akış ---------------------------------------------------------
  _sse(req, res) {
    // Her SSE bağlantısı bir zamanlayıcı ve bir açık soket tutar. Tavan
    // olmadan, oturumu olan tek bir tarayıcı sekmesi bile (yenilenip duran bir
    // sayfa, kapanmayan bağlantılar) sunucuyu kendi kendine yorabilirdi.
    if (this._sseClients.size >= MAX_SSE_CLIENTS) {
      return this._json(res, 503, { error: 'too_many_streams' });
    }
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
    });
    res.write(': bağlandı\n\n');
    this._sseClients.add(res);

    const timer = setInterval(() => {
      try {
        res.write(`event: overview\ndata: ${JSON.stringify(this.tunnelServer.overview())}\n\n`);
      } catch { /* kapanmış */ }
    }, 2000);
    if (timer.unref) timer.unref();

    req.on('close', () => { clearInterval(timer); this._sseClients.delete(res); });
  }

  _broadcast(event, data) {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of this._sseClients) { try { res.write(payload); } catch { /* kapanmış */ } }
  }

  // ---- yardımcılar --------------------------------------------------------
  _json(res, status, body) {
    const payload = JSON.stringify(body, (k, v) => (typeof v === 'bigint' ? Number(v) : v));
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(payload),
      'cache-control': 'no-store',
    });
    res.end(payload);
  }

  _redirect(res, location) {
    res.writeHead(302, { location, 'cache-control': 'no-store' });
    res.end();
  }

  _static(res, name) {
    const file = path.join(PUBLIC_DIR, path.basename(name));
    fs.readFile(file, (err, data) => {
      if (err) { this._json(res, 404, { error: 'not_found' }); return; }
      res.writeHead(200, {
        'content-type': STATIC_TYPES[path.extname(file)] || 'application/octet-stream',
        'content-length': data.length,
        'cache-control': 'no-cache',
      });
      res.end(data);
    });
  }

  _fail(res, err) {
    const status = err.status || 500;
    if (status >= 500) this.log.error('yönetim isteği başarısız', { err: err.message, stack: err.stack });
    else this.log.debug('yönetim isteği reddedildi', { err: err.message, status });
    if (res.headersSent) { res.end(); return; }
    this._json(res, status, { error: err.code || 'error', message: err.message });
  }
}

function readJson(req, maxBytes = 128 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > maxBytes) { req.destroy(); reject(Object.assign(new Error('gövde çok büyük'), { status: 413 })); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text) { resolve({}); return; }
      try { resolve(JSON.parse(text)); } catch { reject(Object.assign(new Error('geçersiz JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

/** Panelden gelen insan-dostu alanları motorun beklediği biçime çevirir. */
function normalizeInput(body) {
  const out = { ...body };
  if (typeof out.protocol === 'string') out.proto = PROTO_CODE[out.protocol.toLowerCase()] || 1;
  // Panel Mbit/s konuşur; motor bayt/s. Dönüşümü tek yerde yapmak, iki
  // birimin bir yerde karışmasını engelliyor.
  if (out.rateInMbit !== undefined) out.rateInBps = mbitToBytes(Number(out.rateInMbit));
  if (out.rateOutMbit !== undefined) out.rateOutBps = mbitToBytes(Number(out.rateOutMbit));
  delete out.rateInMbit;
  delete out.rateOutMbit;
  delete out.protocol;
  return out;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

module.exports = {
  AdminServer, SECURITY_HEADERS, BASE_HEADERS, buildCsp, CLOUDFLARE_INSIGHTS,
};
