'use strict';
// Yönetim yüzeyinin testi — gerçek HTTP sunucusu, gerçek OAuth 2.0 + PKCE akışı.
//
// Kimlik sağlayıcı taklit ediliyor ama PROTOKOL taklit edilmiyor: sahte IdP
// gerçek bir HTTP sunucusu ve `code_verifier`'ı gerçekten doğruluyor. Yalnızca
// "istek atıldı mı" diye bakan bir test, PKCE'nin yanlış hesaplandığını
// göremezdi.

const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { Runner } = require('../../tests/helpers.js');
const { TunnelServer } = require('../src/server/index.js');
const { loadServerConfig } = require('../src/server/config.js');

const CERTS = path.join(__dirname, '..', '..', 'certs');

// ---------------------------------------------------------------------------
// Sahte kimlik sağlayıcı
// ---------------------------------------------------------------------------
function startMockIdp({ user }) {
  const issued = new Map(); // code -> { challenge }
  const tokens = new Map(); // access_token -> user

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://idp.local');

    if (url.pathname === '/oauth/authorize') {
      // Gerçek IdP burada kullanıcıya giriş ekranı gösterir; test için doğrudan
      // onaylanmış sayıp geri yönlendiriyoruz.
      const code = crypto.randomBytes(12).toString('base64url');
      issued.set(code, { challenge: url.searchParams.get('code_challenge') });
      const back = new URL(url.searchParams.get('redirect_uri'));
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state'));
      res.writeHead(302, { location: back.toString() });
      res.end();
      return;
    }

    if (url.pathname === '/oauth/token' && req.method === 'POST') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));
        const entry = issued.get(body.code);
        const expected = entry && crypto.createHash('sha256').update(body.code_verifier || '').digest('base64url');

        if (!entry || expected !== entry.challenge) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE doğrulaması başarısız' }));
          return;
        }
        issued.delete(body.code);           // tek kullanımlık
        const at = crypto.randomBytes(16).toString('base64url');
        tokens.set(at, user);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ access_token: at, token_type: 'Bearer', expires_in: 600 }));
      });
      return;
    }

    if (url.pathname === '/oauth/userinfo') {
      const at = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const who = tokens.get(at);
      if (!who) { res.writeHead(401); res.end('{}'); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(who));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      url: `http://127.0.0.1:${server.address().port}`,
      setUser: (u) => { Object.assign(user, u); },
      close: () => new Promise((r) => server.close(r)),
    }));
  });
}

// ---------------------------------------------------------------------------
// Küçük HTTP istemcisi — çerezleri tarayıcı gibi taşır
// ---------------------------------------------------------------------------
class Browser {
  constructor(base) {
    this.base = base;
    // KÖKEN BAŞINA çerez kavanozu. Tek bir kavanoz kullanmak, sahte IdP'ye
    // panelin oturum çerezini sızdırırdı; hiç kavanoz taşımamak ise
    // yönlendirme zincirinde (panel → IdP → panel) PKCE çerezini kaybettirir
    // ve akış "state uyuşmuyor" ile biterdi. Gerçek tarayıcı davranışı budur.
    this.jars = new Map();
  }

  _jar(origin) {
    if (!this.jars.has(origin)) this.jars.set(origin, new Map());
    return this.jars.get(origin);
  }

  request(method, url, {
    body, headers = {}, follow = true, sameOrigin = true, maxHops = 8,
  } = {}) {
    const target = new URL(url, this.base);
    const jar = this._jar(target.origin);
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const outHeaders = { ...(sameOrigin ? { 'sec-fetch-site': 'same-origin' } : {}), ...headers };
    if (jar.size) outHeaders.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    if (payload) {
      outHeaders['content-type'] = 'application/json';
      outHeaders['content-length'] = payload.length;
    }

    return new Promise((resolve, reject) => {
      const req = http.request(target, { method, headers: outHeaders }, (res) => {
        for (const raw of res.headers['set-cookie'] || []) {
          const [pair] = raw.split(';');
          const i = pair.indexOf('=');
          const name = pair.slice(0, i).trim();
          const value = pair.slice(i + 1).trim();
          if (/Max-Age=0/i.test(raw) || value === '') jar.delete(name);
          else jar.set(name, value);
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', async () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch { /* HTML olabilir */ }

          if (follow && maxHops > 0 && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            const next = new URL(res.headers.location, target);
            try {
              resolve(await this.request('GET', next.toString(), {
                follow, maxHops: maxHops - 1, sameOrigin: next.origin === target.origin,
              }));
            } catch (e) { reject(e); }
            return;
          }
          resolve({ status: res.statusCode, json, text, headers: res.headers });
        });
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  get(url, opts) { return this.request('GET', url, opts); }
  post(url, body, opts) { return this.request('POST', url, { body, ...opts }); }
  patch(url, body, opts) { return this.request('PATCH', url, { body, ...opts }); }
  del(url, opts) { return this.request('DELETE', url, opts); }
}

// ---------------------------------------------------------------------------
async function startStack({ adminOverrides = {}, user } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitfak-admin-test-'));
  const idp = await startMockIdp({ user });

  // Port 0 ile başlatıp gerçek adresi öğrenmemiz gerekiyor, ama redirect_uri
  // yapılandırmada ÖNCEDEN gerekli. Bu yüzden önce boş bir port kapıp
  // bırakıyoruz — testin dışında bu adres zaten sabittir.
  const probe = http.createServer();
  await new Promise((res) => probe.listen(0, '127.0.0.1', res));
  const adminPort = probe.address().port;
  await new Promise((res) => probe.close(res));

  const config = loadServerConfig({
    host: '127.0.0.1',
    port: 0,
    publicHost: '127.0.0.1',
    certPath: path.join(CERTS, 'server.crt'),
    keyPath: path.join(CERTS, 'server.key'),
    caPath: path.join(CERTS, 'ca.crt'),
    revocation: 'off',
    portMin: 42000,
    portMax: 42099,
    dataDir,
    metricsIntervalMs: 3_600_000,
    db: { target: null, identityDir: path.join(dataDir, 'identity') },
    admin: {
      enabled: true,
      host: '127.0.0.1',
      port: adminPort,
      idpUrl: idp.url,
      clientId: 'fitfak-tunnel-admin',
      clientSecret: 'test-secret',
      redirectUri: `http://127.0.0.1:${adminPort}/oauth/callback`,
      sessionTtlMs: 3600_000,
      adminEmail: '',
      insecureNoAuth: false,
      ...adminOverrides,
    },
  });

  const server = new TunnelServer(config);
  await server.start();
  const base = `http://127.0.0.1:${adminPort}`;

  return {
    server,
    idp,
    base,
    browser: () => new Browser(base),
    async close() {
      await server.stop().catch(() => {});
      await idp.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

// ---------------------------------------------------------------------------
(async () => {
  const r = new Runner('tünel — yönetim yüzeyi');

  await r.test('kimlik doğrulamasız erişim reddedilir, API 401 döner', async () => {
    const s = await startStack({ user: { sub: 'u1', preferred_username: 'admin', role: 'admin' } });
    try {
      const b = s.browser();
      const api = await b.get('/api/overview', { follow: false });
      assert.strictEqual(api.status, 401);
      assert.strictEqual(api.json.error, 'unauthenticated');

      // Sayfa isteği giriş akışına yönlendirilir (API gibi 401 dönmez —
      // tarayıcıda ham JSON göstermek kullanışsız).
      const page = await b.get('/', { follow: false });
      assert.strictEqual(page.status, 302);
      assert.match(page.headers.location, /^\/login/);
    } finally { await s.close(); }
  });

  await r.test('OAuth + PKCE ile yönetici girişi ve oturum çerezi', async () => {
    const s = await startStack({
      user: {
        sub: 'u1', preferred_username: 'aybars', email: 'a@fitfak.net', email_verified: true, role: 'admin',
      },
    });
    try {
      const b = s.browser();
      const res = await b.get('/login');
      assert.strictEqual(res.status, 200, 'giriş akışı panele dönmeli');
      assert.match(res.text, /fitfak/);

      const me = await b.get('/api/overview');
      assert.strictEqual(me.status, 200);
      assert.strictEqual(me.json.me.username, 'aybars');
      assert.strictEqual(me.json.me.role, 'admin');
      assert.strictEqual(me.json.persistence, 'memory');

      // Çıkış çerezi geçersiz kılar.
      const out = await b.post('/logout', {});
      assert.strictEqual(out.status, 200);
      const after = await b.get('/api/overview', { follow: false });
      assert.strictEqual(after.status, 401);
    } finally { await s.close(); }
  });

  await r.test('yönetici olmayan kullanıcı reddedilir', async () => {
    const s = await startStack({
      user: {
        sub: 'u2', preferred_username: 'normal', email: 'n@fitfak.net', email_verified: true, role: 'user',
      },
    });
    try {
      const b = s.browser();
      const res = await b.get('/login');
      assert.strictEqual(res.status, 403, 'yetkisiz hesap 403 almalı');
      assert.match(res.text, /yönetim yetkisi yok/);

      const api = await b.get('/api/overview', { follow: false });
      assert.strictEqual(api.status, 401, 'başarısız giriş oturum bırakmamalı');
    } finally { await s.close(); }
  });

  await r.test('yapılandırılmış yönetici e-postası ikinci kabul yolu', async () => {
    const s = await startStack({
      adminOverrides: { adminEmail: 'sef@fitfak.net' },
      user: {
        sub: 'u3', preferred_username: 'sef', email: 'sef@fitfak.net', email_verified: true, role: 'user',
      },
    });
    try {
      const b = s.browser();
      await b.get('/login');
      const me = await b.get('/api/overview');
      assert.strictEqual(me.status, 200);
      assert.strictEqual(me.json.me.username, 'sef');
    } finally { await s.close(); }
  });

  await r.test('doğrulanmamış e-posta yönetici yapmaz', async () => {
    const s = await startStack({
      adminOverrides: { adminEmail: 'sef@fitfak.net' },
      user: {
        sub: 'u4', preferred_username: 'sahte', email: 'sef@fitfak.net', email_verified: false, role: 'user',
      },
    });
    try {
      const res = await s.browser().get('/login');
      assert.strictEqual(res.status, 403,
        'doğrulanmamış bir adresi kabul etmek, kayıtta o adresi yazmayı yöneticilik için yeterli kılardı');
    } finally { await s.close(); }
  });

  await r.test('state uyuşmazlığı reddedilir (login CSRF)', async () => {
    const s = await startStack({
      user: {
        sub: 'u5', preferred_username: 'admin', email: 'a@fitfak.net', email_verified: true, role: 'admin',
      },
    });
    try {
      const b = s.browser();
      // Saldırganın kendi kodunu kurbanın tarayıcısına enjekte etmesi: çerezde
      // saklanan state ile sorgudaki eşleşmezse akış reddedilmeli.
      const res = await b.get('/oauth/callback?code=abc&state=saldirgan', { follow: false });
      assert.strictEqual(res.status, 400);
      assert.match(res.text, /state uyuşmuyor|akış bulunamadı/);
    } finally { await s.close(); }
  });

  await r.test('çapraz-site istekleri köken kapısına takılır', async () => {
    const s = await startStack({
      user: {
        sub: 'u6', preferred_username: 'admin', email: 'a@fitfak.net', email_verified: true, role: 'admin',
      },
    });
    try {
      const b = s.browser();
      await b.get('/login');

      const evil = await b.request('POST', '/api/apps', {
        body: { clientId: 'x', localPort: 80 },
        headers: { 'sec-fetch-site': 'cross-site', origin: 'https://kotu.example' },
        sameOrigin: false,
        follow: false,
      });
      assert.strictEqual(evil.status, 403);

      // GET'ler durum değiştirmez, kapıdan geçmeleri gerekmiyor.
      const ok = await b.request('GET', '/api/overview', { sameOrigin: false, follow: false });
      assert.strictEqual(ok.status, 200);
    } finally { await s.close(); }
  });

  await r.test('REST: uygulama, port, koruma ve denetim uçları çalışıyor', async () => {
    const s = await startStack({
      user: {
        sub: 'u7', preferred_username: 'admin', email: 'a@fitfak.net', email_verified: true, role: 'admin',
      },
    });
    try {
      const b = s.browser();
      await b.get('/login');

      // Bağlı istemci yokken bile uygulama tanımlanabilmeli: panel, istemci
      // çevrimdışıyken de yapılandırılabilir olmalı.
      const created = await b.post('/api/apps', {
        clientId: 'a'.repeat(64),
        name: 'gelecek',
        localHost: '127.0.0.9',
        localPort: 5432,
        protocol: 'tcp',
        rateOutMbit: 10,
      });
      assert.strictEqual(created.status, 201);
      assert.strictEqual(created.json.localHost, '127.0.0.9');
      assert.strictEqual(created.json.publicPort, null, 'istemci yokken port bağlanmaz');
      assert.strictEqual(created.json.rateOutBps, 1_250_000, '10 Mbit/s = 1.25 MB/s');

      const list = await b.get('/api/apps');
      assert.strictEqual(list.json.apps.length, 1);

      const patched = await b.patch(`/api/apps/${created.json.appId}`, { enabled: false, rateInMbit: 5 });
      assert.strictEqual(patched.status, 200);
      assert.strictEqual(patched.json.enabled, false);
      assert.strictEqual(patched.json.rateInBps, 625_000);

      const ports = await b.get('/api/ports');
      assert.strictEqual(ports.json.stats.poolMin, 42000);
      assert.strictEqual(ports.json.stats.poolMax, 42099);

      const guard = await b.get('/api/guard');
      assert.ok(guard.json.limits.maxConnectionsPerIp > 0);
      assert.deepStrictEqual(guard.json.bans, []);

      const removed = await b.del(`/api/apps/${created.json.appId}`);
      assert.strictEqual(removed.json.deleted, true);

      const events = await b.get('/api/events');
      const kinds = events.json.events.map((e) => e.kind);
      assert.ok(kinds.includes('app.create'), 'oluşturma denetim kaydına yazılmalı');
      assert.ok(kinds.includes('app.delete'), 'silme denetim kaydına yazılmalı');
      const actor = events.json.events.find((e) => e.kind === 'app.create').actor;
      assert.match(actor, /admin<a@fitfak\.net>/, 'kimin yaptığı kayda geçmeli');

      const bad = await b.post('/api/apps', { clientId: 'x', localPort: 0 }, { follow: false });
      assert.strictEqual(bad.status, 400, 'geçersiz girdi bir sunucu arızası değil, 400 olmalı');
      assert.strictEqual(bad.json.error, 'invalid_request');
    } finally { await s.close(); }
  });

  await r.test('konsol varlıkları güvenlik başlıklarıyla sunuluyor', async () => {
    const s = await startStack({
      user: {
        sub: 'u8', preferred_username: 'admin', email: 'a@fitfak.net', email_verified: true, role: 'admin',
      },
    });
    try {
      const b = s.browser();
      await b.get('/login');

      const page = await b.get('/');
      assert.strictEqual(page.status, 200);
      assert.match(page.headers['content-type'], /text\/html/);
      // Satır içi script YOK: içerik güvenliği politikası onu engelliyor ve
      // sayfanın buna uyduğunu burada sabitliyoruz.
      assert.ok(!/<script>[^<]/.test(page.text), 'satır içi script olmamalı');
      assert.match(page.headers['content-security-policy'], /script-src 'self'/);
      assert.strictEqual(page.headers['x-frame-options'], 'DENY');
      assert.strictEqual(page.headers['x-content-type-options'], 'nosniff');

      const css = await b.get('/tunnel-ui.css');
      assert.match(css.headers['content-type'], /text\/css/);
      const js = await b.get('/tunnel-console.js');
      assert.match(js.headers['content-type'], /javascript/);

      // Dizin dışına çıkma denemesi.
      const escape = await b.get('/api/../../../etc/passwd', { follow: false });
      assert.ok(escape.status === 404 || escape.status === 401 || escape.status === 302);
    } finally { await s.close(); }
  });

  await r.test('sağlık ucu kimlik doğrulaması istemez', async () => {
    const s = await startStack({ user: { sub: 'u9', role: 'admin' } });
    try {
      const res = await s.browser().get('/healthz', { follow: false });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.ok, true);
    } finally { await s.close(); }
  });

  r.exit();
})();
