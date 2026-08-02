'use strict';
// Yönetim yüzeyinin kimlik doğrulaması: fitfak-idp'ye OAuth 2.0 + PKCE.
//
// Bu panel kendi kullanıcı veritabanını TUTMAZ ve kendi parolasını SORMAZ.
// Ayrı bir kullanıcı listesi, ayrı bir parola politikası, ayrı bir 2FA kurulumu
// ve — en kötüsü — birisi işten ayrıldığında unutulacak ayrı bir iptal noktası
// demek olurdu. Kimlik tek yerden gelir: session.fitfak.net.
//
// PKCE (RFC 7636) sunucu-tarafı bir istemcide bile açık: yetkilendirme kodu,
// tarayıcının adres çubuğundan ve HTTP günlüklerinden geçer. `code_verifier`
// olmadan, o kodu bir şekilde ele geçiren biri onu kendi token'ına çevirebilir.
//
// YETKİ: kullanıcının IdP'deki `role` alanı 'admin' olmalı. İkinci bir kabul
// yolu olarak yapılandırılmış bir e-posta adresi de tanınır (IdP'nin kendi
// yönetici tanımıyla aynı desen). Bu iki yol dışında hiçbir şey — özellikle
// "yerel ağdan geliyor" — yetki üretmez: 127.0.1.3'e ulaşabilen her süreç
// yönetici olabilseydi, panelin kimlik doğrulaması olmazdı.

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');

const SESSION_COOKIE = 'fitfak_tunnel_admin';
const PKCE_COOKIE = 'fitfak_tunnel_pkce';

function b64url(buf) { return buf.toString('base64url'); }

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { out[k] = part.slice(i + 1).trim(); }
  }
  return out;
}

function httpJson(method, url, { body, headers = {}, form = false, timeoutMs = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(url); } catch { reject(new Error(`geçersiz URL: ${url}`)); return; }
    const lib = target.protocol === 'https:' ? https : http;

    let payload = null;
    const outHeaders = { accept: 'application/json', 'user-agent': 'fitfak-tunnel-admin/1', ...headers };
    if (body) {
      payload = form
        ? Buffer.from(new URLSearchParams(body).toString())
        : Buffer.from(JSON.stringify(body));
      outHeaders['content-type'] = form ? 'application/x-www-form-urlencoded' : 'application/json';
      outHeaders['content-length'] = payload.length;
    }

    const req = lib.request(target, { method, headers: outHeaders, timeout: timeoutMs }, (res) => {
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > 512 * 1024) { req.destroy(new Error('yanıt çok büyük')); return; }
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

class AdminAuth {
  constructor({ config, log }) {
    this.config = config;
    this.log = log;
    /** sid -> { userId, username, email, role, createdAt, expiresAt } */
    this.sessions = new Map();
    /** state -> { verifier, createdAt, returnTo } */
    this.flows = new Map();

    this._sweepTimer = setInterval(() => this.sweep(), 60_000);
    if (this._sweepTimer.unref) this._sweepTimer.unref();
  }

  get enabled() { return !this.config.insecureNoAuth; }

  sweep(now = Date.now()) {
    for (const [sid, s] of this.sessions) if (s.expiresAt <= now) this.sessions.delete(sid);
    for (const [state, f] of this.flows) if (now - f.createdAt > 600_000) this.flows.delete(state);
  }

  // -------------------------------------------------------------------------
  /** @returns {{location: string, cookie: string}} */
  beginLogin({ returnTo = '/' } = {}) {
    const state = b64url(crypto.randomBytes(24));
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());

    this.flows.set(state, { verifier, createdAt: Date.now(), returnTo });

    const url = new URL('/oauth/authorize', this.config.idpUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', 'openid profile email');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return {
      location: url.toString(),
      // Panel düz HTTP üzerinde (127.0.1.3) çalıştığı için `Secure` yok:
      // konulsaydı tarayıcı çerezi hiç göndermezdi ve giriş sonsuz döngüye
      // girerdi. Bağlantı adresi bir geri döngü adresi olduğu için trafik
      // makineden hiç çıkmıyor.
      cookie: `${PKCE_COOKIE}=${state}; HttpOnly; SameSite=Lax; Max-Age=600; Path=/`,
    };
  }

  /**
   * @returns {Promise<{sid: string, session: object, returnTo: string}>}
   * @throws yetki yoksa ya da değişim başarısızsa
   */
  async completeLogin({ code, state, cookieState }) {
    if (!code || !state) throw new Error('eksik yetkilendirme yanıtı');
    // `state` HEM çerezden HEM sorgu dizesinden geliyor ve eşleşmeleri
    // gerekiyor: yalnızca sorgudakine bakmak, saldırganın kendi kodunu
    // kurbanın oturumuna enjekte etmesine (login CSRF) izin verirdi.
    if (!cookieState || cookieState !== state) throw new Error('state uyuşmuyor');

    const flow = this.flows.get(state);
    if (!flow) throw new Error('yetkilendirme akışı bulunamadı ya da süresi doldu');
    this.flows.delete(state);

    const tokenRes = await httpJson('POST', `${this.config.idpUrl}/oauth/token`, {
      form: true,
      body: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirectUri,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code_verifier: flow.verifier,
      },
    });
    if (tokenRes.status !== 200 || !tokenRes.json?.access_token) {
      throw new Error(`token değişimi başarısız (HTTP ${tokenRes.status}): ${tokenRes.json?.error_description || tokenRes.text.slice(0, 200)}`);
    }

    const infoRes = await httpJson('GET', `${this.config.idpUrl}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${tokenRes.json.access_token}` },
    });
    if (infoRes.status !== 200 || !infoRes.json?.sub) {
      throw new Error(`kullanıcı bilgisi alınamadı (HTTP ${infoRes.status})`);
    }
    const info = infoRes.json;

    const email = String(info.email || '').toLowerCase();
    const isAdmin = info.role === 'admin'
      || (this.config.adminEmail && email === this.config.adminEmail && info.email_verified);

    if (!isAdmin) {
      const err = new Error('bu hesabın yönetim yetkisi yok');
      err.status = 403;
      err.user = info.preferred_username || info.sub;
      throw err;
    }

    const sid = b64url(crypto.randomBytes(32));
    const session = {
      userId: info.sub,
      username: info.preferred_username || info.username || info.sub,
      email,
      role: info.role || 'user',
      createdAt: Date.now(),
      expiresAt: Date.now() + this.config.sessionTtlMs,
    };
    this.sessions.set(sid, session);
    this.log.info('yönetici oturum açtı', { user: session.username, email });
    return { sid, session, returnTo: flow.returnTo || '/' };
  }

  sessionCookie(sid) {
    const maxAge = Math.floor(this.config.sessionTtlMs / 1000);
    return `${SESSION_COOKIE}=${sid}; HttpOnly; SameSite=Lax; Max-Age=${maxAge}; Path=/`;
  }

  clearCookies() {
    return [
      `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`,
      `${PKCE_COOKIE}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`,
    ];
  }

  /** @returns {object|null} geçerli oturum */
  resolve(req) {
    if (!this.enabled) {
      return {
        userId: 'local', username: 'yerel', email: '', role: 'admin', insecure: true,
      };
    }
    const sid = parseCookies(req)[SESSION_COOKIE];
    if (!sid) return null;
    const session = this.sessions.get(sid);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) { this.sessions.delete(sid); return null; }
    return session;
  }

  logout(req) {
    const sid = parseCookies(req)[SESSION_COOKIE];
    if (sid) this.sessions.delete(sid);
  }

  stop() { if (this._sweepTimer) clearInterval(this._sweepTimer); }
}

/**
 * Durum değiştiren istekler için köken kapısı.
 *
 * Oturum çerezi `SameSite=Lax` — çapraz-site POST'ta zaten gönderilmez. Bu
 * kontrol o davranışa tek başına güvenmemek içindir: `Lax` bir TARAYICI
 * davranışıdır ve bir gün durum değiştiren bir ucu yanlışlıkla GET olarak
 * yazarsak koruma tek bir HTTP fiiline bağlı kalır.
 */
function assertSameOrigin(req, allowedOrigins) {
  const site = req.headers['sec-fetch-site'];
  if (site) {
    if (site === 'same-origin' || site === 'none') return;
    throw Object.assign(new Error('istek başka bir siteden geldi'), { status: 403 });
  }
  const origin = req.headers.origin;
  if (origin) {
    if (allowedOrigins.includes(origin)) return;
    throw Object.assign(new Error('istek başka bir kökenden geldi'), { status: 403 });
  }
  // Ne Sec-Fetch-Site ne Origin: bir tarayıcının durum değiştiren isteği
  // bunlar olmadan yapması beklenmez. Betikler böyle davranır ve onların
  // çerezi de yoktur; reddetmek doğru varsayılan.
  throw Object.assign(new Error('isteğin kökeni belirlenemedi'), { status: 403 });
}

module.exports = {
  AdminAuth, parseCookies, httpJson, assertSameOrigin, SESSION_COOKIE, PKCE_COOKIE,
};
