'use strict';
// Sürüm müzakeresi, ortak ClientHello üretimi, SNI ve ALPN seçimi.
//
// İstemci tek bir ClientHello ile hem DTLS 1.3 hem 1.2 teklif eder
// (supported_versions + hem 1.3 hem 1.2 cipher suite'leri). Sunucunun cevabı
// hangi makinenin devralacağını belirler:
//   HelloVerifyRequest        → sunucu 1.2  (RFC 6347 cookie takası)
//   ServerHello + supported_versions=0xfefc → 1.3
//   ServerHello (uzantısız)   → 1.2

const crypto = require('node:crypto');
const {
  VERSION, HS_TYPE, EXT_TYPE, ALERT_DESC,
} = require('../constants.js');
const { buildClientHello, parseClientHello, parseServerHello } = require('../handshake/framing.js');
const ext = require('../handshake/extensions.js');
const ecdhe = require('../crypto/ecdhe.js');

function protocolError(msg, desc = ALERT_DESC.PROTOCOL_VERSION) {
  const e = new Error(msg);
  e.alertDescription = desc;
  return e;
}

module.exports = {
  // ==========================================================================
  // İstemci: ilk ClientHello
  // ==========================================================================
  async h_clientStart() {
    const o = this.options;
    this.clientRandom = crypto.randomBytes(32);
    this.chosenGroup = o.groups[0];
    if (o.allow13) this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);

    this.beginFlight();
    const body = this.buildClientHelloBody();
    this.ch1Wire = await this.sendHandshakeMessage(HS_TYPE.CLIENT_HELLO, body, { transcript: false });
    await this.endFlight();
    this.state = 'WAIT_SERVER_HELLO';
  },

  /**
   * Hem 1.3 hem 1.2 için geçerli ClientHello gövdesi.
   * @param {object} [o]
   * @param {Buffer} [o.cookie13]     HelloRetryRequest cookie uzantısı için
   * @param {Buffer} [o.legacyCookie] DTLS 1.2 HelloVerifyRequest cookie alanı için
   */
  buildClientHelloBody({ cookie13 = null, legacyCookie = null } = {}) {
    const o = this.options;
    const exts = [];

    if (this.servername) exts.push(ext.ext_serverName(this.servername));

    // Yalnızca 1.2 isteniyorsa supported_versions hiç gönderilmez; legacy_version yeter.
    if (o.allow13) exts.push(ext.ext_supportedVersionsClient(o.versions));

    exts.push(ext.ext_supportedGroups(o.groups));
    exts.push(ext.ext_signatureAlgorithms(o.sigSchemes));

    if (o.allow13) {
      exts.push(ext.ext_keyShareClient([
        { group: this.chosenGroup, keyExchange: this.keyPair.publicRaw },
      ]));
      exts.push(ext.ext_pskKeyExchangeModes([0x01]));
    }
    if (o.allow12) {
      exts.push(ext.ext_ecPointFormats([0x00]));
      if (o.extendedMasterSecret) exts.push(ext.ext_extendedMasterSecret());
      exts.push(ext.ext_renegotiationInfo());
    }
    if (o.srtp.enabled) exts.push(ext.ext_useSrtp(o.srtp.profiles));
    if (o.alpn) exts.push(ext.ext_alpn(o.alpn));
    // OCSP zımbalama talebi — iptal denetimi açıksa varsayılan olarak istenir;
    // sunucu zımbalarsa istemci OCSP responder'ına hiç bağlanmak zorunda kalmaz.
    if (o.requestOCSP) exts.push(ext.ext_statusRequest());
    if (cookie13) exts.push(ext.ext_cookie(cookie13));

    const cipherSuites = [];
    if (o.allow13) cipherSuites.push(...o.cipherSuites13);
    if (o.allow12) cipherSuites.push(...o.cipherSuites12);

    return buildClientHello({
      random: this.clientRandom,
      legacyCookie,
      cipherSuites,
      extensions: exts,
    });
  },

  // ==========================================================================
  // Sürüm kararı
  // ==========================================================================
  _negotiateVersion(m) {
    return this.role === 'server'
      ? this._serverNegotiateVersion(m)
      : this._clientNegotiateVersion(m);
  },

  _serverNegotiateVersion(m) {
    if (m.msgType !== HS_TYPE.CLIENT_HELLO) {
      throw protocolError('ClientHello beklenirken başka mesaj geldi', ALERT_DESC.UNEXPECTED_MESSAGE);
    }
    const ch = parseClientHello(m.body);
    const o = this.options;

    const sv = ext.findExt(ch.extensions, EXT_TYPE.SUPPORTED_VERSIONS);
    let wants13 = false;
    if (sv) {
      let versions;
      try { versions = ext.parse_supportedVersionsClient(sv.data); }
      catch { throw protocolError('bozuk supported_versions', ALERT_DESC.DECODE_ERROR); }
      wants13 = versions.includes(VERSION.DTLS_1_3);
    }

    if (wants13 && o.allow13) {
      this.version = VERSION.DTLS_1_3;
    } else if (o.allow12 &&
               (ch.legacyVersion === VERSION.DTLS_1_2 || ch.legacyVersion === VERSION.DTLS_1_0)) {
      this.version = VERSION.DTLS_1_2;
    } else {
      throw protocolError(
        `ortak DTLS sürümü yok (istemci legacy=0x${ch.legacyVersion.toString(16)}, ` +
        `1.3 teklif=${wants13}, sunucu aralığı=${o.minVersion.toString(16)}..${o.maxVersion.toString(16)})`);
    }

    this._log('info', 'sürüm seçildi', {
      version: this.version === VERSION.DTLS_1_3 ? 'DTLSv1.3' : 'DTLSv1.2',
    });
    return this.version === VERSION.DTLS_1_3 ? this.h13_handle(m, ch) : this.h12_handle(m, ch);
  },

  _clientNegotiateVersion(m) {
    if (m.msgType === HS_TYPE.HELLO_VERIFY_REQUEST) {
      if (!this.options.allow12) {
        throw protocolError('sunucu DTLS 1.2 HelloVerifyRequest gönderdi ama 1.2 kapalı');
      }
      this.version = VERSION.DTLS_1_2;
      this._log('info', 'sürüm seçildi', { version: 'DTLSv1.2', via: 'HelloVerifyRequest' });
      return this.h12_handle(m);
    }

    if (m.msgType !== HS_TYPE.SERVER_HELLO) {
      throw protocolError('ServerHello beklenirken başka mesaj geldi', ALERT_DESC.UNEXPECTED_MESSAGE);
    }

    const sh = parseServerHello(m.body);
    const sv = ext.findExt(sh.extensions, EXT_TYPE.SUPPORTED_VERSIONS);
    const chosen = sv ? ext.parse_supportedVersionsServer(sv.data) : sh.legacyVersion;

    if (chosen === VERSION.DTLS_1_3) {
      if (!this.options.allow13) throw protocolError('sunucu DTLS 1.3 seçti ama 1.3 kapalı');
      this.version = VERSION.DTLS_1_3;
      return this.h13_handle(m, sh);
    }
    if (chosen === VERSION.DTLS_1_2 || chosen === VERSION.DTLS_1_0) {
      if (!this.options.allow12) {
        throw protocolError('sunucu DTLS 1.2 seçti ama minVersion DTLSv1.3');
      }
      // Downgrade koruması: 1.3 teklif ettiysek ve sunucu 1.2'ye düşürdüyse
      // ServerHello.random'ın son 8 baytı sentinel olmamalı (RFC 8446 §4.1.3).
      this.version = VERSION.DTLS_1_2;
      this._log('info', 'sürüm seçildi', { version: 'DTLSv1.2', via: 'ServerHello' });
      return this.h12_handle(m, sh);
    }
    throw protocolError(`sunucu desteklenmeyen sürüm seçti: 0x${chosen.toString(16)}`);
  },

  // ==========================================================================
  // SNI — sunucu tarafında hostname'e göre sertifika seçimi
  // ==========================================================================
  async _resolveSecureContext(servername) {
    const o = this.options;
    this.servername = servername || null;
    if (!servername) return;

    if (o.contexts) {
      const ctx = o.contexts.get(servername.toLowerCase());
      if (ctx) { this.ctx = ctx; return; }
    }
    if (o.SNICallback) {
      const ctx = await new Promise((resolve, reject) => {
        let done = false;
        const cb = (err, c) => { if (done) return; done = true; err ? reject(err) : resolve(c); };
        try {
          const r = o.SNICallback(servername, cb);
          if (r && typeof r.then === 'function') r.then((c) => cb(null, c), cb);
        } catch (e) { cb(e); }
      });
      if (ctx) { this.ctx = ctx.certDER ? ctx : require('../options.js').createSecureContext(ctx); return; }
    }
    // Eşleşme yoksa varsayılan bağlamla devam edilir (node:tls davranışı).
  },

  // ==========================================================================
  // ALPN
  // ==========================================================================
  _selectAlpn(clientProtocols) {
    const mine = this.options.alpn;
    if (!mine || !clientProtocols || clientProtocols.length === 0) return null;
    for (const p of mine) if (clientProtocols.includes(p)) return p;
    const e = new Error('ortak ALPN protokolü yok');
    e.alertDescription = ALERT_DESC.NO_APPLICATION_PROTOCOL;
    throw e;
  },

  // ==========================================================================
  // use_srtp — RFC 5764 §4.1.1
  // ==========================================================================
  /** Sunucu: istemcinin listesinden bizim tercih sıramıza göre profil seç. */
  _selectSrtpProfile(extensions) {
    if (!this.options.srtp.enabled) return null;
    const e = ext.findExt(extensions, EXT_TYPE.USE_SRTP);
    if (!e) return null;
    let offered;
    try { offered = ext.parse_useSrtp(e.data).profiles; }
    catch { return null; }
    for (const p of this.options.srtp.profiles) if (offered.includes(p)) return p;
    const err = new Error('ortak SRTP profili yok');
    err.alertDescription = ALERT_DESC.INSUFFICIENT_SECURITY;
    throw err;
  },

  /** İstemci: sunucunun seçtiği profili doğrula. */
  _acceptSrtpProfile(extensions) {
    const e = ext.findExt(extensions, EXT_TYPE.USE_SRTP);
    if (!e) {
      if (this.options.srtp.enabled) {
        this._log('warn', 'SRTP istendi ama sunucu use_srtp döndürmedi — düz DTLS devam ediyor');
      }
      return null;
    }
    const { profiles } = ext.parse_useSrtp(e.data);
    if (profiles.length !== 1 || !this.options.srtp.profiles.includes(profiles[0])) {
      const err = new Error('sunucu teklif etmediğimiz bir SRTP profili seçti');
      err.alertDescription = ALERT_DESC.ILLEGAL_PARAMETER;
      throw err;
    }
    return profiles[0];
  },

  /** Sunucu tarafında ortak grubu seç: key_share > supported_groups. */
  _pickGroup(chExtensions) {
    const sg = ext.findExt(chExtensions, EXT_TYPE.SUPPORTED_GROUPS);
    const clientGroups = sg ? ext.parse_supportedGroups(sg.data) : [];
    const ks = ext.findExt(chExtensions, EXT_TYPE.KEY_SHARE);
    const ksGroups = ks ? ext.parse_keyShareClient(ks.data).map((e) => e.group) : [];

    for (const g of this.options.groups) {
      if (ksGroups.includes(g) && clientGroups.includes(g)) return { group: g, haveShare: true };
    }
    for (const g of this.options.groups) {
      if (clientGroups.includes(g)) return { group: g, haveShare: false };
    }
    return { group: null, haveShare: false };
  },

  protocolError,
};
