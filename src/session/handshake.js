'use strict';
// Handshake durum makinesi — HER İKİ DTLS SÜRÜMÜ İÇİN TEK DOSYA.
//
//   BÖLÜM 1: DTLS 1.3 — RFC 9147 (+ RFC 8446)
//   BÖLÜM 2: DTLS 1.2 — RFC 6347 + RFC 5246 + RFC 8422 (ECDHE) + RFC 7627 (EMS)
//   BÖLÜM 3: Ortak yardımcılar — sertifika doğrulama, iptal denetimi, zımbalama
//
// DTLS 1.3 uçuşları:
//   1) client → ClientHello
//   2) server → HelloRetryRequest (cookie / grup)            [opsiyonel]
//   3) client → ClientHello (cookie ile)                     [opsiyonel]
//   4) server → ServerHello | {EncryptedExtensions,
//                              [CertificateRequest], Certificate,
//                              CertificateVerify, Finished}
//   5) client → {[Certificate], [CertificateVerify], Finished}
//
// DTLS 1.2 uçuşları:
//   1) client → ClientHello
//   2) server → HelloVerifyRequest                              [cookie]
//   3) client → ClientHello (cookie ile)
//   4) server → ServerHello, Certificate, [CertificateStatus],
//               ServerKeyExchange, [CertificateRequest], ServerHelloDone
//   5) client → [Certificate], ClientKeyExchange, [CertificateVerify],
//               ChangeCipherSpec, Finished
//   6) server → ChangeCipherSpec, Finished
//
// Yalnızca AEAD cipher suite'leri (AES-GCM / ChaCha20-Poly1305) desteklenir;
// CBC tabanlı suite'ler bilinçli olarak dışarıda bırakıldı.
//
// Bu modül Session.prototype'a mixin olarak eklenir; ortak durum session.js'te
// tanımlıdır. İki sürümün tek dosyada durmasının pratik faydası: sertifika
// doğrulama, iptal (OCSP/CRL) ve zımbalama mantığı TEK yerde yaşar — daha önce
// `h13_applyPeerVerification` ve `h12_applyPeerVerification` neredeyse birebir
// aynıydı ve birinde yapılan düzeltme diğerine taşınmayı bekliyordu.

const crypto = require('node:crypto');
const {
  CONTENT_TYPE, VERSION, HS_TYPE, EXT_TYPE, EPOCH, ALERT_DESC, NAMES, CLIENT_CERT_TYPE,
} = require('../constants.js');
const { buildServerHello, parseServerHello, parseClientHello } = require('../handshake/framing.js');
const ext = require('../handshake/extensions.js');
const { getSuite, selectSuite } = require('../crypto/cipher-suite.js');
const ecdhe = require('../crypto/ecdhe.js');
const { Transcript, Transcript12 } = require('../handshake/transcript.js');
const {
  deriveHandshakeStage, deriveApplicationStage,
  masterSecret12, extendedMasterSecret12, keyBlock12, verifyData12,
} = require('../crypto/key-schedule.js');
const { ReplayWindow } = require('../record/replay-window.js');
const msg = require('../handshake/messages.js');
const {
  buildEncryptedExtensions, parseEncryptedExtensions,
  buildCertificate, parseCertificate,
  buildCertificateRequest, parseCertificateRequest, chooseSigScheme13,
  signCertVerify, parseCertVerify, verifyCertVerify,
  buildFinished, verifyFinished,
} = msg;
const { buildKeyUpdate, parseKeyUpdate, advanceTrafficSecret } = require('../crypto/key-update.js');
const { verifyPeer } = require('./verify.js');
const pki = require('../crypto/pki.js');

const CCS_BODY = Buffer.from([0x01]);

function fail(msgText, desc = ALERT_DESC.HANDSHAKE_FAILURE) {
  const e = new Error(msgText);
  e.alertDescription = desc;
  return e;
}

module.exports = {
  // ==========================================================================
  // BÖLÜM 1 — DTLS 1.3
  // ==========================================================================

  h13_handle(m, preparsed) {
    if (this.role === 'server') {
      switch (m.msgType) {
        case HS_TYPE.CLIENT_HELLO:       return this.h13_serverOnCH(m, preparsed);
        case HS_TYPE.CERTIFICATE:        return this.h13_serverOnClientCert(m);
        case HS_TYPE.CERTIFICATE_VERIFY: return this.h13_serverOnClientCV(m);
        case HS_TYPE.FINISHED:           return this.h13_serverOnFinished(m);
        case HS_TYPE.KEY_UPDATE:         return this.h13_onKeyUpdate(m);
        default:
          throw fail(`sunucuda beklenmedik mesaj: ${NAMES.HS_TYPE[m.msgType] || m.msgType}`,
                     ALERT_DESC.UNEXPECTED_MESSAGE);
      }
    }
    switch (m.msgType) {
      case HS_TYPE.SERVER_HELLO:         return this.h13_clientOnSH(m, preparsed);
      case HS_TYPE.ENCRYPTED_EXTENSIONS: return this.h13_clientOnEE(m);
      case HS_TYPE.CERTIFICATE_REQUEST:  return this.h13_clientOnCertReq(m);
      case HS_TYPE.CERTIFICATE:          return this.h13_clientOnCert(m);
      case HS_TYPE.CERTIFICATE_VERIFY:   return this.h13_clientOnCV(m);
      case HS_TYPE.FINISHED:             return this.h13_clientOnFinished(m);
      case HS_TYPE.KEY_UPDATE:           return this.h13_onKeyUpdate(m);
      case HS_TYPE.NEW_SESSION_TICKET:   return; // oturum devamı desteklenmiyor, yoksay
      default:
        throw fail(`istemcide beklenmedik mesaj: ${NAMES.HS_TYPE[m.msgType] || m.msgType}`,
                   ALERT_DESC.UNEXPECTED_MESSAGE);
    }
  },

  // ==========================================================================
  // SUNUCU
  // ==========================================================================
  async h13_serverOnCH(m, preparsed) {
    const ch = preparsed || parseClientHello(m.body);

    // Yinelenen ClientHello (uçuşumuz kaybolmuş) → son uçuşu tekrar gönder.
    if (this.state === 'WAIT_CLIENT_FINISHED' || this.handshakeComplete) {
      return this.retransmitNow();
    }

    const suite = selectSuite(ch.cipherSuites.map((c) => c.value), this.options.cipherSuites13,
                              { tls13: true });
    if (!suite) throw fail('ortak DTLS 1.3 cipher suite yok');
    this.suite = suite;
    this.clientRandom = ch.random;

    // SNI → sertifika bağlamı
    if (this.state === 'WAIT_CH') {
      await this._resolveSecureContext(ext.sniHostname(ch.extensions));
    }
    if (!this.ctx.certDER) throw fail('sunucu sertifikası yapılandırılmadı', ALERT_DESC.INTERNAL_ERROR);

    const cookieExt = ext.findExt(ch.extensions, EXT_TYPE.COOKIE);
    const cookie = cookieExt ? ext.parse_cookie(cookieExt.data) : null;

    if (this.state === 'WAIT_CH') {
      this.ch1Wire = Buffer.from(m.wire);
      const picked = this._pickGroup(ch.extensions);
      if (picked.group === null) throw fail('ortak named_group yok', ALERT_DESC.HANDSHAKE_FAILURE);
      this.chosenGroup = picked.group;

      // Cookie zorunluysa ya da istemci uygun key_share göndermediyse HRR gerekir.
      if ((this.options.cookie && !cookie) || !picked.haveShare) {
        return this.h13_sendHRR(suite, !picked.haveShare);
      }
    } else if (this.state === 'WAIT_CH2') {
      this.ch2Wire = Buffer.from(m.wire);
      if (this.options.cookie) {
        if (!cookie) throw fail('HRR sonrası cookie yok', ALERT_DESC.ILLEGAL_PARAMETER);
        const v = this.cookieMinter.verify(cookie, this.peer, this.ch1Hash);
        if (!v.ok) throw fail(`cookie geçersiz: ${v.reason}`, ALERT_DESC.ILLEGAL_PARAMETER);
      }
    }

    // --- ECDHE
    const ksExt = ext.findExt(ch.extensions, EXT_TYPE.KEY_SHARE);
    if (!ksExt) throw fail('key_share yok', ALERT_DESC.MISSING_EXTENSION);
    const entry = ext.parse_keyShareClient(ksExt.data).find((e) => e.group === this.chosenGroup);
    if (!entry) throw fail('seçilen grup için key_share yok', ALERT_DESC.ILLEGAL_PARAMETER);

    this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);
    const peerPub = ecdhe.importPeerPublic(this.chosenGroup, entry.keyExchange);
    this.sharedSecret = ecdhe.computeSharedSecret(this.keyPair.privateKey, peerPub);

    // --- uzantı müzakereleri
    this.negotiatedSrtpProfile = this._selectSrtpProfile(ch.extensions);
    const alpnExt = ext.findExt(ch.extensions, EXT_TYPE.ALPN);
    this.alpnProtocol = alpnExt ? this._selectAlpn(ext.parse_alpn(alpnExt.data)) : null;
    const sigExt = ext.findExt(ch.extensions, EXT_TYPE.SIGNATURE_ALGORITHMS);
    this.peerSigSchemes = sigExt ? ext.parse_signatureAlgorithms(sigExt.data) : [];
    this.peerWantsOcsp = !!ext.findExt(ch.extensions, EXT_TYPE.STATUS_REQUEST);

    // --- transcript
    this.transcript = new Transcript(suite.hash);
    if (this.hrrWire) {
      this.transcript.replaceWithMessageHash(this.ch1Wire);
      this.transcript.appendDtls(this.hrrWire);
      this.transcript.appendDtls(this.ch2Wire);
    } else {
      this.transcript.appendDtls(this.ch1Wire);
    }

    // --- uçuş 4
    this.beginFlight();

    const shBody = buildServerHello({
      random: crypto.randomBytes(32),
      cipherSuite: suite.id,
      extensions: [
        ext.ext_supportedVersionsServer(VERSION.DTLS_1_3),
        ext.ext_keyShareServer({ group: this.chosenGroup, keyExchange: this.keyPair.publicRaw }),
      ],
    });
    await this.sendHandshakeMessage(HS_TYPE.SERVER_HELLO, shBody);

    // ServerHello transcript'e girdi → handshake anahtarları türetilebilir.
    this.handshakeKeys = deriveHandshakeStage({
      suite, sharedSecret: this.sharedSecret, transcriptCH_SH: this.transcript.digest(),
    });
    this.emit('secrets', { stage: 'handshake', keys: this.handshakeKeys, clientRandom: this.clientRandom });
    this._enterEpoch13(EPOCH.HANDSHAKE);

    // EncryptedExtensions
    const eeExts = [];
    if (this.servername) eeExts.push(ext.ext_serverNameAck());
    if (this.alpnProtocol) eeExts.push(ext.ext_alpn([this.alpnProtocol]));
    if (this.negotiatedSrtpProfile) eeExts.push(ext.ext_useSrtp([this.negotiatedSrtpProfile]));
    await this.sendHandshakeMessage(HS_TYPE.ENCRYPTED_EXTENSIONS,
                                    buildEncryptedExtensions(eeExts), { encrypted: true });

    // mTLS: istemci sertifikası iste
    if (this.options.requestCert) {
      // certificate_request_context boş bırakılır; post-handshake auth yok.
      this.certRequestContext = Buffer.alloc(0);
      await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_REQUEST,
        buildCertificateRequest({
          context: this.certRequestContext,
          extensions: [ext.ext_signatureAlgorithms(this.options.sigSchemes)],
        }), { encrypted: true });
      this.expectClientCert = true;
    }

    // OCSP zımbalama (RFC 8446 §4.4.2.1): yanıt LEAF girdisinin uzantısına gider.
    const staple = await this._resolveOcspStaple();
    const entryExtensions = staple ? [[ext.ext_statusRequestResponse(staple)]] : null;
    if (staple) this._log('debug', 'OCSP yanıtı zımbalandı', { bytes: staple.length });

    await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE,
      buildCertificate({ certChainDER: this.ctx.certDER, entryExtensions }), { encrypted: true });

    const sigScheme = chooseSigScheme13(this.ctx.keyType, this.peerSigSchemes);
    await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_VERIFY,
      signCertVerify({
        role: 'server', privateKey: this.ctx.privateKey, sigScheme,
        transcriptHash: this.transcript.digest(),
      }), { encrypted: true });

    const thBeforeSF = this.transcript.digest();
    await this.sendHandshakeMessage(HS_TYPE.FINISHED, buildFinished({
      hash: suite.hash,
      finishedKey: this.handshakeKeys.serverHandshake.finishedKey,
      transcriptHash: thBeforeSF,
    }), { encrypted: true });

    await this.endFlight();

    // Uygulama anahtarları CH..ServerFinished transcript'i üzerinden türetilir.
    this.appKeys = deriveApplicationStage({
      suite, handshakeSecret: this.handshakeKeys.handshakeSecret,
      transcriptCH_SF: this.transcript.digest(),
    });
    this.emit('secrets', { stage: 'application', keys: this.appKeys, clientRandom: this.clientRandom });
    this.state = 'WAIT_CLIENT_FINISHED';
  },

  async h13_sendHRR(suite, needShare) {
    const th = new Transcript(suite.hash);
    th.appendDtls(this.ch1Wire);
    this.ch1Hash = th.digest();

    const exts = [ext.ext_supportedVersionsServer(VERSION.DTLS_1_3)];
    if (needShare) exts.push(ext.ext_keyShareHRR(this.chosenGroup));
    if (this.options.cookie) {
      exts.push(ext.ext_cookie(this.cookieMinter.mint(this.peer, this.ch1Hash)));
    }

    this.beginFlight();
    this.hrrWire = await this.sendHandshakeMessage(HS_TYPE.SERVER_HELLO,
      buildServerHello({ cipherSuite: suite.id, extensions: exts, isHRR: true }),
      { transcript: false });
    await this.endFlight();
    this.state = 'WAIT_CH2';
  },

  async h13_serverOnClientCert(m) {
    if (!this.expectClientCert) throw fail('beklenmedik istemci sertifikası', ALERT_DESC.UNEXPECTED_MESSAGE);
    const { entries } = parseCertificate(m.body);
    this.transcript.appendDtls(m.wire);
    this.peerCertChainDER = entries.map((e) => e.cert);
    this.clientSentCert = entries.length > 0;
    if (!this.clientSentCert) await this._applyPeerVerification([]);
  },

  async h13_serverOnClientCV(m) {
    if (!this.clientSentCert) throw fail('sertifikasız CertificateVerify', ALERT_DESC.UNEXPECTED_MESSAGE);
    const th = this.transcript.digest();
    const { sigScheme, signature } = parseCertVerify(m.body);
    const chain = await this._applyPeerVerification(this.peerCertChainDER);
    const ok = verifyCertVerify({
      role: 'client', publicKey: chain.cert.publicKey, sigScheme, signature, transcriptHash: th,
    });
    if (!ok) throw fail('istemci CertificateVerify imzası geçersiz', ALERT_DESC.DECRYPT_ERROR);
    this.transcript.appendDtls(m.wire);
  },

  async h13_serverOnFinished(m) {
    if (this.expectClientCert && this.options.requestCert &&
        this.options.rejectUnauthorized && !this.authorized) {
      // Alarm kodu doğrulamanın GERÇEK sebebini yansıtmalı: iptal edilmiş bir
      // sertifikaya "certificate_required" demek, karşı tarafa "sertifika
      // göndermedin" dedirtir ve hatayı teşhis edilemez hâle getirir.
      throw fail(`istemci doğrulaması başarısız: ${this.authorizationError || 'sertifika yok'}`,
                 this._verifyAlert || ALERT_DESC.CERTIFICATE_REQUIRED);
    }
    const th = this.transcript.digest();
    const ok = verifyFinished({
      hash: this.suite.hash,
      finishedKey: this.handshakeKeys.clientHandshake.finishedKey,
      transcriptHash: th, received: m.body,
    });
    if (!ok) throw fail('istemci Finished MAC hatası', ALERT_DESC.DECRYPT_ERROR);

    this._cancelRetransmit();
    this.transcript.appendDtls(m.wire);
    this._enterEpoch13(EPOCH.APPLICATION);
    this._finishHandshake();
    this.flushAcks().catch(() => {});
  },

  // ==========================================================================
  // İSTEMCİ
  // ==========================================================================
  async h13_clientOnSH(m, preparsed) {
    const sh = preparsed || parseServerHello(m.body);
    this._cancelRetransmit();
    this.suite = getSuite(sh.cipherSuite.value);
    this.serverRandom = sh.random;

    if (sh.isHRR) {
      if (this.hrrWire) throw fail('ikinci HelloRetryRequest', ALERT_DESC.UNEXPECTED_MESSAGE);
      this.hrrWire = m.wire;

      const cookieExt = ext.findExt(sh.extensions, EXT_TYPE.COOKIE);
      const ksExt = ext.findExt(sh.extensions, EXT_TYPE.KEY_SHARE);
      const cookie = cookieExt ? ext.parse_cookie(cookieExt.data) : null;

      if (ksExt) {
        const ks = ext.parse_keyShareServer(ksExt.data);
        if (ks.selectedGroup && ks.selectedGroup !== this.chosenGroup) {
          if (!this.options.groups.includes(ks.selectedGroup)) {
            throw fail('HRR desteklemediğimiz bir grup istedi', ALERT_DESC.ILLEGAL_PARAMETER);
          }
          this.chosenGroup = ks.selectedGroup;
          this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);
        }
      }

      this.beginFlight();
      this.ch2Wire = await this.sendHandshakeMessage(HS_TYPE.CLIENT_HELLO,
        this.buildClientHelloBody({ cookie13: cookie }), { transcript: false });
      await this.endFlight();
      this.state = 'WAIT_SERVER_HELLO_2';
      return;
    }

    // --- transcript
    this.transcript = new Transcript(this.suite.hash);
    if (this.hrrWire) {
      this.transcript.replaceWithMessageHash(this.ch1Wire);
      this.transcript.appendDtls(this.hrrWire);
      this.transcript.appendDtls(this.ch2Wire);
    } else {
      this.transcript.appendDtls(this.ch1Wire);
    }
    this.transcript.appendDtls(m.wire);

    // --- ECDHE
    const ksExt = ext.findExt(sh.extensions, EXT_TYPE.KEY_SHARE);
    if (!ksExt) throw fail('ServerHello key_share içermiyor', ALERT_DESC.MISSING_EXTENSION);
    const ks = ext.parse_keyShareServer(ksExt.data);
    if (ks.group !== this.chosenGroup) throw fail('sunucu farklı grup döndürdü', ALERT_DESC.ILLEGAL_PARAMETER);
    const peerPub = ecdhe.importPeerPublic(ks.group, ks.keyExchange);
    this.sharedSecret = ecdhe.computeSharedSecret(this.keyPair.privateKey, peerPub);

    this.handshakeKeys = deriveHandshakeStage({
      suite: this.suite, sharedSecret: this.sharedSecret, transcriptCH_SH: this.transcript.digest(),
    });
    this.emit('secrets', { stage: 'handshake', keys: this.handshakeKeys, clientRandom: this.clientRandom });
    this._enterEpoch13(EPOCH.HANDSHAKE);
    this.state = 'WAIT_EE';
  },

  async h13_clientOnEE(m) {
    const { extensions } = parseEncryptedExtensions(m.body);
    this.transcript.appendDtls(m.wire);

    this.negotiatedSrtpProfile = this._acceptSrtpProfile(extensions);
    const alpnExt = ext.findExt(extensions, EXT_TYPE.ALPN);
    if (alpnExt) this.alpnProtocol = ext.parse_alpn(alpnExt.data)[0] || null;
    this.state = 'WAIT_CERT';
  },

  async h13_clientOnCertReq(m) {
    const { context, extensions } = parseCertificateRequest(m.body);
    this.certRequestContext = Buffer.from(context);
    const sigExt = ext.findExt(extensions, EXT_TYPE.SIGNATURE_ALGORITHMS);
    this.peerSigSchemes = sigExt ? ext.parse_signatureAlgorithms(sigExt.data) : [];
    this.clientAuthRequested = true;
    this.transcript.appendDtls(m.wire);
  },

  async h13_clientOnCert(m) {
    const { entries } = parseCertificate(m.body);
    if (entries.length === 0) throw fail('sunucu boş sertifika gönderdi', ALERT_DESC.BAD_CERTIFICATE);
    this.transcript.appendDtls(m.wire);

    // Zımbalanmış OCSP yanıtı LEAF girdisinin uzantısındadır (RFC 8446 §4.4.2.1);
    // doğrulamadan ÖNCE alınmalı ki iptal denetimi ağ turu atlayabilsin.
    const statusExt = (entries[0].extensions || [])
      .find((e) => e.type === EXT_TYPE.STATUS_REQUEST);
    if (statusExt) {
      this.peerOcspStaple = ext.parse_statusRequestResponse(statusExt.data);
      if (this.peerOcspStaple) this._log('debug', 'zımbalanmış OCSP yanıtı alındı');
    }

    await this._applyPeerVerification(entries.map((e) => e.cert));
    if (this.options.rejectUnauthorized && !this.authorized) {
      throw fail(`sunucu doğrulaması başarısız: ${this.authorizationError}`,
                 this._verifyAlert || ALERT_DESC.BAD_CERTIFICATE);
    }
    this.state = 'WAIT_CV';
  },

  async h13_clientOnCV(m) {
    const th = this.transcript.digest();
    const { sigScheme, signature } = parseCertVerify(m.body);
    const ok = verifyCertVerify({
      role: 'server', publicKey: this.peerCertificateX509.publicKey,
      sigScheme, signature, transcriptHash: th,
    });
    if (!ok) throw fail('sunucu CertificateVerify imzası geçersiz', ALERT_DESC.DECRYPT_ERROR);
    this.transcript.appendDtls(m.wire);
    this.state = 'WAIT_SF';
  },

  async h13_clientOnFinished(m) {
    const thBeforeSF = this.transcript.digest();
    const ok = verifyFinished({
      hash: this.suite.hash,
      finishedKey: this.handshakeKeys.serverHandshake.finishedKey,
      transcriptHash: thBeforeSF, received: m.body,
    });
    if (!ok) throw fail('sunucu Finished MAC hatası', ALERT_DESC.DECRYPT_ERROR);
    this._cancelRetransmit();
    this.transcript.appendDtls(m.wire);

    // Uygulama anahtarları CH..ServerFinished üzerinden.
    const thForApp = this.transcript.digest();

    this.beginFlight();

    // mTLS: sunucu sertifika istediyse gönder (yoksa boş Certificate).
    if (this.clientAuthRequested) {
      const haveCert = !!this.ctx.certDER;
      await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE, buildCertificate({
        certChainDER: haveCert ? this.ctx.certDER : [],
        context: this.certRequestContext,
      }), { encrypted: true });

      if (haveCert) {
        const sigScheme = chooseSigScheme13(this.ctx.keyType, this.peerSigSchemes);
        await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_VERIFY, signCertVerify({
          role: 'client', privateKey: this.ctx.privateKey, sigScheme,
          transcriptHash: this.transcript.digest(),
        }), { encrypted: true });
      } else {
        this._log('warn', 'sunucu istemci sertifikası istedi ama yapılandırılmadı');
      }
    }

    await this.sendHandshakeMessage(HS_TYPE.FINISHED, buildFinished({
      hash: this.suite.hash,
      finishedKey: this.handshakeKeys.clientHandshake.finishedKey,
      transcriptHash: this.transcript.digest(),
    }), { encrypted: true });

    this.appKeys = deriveApplicationStage({
      suite: this.suite, handshakeSecret: this.handshakeKeys.handshakeSecret,
      transcriptCH_SF: thForApp,
    });
    this.emit('secrets', { stage: 'application', keys: this.appKeys, clientRandom: this.clientRandom });

    await this.endFlight();
    this._enterEpoch13(EPOCH.APPLICATION);
    this._finishHandshake();
  },

  /** Kayıt epoch'unu ilerlet ve o epoch için sayaç/replay durumunu kur. */
  _enterEpoch13(epoch) {
    this.sendEpoch = epoch;
    this.sendSeq.set(epoch, 0);
    this.recvEpoch = epoch;
    this.recvLastSeq.set(epoch, -1);
    this.recvReplay.set(epoch, new ReplayWindow(this.options.replayWindow));
  },

  // ==========================================================================
  // KeyUpdate — RFC 8446 §4.6.3 / RFC 9147 §8
  // ==========================================================================
  async requestKeyUpdate(requestPeer = false) {
    if (this.version !== VERSION.DTLS_1_3) {
      throw new Error('KeyUpdate yalnızca DTLS 1.3\'te vardır');
    }
    if (!this.appKeys) throw new Error('uygulama anahtarları henüz yok');
    await this.sendHandshakeMessage(HS_TYPE.KEY_UPDATE, buildKeyUpdate(requestPeer ? 1 : 0),
                                    { encrypted: true, transcript: false });
    this.h13_advanceWriteEpoch();
  },

  h13_advanceWriteEpoch() {
    const k = this.appKeys[this.role + 'Application'];
    this.appKeys[this.role + 'Application'] =
      advanceTrafficSecret({ suite: this.suite, currentSecret: k.trafficSecret });
    this.sendEpoch += 1;
    this.sendSeq.set(this.sendEpoch, 0);
    if (this.sendEpoch - 2 >= 3) this.sendSeq.delete(this.sendEpoch - 2);
    this._log('info', 'gönderme epoch\'u ilerledi', { epoch: this.sendEpoch });
  },

  h13_advanceReadEpoch() {
    const other = this.role === 'client' ? 'server' : 'client';
    const k = this.appKeys[other + 'Application'];
    this.appKeys[other + 'Application'] =
      advanceTrafficSecret({ suite: this.suite, currentSecret: k.trafficSecret });
    this.recvEpoch += 1;
    this.recvLastSeq.set(this.recvEpoch, -1);
    this.recvReplay.set(this.recvEpoch, new ReplayWindow(this.options.replayWindow));
    // Eski epoch durumunu bırak — çok sayıda KeyUpdate yapan uzun ömürlü
    // oturumlarda bu haritalar sınırsız büyürdü. Bir önceki epoch, geciken
    // kayıtlar için tutulur.
    const drop = this.recvEpoch - 2;
    if (drop >= 3) { this.recvLastSeq.delete(drop); this.recvReplay.delete(drop); }
    this._log('info', 'alma epoch\'u ilerledi', { epoch: this.recvEpoch });
  },

  async h13_onKeyUpdate(m) {
    const { requestUpdate } = parseKeyUpdate(m.body);
    this.h13_advanceReadEpoch();
    if (requestUpdate === 1) await this.requestKeyUpdate(false);
    // Handshake sonrası mesajlar da ACK'lenir (RFC 9147 §7); ayrıca bu, bekleyen
    // ACK listesinin birikmesini engeller.
    await this.flushAcks().catch(() => {});
  },

  // ==========================================================================
  // BÖLÜM 2 — DTLS 1.2
  // ==========================================================================

  h12_handle(m, preparsed) {
    if (this.role === 'server') {
      switch (m.msgType) {
        case HS_TYPE.CLIENT_HELLO:       return this.h12_serverOnCH(m, preparsed);
        case HS_TYPE.CERTIFICATE:        return this.h12_serverOnClientCert(m);
        case HS_TYPE.CLIENT_KEY_EXCHANGE:return this.h12_serverOnCKE(m);
        case HS_TYPE.CERTIFICATE_VERIFY: return this.h12_serverOnClientCV(m);
        case HS_TYPE.FINISHED:           return this.h12_serverOnFinished(m);
        default:
          throw fail(`sunucuda beklenmedik 1.2 mesajı: ${NAMES.HS_TYPE[m.msgType] || m.msgType}`,
                     ALERT_DESC.UNEXPECTED_MESSAGE);
      }
    }
    switch (m.msgType) {
      case HS_TYPE.HELLO_VERIFY_REQUEST: return this.h12_clientOnHVR(m);
      case HS_TYPE.SERVER_HELLO:         return this.h12_clientOnSH(m, preparsed);
      case HS_TYPE.CERTIFICATE:          return this.h12_clientOnCert(m);
      case HS_TYPE.CERTIFICATE_STATUS:   return this.h12_clientOnCertStatus(m);
      case HS_TYPE.SERVER_KEY_EXCHANGE:  return this.h12_clientOnSKE(m);
      case HS_TYPE.CERTIFICATE_REQUEST:  return this.h12_clientOnCertReq(m);
      case HS_TYPE.SERVER_HELLO_DONE:    return this.h12_clientOnSHD(m);
      case HS_TYPE.FINISHED:             return this.h12_clientOnFinished(m);
      case HS_TYPE.HELLO_REQUEST:
        // Renegotiation desteklenmiyor — RFC 5746 uyarınca no_renegotiation uyarısı.
        return this.sendAlert(1, ALERT_DESC.NO_RENEGOTIATION, 'renegotiation kapalı');
      default:
        throw fail(`istemcide beklenmedik 1.2 mesajı: ${NAMES.HS_TYPE[m.msgType] || m.msgType}`,
                   ALERT_DESC.UNEXPECTED_MESSAGE);
    }
  },

  // ==========================================================================
  // SUNUCU
  // ==========================================================================
  async h12_serverOnCH(m, preparsed) {
    const ch = preparsed || parseClientHello(m.body);

    if (this.state === 'WAIT_CLIENT_FINISHED' || this.handshakeComplete) {
      return this.retransmitNow();
    }

    // --- cookie takası (RFC 6347 §4.2.1)
    if (this.options.cookie && this.state === 'WAIT_CH') {
      this.ch1Wire = Buffer.from(m.wire);
      this.ch1Hash = crypto.createHash('sha256').update(m.body).digest();
      const cookie = this.cookieMinter.mint(this.peer, this.ch1Hash);
      this.beginFlight();
      await this.sendHandshakeMessage(HS_TYPE.HELLO_VERIFY_REQUEST,
        msg.buildHelloVerifyRequest(cookie), { transcript: false });
      await this.endFlight();
      this.state = 'WAIT_CH2';
      return;
    }
    if (this.options.cookie) {
      if (!ch.legacyCookie || ch.legacyCookie.length === 0) {
        throw fail('cookie bekleniyordu', ALERT_DESC.ILLEGAL_PARAMETER);
      }
      const v = this.cookieMinter.verify(Buffer.from(ch.legacyCookie), this.peer, this.ch1Hash);
      if (!v.ok) throw fail(`cookie geçersiz: ${v.reason}`, ALERT_DESC.ILLEGAL_PARAMETER);
    }

    this.clientRandom = ch.random;
    await this._resolveSecureContext(ext.sniHostname(ch.extensions));
    if (!this.ctx.certDER) throw fail('sunucu sertifikası yok', ALERT_DESC.INTERNAL_ERROR);

    // --- suite seçimi: anahtar tipi suite ailesini belirler
    const suite = selectSuite(ch.cipherSuites.map((c) => c.value), this.options.cipherSuites12,
                              { tls13: false, auth: this.ctx.keyType });
    if (!suite) throw fail('ortak DTLS 1.2 cipher suite yok');
    this.suite = suite;

    // --- grup seçimi (ECDHE)
    const picked = this._pickGroup(ch.extensions);
    if (picked.group === null) throw fail('ortak named_group yok');
    this.chosenGroup = picked.group;
    this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);

    // --- uzantılar
    const sigExt = ext.findExt(ch.extensions, EXT_TYPE.SIGNATURE_ALGORITHMS);
    this.peerSigSchemes = sigExt ? ext.parse_signatureAlgorithms(sigExt.data) : [];
    this.useEms = this.options.extendedMasterSecret &&
                  !!ext.findExt(ch.extensions, EXT_TYPE.EXTENDED_MASTER_SECRET);
    this.negotiatedSrtpProfile = this._selectSrtpProfile(ch.extensions);
    const alpnExt = ext.findExt(ch.extensions, EXT_TYPE.ALPN);
    this.alpnProtocol = alpnExt ? this._selectAlpn(ext.parse_alpn(alpnExt.data)) : null;
    this.peerWantsOcsp = !!ext.findExt(ch.extensions, EXT_TYPE.STATUS_REQUEST);

    this.serverRandom = crypto.randomBytes(32);
    this.transcript = new Transcript12(suite.hash);
    this.transcript.append(m.wire); // CH2 (cookie'li) — CH1 ve HVR transcript'e girmez

    // --- uçuş 4
    this.beginFlight();

    // Zımbalanacak yanıt ServerHello'dan ÖNCE çözülür: status_request'i ancak
    // gerçekten gönderecek yanıtımız varsa onaylamalıyız (RFC 6066 §8).
    const staple12 = await this._resolveOcspStaple();

    const shExts = [];
    if (this.servername) shExts.push(ext.ext_serverNameAck());
    if (this.useEms) shExts.push(ext.ext_extendedMasterSecret());
    shExts.push(ext.ext_renegotiationInfo());
    shExts.push(ext.ext_ecPointFormats([0x00]));
    if (this.alpnProtocol) shExts.push(ext.ext_alpn([this.alpnProtocol]));
    if (this.negotiatedSrtpProfile) shExts.push(ext.ext_useSrtp([this.negotiatedSrtpProfile]));
    if (staple12) shExts.push(ext.ext_statusRequestAck());

    await this.sendHandshakeMessage(HS_TYPE.SERVER_HELLO, buildServerHello({
      random: this.serverRandom, cipherSuite: suite.id, extensions: shExts,
    }));

    await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE,
      msg.buildCertificate12(this.ctx.certDER));

    // CertificateStatus, RFC 6066 §8 uyarınca Certificate'i HEMEN izler.
    if (staple12) {
      this._log('debug', 'OCSP yanıtı zımbalandı (1.2)', { bytes: staple12.length });
      await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_STATUS,
        msg.buildCertificateStatus(staple12));
    }

    const sigScheme = msg.chooseSigScheme12(this.ctx.keyType, this.peerSigSchemes);
    await this.sendHandshakeMessage(HS_TYPE.SERVER_KEY_EXCHANGE, msg.buildServerKeyExchange({
      group: this.chosenGroup, publicRaw: this.keyPair.publicRaw,
      sigScheme, privateKey: this.ctx.privateKey,
      clientRandom: this.clientRandom, serverRandom: this.serverRandom,
    }));

    if (this.options.requestCert) {
      this.expectClientCert = true;
      await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_REQUEST,
        msg.buildCertificateRequest12({
          certTypes: [CLIENT_CERT_TYPE.ECDSA_SIGN, CLIENT_CERT_TYPE.RSA_SIGN],
          sigSchemes: this.options.sigSchemes,
        }));
    }

    await this.sendHandshakeMessage(HS_TYPE.SERVER_HELLO_DONE, msg.SERVER_HELLO_DONE_BODY);
    await this.endFlight();
    this.state = 'WAIT_CKE';
  },

  async h12_serverOnClientCert(m) {
    if (!this.expectClientCert) throw fail('beklenmedik istemci sertifikası', ALERT_DESC.UNEXPECTED_MESSAGE);
    this.transcript.append(m.wire);
    const { entries } = msg.parseCertificate12(m.body);
    this.peerCertChainDER = entries.map((e) => e.cert);
    this.clientSentCert = entries.length > 0;
    await this._applyPeerVerification(this.peerCertChainDER);
  },

  async h12_serverOnCKE(m) {
    const { publicRaw } = msg.parseClientKeyExchange(m.body);
    // CertificateVerify, CKE dahil tüm mesajlar üzerinden imzalanır.
    const beforeCke = this.transcript.rawBytes();
    this.transcript.append(m.wire);
    this._cvHandshakeMessages = Buffer.concat([beforeCke, m.wire]);

    const peerPub = ecdhe.importPeerPublic(this.chosenGroup, publicRaw);
    const pms = ecdhe.computeSharedSecret(this.keyPair.privateKey, peerPub);
    this.h12_deriveKeys(pms);
    this.state = this.clientSentCert ? 'WAIT_CV' : 'WAIT_CLIENT_CCS';
  },

  async h12_serverOnClientCV(m) {
    if (!this.clientSentCert) throw fail('sertifikasız CertificateVerify', ALERT_DESC.UNEXPECTED_MESSAGE);
    const { sigScheme, signature } = msg.parseCertificateVerify12(m.body);
    const ok = msg.verifyCertificateVerify12({
      publicKey: this.peerCertificateX509.publicKey, sigScheme, signature,
      handshakeMessages: this._cvHandshakeMessages,
    });
    if (!ok) throw fail('istemci CertificateVerify imzası geçersiz', ALERT_DESC.DECRYPT_ERROR);
    this.transcript.append(m.wire);
    this.state = 'WAIT_CLIENT_CCS';
  },

  async h12_serverOnFinished(m) {
    if (!this.recvCipherActive) throw fail('Finished şifresiz geldi', ALERT_DESC.UNEXPECTED_MESSAGE);
    if (this.options.requestCert && this.options.rejectUnauthorized && !this.authorized) {
      // Alarm kodu doğrulamanın GERÇEK sebebini yansıtmalı: iptal edilmiş bir
      // sertifikaya "certificate_required" demek, karşı tarafa "sertifika
      // göndermedin" dedirtir ve hatayı teşhis edilemez hâle getirir.
      throw fail(`istemci doğrulaması başarısız: ${this.authorizationError || 'sertifika yok'}`,
                 this._verifyAlert || ALERT_DESC.CERTIFICATE_REQUIRED);
    }

    const expected = verifyData12({
      hash: this.suite.hash, masterSecret: this.masterSecret,
      label: 'client finished', handshakeHash: this.transcript.digest(),
    });
    if (expected.length !== m.body.length || !crypto.timingSafeEqual(expected, m.body)) {
      throw fail('istemci Finished doğrulanamadı', ALERT_DESC.DECRYPT_ERROR);
    }
    this._cancelRetransmit();
    this.transcript.append(m.wire);

    // --- uçuş 6: CCS + Finished
    this.beginFlight();
    await this.sendPlaintextRecord(CONTENT_TYPE.CHANGE_CIPHER_SPEC, CCS_BODY);
    this.sendEpoch = 1;
    this.sendSeq.set(1, 0);
    await this.sendHandshakeMessage(HS_TYPE.FINISHED, verifyData12({
      hash: this.suite.hash, masterSecret: this.masterSecret,
      label: 'server finished', handshakeHash: this.transcript.digest(),
    }), { encrypted: true });
    await this.endFlight({ arm: false });

    this.transcript.releaseRaw();
    this._finishHandshake();
  },

  // ==========================================================================
  // İSTEMCİ
  // ==========================================================================
  async h12_clientOnHVR(m) {
    const { cookie } = msg.parseHelloVerifyRequest(m.body);
    this._cancelRetransmit();
    this.beginFlight();
    this.ch2Wire = await this.sendHandshakeMessage(HS_TYPE.CLIENT_HELLO,
      this.buildClientHelloBody({ legacyCookie: Buffer.from(cookie) }), { transcript: false });
    await this.endFlight();
    this.state = 'WAIT_SERVER_HELLO';
  },

  async h12_clientOnSH(m, preparsed) {
    const sh = preparsed || parseServerHello(m.body);
    this._cancelRetransmit();
    this.suite = getSuite(sh.cipherSuite.value);
    if (this.suite.tls13) throw fail('sunucu DTLS 1.2\'de TLS 1.3 suite\'i seçti', ALERT_DESC.ILLEGAL_PARAMETER);
    this.serverRandom = sh.random;

    this.useEms = this.options.extendedMasterSecret &&
                  !!ext.findExt(sh.extensions, EXT_TYPE.EXTENDED_MASTER_SECRET);
    if (this.options.extendedMasterSecret && !this.useEms) {
      this._log('warn', 'sunucu extended_master_secret desteklemiyor (RFC 7627)');
    }
    this.negotiatedSrtpProfile = this._acceptSrtpProfile(sh.extensions);
    const alpnExt = ext.findExt(sh.extensions, EXT_TYPE.ALPN);
    if (alpnExt) this.alpnProtocol = ext.parse_alpn(alpnExt.data)[0] || null;
    // Sunucu status_request'i onayladıysa Certificate'in ardından bir
    // CertificateStatus gelecek; sertifika doğrulaması o mesaja kadar bekler ki
    // iptal denetimi zımbalanmış yanıtı kullanabilsin.
    this.expectCertStatus = !!ext.findExt(sh.extensions, EXT_TYPE.STATUS_REQUEST);

    // Transcript CH2 (varsa) ile başlar; HVR ve CH1 dahil edilmez.
    this.transcript = new Transcript12(this.suite.hash);
    this.transcript.append(this.ch2Wire || this.ch1Wire);
    this.transcript.append(m.wire);
    this.state = 'WAIT_CERT';
  },

  async h12_clientOnCert(m) {
    this.transcript.append(m.wire);
    const { entries } = msg.parseCertificate12(m.body);
    if (entries.length === 0) throw fail('sunucu boş sertifika gönderdi', ALERT_DESC.BAD_CERTIFICATE);
    this._pendingServerChainDER = entries.map((e) => e.cert);
    if (!this.expectCertStatus) await this._h12_verifyServerCert();
    this.state = this.expectCertStatus ? 'WAIT_CERT_STATUS' : 'WAIT_SKE';
  },

  /** CertificateStatus — RFC 6066 §8: zımbalanmış OCSP yanıtı. */
  async h12_clientOnCertStatus(m) {
    this.transcript.append(m.wire);
    try {
      const { statusType, response } = msg.parseCertificateStatus(m.body);
      if (statusType === ext.STATUS_TYPE_OCSP && response.length) {
        this.peerOcspStaple = Buffer.from(response);
        this._log('debug', 'zımbalanmış OCSP yanıtı alındı (1.2)');
      }
    } catch (e) {
      // Bozuk zımba, sertifikayı geçersiz kılmaz — iptal denetimi ağdan devam eder.
      this._log('warn', 'CertificateStatus çözümlenemedi', { err: e.message });
    }
    await this._h12_verifyServerCert();
    this.state = 'WAIT_SKE';
  },

  /** Sunucu sertifikasını (henüz doğrulanmadıysa) doğrular. */
  async _h12_verifyServerCert() {
    if (!this._pendingServerChainDER) return;
    const chainDER = this._pendingServerChainDER;
    this._pendingServerChainDER = null;
    const res = await this._applyPeerVerification(chainDER);
    if (this.options.rejectUnauthorized && !res.authorized) {
      throw fail(`sunucu doğrulaması başarısız: ${res.error}`,
                 res.alert || ALERT_DESC.BAD_CERTIFICATE);
    }
  },

  async h12_clientOnSKE(m) {
    // Sunucu status_request'i onayladı ama CertificateStatus göndermediyse
    // (uyumsuz uygulama) doğrulamayı burada tamamla.
    await this._h12_verifyServerCert();
    this.transcript.append(m.wire);
    const ske = msg.parseServerKeyExchange(m.body);
    if (!this.peerCertificateX509) throw fail('ServerKeyExchange sertifikadan önce geldi', ALERT_DESC.UNEXPECTED_MESSAGE);

    const ok = msg.verifyServerKeyExchange({
      publicKey: this.peerCertificateX509.publicKey,
      clientRandom: this.clientRandom, serverRandom: this.serverRandom,
      params: ske.params, sigScheme: ske.sigScheme, signature: ske.signature,
    });
    if (!ok) throw fail('ServerKeyExchange imzası geçersiz', ALERT_DESC.DECRYPT_ERROR);
    if (!this.options.groups.includes(ske.group)) {
      throw fail('sunucu desteklemediğimiz bir grup seçti', ALERT_DESC.ILLEGAL_PARAMETER);
    }

    this.chosenGroup = ske.group;
    this.serverEcdhPublic = Buffer.from(ske.publicRaw);
    this.state = 'WAIT_SHD';
  },

  async h12_clientOnCertReq(m) {
    this.transcript.append(m.wire);
    const cr = msg.parseCertificateRequest12(m.body);
    this.peerSigSchemes = cr.sigSchemes;
    this.clientAuthRequested = true;
  },

  async h12_clientOnSHD(m) {
    this.transcript.append(m.wire);
    this._cancelRetransmit();
    if (!this.serverEcdhPublic) throw fail('ServerKeyExchange gelmedi', ALERT_DESC.UNEXPECTED_MESSAGE);

    this.beginFlight();

    // --- Certificate (mTLS)
    const haveCert = this.clientAuthRequested && !!this.ctx.certDER;
    if (this.clientAuthRequested) {
      await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE,
        msg.buildCertificate12(haveCert ? this.ctx.certDER : []));
      if (!haveCert) this._log('warn', 'sunucu istemci sertifikası istedi ama yapılandırılmadı');
    }

    // --- ClientKeyExchange
    this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);
    const beforeCke = this.transcript.rawBytes();
    const ckeWire = await this.sendHandshakeMessage(HS_TYPE.CLIENT_KEY_EXCHANGE,
      msg.buildClientKeyExchange(this.keyPair.publicRaw));

    const peerPub = ecdhe.importPeerPublic(this.chosenGroup, this.serverEcdhPublic);
    const pms = ecdhe.computeSharedSecret(this.keyPair.privateKey, peerPub);
    this.h12_deriveKeys(pms);

    // --- CertificateVerify (CKE dahil tüm handshake baytları üzerinden)
    if (haveCert) {
      const sigScheme = msg.chooseSigScheme12(this.ctx.keyType, this.peerSigSchemes);
      await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_VERIFY, msg.buildCertificateVerify12({
        sigScheme, privateKey: this.ctx.privateKey,
        handshakeMessages: Buffer.concat([beforeCke, ckeWire]),
      }));
    }

    // --- ChangeCipherSpec + Finished
    await this.sendPlaintextRecord(CONTENT_TYPE.CHANGE_CIPHER_SPEC, CCS_BODY);
    this.sendEpoch = 1;
    this.sendSeq.set(1, 0);
    await this.sendHandshakeMessage(HS_TYPE.FINISHED, verifyData12({
      hash: this.suite.hash, masterSecret: this.masterSecret,
      label: 'client finished', handshakeHash: this.transcript.digest(),
    }), { encrypted: true });

    await this.endFlight();
    this.state = 'WAIT_SERVER_FINISHED';
  },

  async h12_clientOnFinished(m) {
    if (!this.recvCipherActive) throw fail('Finished şifresiz geldi', ALERT_DESC.UNEXPECTED_MESSAGE);
    const expected = verifyData12({
      hash: this.suite.hash, masterSecret: this.masterSecret,
      label: 'server finished', handshakeHash: this.transcript.digest(),
    });
    if (expected.length !== m.body.length || !crypto.timingSafeEqual(expected, m.body)) {
      throw fail('sunucu Finished doğrulanamadı', ALERT_DESC.DECRYPT_ERROR);
    }
    this._cancelRetransmit();
    this.transcript.releaseRaw();
    this._finishHandshake();
  },

  // ==========================================================================
  // Ortak
  // ==========================================================================
  h12_deriveKeys(preMasterSecret) {
    const suite = this.suite;
    this.masterSecret = this.useEms
      ? extendedMasterSecret12({
          hash: suite.hash, preMasterSecret, sessionHash: this.transcript.digest(),
        })
      : masterSecret12({
          hash: suite.hash, preMasterSecret,
          clientRandom: this.clientRandom, serverRandom: this.serverRandom,
        });

    this.keys12 = keyBlock12({
      suite, masterSecret: this.masterSecret,
      clientRandom: this.clientRandom, serverRandom: this.serverRandom,
    });
    this.emit('secrets', {
      stage: 'application12', masterSecret: this.masterSecret, clientRandom: this.clientRandom,
    });
  },

  /** Karşı taraf ChangeCipherSpec gönderdi — alma yönünü şifreli moda al. */
  h12_onChangeCipherSpec() {
    if (!this.keys12) {
      this._log('warn', 'anahtarlar hazır değilken CCS geldi');
      return;
    }
    this.recvCipherActive = true;
    this.recvEpoch = 1;
    this.recvReplay.set(1, new ReplayWindow(this.options.replayWindow));
    this._log('debug', 'alma yönü şifreli moda geçti (epoch 1)');
  },

  // ==========================================================================
  // BÖLÜM 3 — Ortak yardımcılar (her iki sürüm)
  // ==========================================================================

  /**
   * Karşı tarafın sertifika zincirini doğrular ve sonucu oturuma yazar.
   *
   * ASENKRONDUR: `revocation` açıkken OCSP/CRL ağ turu gerekebilir. Zımbalanmış
   * bir yanıt (`this.peerOcspStaple`) varsa o kullanılır ve tur atlanır.
   *
   * @returns {Promise<object>} verifyPeer sonucu
   */
  async _applyPeerVerification(chainDER) {
    const res = await verifyPeer({
      chainDER,
      opts: { ...this.options, secureContext: this.ctx },
      role: this.role,
      servername: this.servername,
      staple: this.peerOcspStaple || null,
    });

    this.authorized = res.authorized;
    this.authorizationError = res.error;
    this._verifyAlert = res.alert;
    this.peerCertificateX509 = res.cert;
    this.peerCertificateChain = res.chain;
    this.peerCertificatePath = res.path;
    this.peerRevocation = res.revocation;
    this.peerCertificate = res.cert ? pki.summarizeCertificate(res.cert) : null;

    if (res.revocation && res.revocation.results.length) {
      this._log('info', 'iptal denetimi tamamlandı', {
        methods: res.revocation.results.map((r) => `${r.method}:${r.status}`).join(','),
      });
    }
    if (res.cert) this.emit('peer-certificate', this.peerCertificate, res.chain, res);
    return res;
  },

  // Eski adlar — dışarıdan çağıran kod kırılmasın.
  h13_applyPeerVerification(chainDER) { return this._applyPeerVerification(chainDER); },
  h12_applyPeerVerification(chainDER) { return this._applyPeerVerification(chainDER); },

  /**
   * Sunucu: zımbalanacak OCSP yanıtını çözer. `ocspResponse` bir Buffer ya da
   * (secureContext) => Buffer|Promise<Buffer> olabilir; ikincisi yanıtın
   * süresi dolduğunda tazelenmesini mümkün kılar.
   * @returns {Promise<Buffer|null>}
   */
  async _resolveOcspStaple() {
    if (!this.peerWantsOcsp) return null;
    const src = this.ctx.ocspResponse;
    if (!src) return null;
    try {
      const val = typeof src === 'function' ? await src(this.ctx, this) : src;
      if (!val || !Buffer.isBuffer(val) || val.length === 0) return null;
      return val;
    } catch (e) {
      // Zımbalama en iyi çaba işidir; başarısızlığı handshake'i düşürmemeli.
      this._log('warn', 'OCSP yanıtı hazırlanamadı, zımbalanmadan devam', { err: e.message });
      return null;
    }
  },
};
