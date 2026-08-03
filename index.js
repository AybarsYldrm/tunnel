'use strict';
/**
 * node-dtls — sıfır bağımlılıklı, saf Node.js DTLS 1.3 / DTLS 1.2 yığını.
 *
 * Üç çalışma kipi aynı çekirdeği paylaşır:
 *   1. Düz DTLS   — güvenli datagram taşıma (mTLS, SNI, ALPN)
 *   2. SRTP       — DTLS-SRTP anahtar takası + SRTP/SRTCP medya koruması (WebRTC)
 *   3. Reliable   — QUIC benzeri kayıp kurtarma katmanı (sıralı veya SIRASIZ)
 *
 * @example Sunucu
 *   const dtls = require('node-dtls');
 *   const server = dtls.createServer({
 *     cert: fs.readFileSync('certs/server.crt'),
 *     key:  fs.readFileSync('certs/server.key'),
 *     ca:   fs.readFileSync('certs/ca.crt'),
 *     requestCert: true,          // mTLS
 *     rejectUnauthorized: true,
 *   });
 *   server.on('secureConnection', (sock) => {
 *     console.log(sock.protocol, sock.cipher, sock.getPeerCertificate().subject);
 *     sock.on('data', (buf) => sock.send(buf));
 *   });
 *   await server.listen(4444);
 *
 * @example İstemci
 *   const sock = await dtls.connect({
 *     host: 'example.com', port: 4444, servername: 'example.com',
 *     ca: fs.readFileSync('certs/ca.crt'),
 *     cert: fs.readFileSync('certs/client.crt'),
 *     key:  fs.readFileSync('certs/client.key'),
 *   });
 *   await sock.send(Buffer.from('merhaba'));
 */

const { DtlsServer } = require('./src/api/server.js');
const { connect } = require('./src/api/client.js');
const { Session } = require('./src/session/session.js');
const { normalizeOptions, createSecureContext } = require('./src/options.js');
const constants = require('./src/constants.js');
const pki = require('./src/crypto/pki.js');
const x509 = require('./src/crypto/x509.js');
const der = require('./src/crypto/der.js');
const revocation = require('./src/crypto/revocation.js');
const { SrtpContext, demuxPacket, createSrtpPair } = require('./src/record/srtp.js');
const { ReliableChannel } = require('./src/reliable/channel.js');
const { LossRecovery, DEFAULT_CONGESTION_CONTROL } = require('./src/reliable/recovery.js');
const {
  createCongestionController, Bbr3Controller, NewRenoController, BBR_DEFAULTS, BBR_STATE,
} = require('./src/reliable/congestion.js');
const { Pacer } = require('./src/reliable/pacing.js');
const cipherSuite = require('./src/crypto/cipher-suite.js');
const { UdpEndpoint } = require('./src/transport/udp.js');
const { createStunBindingResponse } = require('./src/transport/stun.js');
const { setLevel: setLogLevel } = require('./src/logger.js');

/**
 * Yeni bir DTLS sunucusu oluşturur (henüz dinlemeye başlamaz).
 * @param {object} options
 * @param {Function} [onSecureConnection] kısayol: 'secureConnection' dinleyicisi
 */
function createServer(options, onSecureConnection) {
  const server = new DtlsServer(options);
  if (typeof onSecureConnection === 'function') {
    server.on('secureConnection', onSecureConnection);
  }
  return server;
}

module.exports = {
  // Ana API
  createServer,
  connect,
  DtlsServer,
  Session,          // sockets bu sınıfın örnekleridir
  DtlsSocket: Session,

  // Yapılandırma
  createSecureContext,
  normalizeOptions,
  setLogLevel,

  // Alt katman yapı taşları (ileri kullanım)
  SrtpContext,
  createSrtpPair,
  demuxPacket,
  ReliableChannel,
  LossRecovery,       // RFC 9002 kayıp tespiti + takılabilir tıkanıklık denetimi
  UdpEndpoint,
  createStunBindingResponse,

  // Tıkanıklık denetimi (varsayılan BBRv3; NewReno seçilebilir)
  createCongestionController,
  Bbr3Controller,
  NewRenoController,
  Pacer,
  BBR_DEFAULTS,
  BBR_STATE,
  DEFAULT_CONGESTION_CONTROL,

  // Şifreleme paketi seçimi
  cipherSuite,
  CIPHER_POLICY: cipherSuite.CIPHER_POLICY,
  cipherPolicyNames: cipherSuite.cipherPolicyNames,

  // PKI / X.509 / iptal denetimi
  pki,
  x509,               // sertifika uzantılarını okuma (AIA, CDP, KU, EKU, ...)
  der,                // minimal DER kodlayıcı/çözücü
  revocation,         // OCSP (RFC 6960) + CRL (RFC 5280) istemcisi
  RevocationChecker: revocation.RevocationChecker,

  // Sabitler
  constants,
  VERSION: constants.VERSION,
  CIPHER_SUITE: constants.CIPHER_SUITE,
  SRTP_PROFILE: constants.SRTP_PROFILE,
  NAMED_GROUP: constants.NAMED_GROUP,
  ALERT_DESC: constants.ALERT_DESC,
};
