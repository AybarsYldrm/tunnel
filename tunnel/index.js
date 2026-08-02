'use strict';
// @fitfak/dtls — tünel katmanı.
//
// DTLS 1.3 + mTLS üzerine kurulu, cloudflared benzeri bir ters proxy: port
// açamayan bir istemci yerel bir servisini bu sunucu üzerinden dış dünyaya
// yayınlar. Kimlik trust.fitfak.net'in verdiği sertifikadan, yetki
// session.fitfak.net'ten gelir.
//
//   const { startTunnelServer } = require('@fitfak/dtls/tunnel');
//   const server = await startTunnelServer();
//
//   const { startTunnelClient } = require('@fitfak/dtls/tunnel');
//   const client = await startTunnelClient({ host, port, binds: [...] });

const constants = require('./src/protocol/constants.js');
const frames = require('./src/protocol/frames.js');
const codec = require('./src/protocol/codec.js');

module.exports = {
  // ---- sunucu ----
  get TunnelServer() { return require('./src/server/index.js').TunnelServer; },
  get startTunnelServer() { return require('./src/server/index.js').startTunnelServer; },
  get loadServerConfig() { return require('./src/server/config.js').loadServerConfig; },
  get Tunnel() { return require('./src/server/tunnel.js').Tunnel; },
  get PortAllocator() { return require('./src/server/ports.js').PortAllocator; },
  get Guard() { return require('./src/server/guard.js').Guard; },
  get createStore() { return require('./src/server/store.js').createStore; },
  get tunnelSchema() { return require('./src/server/schema.js'); },
  get AdminServer() { return require('./src/server/admin/server.js').AdminServer; },

  // ---- istemci ----
  get TunnelClient() { return require('./src/client/index.js').TunnelClient; },
  get startTunnelClient() { return require('./src/client/index.js').startTunnelClient; },
  get ensureIdentity() { return require('./src/client/identity.js').ensureIdentity; },
  get deviceLogin() { return require('./src/client/identity.js').deviceLogin; },
  get createCsr() { return require('./src/client/csr.js').createCsr; },
  get generateKeyPair() { return require('./src/client/csr.js').generateKeyPair; },

  // ---- ortak yapı taşları ----
  get Mux() { return require('./src/common/mux.js').Mux; },
  get bindSocketToStream() { return require('./src/common/pipe.js').bindSocketToStream; },
  get loadTrustAnchor() { return require('./src/common/trust.js').loadTrustAnchor; },
  get TokenBucket() { return require('./src/common/rate.js').TokenBucket; },
  get RateMeter() { return require('./src/common/rate.js').RateMeter; },

  // ---- protokol ----
  constants,
  frames,
  codec,
  PROTOCOL_VERSION: constants.PROTOCOL_VERSION,
};
