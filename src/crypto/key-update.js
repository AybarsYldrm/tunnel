'use strict';
// KeyUpdate — RFC 8446 §4.6.3; DTLS'de RFC 9147 §5.8 ekleri.
//
//   enum { update_not_requested(0), update_requested(1) } KeyUpdateRequest;
//   struct { KeyUpdateRequest request_update; } KeyUpdate;
//
// Traffic secret advance:
//   application_traffic_secret_{N+1} = HKDF-Expand-Label(
//       application_traffic_secret_N, "traffic upd", "", Hash.length)
// Ardından yeni key/iv/sn türet. DTLS'de epoch += 1.

const { updateTrafficSecret, trafficKeyIv, snKey } = require('./key-schedule.js');
const { DTLS13_LABEL_PREFIX } = require('./hkdf.js');

function buildKeyUpdate(requestUpdate = 0) {
  return Buffer.from([requestUpdate & 0x01]);
}
function parseKeyUpdate(body) {
  return { requestUpdate: body.readUInt8(0) };
}

function advanceTrafficSecret({ suite, currentSecret }) {
  // DTLS 1.3: AEAD key material derivation uses "dtls13" HKDF prefix
  // (matches wolfSSL Tls13DeriveKey path); the "traffic upd" derivation
  // does as well so the next-epoch traffic_secret stays in sync with peers.
  const newSecret = updateTrafficSecret(suite.hash, currentSecret, suite.hashLen, DTLS13_LABEL_PREFIX);
  return {
    trafficSecret: newSecret,
    ...trafficKeyIv(suite.hash, newSecret, { keyLen: suite.keyLen, ivLen: suite.ivLen }, DTLS13_LABEL_PREFIX),
    sn: snKey(suite.hash, newSecret, suite.sn_keyLen, DTLS13_LABEL_PREFIX),
  };
}

module.exports = { buildKeyUpdate, parseKeyUpdate, advanceTrafficSecret };
