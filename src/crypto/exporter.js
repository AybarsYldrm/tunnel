'use strict';
// Keying Material Exporter — RFC 8446 §7.5 (TLS/DTLS 1.3) ve RFC 5705 (TLS/DTLS 1.2).
//
// DTLS-SRTP (RFC 5764 §4.2) SRTP anahtarlarını buradan çeker. İki protokolde
// türetme tamamen farklıdır; ortak arayüz `exportKeyingMaterial()`.
//
// TLS 1.3:
//   TLS-Exporter(label, context, len) =
//     HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""),
//                       "exporter", Hash(context), len)
//   DTLS 1.3'te HKDF-Expand-Label prefix'i "dtls13"tür (RFC 9147 §5.9).
//
// TLS 1.2 (context YOK):
//   PRF(master_secret, label, client_random || server_random)[0..len]
// TLS 1.2 (context VAR):
//   PRF(master_secret, label, client_random || server_random ||
//       uint16(len(context)) || context)[0..len]

const crypto = require('node:crypto');
const { hkdfExpandLabel, deriveSecret, hashEmpty, DTLS13_LABEL_PREFIX } = require('./hkdf.js');
const { prf12 } = require('./key-schedule.js');
const { SRTP_PROFILE_PARAMS } = require('../constants.js');

const SRTP_EXPORTER_LABEL = 'EXTRACTOR-dtls_srtp'; // RFC 5764 §4.2

/**
 * DTLS 1.3 exporter.
 * @param {string} hash            suite.hash
 * @param {Buffer} exporterSecret  exporter_master_secret
 * @param {string} label
 * @param {Buffer|null} context    null => boş context (Hash("") kullanılır)
 * @param {number} length
 * @param {Buffer} [prefix]        HKDF label prefix (varsayılan "dtls13")
 */
function exporter13(hash, exporterSecret, label, context, length, prefix = DTLS13_LABEL_PREFIX) {
  const base = deriveSecret(hash, exporterSecret, label, hashEmpty(hash), prefix);
  const ctxHash = context && context.length
    ? crypto.createHash(hash).update(context).digest()
    : hashEmpty(hash);
  return hkdfExpandLabel(hash, base, 'exporter', ctxHash, length, prefix);
}

/**
 * DTLS 1.2 exporter (RFC 5705).
 * @param {string} hash          suite.hash
 * @param {Buffer} masterSecret
 * @param {string} label
 * @param {Buffer} clientRandom
 * @param {Buffer} serverRandom
 * @param {Buffer|null} context  null => "no context" (uzunluk alanı hiç eklenmez)
 * @param {number} length
 */
function exporter12(hash, masterSecret, label, clientRandom, serverRandom, context, length) {
  let seed = Buffer.concat([clientRandom, serverRandom]);
  if (context !== null && context !== undefined) {
    const lenBuf = Buffer.allocUnsafe(2);
    lenBuf.writeUInt16BE(context.length, 0);
    seed = Buffer.concat([seed, lenBuf, context]);
  }
  return prf12(hash, masterSecret, label, seed, length);
}

/**
 * Sürümden bağımsız exporter. `ctx` session'ın export bağlamıdır:
 *   { version13:boolean, hash, exporterSecret?, masterSecret?, clientRandom?, serverRandom? }
 */
function exportKeyingMaterial(ctx, label, context, length) {
  if (ctx.version13) {
    return exporter13(ctx.hash, ctx.exporterSecret, label, context ?? null, length);
  }
  return exporter12(ctx.hash, ctx.masterSecret, label,
                    ctx.clientRandom, ctx.serverRandom, context ?? null, length);
}

/**
 * DTLS-SRTP anahtar materyali — RFC 5764 §4.2.
 * Çıktı düzeni:
 *   client_write_SRTP_master_key  | server_write_SRTP_master_key
 *   client_write_SRTP_master_salt | server_write_SRTP_master_salt
 *
 * @param {object} ctx      exportKeyingMaterial bağlamı
 * @param {number} profile  SRTP_PROFILE.*
 */
function exportSrtpKeyingMaterial(ctx, profile) {
  const params = SRTP_PROFILE_PARAMS[profile];
  if (!params) throw new Error(`unknown SRTP profile: 0x${Number(profile).toString(16)}`);
  const { keyLen, saltLen } = params;
  const total = 2 * (keyLen + saltLen);
  // RFC 5764: context yok (TLS 1.2'de "no context", TLS 1.3'te boş context).
  const km = exportKeyingMaterial(ctx, SRTP_EXPORTER_LABEL, null, total);

  let o = 0;
  const clientMasterKey = km.subarray(o, o += keyLen);
  const serverMasterKey = km.subarray(o, o += keyLen);
  const clientMasterSalt = km.subarray(o, o += saltLen);
  const serverMasterSalt = km.subarray(o, o += saltLen);
  return { profile, params, clientMasterKey, serverMasterKey, clientMasterSalt, serverMasterSalt };
}

module.exports = {
  SRTP_EXPORTER_LABEL,
  exporter13, exporter12,
  exportKeyingMaterial, exportSrtpKeyingMaterial,
};
