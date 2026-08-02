'use strict';
// TLS/DTLS Extensions — RFC 8446 §4.2, RFC 6066, RFC 5764, RFC 7301, RFC 7627, RFC 8422.
//
// Wrapper format:
//   uint16 extension_type
//   opaque extension_data<0..2^16-1>
//
// extensions<8..2^16-1> container: 2 baytlık toplam uzunluk + arka arkaya uzantılar.

const { EXT_TYPE, VERSION, NAMED_GROUP, SIG_SCHEME, NAMES } = require('../constants.js');

function encodeExtension(type, data) {
  const out = Buffer.allocUnsafe(4 + data.length);
  out.writeUInt16BE(type, 0);
  out.writeUInt16BE(data.length, 2);
  data.copy(out, 4);
  return out;
}

function encodeExtensions(exts) {
  let total = 0;
  for (const e of exts) total += e.length;
  const out = Buffer.allocUnsafe(2 + total);
  out.writeUInt16BE(total, 0);
  let o = 2;
  for (const e of exts) { e.copy(out, o); o += e.length; }
  return out;
}

function decodeExtensions(buf, offset) {
  if (offset >= buf.length) return { extensions: [], bytesConsumed: 0 }; // uzantısız Hello
  const totalLen = buf.readUInt16BE(offset);
  const start = offset + 2;
  const end = start + totalLen;
  if (end > buf.length) throw new Error(`extensions truncated: need ${totalLen}`);
  const extensions = [];
  let o = start;
  while (o < end) {
    if (o + 4 > end) throw new Error('extension header truncated');
    const type = buf.readUInt16BE(o);
    const dataLen = buf.readUInt16BE(o + 2);
    const dataStart = o + 4;
    const dataEnd = dataStart + dataLen;
    if (dataEnd > end) throw new Error(`extension data truncated (type=${type})`);
    extensions.push({
      type,
      typeName: NAMES.EXT_TYPE[type] || `UNKNOWN(${type})`,
      data: buf.subarray(dataStart, dataEnd),
    });
    o = dataEnd;
  }
  return { extensions, bytesConsumed: 2 + totalLen };
}

/** Uzantı listesinde tip araması — hot path'te tekrar tekrar find() yapmamak için. */
function findExt(extensions, type) {
  for (let i = 0; i < extensions.length; i++) if (extensions[i].type === type) return extensions[i];
  return null;
}

// ============================================================================
// Builders
// ============================================================================

// supported_versions — client: ProtocolVersion versions<2..254>
function ext_supportedVersionsClient(versions = [VERSION.DTLS_1_3]) {
  const listLen = versions.length * 2;
  const body = Buffer.allocUnsafe(1 + listLen);
  body.writeUInt8(listLen, 0);
  versions.forEach((v, i) => body.writeUInt16BE(v, 1 + i * 2));
  return encodeExtension(EXT_TYPE.SUPPORTED_VERSIONS, body);
}

// server: tek seçilmiş sürüm
function ext_supportedVersionsServer(version = VERSION.DTLS_1_3) {
  const body = Buffer.allocUnsafe(2);
  body.writeUInt16BE(version, 0);
  return encodeExtension(EXT_TYPE.SUPPORTED_VERSIONS, body);
}

function u16List(type, values) {
  const body = Buffer.allocUnsafe(2 + values.length * 2);
  body.writeUInt16BE(values.length * 2, 0);
  values.forEach((v, i) => body.writeUInt16BE(v, 2 + i * 2));
  return encodeExtension(type, body);
}

function ext_supportedGroups(groups = [NAMED_GROUP.X25519, NAMED_GROUP.SECP256R1]) {
  return u16List(EXT_TYPE.SUPPORTED_GROUPS, groups);
}

function ext_signatureAlgorithms(schemes = [
  SIG_SCHEME.ECDSA_SECP256R1_SHA256,
  SIG_SCHEME.RSA_PSS_RSAE_SHA256,
  SIG_SCHEME.ED25519,
  SIG_SCHEME.RSA_PKCS1_SHA256,
]) {
  return u16List(EXT_TYPE.SIGNATURE_ALGORITHMS, schemes);
}

// ec_point_formats — RFC 8422 §5.1.2. TLS 1.2'de bazı peer'lar bunu bekler.
// Yalnızca "uncompressed" (0) desteklenir.
function ext_ecPointFormats(formats = [0x00]) {
  const body = Buffer.allocUnsafe(1 + formats.length);
  body.writeUInt8(formats.length, 0);
  formats.forEach((f, i) => body.writeUInt8(f, 1 + i));
  return encodeExtension(EXT_TYPE.EC_POINT_FORMATS, body);
}

// extended_master_secret — RFC 7627. Gövdesi boş.
function ext_extendedMasterSecret() {
  return encodeExtension(EXT_TYPE.EXTENDED_MASTER_SECRET, Buffer.alloc(0));
}

// renegotiation_info — RFC 5746. İlk handshake'te boş renegotiated_connection.
// Renegotiation'ı hiç desteklemiyoruz; bunu göndermek "secure renegotiation"
// bekleyen 1.2 peer'ları ile uyumluluk sağlar.
function ext_renegotiationInfo(verifyData = Buffer.alloc(0)) {
  const body = Buffer.allocUnsafe(1 + verifyData.length);
  body.writeUInt8(verifyData.length, 0);
  verifyData.copy(body, 1);
  return encodeExtension(EXT_TYPE.RENEGOTIATION_INFO, body);
}

// ---------------------------------------------------------------------------
// status_request (OCSP zımbalama) — RFC 6066 §8, RFC 8446 §4.4.2.1
// ---------------------------------------------------------------------------
//   struct { CertificateStatusType status_type;    // ocsp(1)
//            OCSPStatusRequest request; } CertificateStatusRequest;
//   OCSPStatusRequest: ResponderID responder_id_list<0..2^16-1>;
//                      Extensions request_extensions;
//
// Zımbalama, iptal denetiminin ağ turunu ORTADAN KALDIRIR: sunucu kendi OCSP
// yanıtını önceden alıp handshake içinde taşır. İstemci böylece OCSP
// responder'ına hiç bağlanmadan iptal durumunu öğrenir — hem daha hızlı hem
// de gizlilik açısından daha iyi (responder istemcinin kimi ziyaret ettiğini
// görmez).
const STATUS_TYPE_OCSP = 1;

/** İstemci: "OCSP yanıtı zımbalayabilirsin" — boş responder listesi + boş uzantı. */
function ext_statusRequest() {
  const body = Buffer.from([STATUS_TYPE_OCSP, 0x00, 0x00, 0x00, 0x00]);
  return encodeExtension(EXT_TYPE.STATUS_REQUEST, body);
}

/** Sunucu (DTLS 1.2 ServerHello): "zımbalayacağım" — gövde BOŞ olmalıdır. */
function ext_statusRequestAck() {
  return encodeExtension(EXT_TYPE.STATUS_REQUEST, Buffer.alloc(0));
}

/**
 * Sunucu (DTLS 1.3 CertificateEntry): yanıtın kendisi.
 * Gövde = CertificateStatus yapısı: status_type(1) || uint24 len || response.
 */
function ext_statusRequestResponse(ocspResponseDer) {
  const body = Buffer.allocUnsafe(4 + ocspResponseDer.length);
  body.writeUInt8(STATUS_TYPE_OCSP, 0);
  body.writeUIntBE(ocspResponseDer.length, 1, 3);
  ocspResponseDer.copy(body, 4);
  return encodeExtension(EXT_TYPE.STATUS_REQUEST, body);
}

/** DTLS 1.3 CertificateEntry status_request gövdesinden OCSP DER'ini çıkarır. */
function parse_statusRequestResponse(data) {
  if (!data || data.length < 4) return null;
  if (data.readUInt8(0) !== STATUS_TYPE_OCSP) return null;
  const len = data.readUIntBE(1, 3);
  if (4 + len > data.length) return null;
  return data.subarray(4, 4 + len);
}

/** İstemcinin status_request gövdesi geçerli mi? (boş gövde de kabul edilir) */
function parse_statusRequest(data) {
  if (!data || data.length === 0) return { statusType: STATUS_TYPE_OCSP };
  return { statusType: data.readUInt8(0) };
}

// key_share (client) — KeyShareEntry client_shares<0..2^16-1>
function ext_keyShareClient(entries /* [{ group, keyExchange: Buffer }] */) {
  let listLen = 0;
  for (const e of entries) listLen += 4 + e.keyExchange.length;
  const body = Buffer.allocUnsafe(2 + listLen);
  body.writeUInt16BE(listLen, 0);
  let o = 2;
  for (const { group, keyExchange } of entries) {
    body.writeUInt16BE(group, o); o += 2;
    body.writeUInt16BE(keyExchange.length, o); o += 2;
    keyExchange.copy(body, o); o += keyExchange.length;
  }
  return encodeExtension(EXT_TYPE.KEY_SHARE, body);
}

function ext_keyShareServer({ group, keyExchange }) {
  const body = Buffer.allocUnsafe(4 + keyExchange.length);
  body.writeUInt16BE(group, 0);
  body.writeUInt16BE(keyExchange.length, 2);
  keyExchange.copy(body, 4);
  return encodeExtension(EXT_TYPE.KEY_SHARE, body);
}

// key_share (HRR) — sadece selected_group (RFC 8446 §4.2.8)
function ext_keyShareHRR(group) {
  const body = Buffer.allocUnsafe(2);
  body.writeUInt16BE(group, 0);
  return encodeExtension(EXT_TYPE.KEY_SHARE, body);
}

// use_srtp — RFC 5764 §4.1.1
//   struct { SRTPProtectionProfiles profiles; opaque srtp_mki<0..255>; }
function ext_useSrtp(profiles, mki = null) {
  const listLen = profiles.length * 2;
  const mkiLen = mki ? mki.length : 0;
  const body = Buffer.allocUnsafe(2 + listLen + 1 + mkiLen);
  body.writeUInt16BE(listLen, 0);
  profiles.forEach((p, i) => body.writeUInt16BE(p, 2 + i * 2));
  body.writeUInt8(mkiLen, 2 + listLen);
  if (mki) mki.copy(body, 3 + listLen);
  return encodeExtension(EXT_TYPE.USE_SRTP, body);
}

function parse_useSrtp(data) {
  if (data.length < 3) throw new Error('use_srtp truncated');
  const listLen = data.readUInt16BE(0);
  if (listLen % 2 || 2 + listLen + 1 > data.length) throw new Error('use_srtp malformed');
  const profiles = [];
  for (let i = 0; i < listLen; i += 2) profiles.push(data.readUInt16BE(2 + i));
  const mkiLen = data.readUInt8(2 + listLen);
  const mki = mkiLen ? data.subarray(3 + listLen, 3 + listLen + mkiLen) : null;
  return { profiles, mki };
}

// application_layer_protocol_negotiation — RFC 7301
function ext_alpn(protocols) {
  let listLen = 0;
  for (const p of protocols) listLen += 1 + Buffer.byteLength(p);
  const body = Buffer.allocUnsafe(2 + listLen);
  body.writeUInt16BE(listLen, 0);
  let o = 2;
  for (const p of protocols) {
    const b = Buffer.from(p, 'utf8');
    body.writeUInt8(b.length, o); o += 1;
    b.copy(body, o); o += b.length;
  }
  return encodeExtension(EXT_TYPE.ALPN, body);
}

function parse_alpn(data) {
  const listLen = data.readUInt16BE(0);
  const out = [];
  let o = 2;
  const end = 2 + listLen;
  while (o < end) {
    const len = data.readUInt8(o); o += 1;
    out.push(data.subarray(o, o + len).toString('utf8')); o += len;
  }
  return out;
}

// server_name (SNI) — RFC 6066 §3
function ext_serverName(hostname) {
  const nameBuf = Buffer.from(hostname, 'utf8');
  const body = Buffer.allocUnsafe(2 + 3 + nameBuf.length);
  body.writeUInt16BE(3 + nameBuf.length, 0);
  body.writeUInt8(0x00, 2); // name_type = host_name
  body.writeUInt16BE(nameBuf.length, 3);
  nameBuf.copy(body, 5);
  return encodeExtension(EXT_TYPE.SERVER_NAME, body);
}

/** Sunucunun SNI'yı kabul ettiğini bildiren boş yanıt uzantısı (RFC 6066 §3). */
function ext_serverNameAck() {
  return encodeExtension(EXT_TYPE.SERVER_NAME, Buffer.alloc(0));
}

function ext_cookie(cookie) {
  const body = Buffer.allocUnsafe(2 + cookie.length);
  body.writeUInt16BE(cookie.length, 0);
  cookie.copy(body, 2);
  return encodeExtension(EXT_TYPE.COOKIE, body);
}

function ext_pskKeyExchangeModes(modes = [0x01] /* psk_dhe_ke */) {
  const body = Buffer.allocUnsafe(1 + modes.length);
  body.writeUInt8(modes.length, 0);
  for (let i = 0; i < modes.length; i++) body.writeUInt8(modes[i], 1 + i);
  return encodeExtension(EXT_TYPE.PSK_KEY_EXCHANGE_MODES, body);
}

// certificate_authorities — RFC 8446 §4.2.4 (CertificateRequest içinde)
function ext_certificateAuthorities(dnList /* Buffer[] — DER encoded DistinguishedName */) {
  let listLen = 0;
  for (const dn of dnList) listLen += 2 + dn.length;
  const body = Buffer.allocUnsafe(2 + listLen);
  body.writeUInt16BE(listLen, 0);
  let o = 2;
  for (const dn of dnList) {
    body.writeUInt16BE(dn.length, o); o += 2;
    dn.copy(body, o); o += dn.length;
  }
  return encodeExtension(EXT_TYPE.CERTIFICATE_AUTHORITIES, body);
}

// ============================================================================
// Parsers
// ============================================================================
function parse_supportedVersionsClient(data) {
  const listLen = data.readUInt8(0);
  if (1 + listLen > data.length) throw new Error('supported_versions truncated');
  if (listLen % 2) throw new Error('odd supported_versions length');
  const out = [];
  for (let i = 0; i < listLen; i += 2) out.push(data.readUInt16BE(1 + i));
  return out;
}

function parse_supportedVersionsServer(data) {
  if (data.length < 2) throw new Error('supported_versions (server) truncated');
  return data.readUInt16BE(0);
}

function parseU16List(data) {
  const listLen = data.readUInt16BE(0);
  if (listLen % 2) throw new Error('odd u16 list length');
  if (2 + listLen > data.length) throw new Error('u16 list truncated');
  const out = new Array(listLen / 2);
  for (let i = 0; i < listLen; i += 2) out[i / 2] = data.readUInt16BE(2 + i);
  return out;
}
const parse_supportedGroups = parseU16List;
const parse_signatureAlgorithms = parseU16List;

function parse_keyShareClient(data) {
  const total = data.readUInt16BE(0);
  const end = 2 + total;
  if (end > data.length) throw new Error('key_share truncated');
  const entries = [];
  let o = 2;
  while (o + 4 <= end) {
    const group = data.readUInt16BE(o); o += 2;
    const keLen = data.readUInt16BE(o); o += 2;
    if (o + keLen > end) throw new Error('key_share entry truncated');
    entries.push({ group, keyExchange: data.subarray(o, o + keLen) }); o += keLen;
  }
  return entries;
}

function parse_keyShareServer(data) {
  if (data.length === 2) return { kind: 'hrr', selectedGroup: data.readUInt16BE(0) };
  const group = data.readUInt16BE(0);
  const keLen = data.readUInt16BE(2);
  return { kind: 'sh', group, keyExchange: data.subarray(4, 4 + keLen) };
}

function parse_serverName(data) {
  if (data.length === 0) return []; // sunucunun boş onay uzantısı
  const listLen = data.readUInt16BE(0);
  const end = 2 + listLen;
  const names = [];
  let o = 2;
  while (o + 3 <= end) {
    const nameType = data.readUInt8(o); o += 1;
    const nameLen = data.readUInt16BE(o); o += 2;
    const name = data.subarray(o, o + nameLen); o += nameLen;
    names.push({ nameType, name: nameType === 0 ? name.toString('utf8') : name });
  }
  return names;
}

/** SNI'dan host_name değerini çeker; yoksa null. */
function sniHostname(extensions) {
  const ext = findExt(extensions, EXT_TYPE.SERVER_NAME);
  if (!ext) return null;
  try {
    const names = parse_serverName(ext.data);
    const host = names.find((n) => n.nameType === 0);
    return host ? host.name : null;
  } catch { return null; }
}

function parse_cookie(data) {
  const len = data.readUInt16BE(0);
  return data.subarray(2, 2 + len);
}

function parse_ecPointFormats(data) {
  const len = data.readUInt8(0);
  const out = [];
  for (let i = 0; i < len; i++) out.push(data.readUInt8(1 + i));
  return out;
}

module.exports = {
  encodeExtension, encodeExtensions, decodeExtensions, findExt,
  // builders
  ext_supportedVersionsClient, ext_supportedVersionsServer,
  ext_supportedGroups, ext_signatureAlgorithms,
  ext_keyShareClient, ext_keyShareServer, ext_keyShareHRR,
  ext_serverName, ext_serverNameAck, ext_cookie, ext_pskKeyExchangeModes,
  ext_useSrtp, ext_alpn, ext_ecPointFormats, ext_extendedMasterSecret,
  ext_renegotiationInfo, ext_certificateAuthorities,
  ext_statusRequest, ext_statusRequestAck, ext_statusRequestResponse,
  parse_statusRequest, parse_statusRequestResponse, STATUS_TYPE_OCSP,
  // parsers
  parse_supportedVersionsClient, parse_supportedVersionsServer,
  parse_supportedGroups, parse_signatureAlgorithms,
  parse_keyShareClient, parse_keyShareServer,
  parse_serverName, sniHostname, parse_cookie,
  parse_useSrtp, parse_alpn, parse_ecPointFormats,
};
