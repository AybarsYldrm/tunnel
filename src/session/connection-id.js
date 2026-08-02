'use strict';
// Connection ID — RFC 9146.
//
//   extension_type = 54 (connection_id)
//   extension_data = opaque cid<0..2^8-1>
//
// Her taraf karşı tarafa "bana şu CID ile gönder" şeklinde kendi CID'ini bildirir.
// CID varsa, protected record'un unified header'ında "C" biti 1 olur ve CID bytes
// header'da firstByte ile seq arasına yerleştirilir.

const { encodeExtension } = require('../handshake/extensions.js');
const { EXT_TYPE } = require('../constants.js');

function ext_connectionId(cid) {
  const body = Buffer.alloc(1 + cid.length);
  body.writeUInt8(cid.length, 0);
  cid.copy(body, 1);
  return encodeExtension(EXT_TYPE.CONNECTION_ID, body);
}

function parse_connectionId(data) {
  const len = data.readUInt8(0);
  return data.slice(1, 1 + len);
}

module.exports = { ext_connectionId, parse_connectionId };
