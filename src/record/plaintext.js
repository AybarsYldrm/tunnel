'use strict';
// DTLS 1.3 Record Layer — RFC 9147 §4.
//
// İki record biçimi var:
//
// 1) DTLSPlaintext (RFC 9147 §4.1) — 13-byte fixed header.
//    ClientHello, ServerHello, HelloRetryRequest için kullanılır.
//    Sonraki her şey DTLSCiphertext.
//
// 2) DTLSCiphertext (RFC 9147 §4) — unified header, ilk byte bit-pack.
//    İlk byte: 0 0 1 C S L E E
//      C  = Connection ID present
//      S  = sequence number length  (0 => 8-bit, 1 => 16-bit)
//      L  = length field present
//      EE = low 2 bits of epoch
//
//    Ardından: [CID?] [seq 8|16] [length 16?] [encrypted payload]
//
// Bu modül şimdilik decode/encode yapısı sağlar; sequence number encryption
// ve AEAD açma/kapama Faz 3'te eklenecek.

const { CONTENT_TYPE, VERSION, NAMES } = require('../constants.js');
const { mk } = require('../logger.js');
const log = mk('record');

// ============================================================================
// DTLSPlaintext
// ============================================================================
const PLAINTEXT_HEADER_LEN = 13;

function encodePlaintext({ type, epoch = 0, sequenceNumber, fragment }) {
  if (!Buffer.isBuffer(fragment)) throw new TypeError('fragment must be Buffer');
  if (fragment.length > 0xffff) throw new RangeError('fragment too large (>65535)');
  const hdr = Buffer.alloc(PLAINTEXT_HEADER_LEN);
  hdr.writeUInt8(type, 0);
  hdr.writeUInt16BE(VERSION.DTLS_1_2, 1); // legacy_record_version
  hdr.writeUInt16BE(epoch, 3);
  writeUInt48BE(hdr, sequenceNumber, 5);
  hdr.writeUInt16BE(fragment.length, 11);
  return Buffer.concat([hdr, fragment]);
}

function decodePlaintext(buf, offset = 0) {
  if (buf.length - offset < PLAINTEXT_HEADER_LEN) {
    throw new Error(`plaintext record too short: need ${PLAINTEXT_HEADER_LEN}, got ${buf.length - offset}`);
  }
  const type = buf.readUInt8(offset);
  const legacyVersion = buf.readUInt16BE(offset + 1);
  const epoch = buf.readUInt16BE(offset + 3);
  const sequenceNumber = readUInt48BE(buf, offset + 5);
  const length = buf.readUInt16BE(offset + 11);
  const start = offset + PLAINTEXT_HEADER_LEN;
  const end = start + length;
  if (end > buf.length) {
    throw new Error(`plaintext truncated: header length=${length}, available=${buf.length - start}`);
  }
  return {
    kind: 'DTLSPlaintext',
    type, legacyVersion, epoch, sequenceNumber, length,
    fragment: buf.slice(start, end),
    bytesConsumed: end - offset,
    typeName: NAMES.CONTENT_TYPE[type] || `UNKNOWN(${type})`,
  };
}

// ============================================================================
// DTLSCiphertext (unified header)
// ============================================================================
function encodeCiphertext({
  epoch,
  sequenceNumber,
  encryptedPayload,
  connectionId = null,
  seq16 = false,
  includeLength = true,
}) {
  const cid = connectionId ? Buffer.from(connectionId) : null;
  const cBit = cid ? 1 : 0;
  const sBit = seq16 ? 1 : 0;
  const lBit = includeLength ? 1 : 0;
  const epochBits = epoch & 0b11;
  const firstByte = 0b00100000 | (cBit << 4) | (sBit << 3) | (lBit << 2) | epochBits;

  const seqLen = seq16 ? 2 : 1;
  const hdrLen = 1 + (cid ? cid.length : 0) + seqLen + (includeLength ? 2 : 0);
  const hdr = Buffer.alloc(hdrLen);

  let o = 0;
  hdr.writeUInt8(firstByte, o); o += 1;
  if (cid) { cid.copy(hdr, o); o += cid.length; }
  if (seq16) { hdr.writeUInt16BE(sequenceNumber & 0xffff, o); o += 2; }
  else       { hdr.writeUInt8(sequenceNumber & 0xff, o);     o += 1; }
  if (includeLength) { hdr.writeUInt16BE(encryptedPayload.length, o); o += 2; }

  return Buffer.concat([hdr, encryptedPayload]);
}

function decodeCiphertext(buf, offset = 0, cidLength = 0) {
  if (buf.length - offset < 2) throw new Error('ciphertext header too short');
  const firstByte = buf.readUInt8(offset);
  if ((firstByte & 0b11100000) !== 0b00100000) return null; // Top 3 bits MUST be 001

  const cBit = (firstByte >> 4) & 1;
  const sBit = (firstByte >> 3) & 1;
  const lBit = (firstByte >> 2) & 1;
  const epochLow = firstByte & 0b11;

  let o = offset + 1;
  let cid = null;
  if (cBit) {
    if (cidLength <= 0) throw new Error('CID bit set but no cidLength configured');
    cid = buf.slice(o, o + cidLength);
    o += cidLength;
  }

  const seqLen = sBit ? 2 : 1;
  const seqTruncated = sBit ? buf.readUInt16BE(o) : buf.readUInt8(o);
  o += seqLen;

  let payloadLen;
  if (lBit) {
    payloadLen = buf.readUInt16BE(o);
    o += 2;
  } else {
    payloadLen = buf.length - o; // length field yoksa datagram sonuna kadar
  }

  if (o + payloadLen > buf.length) throw new Error('ciphertext payload truncated');
  const payload = buf.slice(o, o + payloadLen);

  return {
    kind: 'DTLSCiphertext',
    cid, epochLow, seqTruncated, seqLen, lengthPresent: !!lBit,
    encryptedPayload: payload,
    bytesConsumed: (o - offset) + payloadLen,
    firstByte,
  };
}

// ============================================================================
// Datagram demux — bir UDP datagramı birden fazla record içerebilir
// (RFC 9147 §4.1 "multiple DTLS records MAY be placed in a single datagram").
// ============================================================================
function parseDatagram(datagram, { cidLength = 0 } = {}) {
  const records = [];
  let offset = 0;

  while (offset < datagram.length) {
    const firstByte = datagram.readUInt8(offset);
    const top3 = firstByte & 0b11100000;

    if (top3 === 0b00100000) {
      // DTLSCiphertext
      const rec = decodeCiphertext(datagram, offset, cidLength);
      if (!rec) { log.warn('ciphertext decode returned null', { firstByte: '0x' + firstByte.toString(16) }); break; }
      records.push(rec);
      offset += rec.bytesConsumed;
    } else if (
      firstByte === CONTENT_TYPE.HANDSHAKE ||
      firstByte === CONTENT_TYPE.ALERT ||
      firstByte === CONTENT_TYPE.APPLICATION_DATA ||
      firstByte === CONTENT_TYPE.CHANGE_CIPHER_SPEC ||
      firstByte === CONTENT_TYPE.ACK
    ) {
      const rec = decodePlaintext(datagram, offset);
      records.push(rec);
      offset += rec.bytesConsumed;
    } else {
      log.warn('unknown first byte, parse aborted', {
        byte: '0x' + firstByte.toString(16),
        offset,
      });
      break;
    }
  }

  return records;
}

// ============================================================================
// uint48 big-endian yardımcıları (JS Number safe range: 2^53)
// ============================================================================
function readUInt48BE(buf, offset) {
  const hi = buf.readUInt16BE(offset);
  const lo = buf.readUInt32BE(offset + 2);
  return hi * 0x100000000 + lo;
}
function writeUInt48BE(buf, value, offset) {
  if (value < 0 || value > 0xffffffffffff) throw new RangeError('uint48 out of range');
  const hi = Math.floor(value / 0x100000000);
  const lo = value >>> 0;
  buf.writeUInt16BE(hi, offset);
  buf.writeUInt32BE(lo, offset + 2);
}

module.exports = {
  PLAINTEXT_HEADER_LEN,
  encodePlaintext, decodePlaintext,
  encodeCiphertext, decodeCiphertext,
  parseDatagram,
  readUInt48BE, writeUInt48BE,
};
