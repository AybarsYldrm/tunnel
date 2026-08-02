'use strict';
// Kayıt koruma (AEAD) — HER İKİ DTLS SÜRÜMÜ İÇİN TEK DOSYA.
//
//   BÖLÜM 1: DTLS 1.3 — RFC 9147 §4  (unified header, seq maskeleme)
//   BÖLÜM 2: DTLS 1.2 — RFC 6347 §4.1.2 + RFC 5288/7905 (sabit 13 baytlık başlık)
//
// İki biçim tel üzerinde tamamen farklıdır, ama aynı soruyu yanıtlarlar:
// "bir içerik tipini ve gövdeyi, tel üzerine yazılabilir korumalı bir kayda
// nasıl çeviririm?". Yan yana durduklarında farkları (AAD kurulumu, nonce
// üretimi, uzunluk alanının açık/kapalı olması) doğrudan karşılaştırılabilir.
//
// ============================================================================
// BÖLÜM 1 — DTLS 1.3 (RFC 9147 §4)
// ============================================================================
//
// Unified header (ilk bayt bit-pack):  0 0 1 C S L E E
//   C  = Connection ID var
//   S  = sequence number uzunluğu (0 => 8-bit, 1 => 16-bit)
//   L  = length alanı var
//   EE = epoch'un düşük 2 biti
//
// Sıralama: [firstByte][CID?][seq 8|16][length 16?][ciphertext]
//
// §4.2.3: sequence number MASKELENİR, length alanı AÇIK kalır.
// AAD, maskelemeden ÖNCEKİ başlığın tamamıdır.

const { VERSION } = require('../constants.js');
const {
  buildAeadNonce, buildInnerPlaintext, parseInnerPlaintext,
  aeadSeal, aeadOpen, snMask, reconstructSeq,
} = require('../crypto/aead.js');

/**
 * @returns {Buffer} tel üzerine yazılmaya hazır tam kayıt
 */
function protectRecord({
  contentType, content, recordSeq, epoch,
  writeKey, writeIv, snKey, aeadAlg, snCipher,
  paddingLen = 0, connectionId = null, tagLen = 16,
}) {
  const cid = connectionId && connectionId.length ? connectionId : null;
  const cidLen = cid ? cid.length : 0;
  const firstByte = 0b00100000 | (cid ? 0b10000 : 0) | 0b1000 | 0b100 | (epoch & 0b11);

  const inner = buildInnerPlaintext(contentType, content, paddingLen);
  const ctLen = inner.length + tagLen;

  // Başlığı tek seferde tahsis et: 1 + cid + 2 (seq16) + 2 (length)
  const hdrLen = 1 + cidLen + 4;
  const hdr = Buffer.allocUnsafe(hdrLen);
  hdr[0] = firstByte;
  if (cid) cid.copy(hdr, 1);
  hdr.writeUInt16BE(recordSeq & 0xffff, 1 + cidLen);
  hdr.writeUInt16BE(ctLen, 3 + cidLen);

  // AAD = maskelenmemiş başlık
  const aad = Buffer.from(hdr);

  const nonce = buildAeadNonce(writeIv, recordSeq);
  const ct = aeadSeal({ aead: aeadAlg, key: writeKey, nonce, aad, plaintext: inner, tagLen });

  // Sequence number maskeleme (§4.2.3)
  const mask = snMask(snCipher, snKey, ct);
  hdr[1 + cidLen]     ^= mask[0];
  hdr[1 + cidLen + 1] ^= mask[1];

  const out = Buffer.allocUnsafe(hdrLen + ct.length);
  hdr.copy(out, 0);
  ct.copy(out, hdrLen);
  return out;
}

/**
 * @returns {null|{contentType,content,fullSeq,seqTruncated,bytesConsumed,cid,epochLow}}
 * @throws AEAD doğrulaması başarısızsa
 */
function unprotectRecord({
  record, offset = 0,
  readKey, readIv, snKey, aeadAlg, snCipher,
  lastSeq = 0, epoch = 0, cidLength = 0, tagLen = 16,
}) {
  if (record.length - offset < 2) return null;
  const firstByte = record[offset];
  if ((firstByte & 0b11100000) !== 0b00100000) return null;

  const cBit = (firstByte >> 4) & 1;
  const sBit = (firstByte >> 3) & 1;
  const lBit = (firstByte >> 2) & 1;
  const snLen = sBit ? 2 : 1;
  const snBits = sBit ? 16 : 8;

  let o = offset + 1;
  let cid = null;
  if (cBit) {
    if (cidLength <= 0) return null;
    if (o + cidLength > record.length) return null;
    cid = record.subarray(o, o + cidLength);
    o += cidLength;
  }

  if (o + snLen > record.length) return null;
  const seq0 = record[o];
  const seq1 = sBit ? record[o + 1] : 0;
  o += snLen;

  let ctLen;
  if (lBit) {
    if (o + 2 > record.length) return null;
    ctLen = record.readUInt16BE(o);
    o += 2;
    if (o + ctLen > record.length) return null;
  } else {
    ctLen = record.length - o;
  }
  if (ctLen < tagLen + 1) return null;

  const ct = record.subarray(o, o + ctLen);

  // Maske örneği tam olarak bu kaydın ciphertext'inden alınır — datagramdaki
  // sonraki kayda taşmamalı (gönderen de sadece kendi ct'sini örnekliyor).
  const mask = snMask(snCipher, snKey, ct);
  const truncated = sBit
    ? (((seq0 ^ mask[0]) << 8) | (seq1 ^ mask[1]))
    : (seq0 ^ mask[0]);
  const fullSeq = reconstructSeq(lastSeq, truncated, snBits);

  // AAD'yi maskelenmemiş haliyle yeniden kur.
  const hdrLen = o - offset;
  const aad = Buffer.allocUnsafe(hdrLen);
  record.copy(aad, 0, offset, o);
  aad[1 + (cBit ? cidLength : 0)] = truncated >> (sBit ? 8 : 0) & 0xff;
  if (sBit) aad[2 + (cBit ? cidLength : 0)] = truncated & 0xff;

  const nonce = buildAeadNonce(readIv, fullSeq);
  const inner = aeadOpen({
    aead: aeadAlg, key: readKey, nonce, aad, ciphertextWithTag: ct, tagLen,
  });

  const { contentType, content } = parseInnerPlaintext(inner);
  return {
    contentType, content,
    epochLow: firstByte & 0b11,
    fullSeq, seqTruncated: truncated,
    bytesConsumed: hdrLen + ctLen,
    cid,
  };
}

// ============================================================================
// BÖLÜM 2 — DTLS 1.2 (RFC 6347 §4.1.2 + RFC 5246 §6.2.3.3
//                     + RFC 5288 AES-GCM + RFC 7905 ChaCha20-Poly1305)
// ============================================================================
//
// DTLS 1.2'de kayıt başlığı DAİMA 13 bayttır (unified header yok, sequence
// number şifrelemesi yok). Şifreli kayıtta fragment şu şekildedir:
//
//   AES-GCM : explicit_nonce(8) || ciphertext || tag(16)
//   ChaCha20: ciphertext || tag(16)          (nonce örtük; seq ile XOR)
//
// AAD (her iki AEAD için aynı):
//   seq_num(8 = epoch(2) || sequence_number(6)) || type(1) || version(2) || length(2)
// `length` = ŞİFRELENMEMİŞ fragment uzunluğu.

const HEADER_LEN_12 = 13;

/** 8 baytlık seq_num alanı: epoch(2) || sequence_number(6). Nonce ve AAD ortak kullanır. */
function seqNumField(epoch, seq, out = Buffer.allocUnsafe(8)) {
  out.writeUInt16BE(epoch & 0xffff, 0);
  out.writeUInt16BE(Math.floor(seq / 0x100000000) & 0xffff, 2);
  out.writeUInt32BE(seq >>> 0, 4);
  return out;
}

function buildAad12(seqField, contentType, version, plaintextLen) {
  const aad = Buffer.allocUnsafe(13);
  seqField.copy(aad, 0);
  aad.writeUInt8(contentType, 8);
  aad.writeUInt16BE(version, 9);
  aad.writeUInt16BE(plaintextLen, 11);
  return aad;
}

/**
 * GCM: nonce = salt(4) || explicit(8)
 * ChaCha20 (RFC 7905): nonce = iv(12) XOR left_pad(seq_num, 12)
 */
function buildNonce12(suite, salt, seqField) {
  if (suite.explicitNonceLen === 0) {
    const nonce = Buffer.from(salt); // 12 bayt
    for (let i = 0; i < 8; i++) nonce[4 + i] ^= seqField[i];
    return nonce;
  }
  const nonce = Buffer.allocUnsafe(suite.ivLen);
  salt.copy(nonce, 0);
  seqField.copy(nonce, salt.length);
  return nonce;
}

/** Tek bir DTLS 1.2 kaydını şifreler; 13 baytlık başlık dahil tam kaydı döner. */
function protectRecord12({ contentType, content, epoch, recordSeq, suite, key, salt,
                           version = VERSION.DTLS_1_2 }) {
  const seqField = seqNumField(epoch, recordSeq);
  const aad = buildAad12(seqField, contentType, version, content.length);
  const nonce = buildNonce12(suite, salt, seqField);

  const sealed = aeadSeal({
    aead: suite.aead, key, nonce, aad, plaintext: content, tagLen: suite.tagLen,
  });

  const explicitLen = suite.explicitNonceLen;
  const fragLen = explicitLen + sealed.length;
  const rec = Buffer.allocUnsafe(HEADER_LEN_12 + fragLen);
  rec.writeUInt8(contentType, 0);
  rec.writeUInt16BE(version, 1);
  seqField.copy(rec, 3);           // epoch(2) + seq(6) — seqField düzeni birebir aynı
  rec.writeUInt16BE(fragLen, 11);
  if (explicitLen) seqField.copy(rec, HEADER_LEN_12, 0, explicitLen);
  sealed.copy(rec, HEADER_LEN_12 + explicitLen);
  return rec;
}

/**
 * decodePlaintext() çıktısındaki şifreli fragment'i açar.
 * @returns {{ contentType:number, content:Buffer }}
 * @throws AEAD doğrulaması başarısızsa
 */
function unprotectRecord12({ record, suite, key, salt, version = VERSION.DTLS_1_2 }) {
  const { type, epoch, sequenceNumber, fragment } = record;
  const explicitLen = suite.explicitNonceLen;
  if (fragment.length < explicitLen + suite.tagLen) {
    throw new Error('DTLS 1.2 kaydı çok kısa (explicit nonce + tag sığmıyor)');
  }

  const seqField = seqNumField(epoch, sequenceNumber);
  // GCM'de nonce'ın explicit kısmı tel üzerinden gelir — seq'e eşit varsaymayız.
  let nonce;
  if (explicitLen) {
    nonce = Buffer.allocUnsafe(suite.ivLen);
    salt.copy(nonce, 0);
    fragment.copy(nonce, salt.length, 0, explicitLen);
  } else {
    nonce = buildNonce12(suite, salt, seqField);
  }

  const sealed = fragment.subarray(explicitLen);
  const plaintextLen = sealed.length - suite.tagLen;
  const aad = buildAad12(seqField, type, version, plaintextLen);

  const content = aeadOpen({
    aead: suite.aead, key, nonce, aad, ciphertextWithTag: sealed, tagLen: suite.tagLen,
  });
  return { contentType: type, content };
}

module.exports = {
  // DTLS 1.3
  protectRecord, unprotectRecord,
  // DTLS 1.2
  protectRecord12, unprotectRecord12, seqNumField, HEADER_LEN_12,
};
