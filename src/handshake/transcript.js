'use strict';
// Handshake transcript — iki protokolde iki farklı kural:
//
// DTLS 1.3 (RFC 9147 §5.2): transcript, TLS 1.3'ün 4 baytlık handshake başlığı
//   üzerinden hesaplanır. DTLS'e özgü alanlar (message_seq, fragment_offset,
//   fragment_length) transcript'e GİRMEZ ve mesaj tek parça sayılır.
//
// DTLS 1.2 (RFC 6347 §4.2.6): tam tersi — 12 baytlık DTLS başlığı DAHİL edilir,
//   mesajlar tek fragment olarak yeniden kurulmuş gibi hash'lenir. Ayrıca ilk
//   ClientHello ve HelloVerifyRequest transcript'e HİÇ girmez.

const crypto = require('node:crypto');
const { hashLen } = require('../crypto/hkdf.js');

const DTLS_HS_HEADER_LEN = 12;
const TLS_HS_HEADER_LEN = 4;

/** DTLS 1.3 transcript — DTLS başlığını TLS başlığına indirger. */
class Transcript {
  constructor(hashName) {
    this.hashName = hashName;
    this.hashLen = hashLen(hashName);
    this.h = crypto.createHash(hashName);
  }

  /**
   * Bir veya birden çok arka arkaya DTLS handshake mesajı ekler.
   * Her mesaj tek parça (fragment_offset=0, fragment_length=length) olmalıdır.
   */
  appendDtls(wire) {
    if (!wire || wire.length < DTLS_HS_HEADER_LEN) return this;
    let offset = 0;
    while (offset + DTLS_HS_HEADER_LEN <= wire.length) {
      const msgType = wire[offset];
      const msgLen = (wire[offset + 1] << 16) | (wire[offset + 2] << 8) | wire[offset + 3];
      if (offset + DTLS_HS_HEADER_LEN + msgLen > wire.length) break;

      const tlsHdr = Buffer.allocUnsafe(TLS_HS_HEADER_LEN);
      tlsHdr[0] = msgType;
      tlsHdr[1] = (msgLen >> 16) & 0xff;
      tlsHdr[2] = (msgLen >> 8) & 0xff;
      tlsHdr[3] = msgLen & 0xff;

      this.h.update(tlsHdr);
      this.h.update(wire.subarray(offset + DTLS_HS_HEADER_LEN,
                                  offset + DTLS_HS_HEADER_LEN + msgLen));
      offset += DTLS_HS_HEADER_LEN + msgLen;
    }
    return this;
  }

  // Geriye dönük uyum
  update(wire) { return this.appendDtls(wire); }

  /**
   * HelloRetryRequest sonrası ClientHello1'i message_hash ile değiştirir
   * (RFC 8446 §4.4.1 / RFC 9147 §5.2):
   *   Transcript = MessageHash(Hash(ClientHello1)) || HelloRetryRequest || ...
   */
  replaceWithMessageHash(ch1Wire) {
    if (!ch1Wire) throw new Error('ch1Wire zorunlu');
    const msgLen = (ch1Wire[1] << 16) | (ch1Wire[2] << 8) | ch1Wire[3];
    const tlsHdr = Buffer.from([ch1Wire[0], ch1Wire[1], ch1Wire[2], ch1Wire[3]]);
    const ch1Digest = crypto.createHash(this.hashName)
      .update(tlsHdr)
      .update(ch1Wire.subarray(DTLS_HS_HEADER_LEN, DTLS_HS_HEADER_LEN + msgLen))
      .digest();

    const msgHashHdr = Buffer.from([254, 0, 0, this.hashLen]); // message_hash(254)
    this.h = crypto.createHash(this.hashName).update(msgHashHdr).update(ch1Digest);
    return this;
  }

  digest() { return this.h.copy().digest(); }
}

/**
 * DTLS 1.2 transcript — ham DTLS baytlarını (12 baytlık başlık dahil) hash'ler.
 * CertificateVerify ham baytların tamamı üzerinden imzalandığı için handshake
 * bitene kadar baytlar da saklanır; `releaseRaw()` ile bellek geri verilir.
 */
class Transcript12 {
  constructor(hashName, { keepRaw = true } = {}) {
    this.hashName = hashName;
    this.h = crypto.createHash(hashName);
    this.raw = keepRaw ? [] : null;
    this.rawLen = 0;
  }

  append(wire) {
    this.h.update(wire);
    if (this.raw) { this.raw.push(wire); this.rawLen += wire.length; }
    return this;
  }

  digest() { return this.h.copy().digest(); }

  /** CertificateVerify imzası için o ana kadarki ham handshake baytları. */
  rawBytes() {
    if (!this.raw) throw new Error('Transcript12: ham baytlar tutulmuyor');
    return this.raw.length === 1 ? this.raw[0] : Buffer.concat(this.raw, this.rawLen);
  }

  releaseRaw() { this.raw = null; this.rawLen = 0; }
}

module.exports = { Transcript, Transcript12, DTLS_HS_HEADER_LEN };
