'use strict';
// SRTP / SRTCP — RFC 3711 (AES-CM + HMAC-SHA1) ve RFC 7714 (AEAD AES-GCM).
//
// DTLS-SRTP'de (RFC 5764) DTLS handshake'i yalnızca anahtar takası için kullanılır;
// medya paketleri DTLS kayıt katmanından GEÇMEZ, doğrudan SRTP ile korunur.
// Bu modül o koruma katmanıdır.
//
// Durum yönetimi SSRC başınadır: her akışın kendi ROC'u (roll-over counter),
// en yüksek sequence number'ı ve replay penceresi vardır.

const crypto = require('node:crypto');
const { SRTP_PROFILE, SRTP_PROFILE_PARAMS } = require('../constants.js');
const { ReplayWindow } = require('./replay-window.js');

// RFC 3711 §4.3.1 — KDF etiketleri
const LABEL = Object.freeze({
  SRTP_ENC: 0x00, SRTP_AUTH: 0x01, SRTP_SALT: 0x02,
  SRTCP_ENC: 0x03, SRTCP_AUTH: 0x04, SRTCP_SALT: 0x05,
});

const KDF_SALT_LEN = 14; // KDF daima 14 baytlık salt kullanır (GCM'de 12 bayt sağa sıfır dolgulu)
const RTP_HEADER_MIN = 12;
const RTCP_HEADER_LEN = 8;

/**
 * RFC 3711 §4.3.3 KDF — AES-CM ile anahtar türetimi.
 * kdr (key derivation rate) = 0 kabul edilir; WebRTC bunu hep 0 bırakır.
 */
function srtpKdf(masterKey, masterSalt, label, outLen) {
  const iv = Buffer.alloc(16, 0);
  masterSalt.copy(iv, 0, 0, Math.min(masterSalt.length, KDF_SALT_LEN));
  iv[7] ^= label;
  const alg = masterKey.length === 32 ? 'aes-256-ctr' : 'aes-128-ctr';
  const c = crypto.createCipheriv(alg, masterKey, iv);
  return c.update(Buffer.alloc(outLen, 0));
}

/** RTP başlık uzunluğu (CSRC + uzantı dahil). Geçersizse -1. */
function rtpHeaderLength(pkt) {
  if (pkt.length < RTP_HEADER_MIN) return -1;
  const cc = pkt[0] & 0x0f;
  let len = RTP_HEADER_MIN + cc * 4;
  if ((pkt[0] >> 4) & 1) { // X biti
    if (pkt.length < len + 4) return -1;
    len += 4 + pkt.readUInt16BE(len + 2) * 4;
  }
  return pkt.length >= len ? len : -1;
}

/**
 * RFC 3711 Ek A — kısaltılmış SEQ'ten 48 bitlik paket indeksini kestir.
 * @returns {{ index:number, roc:number, updateRoc:number, updateSl:number }}
 */
function estimateIndex(state, seq) {
  const { roc, sl, started } = state;
  if (!started) return { index: roc * 0x10000 + seq, roc, updateRoc: roc, updateSl: seq };

  let v = roc;
  if (sl < 0x8000) {
    if (seq - sl > 0x8000) v = (roc - 1) >>> 0;
  } else if (sl - 0x8000 > seq) {
    v = (roc + 1) >>> 0;
  }
  const index = v * 0x10000 + seq;
  // Sadece ileri gidiyorsak durumu güncelleriz.
  let updateRoc = roc, updateSl = sl;
  if (v === roc && seq > sl) updateSl = seq;
  else if (v === ((roc + 1) >>> 0)) { updateRoc = v; updateSl = seq; }
  return { index, roc: v, updateRoc, updateSl };
}

/** AES-CTR IV: salt(14) XOR (SSRC<<64) XOR (index<<16) */
function ctrIv(salt, ssrc, index) {
  const iv = Buffer.alloc(16, 0);
  salt.copy(iv, 0, 0, 14);
  iv[4] ^= (ssrc >>> 24) & 0xff;
  iv[5] ^= (ssrc >>> 16) & 0xff;
  iv[6] ^= (ssrc >>> 8) & 0xff;
  iv[7] ^= ssrc & 0xff;
  const hi = Math.floor(index / 0x100000000);
  const lo = index >>> 0;
  iv[8]  ^= (hi >>> 8) & 0xff;
  iv[9]  ^= hi & 0xff;
  iv[10] ^= (lo >>> 24) & 0xff;
  iv[11] ^= (lo >>> 16) & 0xff;
  iv[12] ^= (lo >>> 8) & 0xff;
  iv[13] ^= lo & 0xff;
  return iv;
}

/** RFC 7714 §8.1 GCM IV: salt(12) XOR (0x0000 || SSRC(4) || ROC(4) || SEQ(2)) */
function gcmIv(salt, ssrc, roc, seq) {
  const iv = Buffer.alloc(12, 0);
  salt.copy(iv, 0, 0, 12);
  iv[2] ^= (ssrc >>> 24) & 0xff;
  iv[3] ^= (ssrc >>> 16) & 0xff;
  iv[4] ^= (ssrc >>> 8) & 0xff;
  iv[5] ^= ssrc & 0xff;
  iv[6] ^= (roc >>> 24) & 0xff;
  iv[7] ^= (roc >>> 16) & 0xff;
  iv[8] ^= (roc >>> 8) & 0xff;
  iv[9] ^= roc & 0xff;
  iv[10] ^= (seq >>> 8) & 0xff;
  iv[11] ^= seq & 0xff;
  return iv;
}

/** RFC 7714 §9.1 SRTCP GCM IV: salt(12) XOR (0x0000 || SSRC(4) || 0x0000 || index(4)) */
function gcmIvRtcp(salt, ssrc, index) {
  const iv = Buffer.alloc(12, 0);
  salt.copy(iv, 0, 0, 12);
  iv[2] ^= (ssrc >>> 24) & 0xff;
  iv[3] ^= (ssrc >>> 16) & 0xff;
  iv[4] ^= (ssrc >>> 8) & 0xff;
  iv[5] ^= ssrc & 0xff;
  iv[8]  ^= (index >>> 24) & 0xff;
  iv[9]  ^= (index >>> 16) & 0xff;
  iv[10] ^= (index >>> 8) & 0xff;
  iv[11] ^= index & 0xff;
  return iv;
}

function timingSafeEq(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Tek yönlü SRTP bağlamı (ya okuma ya yazma).
 * Karşılıklı iletişim için iki örnek gerekir — SrtpKeyPair bunu yapar.
 */
class SrtpContext {
  /**
   * @param {object} o
   * @param {number} o.profile     SRTP_PROFILE.*
   * @param {Buffer} o.masterKey
   * @param {Buffer} o.masterSalt
   * @param {boolean} [o.replayProtection]
   */
  constructor({ profile = SRTP_PROFILE.SRTP_AES128_CM_HMAC_SHA1_80,
                masterKey, masterSalt, replayProtection = true }) {
    const params = SRTP_PROFILE_PARAMS[profile];
    if (!params) throw new Error(`bilinmeyen SRTP profili: 0x${Number(profile).toString(16)}`);
    if (masterKey.length !== params.keyLen) {
      throw new Error(`SRTP master key ${params.keyLen} bayt olmalı (gelen ${masterKey.length})`);
    }
    if (masterSalt.length !== params.saltLen) {
      throw new Error(`SRTP master salt ${params.saltLen} bayt olmalı (gelen ${masterSalt.length})`);
    }

    this.profile = profile;
    this.params = params;
    this.replayProtection = replayProtection;

    // KDF salt'ı daima 14 bayta sağa sıfır dolgulanır (libsrtp ile uyumlu).
    const kdfSalt = Buffer.alloc(KDF_SALT_LEN, 0);
    masterSalt.copy(kdfSalt, 0, 0, Math.min(masterSalt.length, KDF_SALT_LEN));

    this.rtp = {
      key:  srtpKdf(masterKey, kdfSalt, LABEL.SRTP_ENC, params.keyLen),
      salt: srtpKdf(masterKey, kdfSalt, LABEL.SRTP_SALT, params.saltLen),
      auth: params.authKeyLen ? srtpKdf(masterKey, kdfSalt, LABEL.SRTP_AUTH, params.authKeyLen) : null,
    };
    this.rtcp = {
      key:  srtpKdf(masterKey, kdfSalt, LABEL.SRTCP_ENC, params.keyLen),
      salt: srtpKdf(masterKey, kdfSalt, LABEL.SRTCP_SALT, params.saltLen),
      auth: params.authKeyLen ? srtpKdf(masterKey, kdfSalt, LABEL.SRTCP_AUTH, params.authKeyLen) : null,
    };

    this.streams = new Map();   // ssrc -> { roc, sl, started, replay }
    this.rtcpIndex = 0;         // giden SRTCP indeksi
    this.rtcpReplay = new Map();// ssrc -> ReplayWindow
  }

  get name() { return this.params.name; }

  _stream(ssrc) {
    let s = this.streams.get(ssrc);
    if (!s) {
      s = { roc: 0, sl: 0, started: false, replay: new ReplayWindow(64) };
      this.streams.set(ssrc, s);
    }
    return s;
  }

  // ---------------------------------------------------------------- SRTP
  /** Ham RTP paketini korur. @returns {Buffer} */
  protectRtp(rtp) {
    const hdrLen = rtpHeaderLength(rtp);
    if (hdrLen < 0) throw new Error('geçersiz RTP paketi');
    const seq = rtp.readUInt16BE(2);
    const ssrc = rtp.readUInt32BE(8);
    const st = this._stream(ssrc);

    // Gönderirken index monotoniktir: SEQ sarmalını biz takip ederiz.
    if (st.started && seq < st.sl && st.sl - seq > 0x8000) st.roc = (st.roc + 1) >>> 0;
    if (!st.started || seq > st.sl || (st.sl - seq > 0x8000)) st.sl = seq;
    st.started = true;
    const roc = st.roc;
    const index = roc * 0x10000 + seq;

    const header = rtp.subarray(0, hdrLen);
    const payload = rtp.subarray(hdrLen);

    if (this.params.kind === 'gcm') {
      const iv = gcmIv(this.rtp.salt, ssrc, roc, seq);
      const c = crypto.createCipheriv(this.params.cipher, this.rtp.key, iv,
                                      { authTagLength: this.params.tagLen });
      c.setAAD(header);
      const enc = Buffer.concat([c.update(payload), c.final()]);
      return Buffer.concat([header, enc, c.getAuthTag()]);
    }

    const iv = ctrIv(this.rtp.salt, ssrc, index);
    const c = crypto.createCipheriv(this.params.cipher, this.rtp.key, iv);
    const enc = Buffer.concat([c.update(payload), c.final()]);

    const rocBuf = Buffer.allocUnsafe(4);
    rocBuf.writeUInt32BE(roc, 0);
    const tag = crypto.createHmac('sha1', this.rtp.auth)
      .update(header).update(enc).update(rocBuf)
      .digest().subarray(0, this.params.tagLen);

    return Buffer.concat([header, enc, tag]);
  }

  /** Korunmuş SRTP paketini açar. @returns {Buffer} ham RTP */
  unprotectRtp(pkt) {
    const { tagLen } = this.params;
    if (pkt.length < RTP_HEADER_MIN + tagLen) throw new Error('SRTP paketi çok kısa');
    const hdrLen = rtpHeaderLength(pkt);
    if (hdrLen < 0 || hdrLen + tagLen > pkt.length) throw new Error('geçersiz SRTP başlığı');

    const seq = pkt.readUInt16BE(2);
    const ssrc = pkt.readUInt32BE(8);
    const st = this._stream(ssrc);
    const est = estimateIndex(st, seq);

    if (this.replayProtection && !st.replay.check(est.index)) {
      throw new Error('SRTP replay (paket zaten görüldü)');
    }

    const header = pkt.subarray(0, hdrLen);
    let plain;

    if (this.params.kind === 'gcm') {
      const iv = gcmIv(this.rtp.salt, ssrc, est.roc, seq);
      const body = pkt.subarray(hdrLen, pkt.length - tagLen);
      const tag = pkt.subarray(pkt.length - tagLen);
      const d = crypto.createDecipheriv(this.params.cipher, this.rtp.key, iv,
                                        { authTagLength: tagLen });
      d.setAAD(header);
      d.setAuthTag(tag);
      try {
        plain = Buffer.concat([d.update(body), d.final()]);
      } catch { throw new Error('SRTP kimlik doğrulaması başarısız'); }
    } else {
      const encEnd = pkt.length - tagLen;
      const enc = pkt.subarray(hdrLen, encEnd);
      const tag = pkt.subarray(encEnd);

      const rocBuf = Buffer.allocUnsafe(4);
      rocBuf.writeUInt32BE(est.roc, 0);
      const expected = crypto.createHmac('sha1', this.rtp.auth)
        .update(pkt.subarray(0, encEnd)).update(rocBuf)
        .digest().subarray(0, tagLen);
      if (!timingSafeEq(tag, expected)) throw new Error('SRTP kimlik doğrulaması başarısız');

      const iv = ctrIv(this.rtp.salt, ssrc, est.index);
      const d = crypto.createDecipheriv(this.params.cipher, this.rtp.key, iv);
      plain = Buffer.concat([d.update(enc), d.final()]);
    }

    // Doğrulama geçtikten SONRA durum güncellenir — sahte paketle ROC ilerletilemez.
    st.roc = est.updateRoc;
    st.sl = est.updateSl;
    st.started = true;
    if (this.replayProtection) st.replay.mark(est.index);

    return Buffer.concat([header, plain]);
  }

  // ---------------------------------------------------------------- SRTCP
  /** RTCP paketini korur (RFC 3711 §3.4). */
  protectRtcp(rtcp) {
    if (rtcp.length < RTCP_HEADER_LEN) throw new Error('geçersiz RTCP paketi');
    const ssrc = rtcp.readUInt32BE(4);
    const index = (this.rtcpIndex = (this.rtcpIndex + 1) & 0x7fffffff);

    const header = rtcp.subarray(0, RTCP_HEADER_LEN);
    const payload = rtcp.subarray(RTCP_HEADER_LEN);

    const eIndex = Buffer.allocUnsafe(4);
    eIndex.writeUInt32BE((0x80000000 | index) >>> 0, 0); // E biti = 1 (şifreli)

    if (this.params.kind === 'gcm') {
      const iv = gcmIvRtcp(this.rtcp.salt, ssrc, index);
      const c = crypto.createCipheriv(this.params.cipher, this.rtcp.key, iv,
                                      { authTagLength: this.params.tagLen });
      c.setAAD(Buffer.concat([header, eIndex]));
      const enc = Buffer.concat([c.update(payload), c.final()]);
      return Buffer.concat([header, enc, c.getAuthTag(), eIndex]);
    }

    const iv = ctrIv(this.rtcp.salt, ssrc, index);
    const c = crypto.createCipheriv(this.params.cipher, this.rtcp.key, iv);
    const enc = Buffer.concat([c.update(payload), c.final()]);
    const authed = Buffer.concat([header, enc, eIndex]);
    const tag = crypto.createHmac('sha1', this.rtcp.auth).update(authed)
      .digest().subarray(0, this.params.tagLen);
    return Buffer.concat([authed, tag]);
  }

  /** Korunmuş SRTCP paketini açar. */
  unprotectRtcp(pkt) {
    const { tagLen } = this.params;
    const minLen = RTCP_HEADER_LEN + 4 + tagLen;
    if (pkt.length < minLen) throw new Error('SRTCP paketi çok kısa');
    const ssrc = pkt.readUInt32BE(4);

    let eIndexOff, index, encrypted, header, body, tag;
    if (this.params.kind === 'gcm') {
      eIndexOff = pkt.length - 4;
      const eIndex = pkt.subarray(eIndexOff);
      index = eIndex.readUInt32BE(0) & 0x7fffffff;
      encrypted = (eIndex[0] & 0x80) !== 0;
      header = pkt.subarray(0, RTCP_HEADER_LEN);
      body = pkt.subarray(RTCP_HEADER_LEN, eIndexOff - tagLen);
      tag = pkt.subarray(eIndexOff - tagLen, eIndexOff);
      if (!this._rtcpReplayCheck(ssrc, index)) throw new Error('SRTCP replay');
      if (!encrypted) return Buffer.concat([header, body]);

      const iv = gcmIvRtcp(this.rtcp.salt, ssrc, index);
      const d = crypto.createDecipheriv(this.params.cipher, this.rtcp.key, iv,
                                        { authTagLength: tagLen });
      d.setAAD(Buffer.concat([header, eIndex]));
      d.setAuthTag(tag);
      let plain;
      try { plain = Buffer.concat([d.update(body), d.final()]); }
      catch { throw new Error('SRTCP kimlik doğrulaması başarısız'); }
      this._rtcpReplayMark(ssrc, index);
      return Buffer.concat([header, plain]);
    }

    const authedEnd = pkt.length - tagLen;
    eIndexOff = authedEnd - 4;
    tag = pkt.subarray(authedEnd);
    const eIndex = pkt.subarray(eIndexOff, authedEnd);
    index = eIndex.readUInt32BE(0) & 0x7fffffff;
    encrypted = (eIndex[0] & 0x80) !== 0;

    const expected = crypto.createHmac('sha1', this.rtcp.auth)
      .update(pkt.subarray(0, authedEnd)).digest().subarray(0, tagLen);
    if (!timingSafeEq(tag, expected)) throw new Error('SRTCP kimlik doğrulaması başarısız');
    if (!this._rtcpReplayCheck(ssrc, index)) throw new Error('SRTCP replay');

    header = pkt.subarray(0, RTCP_HEADER_LEN);
    body = pkt.subarray(RTCP_HEADER_LEN, eIndexOff);
    this._rtcpReplayMark(ssrc, index);
    if (!encrypted) return Buffer.concat([header, body]);

    const iv = ctrIv(this.rtcp.salt, ssrc, index);
    const d = crypto.createDecipheriv(this.params.cipher, this.rtcp.key, iv);
    return Buffer.concat([header, d.update(body), d.final()]);
  }

  _rtcpReplayCheck(ssrc, index) {
    if (!this.replayProtection) return true;
    let w = this.rtcpReplay.get(ssrc);
    if (!w) { w = new ReplayWindow(64); this.rtcpReplay.set(ssrc, w); }
    return w.check(index);
  }

  _rtcpReplayMark(ssrc, index) {
    if (!this.replayProtection) return;
    this.rtcpReplay.get(ssrc)?.mark(index);
  }
}

/**
 * DTLS handshake'inden çıkan anahtar materyalinden okuma/yazma bağlam çifti kurar.
 * @param {object} km  exportSrtpKeyingMaterial() çıktısı
 * @param {'client'|'server'} role
 */
function createSrtpPair(km, role) {
  const { profile, clientMasterKey, serverMasterKey, clientMasterSalt, serverMasterSalt } = km;
  const client = () => new SrtpContext({ profile, masterKey: clientMasterKey, masterSalt: clientMasterSalt });
  const server = () => new SrtpContext({ profile, masterKey: serverMasterKey, masterSalt: serverMasterSalt });
  return role === 'server'
    ? { read: client(), write: server() }   // sunucu: istemcinin anahtarıyla okur
    : { read: server(), write: client() };  // istemci: sunucunun anahtarıyla okur
}

/**
 * Bir UDP datagramının türünü ayırt eder (RFC 7983).
 *   0-1    : STUN
 *   20-63  : DTLS
 *   64-79  : TURN Channel
 *   128-191: RTP/RTCP  (RTCP payload type 192-223 aralığındaysa RTCP)
 */
function demuxPacket(buf) {
  if (buf.length === 0) return 'unknown';
  const b = buf[0];
  if (b < 2) return 'stun';
  if (b >= 20 && b <= 63) return 'dtls';
  if (b >= 64 && b <= 79) return 'turn';
  if (b >= 128 && b <= 191) {
    if (buf.length < 2) return 'unknown';
    const pt = buf[1] & 0x7f;
    return (pt >= 64 && pt <= 95) ? 'rtcp' : 'rtp';
  }
  return 'unknown';
}

module.exports = {
  SrtpContext, createSrtpPair, demuxPacket,
  rtpHeaderLength, srtpKdf, estimateIndex, LABEL,
};
