'use strict';
// ECDHE for TLS/DTLS 1.3 — RFC 8446 §4.2.8, §7.4.
//
// İki curve destekliyoruz:
//   - X25519   (NamedGroup 0x001d) — 32-byte raw public, 32-byte shared secret
//   - SECP256R1 (NamedGroup 0x0017) — 65-byte uncompressed point (0x04 || X || Y), 32-byte shared
//
// Node built-in'leri:
//   crypto.generateKeyPairSync('x25519')          — raw export JWK/PKCS8
//   crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
//   crypto.diffieHellman({ privateKey, publicKey }) — shared secret
//
// Wire format:
//   X25519   : 32 byte raw public
//   SECP256R1: 65 byte (0x04 || X32 || Y32) uncompressed
//
// TLS 1.3 RFC 8446 §7.4.2: EC public key MUST be uncompressed (0x04 prefix).

const crypto = require('node:crypto');
const { NAMED_GROUP, NAMES } = require('../constants.js');

// --------------------------------------------------------------------------
// Keypair üretme
// --------------------------------------------------------------------------
function generateKeyPair(group) {
  switch (group) {
    case NAMED_GROUP.X25519: {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      return { group, publicKey, privateKey, publicRaw: exportX25519Public(publicKey) };
    }
    case NAMED_GROUP.SECP256R1: {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      return { group, publicKey, privateKey, publicRaw: exportP256PublicUncompressed(publicKey) };
    }
    default:
      throw new Error(`unsupported group: ${NAMES.NAMED_GROUP[group] || group}`);
  }
}

// --------------------------------------------------------------------------
// Peer public'i KeyObject'e çevir (wire → KeyObject)
// --------------------------------------------------------------------------
function importPeerPublic(group, raw) {
  switch (group) {
    case NAMED_GROUP.X25519:
      if (raw.length !== 32) throw new Error(`x25519 public must be 32 bytes, got ${raw.length}`);
      return importX25519Public(raw);
    case NAMED_GROUP.SECP256R1:
      if (raw.length !== 65 || raw[0] !== 0x04) {
        throw new Error(`p256 public must be 65 bytes uncompressed (0x04), got len=${raw.length} prefix=0x${raw[0]?.toString(16)}`);
      }
      return importP256PublicUncompressed(raw);
    default:
      throw new Error(`unsupported group: ${group}`);
  }
}

// --------------------------------------------------------------------------
// Shared secret hesapla — tüm curve'ler için 32-byte (X25519) veya P-256 için X-coord (32 byte)
// Node'un diffieHellman() zaten doğru boyu döndürür; TLS ise ek kısma yapmaz.
// --------------------------------------------------------------------------
function computeSharedSecret(privateKey, peerPublicKey) {
  return crypto.diffieHellman({ privateKey, publicKey: peerPublicKey });
}

// --------------------------------------------------------------------------
// X25519 export/import — JWK "x" alanı base64url encoded 32-byte raw public.
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
// X25519 export/import - JWK "x" alanı base64url encoded 32-byte raw public.
// --------------------------------------------------------------------------

function exportX25519Public(pubKeyObj) {
  const jwk = pubKeyObj.export({ format: 'jwk' });
  const rawBytes = Buffer.from(jwk.x, 'base64url');
  
  if (rawBytes.length !== 32) {
    throw new Error(`X25519 RAW Public Key export hatası: Beklenen 32 byte, dönen ${rawBytes.length}`);
  }
  return rawBytes;
}

function importX25519Public(raw32) {
  if (raw32.length !== 32) {
    throw new Error(`X25519 RAW Public Key import hatası: Beklenen 32 byte, gelen ${raw32.length}`);
  }
  
  // JWK formatını kullanarak Node.js'e 32 byte'ı ASN.1 olmadan zorla tanıtıyoruz
  const jwk = { 
    kty: 'OKP', 
    crv: 'X25519', 
    x: raw32.toString('base64url') 
  };
  
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// --------------------------------------------------------------------------
// P-256 uncompressed export/import — JWK "x"/"y" alanları 32-byte big-endian.
// Wire: 0x04 || X || Y
// --------------------------------------------------------------------------
function exportP256PublicUncompressed(pubKeyObj) {
  const jwk = pubKeyObj.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  if (x.length !== 32 || y.length !== 32) throw new Error('P-256 JWK coord length != 32');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function importP256PublicUncompressed(raw65) {
  const x = raw65.slice(1, 33);
  const y = raw65.slice(33, 65);
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: x.toString('base64url'),
    y: y.toString('base64url'),
  };
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

module.exports = {
  generateKeyPair,
  importPeerPublic,
  computeSharedSecret,
};
