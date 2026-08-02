'use strict';
const crypto = require('node:crypto');

// Sıfır bağımlılık için kendi minik CRC32 tablomuz (FINGERPRINT için gerekli)
const crc32Table = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
        c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
    }
    crc32Table[i] = c;
}

function crc32(buffer) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buffer.length; i++) {
        crc = crc32Table[(crc ^ buffer[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function createStunBindingResponse(requestBuffer, serverIp, serverPort, icePwd) {
  // STUN Binding Request kontrolü
  if (requestBuffer.readUInt16BE(0) !== 0x0001) return null;
  const transactionId = requestBuffer.slice(8, 20);
  
  // Neler eklenecek?
  // 1. XOR-MAPPED-ADDRESS: 12 byte
  // 2. MESSAGE-INTEGRITY:  24 byte
  // 3. FINGERPRINT:         8 byte
  // Toplam Attributes:     44 byte
  
  const buf = Buffer.alloc(20 + 44);
  
  // --- STUN HEADER ---
  buf.writeUInt16BE(0x0101, 0); // Binding Success Response
  buf.writeUInt16BE(44, 2);     // Toplam attribute uzunluğu
  buf.writeUInt32BE(0x2112A442, 4); // Magic Cookie
  transactionId.copy(buf, 8);
  
  // --- 1. XOR-MAPPED-ADDRESS (Type: 0x0020) ---
  buf.writeUInt16BE(0x0020, 20); 
  buf.writeUInt16BE(8, 22);      
  buf.writeUInt8(0, 24);
  buf.writeUInt8(1, 25);         // IPv4
  const xorPort = serverPort ^ (0x2112A442 >>> 16);
  buf.writeUInt16BE(xorPort, 26);
  const ipParts = serverIp.split('.').map(Number);
  const xorIp = (((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) ^ 0x2112A442) >>> 0;
  buf.writeUInt32BE(xorIp, 28);
  
  // --- 2. MESSAGE-INTEGRITY (Type: 0x0008) ---
  buf.writeUInt16BE(0x0008, 32); 
  buf.writeUInt16BE(20, 34);     
  
  // HMAC-SHA1 kuralı: Sadece bu attribute'a kadar olan kısım hash'lenir!
  // Bu yüzden header'daki length alanını geçici olarak 36 (12+24) yapıyoruz.
  buf.writeUInt16BE(36, 2); 
  
  const hmac = crypto.createHmac('sha1', icePwd);
  hmac.update(buf.slice(0, 32)); 
  const mac = hmac.digest();
  mac.copy(buf, 36);
  
  // --- 3. FINGERPRINT (Type: 0x8028) ---
  buf.writeUInt16BE(0x8028, 56); 
  buf.writeUInt16BE(4, 58);      
  
  // Orijinal toplam uzunluğu (44) FINGERPRINT hesabı için geri koyuyoruz.
  buf.writeUInt16BE(44, 2); 
  
  // FINGERPRINT kuralı: Paketin buraya kadar olan kısmının CRC32'si XOR 0x5354554e
  const crc = crc32(buf.slice(0, 56));
  buf.writeUInt32BE((crc ^ 0x5354554e) >>> 0, 60);
  
  return buf;
}

module.exports = { createStunBindingResponse };