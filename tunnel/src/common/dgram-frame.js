'use strict';
// Güvenilir bir AKIŞ üzerinde datagram sınırlarını korumak.
//
// Neden gerekli? Çoklayıcı bir BAYT AKIŞI sunar, mesaj kuyruğu değil:
// zamanlayıcı bir yazıyı bölebilir (segment sınırında) ya da iki yazıyı
// birleştirebilir (aynı segmentte). Bu, TCP için doğru ve istenen davranıştır
// — orada zaten bayt akışı vardır. Ama UDP'nin sözleşmesi başkadır: "bir
// datagram gönderdim, bir datagram alacaksın". Sınırlar korunmazsa iki DNS
// yanıtı tek pakette birleşir ve alıcı ikisini de çözemez.
//
// Uzunluk öneki 2 bayt: azami datagram boyutu zaten tek DTLS kaydına sığacak
// kadar (bkz. LIMITS.MAX_DATAGRAM), yani 64 KiB fazlasıyla yeter.

const LENGTH_BYTES = 2;
const MAX_FRAME = 0xffff;

function frameDatagram(payload) {
  if (payload.length > MAX_FRAME) throw new Error(`datagram çok büyük: ${payload.length}`);
  const out = Buffer.allocUnsafe(LENGTH_BYTES + payload.length);
  out.writeUInt16BE(payload.length, 0);
  payload.copy(out, LENGTH_BYTES);
  return out;
}

/**
 * Parçalı gelen baytlardan tam datagramları çıkarır.
 *
 * Sınırlı tampon: bozuk ya da kötü niyetli bir karşı taraf, hiç tamamlanmayan
 * bir uzunluk bildirip belleği doldurmaya çalışabilir. Tampon tavanı aşılırsa
 * ayrıştırıcı hata verir ve çağıran akışı düşürür.
 */
class DatagramDeframer {
  constructor({ maxBuffered = 256 * 1024 } = {}) {
    this.buffer = Buffer.alloc(0);
    this.maxBuffered = maxBuffered;
  }

  /**
   * @param {Buffer} chunk
   * @returns {Buffer[]} tamamlanan datagramlar
   */
  push(chunk) {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > this.maxBuffered) {
      throw new Error(`datagram tamponu taştı (${this.buffer.length} bayt)`);
    }

    const out = [];
    let off = 0;
    while (this.buffer.length - off >= LENGTH_BYTES) {
      const len = this.buffer.readUInt16BE(off);
      if (this.buffer.length - off - LENGTH_BYTES < len) break;
      out.push(this.buffer.subarray(off + LENGTH_BYTES, off + LENGTH_BYTES + len));
      off += LENGTH_BYTES + len;
    }
    // Kalanı kopyalayarak sakla: `subarray` alttaki büyük tamponu canlı
    // tutardı ve 2 baytlık bir kalıntı yüzünden megabaytlar serbest kalmazdı.
    this.buffer = off === 0 ? this.buffer : Buffer.from(this.buffer.subarray(off));
    return out;
  }
}

module.exports = { frameDatagram, DatagramDeframer, LENGTH_BYTES, MAX_FRAME };
