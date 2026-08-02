'use strict';
// Bir TCP soketiyle mantıksal bir akışı birbirine bağlar — ve bunu geri
// basıncı HİÇBİR NOKTADA kırmadan yapar.
//
// Zincir şu: uzak TCP → yerel soket → mantıksal akış → DTLS kanalı → karşı
// tünel → oradaki soket → hedef servis. Bu zincirde tek bir yerde bile
// "önce tampona al, sonra bakarız" dersen, en yavaş halkanın hızı değil en
// hızlı halkanın hızı belirleyici olur ve fark bellekte birikir.
//
// İki yön iki farklı mekanizma kullanır ve ikisi de EK TAMPON GEREKTİRMEZ:
//
//   sokete gelen → akışa     : `stream.write()` false dönerse soket duraklatılır
//   akıştan gelen → sokete   : kredi, veri sokete YAZILDIKTAN sonra verilir
//
// İkinci yöndeki hız sınırı da krediyle yapılır: saniyede R bayt kredi verirsen
// uzun vadeli hız R olur, patlama ise pencere kadar sınırlı kalır. Bunun için
// ayrıca bir kuyruk tutmaya gerek yoktur — sınırlama, veriyi biriktirerek değil
// istemeyerek uygulanır.

const { RST_CODE } = require('../protocol/constants.js');

/**
 * Krediyi bir jeton kovasının hızında serbest bırakır.
 * Bu, tünelden yerel/genel sokete akan yönün bant genişliği sınırıdır.
 */
class CreditShaper {
  constructor(stream, bucket) {
    this.stream = stream;
    this.bucket = bucket;
    this.pending = 0;
    this.timer = null;
  }

  release(bytes) {
    if (bytes <= 0) return;
    if (!this.bucket || this.bucket.unlimited) { this.stream.consumed(bytes); return; }
    this.pending += bytes;
    this._drain();
  }

  _drain() {
    if (this.stream.closed) { this.pending = 0; this._clear(); return; }
    const granted = this.bucket.takePartial(this.pending);
    if (granted > 0) {
      this.pending -= granted;
      this.stream.consumed(granted);
    }
    if (this.pending > 0) this._arm(this.bucket.msUntil(Math.min(this.pending, 1500)));
    else this._clear();
  }

  _arm(ms) {
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = null; this._drain(); }, Math.min(Math.max(ms, 2), 200));
    if (this.timer.unref) this.timer.unref();
  }

  _clear() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
  }
}

/**
 * TCP soketi ↔ mantıksal akış.
 *
 * @param {import('node:net').Socket} socket
 * @param {import('./mux.js').TunnelStream} stream
 * @param {object} [o]
 * @param {object} [o.ingressBucket] soketten tünele giden yön için hız sınırı
 * @param {object} [o.egressBucket]  tünelden sokete giden yön için hız sınırı
 * @param {(dir:'in'|'out', bytes:number)=>void} [o.onBytes] ölçüm kancası
 * @param {number} [o.idleMs] iki yönde de hareket olmazsa bağlantıyı düşür
 */
function bindSocketToStream(socket, stream, {
  ingressBucket = null, egressBucket = null, onBytes = null, idleMs = 0,
} = {}) {
  let finished = false;
  const shaper = new CreditShaper(stream, egressBucket);

  let idleTimer = null;
  const touch = () => {
    if (!idleMs) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => finish(RST_CODE.TIMEOUT, 'boşta kalma'), idleMs);
    if (idleTimer.unref) idleTimer.unref();
  };

  function finish(code, reason) {
    if (finished) return;
    finished = true;
    if (idleTimer) clearTimeout(idleTimer);
    shaper._clear();
    socket.destroy();
    if (!stream.closed) stream.reset(code ?? RST_CODE.UNSPECIFIED);
  }

  socket.setNoDelay(true);

  // ---- soket → akış -------------------------------------------------------
  let ingressTimer = null;
  socket.on('data', (chunk) => {
    touch();
    if (onBytes) onBytes('in', chunk.length);
    if (ingressBucket && !ingressBucket.unlimited) {
      // Kova boşsa soketi duraklat. Veriyi alıp beklemek yerine hiç almamak,
      // sınırın karşı taraftaki TCP penceresine kadar geri gitmesini sağlar.
      if (ingressBucket.take(chunk.length) === 0) {
        socket.pause();
        const wait = ingressBucket.msUntil(chunk.length);
        if (!ingressTimer) {
          ingressTimer = setTimeout(() => {
            ingressTimer = null;
            ingressBucket.take(chunk.length);
            if (!finished) socket.resume();
          }, Math.min(Math.max(wait, 2), 250));
          if (ingressTimer.unref) ingressTimer.unref();
        }
      }
    }
    if (!stream.write(chunk)) socket.pause();
  });

  stream.on('drain', () => { if (!finished && !ingressTimer) socket.resume(); });

  socket.on('end', () => {
    // Yarı kapatma: karşı taraf hâlâ bize yazabilir, akışı RESET'lemiyoruz.
    stream.end();
  });

  socket.on('error', () => finish(RST_CODE.LOCAL_ERROR, 'soket hatası'));
  socket.on('close', () => {
    if (finished) return;
    // `end` görülmeden kapandıysa bu bir yarım kapanma değil kopmadır.
    if (stream.writable) finish(RST_CODE.LOCAL_ERROR, 'soket kapandı');
    else { finished = true; if (idleTimer) clearTimeout(idleTimer); shaper._clear(); }
  });

  // ---- akış → soket -------------------------------------------------------
  stream.on('data', (chunk) => {
    touch();
    if (onBytes) onBytes('out', chunk.length);
    if (socket.destroyed) { shaper.release(chunk.length); return; }
    // Kredi, veri çekirdeğe teslim EDİLDİKTEN sonra verilir. Hemen vermek,
    // pencereyi "aldım" anlamına indirger; oysa soruyu "işledim mi" diye
    // sormamız gerekiyor.
    socket.write(chunk, () => shaper.release(chunk.length));
  });

  stream.on('end', () => {
    if (!socket.destroyed) socket.end();
  });

  stream.on('close', () => {
    if (finished) return;
    finished = true;
    if (idleTimer) clearTimeout(idleTimer);
    shaper._clear();
    if (!socket.destroyed) socket.destroy();
  });

  touch();
  return { finish };
}

module.exports = { bindSocketToStream, CreditShaper };
