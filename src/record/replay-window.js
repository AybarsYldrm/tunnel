'use strict';
// Replay window — RFC 9147 §4.5.2.
//
// 64-wide sliding bitmap. Epoch başına bir window. Tekrar paketleri reddet.

class ReplayWindow {
  constructor(size = 64) {
    if (size > 64) throw new Error('size > 64 desteklenmiyor');
    this.size = size;
    this.high = -1; // en yüksek kabul edilmiş seq
    this.bits = 0n; // bit N = (high - N)'inci seq görüldü mü
  }

  // seq ilk defa görüldüyse true döner, gördüysek/çok eskiyse false
  check(seq) {
    if (seq < 0) return false;
    if (seq > this.high) return true;
    const delta = this.high - seq;
    if (delta >= this.size) return false; // pencerenin dışında
    const mask = 1n << BigInt(delta);
    return (this.bits & mask) === 0n;
  }

  mark(seq) {
    if (seq > this.high) {
      const shift = seq - this.high;
      if (shift >= this.size) this.bits = 1n;
      else this.bits = ((this.bits << BigInt(shift)) | 1n) & ((1n << BigInt(this.size)) - 1n);
      this.high = seq;
    } else {
      const delta = this.high - seq;
      this.bits |= (1n << BigInt(delta));
    }
  }

  // Atomik: önce kontrol, sonra işaretle. Replay ise false.
  accept(seq) {
    if (!this.check(seq)) return false;
    this.mark(seq);
    return true;
  }
}

module.exports = { ReplayWindow };
