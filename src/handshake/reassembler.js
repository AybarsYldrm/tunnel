'use strict';
// Handshake fragment reassembly — RFC 9147 §5.5.
//
// Certificate ve benzeri büyük mesajlar UDP MTU'suna sığmayıp birden çok handshake
// fragment'ına bölünür. Bu modül message_seq başına bir buffer tutar, her fragment
// geldiğinde doğru offset'e yerleştirir, tüm boşluklar kapandığında "complete" döner.

class HsReassembler {
  constructor() {
    // messageSeq -> { msgType, length, data:Buffer, got:Array<[start,end]> }
    this.messages = new Map();
  }

  // hdr: { msgType, length, messageSeq, fragmentOffset, fragmentLength, body (fragment) }
  add(hdr) {
    const key = hdr.messageSeq;
    let m = this.messages.get(key);
    if (!m) {
      m = { msgType: hdr.msgType, length: hdr.length, data: Buffer.alloc(hdr.length), got: [] };
      this.messages.set(key, m);
    }
    if (m.msgType !== hdr.msgType || m.length !== hdr.length) {
      throw new Error(`fragment inconsistent for seq=${key}`);
    }
    const start = hdr.fragmentOffset;
    const end = start + hdr.fragmentLength;
    if (end > m.length) throw new Error('fragment overflow');
    hdr.body.copy(m.data, start);
    m.got.push([start, end]);
    m.got.sort((a, b) => a[0] - b[0]);
    // Merge overlapping intervals
    const merged = [];
    for (const [s, e] of m.got) {
      if (merged.length && merged[merged.length - 1][1] >= s) {
        merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], e);
      } else merged.push([s, e]);
    }
    m.got = merged;
    const complete = merged.length === 1 && merged[0][0] === 0 && merged[0][1] === m.length;
    if (complete) {
      this.messages.delete(key);
      return {
        complete: true,
        messageSeq: key,
        msgType: m.msgType,
        length: m.length,
        body: m.data,
      };
    }
    return { complete: false, messageSeq: key, covered: merged };
  }

  clear() { this.messages.clear(); }
}

module.exports = { HsReassembler };
