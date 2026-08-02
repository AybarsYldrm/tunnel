'use strict';
// RFC 9147 §7 — ACK Content Type = 26.
//
//   struct {
//     RecordNumber record_numbers<0..2^16-1>;
//   } ACK;
//   struct { uint64 epoch; uint64 sequence_number; } RecordNumber;

function buildAck(recordNumbers /* [{epoch, seq}] */) {
  const body = Buffer.alloc(recordNumbers.length * 16);
  let o = 0;
  for (const { epoch, seq } of recordNumbers) {
    body.writeBigUInt64BE(BigInt(epoch), o); o += 8;
    body.writeBigUInt64BE(BigInt(seq),   o); o += 8;
  }
  const out = Buffer.alloc(2 + body.length);
  out.writeUInt16BE(body.length, 0);
  body.copy(out, 2);
  return out;
}

function parseAck(body) {
  const len = body.readUInt16BE(0);
  const out = [];
  let o = 2;
  while (o < 2 + len) {
    const epoch = Number(body.readBigUInt64BE(o)); o += 8;
    const seq   = Number(body.readBigUInt64BE(o)); o += 8;
    out.push({ epoch, seq });
  }
  return out;
}

module.exports = { buildAck, parseAck };
