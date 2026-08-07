'use strict';
// FTP çerçeveleri — kodlama ve çözme.
//
// Üç ayrı taşıma yolu vardır ve hangisinin kullanıldığı ÇERÇEVENİN KENDİSİNDEN
// değil, geldiği akıştan bellidir:
//
//   denetim akışı (streamId 0)  -> CTRL.*    sıralı, güvenilir
//   veri akışı    (streamId>0)  -> DATA.*    sıralı, güvenilir, akış başına
//   RAW datagram  (akışsız)     -> DGRAM.*   tek atım, yeniden gönderim yok
//
// Bu ayrım sayesinde veri çerçevesinin başlığı TEK BAYTTIR: akış numarası ve
// sıra bilgisini alt katman zaten taşıyor, burada tekrar etmek onu iki kez
// ödemek olurdu.

const {
  Writer, Reader, ProtocolError, encodeIp, decodeIp,
} = require('./codec.js');
const {
  CTRL, DATA, DGRAM, LIMITS, PROTOCOL_VERSION,
} = require('./constants.js');

/** CREDIT içinde tünel geneli pencereyi gösteren sözde akış numarası. */
const CONNECTION_STREAM = 0xffff;

// ===========================================================================
// Denetim düzlemi
// ===========================================================================

function encodeHello({
  version = PROTOCOL_VERSION, agent = '', hostname = '', clientName = '', features = 0,
}) {
  return new Writer(96)
    .u8(CTRL.HELLO).u8(version).u32(features)
    .str8(agent).str8(hostname).str8(clientName)
    .done();
}

function encodeHelloOk({
  version = PROTOCOL_VERSION, tunnelId, heartbeatMs, maxStreams,
  streamWindow, connectionWindow, segmentBytes, features = 0,
}) {
  return new Writer(64)
    .u8(CTRL.HELLO_OK).u8(version).u32(features)
    .str8(tunnelId)
    .u32(heartbeatMs).u16(maxStreams)
    .u32(streamWindow).u32(connectionWindow).u32(segmentBytes)
    .done();
}

function encodeHelloErr({ code, message = '' }) {
  return new Writer(64).u8(CTRL.HELLO_ERR).u8(code).str8(message).done();
}

function encodeBindReq({
  reqId, proto, delivery, ordered = true, localHost, localPort,
  desiredPublicPort = 0, name = '',
}) {
  return new Writer(96)
    .u8(CTRL.BIND_REQ).u32(reqId)
    .u8(proto).u8(delivery).u8(ordered ? 1 : 0)
    .str8(localHost).u16(localPort)
    .u16(desiredPublicPort).str8(name)
    .done();
}

function encodeBindOk({
  reqId, appIdx, appId, publicHost = '', publicPort, proto, delivery, ordered = true,
}) {
  return new Writer(96)
    .u8(CTRL.BIND_OK).u32(reqId)
    .u16(appIdx).str8(appId)
    .str8(publicHost).u16(publicPort)
    .u8(proto).u8(delivery).u8(ordered ? 1 : 0)
    .done();
}

function encodeBindErr({ reqId, code, message = '' }) {
  return new Writer(96).u8(CTRL.BIND_ERR).u32(reqId).u8(code).str8(message).done();
}

function encodeUnbind({ appIdx, reason = 0 }) {
  return new Writer(8).u8(CTRL.UNBIND).u16(appIdx).u8(reason).done();
}

/** Yönetim panelinden değişen uygulama tablosunun tamamı. Seyrek ve yapısı
 *  değişken olduğu için JSON: ileride alan eklemek istemciyi kırmamalı. */
function encodeAppSync(apps) {
  const body = Buffer.from(JSON.stringify(apps), 'utf8');
  return new Writer(body.length + 8).u8(CTRL.APP_SYNC).blob32(body).done();
}

/**
 * Kredi güncellemeleri toplu gider.
 *
 * Tek tek gönderilseydi yoğun bir aktarımda kredi mesajları veri mesajlarıyla
 * neredeyse birebir oranda olurdu; her biri kanalda ayrı bir paket numarası
 * ve ayrı bir ACK bekleyişi demektir. Bir turda biriken tüm güncellemeleri tek
 * çerçevede toplamak, denetim trafiğini akış sayısından bağımsız kılar.
 *
 * @param {Array<[number, number]>} entries [streamId, delta] çiftleri
 */
function encodeCredit(entries) {
  const list = entries.slice(0, 255);
  const w = new Writer(4 + list.length * 6).u8(CTRL.CREDIT).u8(list.length);
  for (const [streamId, delta] of list) w.u16(streamId).u32(delta);
  return w.done();
}

/**
 * Alıcının pencere TAVANLARINI büyüttüğünü bildirir.
 *
 * KREDİDEN FARKI: kredi "az önce tükettiğim şu kadar baytı geri veriyorum"
 * der ve tavanı değiştirmez. Bu çerçeve tavanın kendisini yükseltir — alıcı,
 * ölçtüğü bant genişliği-gecikme çarpımına göre daha fazla bellek taahhüt
 * etmiştir.
 *
 * SIRA GÜVENLİĞİ: alıcı ÖNCE kendi `recvWindow`unu büyütür, SONRA bu çerçeveyi
 * gönderir. Denetim akışı güvenilir ve sıralı olduğu için gönderen, alıcının
 * taahhüt etmediği bir pencereyi asla kullanamaz.
 */
const WINDOW_BLOCKED_FRAME = Buffer.from([CTRL.WINDOW_BLOCKED]);

function encodeWindow({ streamWindow, connectionWindow }) {
  return new Writer(12).u8(CTRL.WINDOW).u32(streamWindow).u32(connectionWindow).done();
}

/**
 * "Senin pencerenin yüzünden duruyorum."
 *
 * NEDEN GEREKLİ: pencere darboğazını ALICI kendi başına göremez. Alıcının
 * `recvWindow`u kredi üretilir üretilmez geri dolar; gönderenin `sendWindow`u
 * ise o kredi TELDEN GELENE KADAR sıfırda bekler. Yani tıkanma yalnızca
 * gönderende görünür. Alıcı taraf "tükeniyor muyum" diye kendine baktığında
 * hep "hayır" cevabını alır ve pencereyi büyütmesi gerektiğini asla anlamaz.
 *
 * Çerçeve yükü taşımaz: tek bilgi, olayın kendisidir. Gönderen tarafta
 * kısıtlanır (ayar aralığında en fazla bir kez), dolayısıyla tıkanmış bir
 * aktarım denetim düzlemini dolduramaz.
 */
function encodeWindowBlocked() { return WINDOW_BLOCKED_FRAME; }

function encodePing({ nonce, sentAt }) {
  return new Writer(12).u8(CTRL.PING).u32(nonce).u48(sentAt).done();
}

/** PONG, PING'in zaman damgasını AYNEN yansıtır: RTT ölçen taraf hiçbir durum
 *  tutmaz, tek çıkarma yapar. Nonce yalnızca eski bir yanıtı elemek için. */
function encodePong({ nonce, sentAt }) {
  return new Writer(12).u8(CTRL.PONG).u32(nonce).u48(sentAt).done();
}

function encodeStats(stats) {
  const body = Buffer.from(JSON.stringify(stats), 'utf8');
  return new Writer(body.length + 8).u8(CTRL.STATS).blob32(body).done();
}

function encodeConfig(config) {
  const body = Buffer.from(JSON.stringify(config), 'utf8');
  return new Writer(body.length + 8).u8(CTRL.CONFIG).blob32(body).done();
}

function encodeShutdown({ code = 0, message = '' }) {
  return new Writer(64).u8(CTRL.SHUTDOWN).u8(code).str8(message).done();
}

function parseJsonBlob(reader, what) {
  const raw = reader.blob32();
  if (raw.length > LIMITS.MAX_CONTROL_MESSAGE) {
    throw new ProtocolError(`${what} çok büyük: ${raw.length} bayt`);
  }
  try { return JSON.parse(raw.toString('utf8')); } catch (e) {
    throw new ProtocolError(`${what} çözümlenemedi: ${e.message}`);
  }
}

/** Denetim akışından gelen bir mesajı çözer. */
function decodeControl(buf) {
  if (!buf || buf.length === 0) throw new ProtocolError('boş denetim çerçevesi');
  const r = new Reader(buf, 1);
  const type = buf[0];

  switch (type) {
    case CTRL.HELLO:
      return {
        type, version: r.u8(), features: r.u32(), agent: r.str8(), hostname: r.str8(), clientName: r.str8(),
      };
    case CTRL.HELLO_OK:
      return {
        type,
        version: r.u8(),
        features: r.u32(),
        tunnelId: r.str8(),
        heartbeatMs: r.u32(),
        maxStreams: r.u16(),
        streamWindow: r.u32(),
        connectionWindow: r.u32(),
        segmentBytes: r.u32(),
      };
    case CTRL.HELLO_ERR:
      return { type, code: r.u8(), message: r.str8() };

    case CTRL.BIND_REQ:
      return {
        type,
        reqId: r.u32(),
        proto: r.u8(),
        delivery: r.u8(),
        ordered: r.u8() === 1,
        localHost: r.str8(),
        localPort: r.u16(),
        desiredPublicPort: r.u16(),
        name: r.str8(),
      };
    case CTRL.BIND_OK:
      return {
        type,
        reqId: r.u32(),
        appIdx: r.u16(),
        appId: r.str8(),
        publicHost: r.str8(),
        publicPort: r.u16(),
        proto: r.u8(),
        delivery: r.u8(),
        ordered: r.u8() === 1,
      };
    case CTRL.BIND_ERR:
      return { type, reqId: r.u32(), code: r.u8(), message: r.str8() };
    case CTRL.UNBIND:
      return { type, appIdx: r.u16(), reason: r.u8() };
    case CTRL.APP_SYNC:
      return { type, apps: parseJsonBlob(r, 'APP_SYNC') };

    case CTRL.CREDIT: {
      const count = r.u8();
      const entries = new Array(count);
      for (let i = 0; i < count; i++) entries[i] = [r.u16(), r.u32()];
      return { type, entries };
    }

    case CTRL.WINDOW:
      return { type, streamWindow: r.u32(), connectionWindow: r.u32() };
    case CTRL.WINDOW_BLOCKED:
      return { type };

    case CTRL.PING:
    case CTRL.PONG:
      return { type, nonce: r.u32(), sentAt: r.u48() };

    case CTRL.STATS:
      return { type, stats: parseJsonBlob(r, 'STATS') };
    case CTRL.CONFIG:
      return { type, config: parseJsonBlob(r, 'CONFIG') };
    case CTRL.SHUTDOWN:
      return { type, code: r.u8(), message: r.str8() };

    default:
      throw new ProtocolError(`bilinmeyen denetim tipi: 0x${type.toString(16)}`);
  }
}

// ===========================================================================
// Veri düzlemi
// ===========================================================================

/**
 * Yük çerçevesi. Tek tahsis, tek kopya — bu fonksiyon tünelin en sıcak yoludur;
 * `Buffer.concat` burada iki tahsis ve iki kopya ederdi.
 */
function frameBytes(payload) {
  const out = Buffer.allocUnsafe(payload.length + 1);
  out[0] = DATA.BYTES;
  payload.copy(out, 1);
  return out;
}

const FIN_FRAME = Buffer.from([DATA.FIN]);
const OPEN_ACK_FRAME = Buffer.from([DATA.OPEN_ACK]);

function frameFin() { return FIN_FRAME; }
function frameRst(code) { return Buffer.from([DATA.RST, code & 0xff]); }
function frameOpenAck() { return OPEN_ACK_FRAME; }

/**
 * Bir veri akışının İLK mesajı. Veriyle aynı sıralı akışta olduğu için
 * kendisinden sonra gelen ilk baytı asla geçirmez — bkz. constants.js'teki
 * DATA yorumu.
 */
function frameOpen({ appIdx, remoteAddress, remotePort }) {
  const w = new Writer(32).u8(DATA.OPEN).u16(appIdx);
  encodeIp(w, remoteAddress);
  return w.u16(remotePort).done();
}

/** Veri akışından gelen bir mesajı çözer. Yük KOPYALANMAZ. */
function decodeData(buf) {
  if (!buf || buf.length === 0) throw new ProtocolError('boş veri çerçevesi');
  switch (buf[0]) {
    case DATA.BYTES: return { type: DATA.BYTES, payload: buf.subarray(1) };
    case DATA.FIN: return { type: DATA.FIN };
    case DATA.RST: return { type: DATA.RST, code: buf.length > 1 ? buf[1] : 0 };
    case DATA.OPEN_ACK: return { type: DATA.OPEN_ACK };
    case DATA.OPEN: {
      const r = new Reader(buf, 1);
      return {
        type: DATA.OPEN, appIdx: r.u16(), remoteAddress: decodeIp(r), remotePort: r.u16(),
      };
    }
    default: throw new ProtocolError(`bilinmeyen veri tipi: 0x${buf[0].toString(16)}`);
  }
}

// ===========================================================================
// Güvenilir olmayan datagramlar
// ===========================================================================

function frameUdp({ flowId, payload }) {
  const out = Buffer.allocUnsafe(5 + payload.length);
  out[0] = DGRAM.UDP;
  out.writeUInt32BE(flowId >>> 0, 1);
  payload.copy(out, 5);
  return out;
}

function frameUdpNew({
  flowId, appIdx, remoteAddress, remotePort, payload,
}) {
  const w = new Writer(payload.length + 32);
  w.u8(DGRAM.UDP_NEW).u32(flowId).u16(appIdx);
  encodeIp(w, remoteAddress);
  w.u16(remotePort).bytes(payload);
  return w.done();
}

function frameUdpClose({ flowId }) {
  const out = Buffer.allocUnsafe(5);
  out[0] = DGRAM.UDP_CLOSE;
  out.writeUInt32BE(flowId >>> 0, 1);
  return out;
}

function decodeDatagram(buf) {
  if (!buf || buf.length === 0) throw new ProtocolError('boş datagram');
  const type = buf[0];
  switch (type) {
    case DGRAM.UDP: {
      if (buf.length < 5) throw new ProtocolError('kısa UDP datagramı');
      return { type, flowId: buf.readUInt32BE(1), payload: buf.subarray(5) };
    }
    case DGRAM.UDP_NEW: {
      const r = new Reader(buf, 1);
      const flowId = r.u32();
      const appIdx = r.u16();
      const remoteAddress = decodeIp(r);
      const remotePort = r.u16();
      return {
        type, flowId, appIdx, remoteAddress, remotePort, payload: r.rest(),
      };
    }
    case DGRAM.UDP_CLOSE: {
      if (buf.length < 5) throw new ProtocolError('kısa UDP_CLOSE');
      return { type, flowId: buf.readUInt32BE(1) };
    }
    default:
      throw new ProtocolError(`bilinmeyen datagram tipi: 0x${type.toString(16)}`);
  }
}

module.exports = {
  CONNECTION_STREAM,

  encodeHello, encodeHelloOk, encodeHelloErr,
  encodeBindReq, encodeBindOk, encodeBindErr, encodeUnbind, encodeAppSync,
  encodeCredit, encodeWindow, encodeWindowBlocked, encodePing, encodePong,
  encodeStats, encodeConfig, encodeShutdown,
  decodeControl,

  frameBytes, frameFin, frameRst, frameOpen, frameOpenAck, decodeData,

  frameUdp, frameUdpNew, frameUdpClose, decodeDatagram,

  ProtocolError,
};
