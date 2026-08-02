'use strict';
// Bir uygulamanın dış dünyaya bakan UDP dinleyicisi.
//
// UDP'de "bağlantı" yoktur, akış vardır: aynı (kaynak IP, kaynak port) ikilisine
// gelen datagramlar bir akış sayılır ve karşı taraftaki yerel sokete aynı
// akıştan gönderilir. Akış tablosu boşta kalma süresiyle temizlenir.
//
// İki tehlike UDP'ye özgüdür ve ikisi de burada karşılanır:
//
//  1. YÜKSELTME. Kaynak adresi doğrulanamaz. Saldırgan kurbanın adresini yazıp
//     bize küçük bir istek atar, biz kurbana büyük bir yanıt göndeririz.
//     Akış "kurulmuş" sayılana kadar (birden fazla gelen paket) çıkan bayt
//     gelen baytın katıyla sınırlanır — guard.checkUdpOutbound.
//  2. AKIŞ TABLOSU ŞİŞMESİ. Her sahte kaynak yeni bir akıştır. Kaynak başına
//     ve genel akış tavanı bunu bağlar.
//
// Teslim politikası uygulama başınadır: 'unreliable' (varsayılan, tek atım —
// ses/video/oyun için doğru olan) ya da 'reliable' (kayıpsız, sıralı; DNS-over-
// UDP gibi kaybı pahalı olan yükler için).

const dgram = require('node:dgram');

const {
  PROTO, DELIVERY, LIMITS, TIMING, RST_CODE,
} = require('../protocol/constants.js');
const frames = require('../protocol/frames.js');
const { frameDatagram, DatagramDeframer } = require('../common/dgram-frame.js');

let nextFlowId = 1;

class PublicUdpEndpoint {
  constructor({
    app, tunnel, guard, host, port, log,
  }) {
    this.app = app;
    this.tunnel = tunnel;
    this.guard = guard;
    this.host = host;
    this.port = port;
    this.log = log;

    this.socket = null;
    this.closed = false;

    /** "ip:port" -> flow */
    this.flows = new Map();
    /** flowId -> flow */
    this.byId = new Map();

    this.packetsIn = 0;
    this.packetsOut = 0;
    this.dropped = 0;

    this._sweepTimer = null;
  }

  get proto() { return PROTO.UDP; }
  get reliableMode() { return this.app.delivery === DELIVERY.RELIABLE; }

  listen() {
    return new Promise((resolve, reject) => {
      const type = this.host.includes(':') ? 'udp6' : 'udp4';
      const socket = dgram.createSocket({ type, reuseAddr: false });

      const onError = (err) => { socket.removeAllListeners(); reject(err); };
      socket.once('error', onError);
      socket.on('message', (msg, rinfo) => this._onMessage(msg, rinfo));

      socket.bind({ address: this.host, port: this.port }, () => {
        socket.removeListener('error', onError);
        socket.on('error', (err) => this.log.error('genel UDP dinleyici hatası', { port: this.port, err: err.message }));
        this.socket = socket;
        this._sweepTimer = setInterval(() => this._sweep(), 10_000);
        if (this._sweepTimer.unref) this._sweepTimer.unref();
        resolve(socket.address());
      });
    });
  }

  // -------------------------------------------------------------------------
  _onMessage(msg, rinfo) {
    if (this.closed || !this.app.enabled) return;
    this.packetsIn++;

    if (msg.length > LIMITS.MAX_DATAGRAM) {
      // Tek DTLS kaydına sığmayacak bir datagramı parçalamak, UDP'nin
      // semantiğini bozardı (alıcı bütün bir datagram bekler). Düşürmek ve
      // saymak, sessizce yarısını iletmekten dürüst.
      this.dropped++;
      return;
    }

    const key = `${rinfo.address}:${rinfo.port}`;
    let flow = this.flows.get(key);
    const isNew = !flow;

    const verdict = this.guard.checkUdpInbound(rinfo.address, msg.length, isNew);
    if (!verdict.ok) { this.dropped++; return; }

    if (isNew) {
      flow = this._createFlow(key, rinfo);
      if (!flow) { this.dropped++; return; }
    }

    flow.lastSeen = Date.now();
    flow.packetsIn++;
    flow.bytesIn += msg.length;

    if (this.reliableMode) {
      if (!flow.stream || flow.stream.closed) { this.dropped++; return; }
      // Uzunluk öneki şart: çoklayıcı bir BAYT AKIŞI sunar ve yazıları
      // bölüp birleştirebilir. Sınır korunmazsa iki datagram tek pakette
      // birleşir (bkz. common/dgram-frame.js).
      if (!flow.stream.write(frameDatagram(msg))) {
        // Pencere doluysa datagramı düşürüyoruz: kuyruklamak, "kayıpsız"
        // sözünü tutmak için gecikmeyi sınırsız büyütmek olurdu.
        this.dropped++;
      }
      return;
    }

    const frame = flow.announced
      ? frames.frameUdp({ flowId: flow.id, payload: msg })
      : frames.frameUdpNew({
        flowId: flow.id,
        appIdx: this.app.appIdx,
        remoteAddress: rinfo.address,
        remotePort: rinfo.port,
        payload: msg,
      });

    // UDP_NEW, karşı taraftan bir yanıt görene kadar tekrar edilir: tek atım
    // bir kanalda ilk paketin kaybı akışın hiç kurulamaması demek olurdu.
    if (!this.tunnel.sendDatagram(frame)) this.dropped++;
  }

  _createFlow(key, rinfo) {
    if (this.flows.size >= this.guard.opt.udpMaxFlowsPerIp * 8) return null;

    const flow = {
      id: (nextFlowId = (nextFlowId + 1) >>> 0) || 1,
      key,
      address: rinfo.address,
      port: rinfo.port,
      createdAt: Date.now(),
      lastSeen: Date.now(),
      packetsIn: 0,
      packetsOut: 0,
      bytesIn: 0,
      bytesOut: 0,
      established: false,
      announced: false,
      stream: null,
    };

    if (this.reliableMode) {
      const stream = this.tunnel.openPublicConnection(this.app, {
        remoteAddress: rinfo.address,
        remotePort: rinfo.port,
        udpFlow: flow,
      });
      if (!stream) return null;
      flow.stream = stream;
      const deframer = new DatagramDeframer();
      stream.on('data', (chunk) => {
        let datagrams;
        try { datagrams = deframer.push(chunk); } catch (err) {
          this.log.warn('bozuk datagram çerçevesi, akış düşürülüyor', { err: err.message });
          stream.reset(RST_CODE.FLOW_VIOLATION);
          return;
        }
        for (const payload of datagrams) this._sendToPeer(flow, payload);
        stream.consumed(chunk.length);
      });
      stream.on('close', () => this._closeFlow(flow));
    }

    this.flows.set(key, flow);
    this.byId.set(flow.id, flow);
    // Akış numaraları süreç genelinde tekildir; tünel, karşıdan gelen bir
    // datagramı hangi dinleyiciye vereceğini bu kayıttan bulur.
    this.tunnel.trackFlow(flow.id, this);
    this.guard.noteUdpFlowOpen(rinfo.address);
    return flow;
  }

  /** Tünelden gelen güvenilir olmayan datagramı dış istemciye iletir. */
  deliver(flowId, payload) {
    const flow = this.byId.get(flowId);
    if (!flow) return false;
    flow.announced = true; // karşı taraf akışı tanıdı
    return this._sendToPeer(flow, payload);
  }

  _sendToPeer(flow, payload) {
    if (this.closed || !this.socket) return false;
    if (!this.guard.checkUdpOutbound(flow, payload.length)) return false;
    flow.lastSeen = Date.now();
    flow.packetsOut++;
    flow.bytesOut += payload.length;
    this.packetsOut++;
    this.socket.send(payload, flow.port, flow.address, (err) => {
      if (err) this.log.debug('UDP yanıtı gönderilemedi', { err: err.message, port: flow.port });
    });
    return true;
  }

  closeFlowById(flowId) {
    const flow = this.byId.get(flowId);
    if (flow) this._closeFlow(flow);
  }

  _closeFlow(flow) {
    if (!this.flows.has(flow.key)) return;
    this.flows.delete(flow.key);
    this.byId.delete(flow.id);
    this.tunnel.untrackFlow(flow.id);
    this.guard.noteUdpFlowClose(flow.address);
    if (flow.stream && !flow.stream.closed) flow.stream.reset(RST_CODE.TIMEOUT);
    if (!this.reliableMode) this.tunnel.sendDatagram(frames.frameUdpClose({ flowId: flow.id }));
  }

  _sweep() {
    const now = Date.now();
    for (const flow of [...this.flows.values()]) {
      if (now - flow.lastSeen > TIMING.UDP_FLOW_IDLE_MS) this._closeFlow(flow);
    }
  }

  close() {
    if (this.closed) return Promise.resolve();
    this.closed = true;
    if (this._sweepTimer) clearInterval(this._sweepTimer);
    for (const flow of [...this.flows.values()]) this._closeFlow(flow);
    if (!this.socket) return Promise.resolve();
    return new Promise((resolve) => {
      try { this.socket.close(() => resolve()); } catch { resolve(); }
    });
  }
}

module.exports = { PublicUdpEndpoint };
