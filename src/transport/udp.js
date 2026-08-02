'use strict';
// node:dgram sarmalayıcısı — event-driven, metrikli, DTLS için optimize.
// Datagram bütünlüğü UDP seviyesinde korunur; record-layer demux üst katmanda.

const dgram = require('node:dgram');
const { EventEmitter } = require('node:events');
const { mk } = require('../logger.js');

class UdpEndpoint extends EventEmitter {
  constructor(opts = {}) {
    super();
    const {
      name = 'udp',
      logComponent,
      type = 'udp4',
      recvBufferSize = 1 << 20,
      host,
      port,
    } = opts;

    this.name = logComponent || name;
    this.log = mk(this.name);
    this.sock = dgram.createSocket({ type, recvBufferSize });
    this.stats = { rxDatagrams: 0, txDatagrams: 0, rxBytes: 0, txBytes: 0 };
    this._defaultHost = host;
    this._defaultPort = port;

    this.sock.on('message', (msg, rinfo) => {
      this.stats.rxDatagrams += 1;
      this.stats.rxBytes += msg.length;
      this.log.trace(`rx ${msg.length}B from ${rinfo.address}:${rinfo.port}`);
      this.emit('datagram', msg, rinfo);
    });

    this.sock.on('error', (err) => {
      this.log.error('socket error', { message: err.message, code: err.code });
      this.emit('error', err);
    });

    this.sock.on('close', () => this.log.info('socket closed'));
  }

  // Üç form:
  //   bind()                      → constructor default host/port
  //   bind(port, address)         → klasik
  //   bind({ host, port })        → objesel
  bind(a, b) {
    let port, address;
    if (typeof a === 'object' && a !== null) {
      port = a.port ?? this._defaultPort ?? 0;
      address = a.host ?? a.address ?? '0.0.0.0';
    } else if (a === undefined && b === undefined) {
      port = this._defaultPort ?? 0;
      address = this._defaultHost ?? '0.0.0.0';
    } else {
      port = a ?? 0;
      address = b ?? '0.0.0.0';
    }
    return new Promise((resolve, reject) => {
      const onErr = (e) => { this.sock.removeListener('error', onErr); reject(e); };
      this.sock.once('error', onErr);
      this.sock.bind(port, address, () => {
        this.sock.removeListener('error', onErr);
        const aa = this.sock.address();
        this.log.info(`listening on ${aa.address}:${aa.port}`);
        resolve(aa);
      });
    });
  }

  // İki form:
  //   send(buf, port, address)
  //   send(buf, { address, port })   (dgram rinfo uyumlu)
  send(buf, aOrRinfo, address) {
    let port, addr;
    if (typeof aOrRinfo === 'object' && aOrRinfo !== null) {
      port = aOrRinfo.port;
      addr = aOrRinfo.address;
    } else {
      port = aOrRinfo;
      addr = address;
    }
    return new Promise((resolve, reject) => {
      this.sock.send(buf, 0, buf.length, port, addr, (err, bytes) => {
        if (err) return reject(err);
        this.stats.txDatagrams += 1;
        this.stats.txBytes += bytes;
        this.log.trace(`tx ${bytes}B to ${addr}:${port}`);
        resolve(bytes);
      });
    });
  }

  address() { return this.sock.address(); }

  close() {
    return new Promise((resolve) => this.sock.close(resolve));
  }
}

module.exports = { UdpEndpoint };
