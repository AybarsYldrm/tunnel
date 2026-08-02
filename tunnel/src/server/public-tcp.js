'use strict';
// Bir uygulamanın dış dünyaya bakan TCP dinleyicisi.
//
// Yaşam süresi TÜNELE bağlıdır: tünel bağlıyken açıktır, koptuğunda kapanır.
// "Açık ama arkasında kimse yok" bir durum bilinçli olarak yoktur — o durumda
// bağlantı kabul edilir, kısa bir süre bekletilir ve sonra düşer; dışarıdaki
// istemci için bu, hemen reddedilmekten çok daha kafa karıştırıcıdır.

const net = require('node:net');

const { PROTO } = require('../protocol/constants.js');

class PublicTcpEndpoint {
  /**
   * @param {object} o
   * @param {object} o.app      bağlı uygulama kaydı
   * @param {object} o.tunnel   sahibi tünel
   * @param {object} o.guard
   * @param {string} o.host     dinlenecek genel adres
   * @param {number} o.port
   */
  constructor({
    app, tunnel, guard, host, port, log, backlog = 511,
  }) {
    this.app = app;
    this.tunnel = tunnel;
    this.guard = guard;
    this.host = host;
    this.port = port;
    this.backlog = backlog;
    this.log = log;
    this.server = null;
    this.closed = false;
    this.accepted = 0;
    this.refused = 0;
  }

  get proto() { return PROTO.TCP; }

  listen() {
    return new Promise((resolve, reject) => {
      const server = net.createServer({ pauseOnConnect: true }, (socket) => this._onConnection(socket));
      server.maxConnections = this.guard.opt.maxConnectionsPerApp;

      const onError = (err) => { server.removeAllListeners(); reject(err); };
      server.once('error', onError);
      server.listen({ host: this.host, port: this.port, backlog: this.backlog }, () => {
        server.removeListener('error', onError);
        server.on('error', (err) => this.log.error('genel TCP dinleyici hatası', { port: this.port, err: err.message }));
        this.server = server;
        resolve(server.address());
      });
    });
  }

  _onConnection(socket) {
    // `pauseOnConnect` ile geliyor: kabul kararını vermeden tek bayt bile
    // okumuyoruz. Okumaya başlayıp sonra reddetmek, reddedilen bağlantının da
    // bellek ve CPU harcaması demek olurdu.
    const ip = socket.remoteAddress || '0.0.0.0';

    if (this.closed || !this.app.enabled) {
      this.refused++;
      socket.destroy();
      return;
    }

    const verdict = this.guard.checkAccept(ip, this.app.appId);
    if (!verdict.ok) {
      this.refused++;
      socket.destroy();
      return;
    }

    const stream = this.tunnel.openPublicConnection(this.app, {
      remoteAddress: ip,
      remotePort: socket.remotePort || 0,
      socket,
    });

    if (!stream) {
      this.refused++;
      this.guard.noteClose(ip, this.app.appId);
      socket.destroy();
      return;
    }

    this.accepted++;
    this.guard.noteOpen(ip, this.app.appId);

    // Slowloris zamanlayıcısı iki yönden de iptal olabilir: istemci konuşursa
    // ya da hedef servis önce konuşursa (SMTP, FTP gibi sunucu-önce konuşan
    // protokoller). Yalnızca istemciyi beklemek onları kırardı.
    const cancel = this.guard.armFirstByte(socket, ip);
    stream.once('data', cancel);
    stream.once('close', () => this.guard.noteClose(ip, this.app.appId));

    socket.resume();
  }

  close() {
    if (this.closed) return Promise.resolve();
    this.closed = true;
    if (!this.server) return Promise.resolve();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }
}

module.exports = { PublicTcpEndpoint };
