'use strict';
// ÖRNEK YAPILANDIRMA — `config.js` adıyla kopyalayın ve düzenleyin.
//
//   cp tunnel/config.example.js tunnel/config.js
//
// Bu dosya ORTAM DEĞİŞKENLERİNİN ÜSTÜNDE, çağrıya geçilen değerlerin ALTINDA
// çalışır. Yalnızca değiştirmek istediğiniz alanları yazmanız yeterli; geri
// kalanı varsayılanlarda kalır (src/server/config.js).
//
// Başka bir yol kullanmak isterseniz:  FITFAK_TUNNEL_CONFIG=/etc/tunnel.js
//
// SIRLAR HAKKINDA: bu dosya diske düz metin yazılır. Sunucuda `chmod 600` ve
// servis kullanıcısına ait olmalı. Sırları ortam değişkeninde tutmayı tercih
// ediyorsanız ilgili satırları silmeniz yeterli — silinen her alan otomatik
// olarak ortam değişkenine düşer.

const path = require('node:path');

const root = path.join(__dirname);
const dataDir = path.join(root, '.tunnel-data');

module.exports = {
  // ---- DTLS dinleyicisi ---------------------------------------------------
  host: '0.0.0.0',
  port: 4443,

  /**
   * 1200 bayt: IPv6'nın asgari MTU'su (1280) eksi IPv6 + UDP başlıkları.
   * Yol MTU keşfine güvenmeden HER yolda parçalanmadan geçer. Yükseltmeyin:
   * parçalanmış bir UDP datagramı tek bir parçanın kaybında tamamen ölür ve
   * bu, teşhis edilmesi en zor "bazen çalışıyor" arızasını üretir.
   */
  mtu: 1200,

  /**
   * Şifreleme paketi tercihi (sunucunun sırası bağlayıcıdır):
   *
   *   'balanced'  AES-128-GCM önce — AES-NI olan makinelerde en hızlı
   *   'aes256'    daha uzun anahtar isteyen kurumsal politikalar
   *   'chacha20'  AES donanım hızlandırması OLMAYAN uçlar (ARM, gömülü)
   *   'mobile'    ChaCha20 önce, AES yedek — karışık istemci parkı
   *   'aes'       yalnızca AES-GCM (FIPS 140-3 uyumu gerekiyorsa)
   *
   * Açık liste de verilebilir:
   *   cipher: ['TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256'],
   */
  cipher: 'balanced',

  /**
   * Tıkanıklık denetimi:
   *
   *   'bbr3'     (varsayılan) Hattın darboğaz hızını ve en küçük gecikmesini
   *              ÖLÇER. Kaybı tıkanıklık saymaz — mobil/Wi-Fi/uydu gibi
   *              rastgele kayıplı hatlarda ve uzun mesafede fark kat
   *              cinsindendir. Derin tamponlu hatlarda kuyruk gecikmesi
   *              üretmez (bufferbloat yok).
   *   'newreno'  RFC 9002 §7 — kayıp odaklı klasik davranış. Yalnızca
   *              karşılaştırma ya da özel bir gereksinim için.
   */
  congestionControl: 'bbr3',

  /** Sunucunun kendi sertifikası — trust.fitfak.net'ten alınır. */
  certPath: '/etc/fitfak/tunnel/server.crt',
  keyPath: '/etc/fitfak/tunnel/server.key',

  /** İstemci sertifikalarının doğrulanacağı güven çıpası (kök CA). */
  caPath: '',
  trustAnchorUrl: 'http://status.trust.fitfak.net/root.crt',
  servername: 'gateway.fitfak.net',

  /**
   * 'hard-fail': OCSP/CRL'e ulaşılamıyorsa BAĞLANMA. Bir tünel istemcisi ağın
   * içine doğrudan yol açtığı için, çalınmış bir anahtarın süresi dolana kadar
   * geçerli kalmasının bedeli, kısa bir erişim kesintisinden çok daha ağırdır.
   */
  revocation: 'hard-fail',

  // ---- genel (dış dünyaya bakan) yüzey ------------------------------------
  publicHost: '0.0.0.0',
  /** Panelde ve istemciye GÖSTERİLEN ad; bağlama adresi değil. */
  publicHostname: 'gateway.fitfak.net',
  portMin: 20000,
  portMax: 30000,
  /** Kopan tünelin portu bu süre boyunca ona ayrılmış kalır. */
  portLingerMs: 20_000,

  // ---- politika -----------------------------------------------------------
  allowClientBinds: true,
  /** İstemci SABİT bir genel port isteyebilir mi. Varsayılan hayır. */
  allowClientPortChoice: false,
  maxTunnels: 2000,

  // ---- yönetim yüzeyi -----------------------------------------------------
  admin: {
    enabled: true,
    host: '127.0.1.3',
    port: 80,
    idpUrl: 'https://session.fitfak.net',

    clientId: '',
    clientSecret: '',
    redirectUri: '',

    /** userinfo'daki role=admin dışında ayrıca kabul edilecek e-posta. */
    adminEmail: '',
    sessionTtlMs: 8 * 3600_000,

    /** CANLI SUNUCUDA ASLA true YAPMAYIN — kimlik doğrulamasını kapatır. */
    insecureNoAuth: false,

    /**
     * İçerik güvenliği politikası.
     *
     * Varsayılan hâliyle panel kendi kaynaklarından başka hiçbir yere gitmez
     * ve satır içi script/stil kullanmaz. Aşağıdakiler yalnızca gerçekten
     * ihtiyaç varsa açılmalı; her biri bir XSS'in kullanabileceği yüzeyi
     * genişletir.
     */
    csp: {
      /**
       * Cloudflare Web Analytics. Paneli Cloudflare'in arkasına koyduysanız
       * beacon.min.js'i O enjekte eder ve varsayılan politika onu engeller
       * (konsolda "Loading the script ... violates CSP" hatası budur).
       *
       * true yapmak TEK BİR kökene izin verir; 'unsafe-inline' AÇMAZ.
       * Alternatif: paneli Cloudflare'in arkasına koymayın — zaten bir geri
       * döngü adresinde dinliyor ve önünde kendi ters proxy'niz olmalı.
       */
      cloudflareInsights: false,

      /** Ek betik kaynakları (tam köken). Örn: ['https://cdn.example.com'] */
      scriptSrc: [],
      /** Ek bağlantı hedefleri (fetch/XHR/EventSource). */
      connectSrc: [],
      imgSrc: [],

      /**
       * Trusted Types: innerHTML'e yazmayı tarayıcı seviyesinde yasaklar.
       * Panel zaten hiç kullanmıyor, bu yüzden bedava geliyor. Yalnızca çok
       * eski bir tarayıcı parkı destekliyorsanız kapatın.
       */
      trustedTypes: true,

      /** İhlal raporlarının gönderileceği uç (isteğe bağlı). */
      reportUri: '',
    },
  },

  // ---- veritabanı ---------------------------------------------------------
  // Boş bırakılırsa BELLEK-İÇİ çalışır: yeniden başlatmada uygulama tanımları,
  // port rezervasyonları, engel listesi ve denetim kaydı KAYBOLUR.
  db: {
    target: '',
    serviceName: 'tunnel-service',
    databaseName: 'tunnel',
    enrolmentSecret: '',
    caFingerprint: '',
    caPath: '',
    dbId: '',
    clientSecret: '',
    identityDir: path.join(dataDir, 'identity'),
  },

  // ---- çoklayıcı sınırları ------------------------------------------------
  limits: {
    segmentBytes: 16 * 1024,
    streamWindow: 256 * 1024,
    connectionWindow: 8 * 1024 * 1024,
    maxStreams: 4096,

    /**
     * Kanalın gönderim kuyruğunda birikmesine izin verilen GECİKME (ms).
     *
     * Bu tek sayı, "hacimli bir aktarım sürerken diğer her şey bekliyor"
     * sorununun düğümü. Çoklayıcı kanala bu süreden fazlasını doldurmaz.
     * Ölçünün bayt değil zaman olması şart: aynı bayt bütçesi 1 Gbit'te 2 ms,
     * 5 Mbit'te altı saniye eder.
     *
     * Düşürmek gecikmeyi iyileştirir ama çok düşürülürse hat boş kalabilir
     * (kanal, ACK geldiğinde gönderecek veri bulamaz). 10-40 ms makul aralık.
     */
    targetQueueMs: 20,
  },

  // ---- çekirdek soket tamponları ------------------------------------------
  /**
   * UDP gönderim tamponu (bayt). 0 = işletim sistemi varsayılanı.
   *
   * Küçültmek NEDEN iyi olabilir: çekirdek tamponu bizim GÖREMEDİĞİMİZ bir
   * kuyruktur. Hız şekillendirici paketleri zamana yayar, ama tampon büyükse
   * paketler oraya yığılır ve öncelik sıralaması etkisiz kalır — gerçek zamanlı
   * bir paket bizim kuyruğumuzu atlar, çekirdektekinin arkasına düşer.
   * Şekillendirici zaten hızı sınırladığı için büyük bir tampona ihtiyaç yok.
   *
   * Yavaş yükleme hatlarında (≤50 Mbit) 256 KB iyi bir başlangıç.
   */
  sendBufferSize: 0,
  recvBufferSize: 1024 * 1024,

  // ---- koruma -------------------------------------------------------------
  guard: {
    acceptPerIpPerSec: 30,
    acceptGlobalPerSec: 2000,
    maxConnectionsPerIp: 128,
    maxConnectionsPerApp: 2048,
    maxConnectionsGlobal: 20000,
    firstByteTimeoutMs: 15_000,
    udpPacketsPerIpPerSec: 500,
    udpBytesPerIpPerSec: 2 * 1024 * 1024,
    udpMaxFlowsPerIp: 64,
  },

  dataDir,
  metricsIntervalMs: 60_000,
};
