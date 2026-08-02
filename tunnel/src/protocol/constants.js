'use strict';
// FTP — Fitfak Tunnel Protocol v1.
//
// Tünel, node-dtls'in GÜVENİLİR KANALI (src/reliable/channel.js) üzerine oturur.
// O katman zaten şunları veriyor: mesaj sınırı, akış (streamId) başına sıra,
// parçalama/birleştirme, RFC 9002 kayıp kurtarma ve NewReno tıkanıklık denetimi.
// Bu protokol onların ÜSTÜNE hiçbirini tekrar etmez; yalnızca kanalın vermediği
// üç şeyi ekler:
//
//   1. ÇOKLAMA        — hangi bayt hangi mantıksal bağlantıya ait
//   2. AKIŞ DENETİMİ  — kredi tabanlı pencere; alıcı yetişemiyorsa gönderen durur
//   3. DENETİM DÜZLEMİ— hangi portun nereye bağlanacağı, ölçümler, yapılandırma
//
// Neden kredi? Kanalın tıkanıklık penceresi AĞIN ne kadar taşıyabildiğini söyler,
// UYGULAMANIN ne kadar tüketebildiğini değil. İkisi karıştırılırsa 1 Gbit'lik bir
// bağlantıdan 1 Mbit'lik bir yerel servise veri pompalamak, farkı tünel sürecinin
// belleğinde biriktirir. Kredi penceresi tam olarak bunu engeller: yerel soket
// okumayı yavaşlatınca kredi akmaz, kredi akmayınca karşı taraf göndermez ve
// geri basınç uçtan uca TCP'ye kadar iner.

/** Kanal üzerindeki akış numarası (streamId) tahsisi. */
const STREAM = Object.freeze({
  /** Denetim düzlemi. Her zaman sıralı ve güvenilir. */
  CONTROL: 0,
  /** Mantıksal bağlantılara verilebilecek ilk/son akış numarası. */
  MIN_DATA: 1,
  MAX_DATA: 0xfffe,
});

/** Denetim düzlemi mesaj tipleri (denetim akışının ilk baytı). */
const CTRL = Object.freeze({
  HELLO: 0x01,
  HELLO_OK: 0x02,
  HELLO_ERR: 0x03,

  BIND_REQ: 0x10,
  BIND_OK: 0x11,
  BIND_ERR: 0x12,
  UNBIND: 0x13,
  /** Sunucu → istemci: yönetim panelinden değişen uygulama tablosunun tamamı. */
  APP_SYNC: 0x14,

  /** Akış denetimi kredisi. Veri akışında DEĞİL denetim akışında taşınır —
   *  aksi hâlde kredi, serbest bırakacağı verinin arkasında sıraya girerdi. */
  CREDIT: 0x30,

  PING: 0x40,
  PONG: 0x41,

  STATS: 0x50,
  CONFIG: 0x60,
  SHUTDOWN: 0x70,
});

/**
 * Veri düzlemi mesaj tipleri (bir veri akışının ilk baytı).
 *
 * OPEN'ın DENETİM AKIŞINDA DEĞİL burada olması bilinçli bir tasarım kararıdır.
 * Denetim akışı (0) ile veri akışı (N) birbirinden bağımsız sıralanır: OPEN
 * denetimden gitseydi, aynı anda gönderilen ilk veri baytları ondan ÖNCE
 * varabilirdi ve alıcı henüz var olmayan bir akışa ait çerçeveyi atardı.
 * Bağlantının ilk baytları kaybolurdu — HTTP'de ilk istek satırı, TLS'te
 * ClientHello. OPEN'ı aynı sıralı akışın İLK mesajı yapmak bunu yapısal olarak
 * imkânsız kılar ve üstelik bir tur da kazandırır: veri, açılışın onaylanmasını
 * beklemeden akmaya başlar.
 */
const DATA = Object.freeze({
  /** Yük baytları. Bu tek bayt, mesaj başına tek ek yüktür. */
  BYTES: 0x01,
  /** Bu yönden EOF (yarı kapatma). Veriyle AYNI sıralı akışta gider, bu yüzden
   *  kendisinden önceki son baytı asla geçemez. */
  FIN: 0x02,
  /** Anormal sonlandırma. */
  RST: 0x03,
  /** Akışın ilk mesajı: hangi uygulama, dışarıdaki istemci kim. */
  OPEN: 0x04,
  /** Yerel hedefe bağlanıldı. Yalnızca ölçüm için — veri beklemez. */
  OPEN_ACK: 0x05,
});

/** Güvenilir OLMAYAN datagram tipleri (kanalın RAW çerçevesinin ilk baytı). */
const DGRAM = Object.freeze({
  /** Bilinen bir akıştaki UDP datagramı. */
  UDP: 0x01,
  /** Yeni bir UDP akışının ilk datagramı — kaynak adresi satır içinde taşır,
   *  böylece yeni akış açmak bir tur gerektirmez. Kaybolursa bir sonraki
   *  datagram akışı yine kurar; UDP zaten kayıp toleranslıdır. */
  UDP_NEW: 0x02,
  /** Akış boşta kaldı, durumu bırak. */
  UDP_CLOSE: 0x03,
});

/** Uygulama protokolü. */
const PROTO = Object.freeze({ TCP: 1, UDP: 2 });
const PROTO_NAME = Object.freeze({ 1: 'tcp', 2: 'udp' });
const PROTO_CODE = Object.freeze({ tcp: 1, udp: 2 });

/** Teslim politikası — yönetim panelinden uygulama başına seçilir. */
const DELIVERY = Object.freeze({
  /** Kayıpsız: RFC 9002 kurtarma. TCP için tek geçerli seçenek. */
  RELIABLE: 1,
  /** Kayıp toleranslı: tek atım, yeniden gönderim yok. Ses/video/oyun için. */
  UNRELIABLE: 2,
});
const DELIVERY_NAME = Object.freeze({ 1: 'reliable', 2: 'unreliable' });

/** Akış/bağlantı sonlandırma sebepleri. */
const RST_CODE = Object.freeze({
  UNSPECIFIED: 0,
  LOCAL_REFUSED: 1,      // yerel hedef bağlantıyı reddetti
  LOCAL_ERROR: 2,        // yerel soket hatası
  REMOTE_CLOSED: 3,      // karşı uç kapattı
  APP_DISABLED: 4,       // uygulama yönetim panelinden kapatıldı
  RATE_LIMITED: 5,       // hız/eşzamanlılık sınırı
  TUNNEL_CLOSING: 6,
  FLOW_VIOLATION: 7,     // kredi penceresi aşıldı — protokol ihlali
  TIMEOUT: 8,
});

/** BIND/OPEN reddi sebepleri. */
const ERR_CODE = Object.freeze({
  UNSPECIFIED: 0,
  UNAUTHORIZED: 1,
  NO_PORT_AVAILABLE: 2,
  INVALID_REQUEST: 3,
  APP_LIMIT: 4,
  PROTO_UNSUPPORTED: 5,
  POLICY: 6,
  PORT_IN_USE: 7,
  NOT_FOUND: 8,
});

const PROTOCOL_VERSION = 1;

/**
 * Boyut sınırları.
 *
 * SEGMENT_BYTES neden 16 KiB? Kanalın gönderim kuyruğu TEK bir FIFO'dur: bir
 * mesajın tüm parçaları kuyruğa birlikte girer. 1 MiB'lik bir mesaj verilirse
 * arkasındaki her akış o mesaj bitene kadar bekler — tam da kaçınmak istediğimiz
 * baş-tıkanması. 16 KiB, MTU'ya bölündüğünde ~15 parçadır: dolaşım süresini
 * dolduracak kadar büyük, adil sıralamayı bozmayacak kadar küçük.
 */
const LIMITS = Object.freeze({
  /** Bir veri akışına tek seferde verilen azami yük. */
  SEGMENT_BYTES: 16 * 1024,
  /** Akış başına başlangıç alım penceresi. */
  STREAM_WINDOW: 256 * 1024,
  /** Tünel geneli alım penceresi — tüm akışların toplam bellek tavanı. */
  CONNECTION_WINDOW: 8 * 1024 * 1024,
  /** Pencerenin bu oranı tüketilince kredi yollanır (her segmentte değil). */
  CREDIT_THRESHOLD: 0.5,
  /** Tünel başına eşzamanlı mantıksal akış tavanı. */
  MAX_STREAMS: 4096,
  /** Bir tünelin bağlayabileceği azami uygulama sayısı. */
  MAX_APPS: 64,
  /** Güvenilir olmayan datagramın azami yükü — tek DTLS kaydına sığmalı. */
  MAX_DATAGRAM: 1024,
  /** Denetim mesajı tavanı (APP_SYNC gibi JSON taşıyanlar dahil). */
  MAX_CONTROL_MESSAGE: 256 * 1024,
  /** Kapanan bir akış numarasının yeniden kullanıma açılmadan önceki bekleme
   *  süresi — TCP'nin TIME_WAIT'iyle aynı gerekçe. */
  STREAM_QUARANTINE_MS: 30_000,
});

/** Zamanlamalar. */
const TIMING = Object.freeze({
  HEARTBEAT_MS: 15_000,
  HEARTBEAT_TIMEOUT_MS: 45_000,
  STATS_INTERVAL_MS: 5_000,
  /** Tünel düştükten sonra portun serbest bırakılmadan bekletildiği süre:
   *  kısa bir kopmada istemci AYNI portu geri alır. */
  PORT_LINGER_MS: 20_000,
  UDP_FLOW_IDLE_MS: 60_000,
  /** OPEN'a yanıt gelmezse mantıksal bağlantı düşürülür. */
  OPEN_TIMEOUT_MS: 10_000,
});

module.exports = {
  PROTOCOL_VERSION,
  STREAM, CTRL, DATA, DGRAM,
  PROTO, PROTO_NAME, PROTO_CODE,
  DELIVERY, DELIVERY_NAME,
  RST_CODE, ERR_CODE,
  LIMITS, TIMING,
};
