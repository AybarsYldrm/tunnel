'use strict';
// Genel yüzeye dışarıdan bağlanan uçların defteri.
//
// Tünelin iki ayrı "istemci" kavramı var ve karıştırılmaları pahalıya patlar:
//
//   İSTEMCİ (client)   tüneli kuran, sertifikayla tanınan taraf. Kimliği
//                      kriptografiktir; engellenmesi kalıcı bir yetki kararıdır.
//   ZİYARETÇİ (peer)   yayınlanmış bir genel porta (örn. 25565) dışarıdan
//                      bağlanan taraf. Kimliği yalnızca IP adresidir.
//
// Bu dosya ikincisini izler: kim bağlı, ne zamandır, ne kadar taşıdı, gecikmesi
// ne. Panelden "at" ve "engelle" işlemlerinin dayanağı da burasıdır.
//
// ---------------------------------------------------------------------------
// GECİKME NASIL ÖLÇÜLÜYOR — ve neden "ping" demiyoruz
// ---------------------------------------------------------------------------
// Ziyaretçiye ICMP echo atmak ham soket (dolayısıyla root) ister ve pek çok ağ
// onu zaten düşürür. TCP'nin çekirdekteki kendi RTT tahmini (TCP_INFO) Node'dan
// görünmez. Uygulama protokolünü (Minecraft, HTTP, SSH...) bilmediğimiz için
// protokole özgü bir yankı paketi de üretemeyiz.
//
// Geriye ölçülebilir tek şey kalıyor: TUR SÜRESİ. Ziyaretçiye son baytı
// yazdığımız an ile ondan gelen bir sonraki bayt arasındaki fark. Bu değer
//
//     ağ gecikmesi + ziyaretçinin düşünme süresi
//
// toplamıdır ve tek bir örnek olarak işe yaramaz. Ama ÖRNEKLERİN EN KÜÇÜĞÜ
// alındığında düşünme süresi terimi sıfıra yaklaşır: sürekli konuşan bir
// protokolde (oyun istemcisi, SSH oturumu, HTTP keep-alive) er ya da geç
// istemcinin hemen yanıtladığı bir tur olur. Kalan, ağ gecikmesidir.
//
// Bu yüzden panelde "ping" değil "gecikme (pasif ölçüm)" yazıyor ve ölçüm
// sayısı da gösteriliyor: iki örnekten çıkan bir sayıya güvenilmemeli.
//
// Süzgeç KAYAN PENCERELİ minimumdur — tek bir minimum tutulsaydı, ziyaretçi
// başka bir ağa geçtiğinde (mobilden Wi-Fi'ye) eski ve artık yanlış olan düşük
// değer bağlantı boyunca ekranda kalırdı.

const crypto = require('node:crypto');

/** Tur süresi örnekleri bu pencerede tutulur; sonra taze yarıya devredilir. */
const RTT_WINDOW_MS = 30_000;
/** Bu değerin üstündeki turlar "düşünme süresi" sayılır ve örneklenmez. */
const RTT_SAMPLE_CEILING_MS = 5_000;
/** Defterin sert tavanı — genel yüzey saldırı altındayken bellek patlamasın. */
const DEFAULT_MAX_PEERS = 50_000;

/**
 * Kayan pencereli minimum: iki kova. Pencere dolunca taze kova ana kovaya
 * devredilir. Üç örnekli Nichols süzgecinin basitleştirilmiş hâli; burada
 * mikro-optimizasyona gerek yok, bağlantı başına saniyede birkaç örnek var.
 */
class WindowedMin {
  constructor(windowMs = RTT_WINDOW_MS) {
    this.windowMs = windowMs;
    this.current = null;
    this.next = null;
    this.rotatedAt = 0;
    this.count = 0;
  }

  add(value, now) {
    this.count++;
    if (this.rotatedAt === 0) this.rotatedAt = now;
    if (now - this.rotatedAt >= this.windowMs) {
      // Pencere kaydı: taze yarı ana tahmin olur, yeni yarı boş başlar.
      this.current = this.next;
      this.next = null;
      this.rotatedAt = now;
    }
    if (this.current === null || value < this.current) this.current = value;
    // İkinci yarıda görülen örnekler, pencere kaydığında devralacak tahmini
    // besler; olmasaydı kayma anında tahmin sıfırlanır ve zıplardı.
    if (now - this.rotatedAt >= this.windowMs / 2) {
      if (this.next === null || value < this.next) this.next = value;
    }
  }

  get value() { return this.current; }
}

class Peer {
  constructor({
    id, appId, appName, protocol, publicPort, tunnelId, tunnelName, address, port, kick,
  }) {
    this.id = id;
    this.appId = appId;
    this.appName = appName;
    this.protocol = protocol;
    this.publicPort = publicPort;
    this.tunnelId = tunnelId;
    this.tunnelName = tunnelName;
    this.address = address;
    this.port = port;
    this._kick = kick;

    this.openedAt = Date.now();
    this.closedAt = 0;
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.packetsIn = 0;
    this.packetsOut = 0;

    this.rtt = new WindowedMin();
    this.lastOutAt = 0;
    this.lastInAt = 0;
    /** İlk baytın gelmesi — slowloris teşhisi ve kaba bir gecikme ipucu. */
    this.firstByteMs = null;
    this.kicked = false;
  }

  get rttMs() { return this.rtt.value; }
  get samples() { return this.rtt.count; }

  toJSON(now = Date.now()) {
    return {
      id: this.id,
      address: this.address,
      port: this.port,
      appId: this.appId,
      appName: this.appName,
      protocol: this.protocol,
      publicPort: this.publicPort,
      tunnelId: this.tunnelId,
      tunnelName: this.tunnelName,
      openedAt: this.openedAt,
      uptimeMs: (this.closedAt || now) - this.openedAt,
      bytesIn: this.bytesIn,
      bytesOut: this.bytesOut,
      packetsIn: this.packetsIn,
      packetsOut: this.packetsOut,
      rttMs: this.rttMs,
      samples: this.samples,
      firstByteMs: this.firstByteMs,
    };
  }
}

class PeerRegistry {
  constructor({ log = null, maxPeers = DEFAULT_MAX_PEERS } = {}) {
    this.log = log;
    this.maxPeers = maxPeers;
    /** peerId -> Peer */
    this.peers = new Map();
    this.stats = { total: 0, kicked: 0, closed: 0, refusedByCap: 0 };
  }

  /**
   * Yeni bir dış bağlantı.
   * @param {object} o
   * @param {() => void} o.kick bu bağlantıyı kapatan işlev (soket ya da akış)
   * @returns {Peer|null} tavan dolduysa null
   */
  open(o) {
    if (this.peers.size >= this.maxPeers) { this.stats.refusedByCap++; return null; }
    const peer = new Peer({ ...o, id: crypto.randomBytes(9).toString('base64url') });
    this.peers.set(peer.id, peer);
    this.stats.total++;
    return peer;
  }

  close(peer) {
    if (!peer || !this.peers.has(peer.id)) return;
    peer.closedAt = Date.now();
    this.peers.delete(peer.id);
    this.stats.closed++;
  }

  /**
   * Ziyaretçiden BİZE gelen veri. Tur süresi örneği burada doğar: son
   * yazdığımız bayttan bu yana geçen süre.
   */
  noteIn(peer, bytes, now = Date.now()) {
    if (!peer) return;
    peer.bytesIn += bytes;
    peer.packetsIn++;
    if (peer.firstByteMs === null) peer.firstByteMs = now - peer.openedAt;

    if (peer.lastOutAt === 0) { peer.lastInAt = now; return; }
    const turnaround = now - peer.lastOutAt;
    // Üst sınır: bu kadar uzun bir tur ağ gecikmesi değil, karşı tarafın
    // sessiz kaldığı süredir. Alt sınır yok — sıfır milisaniye, aynı yığın
    // içindeki bir yanıtın meşru ölçüsüdür.
    if (turnaround >= 0 && turnaround <= RTT_SAMPLE_CEILING_MS) {
      peer.rtt.add(turnaround, now);
      // Örnek tüketildi: aynı yazma için ikinci bir tur sayılmasın.
      peer.lastOutAt = 0;
    }
    peer.lastInAt = now;
  }

  /** Bizden ziyaretçiye giden veri — bir sonraki turun başlangıç anı. */
  noteOut(peer, bytes, now = Date.now()) {
    if (!peer) return;
    peer.bytesOut += bytes;
    peer.packetsOut++;
    // İlk yazma anını koru: art arda yazarken damgayı ilerletmek, turun
    // ölçüsünü küçültüp gecikmeyi olduğundan iyi gösterirdi.
    if (peer.lastOutAt === 0) peer.lastOutAt = now;
  }

  get(id) { return this.peers.get(id) || null; }

  /** @returns {boolean} bağlantı gerçekten kapatıldı mı */
  kick(id) {
    const peer = this.peers.get(id);
    if (!peer) return false;
    peer.kicked = true;
    this.stats.kicked++;
    try { peer._kick(); } catch { /* zaten kapanmış */ }
    this.close(peer);
    return true;
  }

  /** Bir adrese ait TÜM açık bağlantıları kapatır (engelleme sonrası). */
  kickAddress(address) {
    let n = 0;
    for (const peer of [...this.peers.values()]) {
      if (peer.address === address && this.kick(peer.id)) n++;
    }
    return n;
  }

  /** Bir tünel kapandığında ona ait ziyaretçiler de defterden düşer. */
  dropTunnel(tunnelId) {
    for (const peer of [...this.peers.values()]) {
      if (peer.tunnelId === tunnelId) this.close(peer);
    }
  }

  list({ appId = null, address = null, limit = 1000 } = {}) {
    const now = Date.now();
    const out = [];
    for (const peer of this.peers.values()) {
      if (appId && peer.appId !== appId) continue;
      if (address && peer.address !== address) continue;
      out.push(peer.toJSON(now));
      if (out.length >= limit) break;
    }
    // En yeni bağlantı üstte: paneli açan kişi genellikle "şu an ne oluyor"
    // sorusunu soruyor.
    return out.sort((a, b) => b.openedAt - a.openedAt);
  }

  snapshot() {
    const addresses = new Set();
    let rttSum = 0;
    let rttN = 0;
    for (const peer of this.peers.values()) {
      addresses.add(peer.address);
      if (peer.rttMs !== null) { rttSum += peer.rttMs; rttN++; }
    }
    return {
      active: this.peers.size,
      distinctAddresses: addresses.size,
      avgRttMs: rttN ? Math.round(rttSum / rttN) : null,
      ...this.stats,
    };
  }
}

module.exports = {
  PeerRegistry, Peer, WindowedMin,
  RTT_WINDOW_MS, RTT_SAMPLE_CEILING_MS,
};
