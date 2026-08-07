# node-dtls

**Sıfır bağımlılıklı, saf Node.js DTLS 1.3 (RFC 9147) ve DTLS 1.2 (RFC 6347) yığını.**

Tek bir çekirdek üç kullanım biçimini birlikte sunar:

| Kip | Ne için | Nasıl açılır |
|---|---|---|
| **Düz DTLS** | Güvenli UDP datagram taşıma, mTLS, SNI, ALPN | varsayılan |
| **DTLS-SRTP** | WebRTC medya yolu — SRTP/SRTCP anahtar takası ve koruması | `srtp: true` |
| **Güvenilir kanal** | QUIC (RFC 9002) kayıp kurtarma — sıralı **veya sırasız** teslim | `reliable: true` |
| **İptal denetimi** | OCSP (RFC 6960) / CRL (RFC 5280) — sertifika gerçekten geçerli mi? | `revocation: 'hard-fail'` |

Bu çekirdeğin üstüne kurulu tam bir uygulama için bkz. **[tunnel/](tunnel/)** —
mTLS kimlikli, cloudflared benzeri bir ters proxy: port açamayan bir istemci
yerel servisini dış dünyaya yayınlar, yönetim paneli portları/bant genişliğini
ayarlar, kimlik `trust.fitfak.net`'ten gelir.

Hiçbir üçüncü parti bağımlılık yoktur; yalnızca `node:crypto`, `node:dgram`,
`node:events` ve (iptal denetimi için) `node:http` / `node:https` kullanılır.

---

## Kurulum

```bash
npm install @fitfak/dtls
```

Node.js ≥ 20 gerekir.

---

## Hızlı başlangıç

### Sunucu

```js
const fs = require('node:fs');
const dtls = require('node-dtls');

const server = dtls.createServer({
  cert: fs.readFileSync('certs/server.crt'),
  key:  fs.readFileSync('certs/server.key'),
  ca:   fs.readFileSync('certs/ca.crt'),

  requestCert: true,          // mTLS: istemciden sertifika iste
  rejectUnauthorized: true,   // doğrulanamayan istemciyi reddet
});

server.on('secureConnection', (sock) => {
  console.log(sock.protocol, sock.cipher, sock.getPeerCertificate().subject);
  sock.on('data', (buf) => sock.send(Buffer.from(`echo: ${buf}`)));
});

await server.listen(4444, '0.0.0.0');
```

### İstemci

```js
const sock = await dtls.connect({
  host: 'example.com',
  port: 4444,
  servername: 'example.com',        // SNI + hostname doğrulaması

  ca:   fs.readFileSync('certs/ca.crt'),
  cert: fs.readFileSync('certs/client.crt'),   // mTLS kimliği
  key:  fs.readFileSync('certs/client.key'),
});

sock.on('data', (buf) => console.log('<-', buf.toString()));
await sock.send(Buffer.from('merhaba'));
```

Test sertifikaları üretmek için:

```bash
npm run certs      # certs/ altında CA + sunucu + istemci sertifikaları
```

---

## Sürüm müzakeresi

İstemci varsayılan olarak **hem DTLS 1.3 hem 1.2** teklif eder; sunucu hangisini
destekliyorsa o seçilir. Aralık `minVersion` / `maxVersion` ile daraltılır:

```js
{ minVersion: 'DTLSv1.2', maxVersion: 'DTLSv1.3' }   // varsayılan
{ minVersion: 'DTLSv1.3', maxVersion: 'DTLSv1.3' }   // yalnızca 1.3
{ maxVersion: 'DTLSv1.2' }                            // yalnızca 1.2
```

Seçilen sürüm `sock.protocol` ile okunur (`'DTLSv1.3'` / `'DTLSv1.2'`).

**Sürüm farkları uygulama koduna yansımaz** — aynı `send()` / `'data'` arayüzü
ikisinde de çalışır. Alt katmanda:

| | DTLS 1.3 | DTLS 1.2 |
|---|---|---|
| Kayıt başlığı | unified header, sequence number şifreli | 13 bayt, açık |
| Anahtar takası | ECDHE, `key_share` (1-RTT) | ECDHE, ServerKeyExchange |
| Anahtar programı | HKDF (`"dtls13"` etiketi) | PRF + Extended Master Secret |
| Cookie | HelloRetryRequest | HelloVerifyRequest |
| Anahtar yenileme | KeyUpdate (epoch +1) | — |
| Sertifika koruması | Şifreli | Açık |

---

## mTLS ve sertifika doğrulama

Üç güven modeli desteklenir; hangisi yapılandırılmışsa o kullanılır.

### 1. CA zinciri (klasik PKI)

```js
// Sunucu
dtls.createServer({
  cert, key,
  ca: caCert,                 // istemci sertifikalarını bununla doğrula
  requestCert: true,
  rejectUnauthorized: true,   // false → doğrula ama handshake'i kesme
});

// İstemci
await dtls.connect({ host, port, servername: 'example.com', ca: caCert, cert, key });
```

Doğrulananlar (RFC 5280 §6.1'in pratikte önemli olan alt kümesi):

| Kontrol | Ayrıntı |
|---|---|
| İmza zinciri | Geri izlemeli yol kurma — çapraz imzalı CA'lar ve karışık sıralı demetler dahil |
| Geçerlilik süresi | Yoldaki **her** sertifika için |
| `basicConstraints` | CA bayrağı **ve** `pathLenConstraint` |
| `keyUsage` | İmzalayan CA'larda `keyCertSign` |
| `extendedKeyUsage` | Leaf'te `serverAuth` / `clientAuth` (rolüne göre) |
| Kritik uzantılar | Tanınmayan kritik uzantı → reddedilir |
| Hostname | SAN/CN, IP adresleri dahil (yalnızca istemci tarafında) |
| **İptal** | OCSP / CRL — bkz. [İptal denetimi](#i̇ptal-denetimi-ocsp--crl) |

Sonuç her zaman okunabilir — `rejectUnauthorized: false` olsa bile:

```js
sock.authorized             // true | false
sock.authorizationError     // 'HOSTNAME_MISMATCH', 'CERT_REVOKED (...)', ...
sock.getPeerCertificate()   // { subject, issuer, fingerprint256, validTo, ocspUrls, ... }
sock.peerCertificateChain   // karşı tarafın GÖNDERDİĞİ zincir
sock.peerCertificatePath    // DOĞRULANMIŞ yol: leaf → ara CA'lar → güven çıpası
sock.peerRevocation         // { ok, error, results: [{ method, status, ... }] }
```

#### Sertifika zincirleri

`cert` bir **demet** olabilir: leaf + ara CA'lar (+ istenirse kök). Demetin
sırası önemli değildir — leaf yapısal olarak bulunup başa alınır, çünkü TLS
leaf'in ilk sırada olmasını şart koşar (RFC 8446 §4.4.2):

```js
// Hepsi çalışır:
dtls.createServer({ cert: fs.readFileSync('fullchain.pem'), key });   // leaf + ara CA
dtls.createServer({ cert: [leafPem, interPem], key });                // dizi
dtls.createServer({ cert: Buffer.concat([interPem, leafPem]), key }); // ters sıra → düzeltilir
```

Doğrulayan tarafta `ca` deposundaki **her** sertifika bir güven çıpasıdır —
kök olmak zorunda değildir:

```js
// Klasik: köke güven, ara CA'yı karşı taraf gönderir
await dtls.connect({ host, port, ca: rootCa });

// Kısıtlı: yalnızca şu ara CA'ya güven (kök hiç verilmez)
await dtls.connect({ host, port, ca: intermediateCa });

// Demet: kök + ara CA birlikte (sunucu yalnızca leaf gönderse de çalışır)
await dtls.connect({ host, port, ca: Buffer.concat([rootCa, intermediateCa]) });
```

Karşı tarafın gönderdiği zincirde bir kök bulunması **güven üretmez**; güven
yalnızca yerel `ca` deposundan gelir.

### 2. Parmak izi (WebRTC tarzı)

Kendinden imzalı sertifika + dışarıdan (örn. SDP'den) gelen parmak izi:

```js
await dtls.connect({
  host, port,
  peerFingerprint: 'A1:B2:...:FF',      // veya dizi
  peerFingerprintAlgorithm: 'sha-256',  // varsayılan
});
```

### 3. Uygulamaya özel kanca

```js
await dtls.connect({
  host, port, ca,
  // Hata döndürürsen (veya fırlatırsan) handshake reddedilir.
  verifyPeerCertificate: (cert, chain) => {
    if (!cert.subject.includes('O=ACME')) return new Error('yanlış kurum');
    return null;
  },
  // node:tls'in checkServerIdentity muadili
  checkServerIdentity: (hostname, cert) => null,
});
```

> `rejectUnauthorized: true` iken `ca`, `peerFingerprint` veya
> `verifyPeerCertificate`'ten en az biri verilmelidir. Hiçbiri yoksa yapılandırma
> **başlangıçta** hata verir — sessizce güvensiz çalışmaz.

---

## İptal denetimi (OCSP / CRL)

Zincir doğrulaması "bu sertifika doğru CA tarafından, doğru şekilde imzalanmış
mı?" sorusunu yanıtlar. **İptal denetimi** ise ikinci yarıyı yanıtlar:
"bu sertifika hâlâ geçerli mi?" — çalınmış bir istemci anahtarı, süresi dolana
kadar (825 güne kadar) geçerli görünmeye devam eder.

```js
dtls.createServer({
  cert, key, ca,
  requestCert: true,
  rejectUnauthorized: true,
  revocation: 'hard-fail',      // istemci sertifikalarını OCSP/CRL ile denetle
});

await dtls.connect({
  host, port, servername: 'example.com', ca,
  revocation: 'soft-fail',      // sunucu sertifikasını denetle
});
```

### Politikalar

| Değer | Davranış |
|---|---|
| `'off'` (varsayılan), `false` | Denetim yapılmaz, hiçbir ağ isteği çıkmaz |
| `'soft-fail'`, `true` | Durum öğrenilemezse (responder kapalı, AIA/CDP yok) bağlantı **sürer**; sonuç `sock.peerRevocation` içinde raporlanır |
| `'hard-fail'` | Durum öğrenilemezse handshake **reddedilir** |

Her iki modda da **`revoked` cevabı bağlantıyı daima keser** —
`certificate_revoked` alarmıyla.

### Denetlenen sertifikalar

Zincirdeki **kök hariç her sertifika** sırayla denetlenir: leaf'in durumunu
ara CA, ara CA'nın durumunu kök söyler. Kök sorgulanmaz — kendi kendini iptal
edemez, güveni yerel depodan gelir (RFC 5280 §6.1).

Her sertifika için sırayla denenir:

1. **Zımbalanmış (stapled) OCSP yanıtı** — ağ turu yok
2. **OCSP** (RFC 6960) — sertifikanın AIA uzantısındaki responder URL'i
3. **CRL** (RFC 5280 §5) — CRLDistributionPoints'teki URL
4. Hiçbiri yoksa politikaya göre karar

İstekler `node:http` / `node:https` ile yapılır (dış bağımlılık yok). OCSP ve
CRL uç noktaları RFC 5280 §4.2.1.13 uyarınca zaten düz HTTP üzerinden sunulur —
döngüsel güven bağımlılığını kırmak için imzalı nesnelere güvenilir, taşımaya değil.

### Doğrulanan güvenlik özellikleri

- **OCSP imzası**: yanıtı ya CA'nın kendisi ya da CA'nın yetkilendirdiği bir
  responder imzalamalıdır. Delege responder `id-kp-OCSPSigning` EKU'sunu
  taşımak zorundadır (RFC 6960 §4.2.2.2) — aksi hâlde herhangi bir sertifika
  sahibi başkasının sertifikasını "geçerli" ilan edebilirdi.
- **Nonce** (RFC 6960 §4.4.1): istek rastgele bir nonce taşır; responder onu
  yansıtırsa eşleşme kontrol edilir (tekrar oynatma koruması). Yansıtmayan
  önbellekli responder'lar RFC 5019 §4 uyarınca kabul edilir.
- **Tazelik**: `thisUpdate` / `nextUpdate` saat kayması toleransıyla denetlenir.
- **CertID eşleşmesi**: yanıtın gerçekten sorduğumuz sertifikaya ait olduğu
  (issuerNameHash + issuerKeyHash + serialNumber) doğrulanır.
- **CRL imzası ve yetkisi**: `cRLSign` biti aranır; delta CRL'ler tek başına
  yeterli sayılmaz.

### OCSP zımbalama (stapling)

Sunucu kendi OCSP yanıtını önceden alıp handshake içinde taşıyabilir. İstemci
böylece responder'a **hiç bağlanmadan** iptal durumunu öğrenir — daha hızlı ve
daha gizlilik dostu (responder istemcinin kimi ziyaret ettiğini görmez).

```js
dtls.createServer({
  cert, key,
  // Buffer (DER) ya da her handshake'te çağrılan bir fonksiyon:
  ocspResponse: () => cache.getFreshOcspResponse(),
});
```

DTLS 1.3'te yanıt `Certificate` mesajının leaf girdisine (RFC 8446 §4.4.2.1),
DTLS 1.2'de ayrı bir `CertificateStatus` mesajına (RFC 6066 §8) konur — ikisi de
desteklenir. İstemci `status_request` uzantısını `revocation` açıkken
kendiliğinden gönderir (`requestOCSP: false` ile kapatılabilir).

### İnce ayar

```js
revocation: {
  mode: 'hard-fail',
  ocsp: true, crl: true,
  timeoutMs: 5000,        // tek bir HTTP isteği
  cacheTtlMs: 600_000,    // sonuç önbelleği (yanıtın nextUpdate'ini aşmaz)
  clockSkewMs: 300_000,
  hashAlgorithm: 'sha256',
  checkLeafOnly: false,   // true → yalnızca leaf
}
```

Önbellek **sunucu nesnesi başına paylaşılır**: aynı istemci ikinci kez
bağlandığında responder'a tekrar gidilmez. Aynı sertifika için **eş zamanlı**
süren sorgular da tek isteğe birleşir — 100 istemci aynı anda bağlanırsa
responder'a 100 değil 1 istek gider.

---

## SNI

Sunucuda hostname'e göre sertifika seçimi iki şekilde yapılır:

```js
// Statik tablo
dtls.createServer({
  cert, key,                                  // varsayılan bağlam
  contexts: {
    'a.example.com': { cert: certA, key: keyA },
    'b.example.com': { cert: certB, key: keyB, ca: caB },
  },
});

// Dinamik (async destekli)
dtls.createServer({
  cert, key,
  SNICallback: async (servername) => {
    const { cert, key } = await lookup(servername);
    return { cert, key };
  },
});
```

İstemci `servername` ile SNI gönderir ve **aynı isme karşı** sertifikayı doğrular.
`servername` verilmezse `host` bir hostname ise o kullanılır (IP adreslerinde
RFC 6066 gereği SNI gönderilmez).

---

## SRTP (WebRTC medya)

`srtp: true` verildiğinde ClientHello'ya `use_srtp` uzantısı eklenir, sunucu bir
profil seçer ve handshake sonrası SRTP anahtarları RFC 5764 exporter'ı ile türetilir.

```js
const srtp = { profiles: ['SRTP_AEAD_AES_128_GCM', 'SRTP_AES128_CM_HMAC_SHA1_80'] };

const server = dtls.createServer({ cert, key, srtp });
server.on('secureConnection', (sock) => {
  console.log('SRTP profili:', sock.srtpProfile);

  sock.on('media', (rtp) => { /* şifresi çözülmüş RTP */ });
  sock.on('rtcp',  (pkt) => { /* şifresi çözülmüş RTCP */ });

  sock.sendMedia(rtpPacket);   // SRTP ile korunup gönderilir
  sock.sendRtcp(rtcpPacket);   // SRTCP ile korunup gönderilir
});
```

Desteklenen profiller:

| Profil | Şifre | Etiket |
|---|---|---|
| `SRTP_AEAD_AES_128_GCM` | AES-128-GCM | 16 bayt |
| `SRTP_AEAD_AES_256_GCM` | AES-256-GCM | 16 bayt |
| `SRTP_AES128_CM_HMAC_SHA1_80` | AES-128-CTR | 10 bayt |
| `SRTP_AES128_CM_HMAC_SHA1_32` | AES-128-CTR | 4 bayt |

Notlar:

* Medya paketleri **DTLS kayıt katmanından geçmez.** Aynı UDP soketinden akar ve
  RFC 7983'e göre ayrıştırılır (STUN / DTLS / RTP / RTCP).
* ROC (roll-over counter) ve replay penceresi **SSRC başına** tutulur.
* `srtp` kapalıyken `use_srtp` uzantısı hiç gönderilmez — düz DTLS davranışı
  bit düzeyinde değişmez.
* Karşı taraf SRTP istemezse bağlantı düz DTLS olarak devam eder; `sock.srtpProfile`
  `null` olur.
* ICE/STUN bu kütüphanenin kapsamı dışındadır. Sunucu, DTLS olmayan datagramları
  `'unhandled'` olayıyla yukarı verir; `dtls.createStunBindingResponse()` yardımcısı
  da dışa aktarılmıştır.

---

## Güvenilir / sırasız kanal (RFC 9002 + BBRv3)

UDP'de kayıp normaldir. Bazı veriler için bu kabul edilebilir değildir ama
**TCP'nin head-of-line blocking'i de istenmez.** `reliable` seçeneği tam olarak
bu boşluğu doldurur: kayıp tespiti **RFC 9002'nin (QUIC Loss Detection)**
modelini izler, tıkanıklık denetimi ise **takılabilir** — varsayılan **BBRv3**.

```js
const reliable = {
  ordered: false,             // varsayılan: SIRASIZ teslim
  congestionControl: 'bbr3',  // varsayılan; 'newreno' de seçilebilir
  maxRetransmits: 12,         // parça başına vazgeçme sınırı
  initialRtt: 333,            // RTT örneği alınana kadarki tahmin (ms)
  ackDelay: 10,               // ACK'leri toplama gecikmesi (ms)

  // Alıcı bellek tavanları — gönderenin bildirdiği parça sayısına güvenilmez.
  maxMessageBytes: 16 * 1024 * 1024,     // tek mesaj
  maxReassemblyBytes: 64 * 1024 * 1024,  // tüm yarım mesajların toplamı
};

const sock = await dtls.connect({ host, port, ca, reliable });

await sock.send(bigBuffer);                       // teyitlenene kadar bekler
await sock.send(telemetry, { reliable: false });  // tek atım, yeniden gönderilmez
await sock.send(chunk, { streamId: 7 });          // bağımsız sıralanan akış
await sock.send(gamePacket, { priority: 1 });     // öncelikli bant (0 = en yüksek)

sock.on('data', (buf, meta) => {
  // meta = { streamId, msgId, ordered }
});
```

### Neden RFC 9002?

"Kaybolan paketi yeniden gönder" tek başına bir kurtarma stratejisi değildir.
Ağır kayıp altında (%50 gibi) naif bir zamanlayıcı üç tuzağa düşer — ve bu
kütüphanenin önceki sürümü **her üçüne de** düşüyordu:

| Tuzak | Naif davranış | RFC 9002 |
|---|---|---|
| **Tek paket kurtarma** | Zaman aşımında yalnızca en eski paketi gönder → N kayıp için N tur | ACK bilgisinden **tüm** kayıpları aynı anda çıkar (§6.1) |
| **Kör üstel geri çekilme** | Her zaman aşımında RTO'yu ikiye katla → kayıp tıkanıklıktan değilse kurtarma durur | **PTO** yalnızca sonda gönderir; kayıp İLAN ETMEZ, pencereyi küçültmez (§6.2) |
| **Açık döngü gönderim** | Sabit `maxInFlight` ne kapasiteyi kullanır ne tıkanıklığa tepki verir | Pencere ölçüme göre belirlenir (§7 — burada **BBRv3**) |

Uygulanan mekanizmalar:

* **RTT tahmini** (§5) — `smoothed_rtt` / `rttvar` / `min_rtt`; karşı tarafın
  bildirdiği `ack_delay` düşülür.
* **Kayıp tespiti** (§6.1) — paket eşiği (3) **ve** zaman eşiği (9/8 × RTT).
* **PTO** (§6.2) — `smoothed_rtt + max(4·rttvar, granülerlik) + max_ack_delay`,
  üstel geri çekilmeyle; zaman aşımında **iki sonda** gönderilir.
* **Tıkanıklık denetimi** (§7) — varsayılan BBRv3 (aşağıda), alternatif
  NewReno: yavaş başlangıç, kurtarma dönemi, kalıcı tıkanıklık tespiti.
* **Yeniden gönderilen veri YENİ paket numarası alır** — böylece her ACK tek bir
  gönderime karşılık gelir ve RTT örnekleri belirsizliğe düşmez (Karn'a gerek
  kalmaz). Veri kimliği `(streamId, msgId, idx)` üçlüsüdür; alıcı yinelemeyi
  paket numarasından bağımsız eler.
* **Parçalama/birleştirme** — MTU'dan büyük mesajlar otomatik bölünür.
* **Sırasız teslim** (`ordered: false`) — bir mesajın gecikmesi arkasındakileri
  bekletmez; tamamlanan mesaj anında yukarı çıkar.
* **Sıralı teslim** (`ordered: true`) — akış (`streamId`) içinde sıra korunur;
  farklı akışlar birbirini etkilemez.
* **Öncelikli gönderim kuyruğu** (`priority`, 0 = en yüksek) — kuyruk tek bir
  FIFO değil, dört bantlı. Gecikmeye duyarlı küçük bir paket, önündeki hacimli
  verinin boşalmasını beklemez; yeniden gönderimler de kendi bandının başına
  döner, bandını atlamaz. Tünel katmanı bunu uygulama başına hizmet sınıfına
  bağlar (bkz. `tunnel/README.md` — Hizmet sınıfı).

### Tıkanıklık denetimi: BBRv3 (varsayılan)

Kayıp odaklı denetleyicilerin tamamı (Reno, NewReno, CUBIC) tek bir varsayımı
paylaşır: **kayıp = tıkanıklık**. Bu varsayım iki çok yaygın durumda yanlıştır.

**1. Kayıp tıkanıklıktan gelmiyor.** Mobil, Wi-Fi ve uydu hatlarında kayıp
rastgele bit hatasından doğar. Mathis formülüne göre kayıp odaklı bir
denetleyicinin ulaşabileceği tavan `≈ MSS / (RTT · √p)`'dir: %1 kayıplı,
40 ms'lik bir hatta bu ~3 Mbit/s demektir — hat 100 Mbit olsa bile.

**2. Tampon şişmesi (bufferbloat).** Kayıp yalnızca darboğazdaki kuyruk
TAŞTIĞINDA gelir; dolayısıyla kayıp odaklı denetleyici kuyruğu doldurmayı
*hedefler*. Sonuç, aynı hattı paylaşan her şeyin (SSH, oyun, ses) yüz
milisaniyelerce gecikme yemesidir.

BBR bunun yerine hattın **darboğaz bant genişliğini** ve **en küçük gidiş-dönüş
süresini** ölçer, gönderim hızını doğrudan bu modelden türetir ve paketleri
zamana yayar (pacing). Kuyruğu doldurmadan darboğaz hızında gönderir.

Bu depodaki deterministik hat benzetiminin ölçtüğü (`npm run test:bbr`,
30 sn/senaryo, tohumlu rastgelelik):

| Senaryo | BBRv3 | NewReno | Fark |
|---|---|---|---|
| Temiz 10 Mbit/40 ms | %98.5 kullanım, 23 ms kuyruk | %99.4, 76 ms | verim eşit, **gecikme 3× düşük** |
| %1 rastgele kayıp | %89.3 | %26.3 | **3.4×** |
| %2 rastgele kayıp | %78.6 | %18.7 | **4.2×** |
| Derin tampon (512 KB) | %98.6, 23 ms | %99.4, **239 ms** | **10× az kuyruk gecikmesi** |
| Uzun mesafe 150 ms, %0.5 kayıp | %76.9 | %5.1 | **15×** |

Uygulanan BBRv3 mekanizmaları:

* **Teslim hızı örneklemesi** — `delivered / max(gönderim_aralığı, ack_aralığı)`.
  Paydadaki maksimum, ACK'leri yığın hâlinde gönderen ağlarda (Wi-Fi, LTE)
  hızın olduğundan büyük görünmesini engeller.
* **Durum makinesi** — Startup → Drain → ProbeBW (Down/Cruise/Refill/Up) → ProbeRTT.
* **Kayıp tabanlı üst sınırlar** (v2/v3) — `inflight_hi` / `bw_hi` uzun vadeli,
  `inflight_lo` / `bw_lo` kısa vadeli tavan. Kayıp değerlendirmesi **tur
  başınadır**, ACK başına değil: tek bir ACK yığınındaki kayıp oranı
  istatistiksel gürültüdür ve ona tepki vermek BBR'ı NewReno'nun altına indirir.
* **ACK yığılması telafisi** (`extra_acked`) — ACK'ler toplu geldiğinde pencere
  BDP'de kalırsa hat ACK'ler arasında boş kalır; fark ölçülüp pencereye eklenir.
* **ProbeRTT** — `min_rtt` 10 saniyedir tazelenmediyse pencere 200 ms boyunca
  yarı BDP'ye indirilip gerçek gecikme ölçülür (%2'den az verim maliyeti).
* **Pacing** — jeton kovası; paket başına zamanlayıcı kurmak Node'un
  çözünürlüğünde yapay bir tavan yaratacağı için küçük bir patlama payı
  bırakılır. Bant genişliği örneği oluşana kadar hız sınırı yoktur.
* **Zamanlayıcı çözünürlüğü telafisi** — patlama payı sabit değil, **ölçülür**.
  Kovanın kapasitesi iki uyanma arasında biriken hakkın tavanıdır; sabit ~1 ms
  varsaymak `setTimeout(1)`'in gerçekten 1 ms sürdüğünü varsaymaktır. Windows'ta
  bu süre **15.6 ms**'dir ve fark doğrudan verime yansır:

  ```
  gerçek hız ≈ hedef × (kova_süresi / uyanma_aralığı)
  25 Mbit    × (1 ms / 15.6 ms)  ≈  1.6 Mbit
  ```

  Şekillendirici her uyandığında "şu kadar istemiştim, şu kadar uyudum"
  bilgisini geri alır; kova o makinenin gerçek uyanma aralığına göre boyutlanır.
  Ölçüm **pencereli maksimumla** tutulur (ortalama değil: kovanın en kötü
  uyanma aralığını karşılaması gerekir) ve üç sınırla bağlanır — telafi tavanı
  (`maxBurstMs`, 25 ms), mutlak bayt tavanı (`maxBurstBytes`) ve tıkanıklık
  penceresi. Ölçüm `timerLagMs` olarak raporlanır.
* **Uygulama sınırı işaretleme** — gönderilecek veri kalmadığında örnekler
  `app-limited` damgalanır; aksi hâlde BBR, boş kalan hattı yavaş bir hat sanar.

`newreno` hâlâ tam olarak destekleniyor ve RFC 9002 §7 sözleşmesini birebir
uyguluyor:

```js
const sock = await dtls.connect({
  host, port, ca,
  reliable: { congestionControl: 'newreno' },
});
```

> **Pacing marjı neden %2?** Linux'ta %1'dir. Bu yığın zamanı milisaniye
> cinsinden okur (çekirdek mikrosaniye kullanır); 40 ms'lik bir örnekleme
> aralığında ±1 ms yuvarlama %2.5 hata demektir ve bant genişliği tahmini
> *pencereli maksimum* olduğu için bu hatanın sistematik olarak pozitif ucunu
> seçer. %1'lik pay o gürültünün altında kalır ve fark kalıcı kuyruk olarak
> birikir.

> **Bu katman DTLS'in yapısını değiştirmez.** Tamamen `application_data`'nın
> içinde bir çerçeveleme katmanıdır; kayıt katmanı, epoch'lar, replay penceresi ve
> handshake aynen kalır. `reliable` kapalıyken kanal hiç kurulmaz ve tek bir bayt
> bile eklenmez.

Kalıcı kayıpta `send()` reddedilir (`maxRetransmits` aşılınca). Ölçümler:

```js
sock.reliable.rttMs             // güncel smoothed_rtt
sock.reliable.congestionWindow  // bayt
sock.reliable.pacingRate        // hedef gönderim hızı (bayt/s) ya da null
sock.reliable.congestionControl // 'bbr3' | 'newreno'
sock.reliable.getStats()
// { sent, resent, acked, lost, probes, giveUps, duplicates,
//   smoothedRtt, rttvar, minRtt, pto, ptoCount,
//   congestionWindow, bytesInFlight, ssthresh,
//   cc, state, bandwidthBps, pacingRateBps, bdp, extraAcked, appLimited,
//   packetsLost, congestionEvents, persistentCongestion, queued, ... }
```

DTLS handshake'inin **kendi** yeniden gönderimi (RFC 9147 §5.8) bu katmandan
bağımsızdır ve her zaman açıktır; o da ölçülen uçuş RTT'sine göre uyarlanır.

`srtp` ve `reliable` aynı anda kullanılamaz — SRTP medya akışı zaten kayıp
toleranslıdır ve yeniden gönderim medyaya zarar verir.

---

## API

### `dtls.createServer(options[, onSecureConnection]) → DtlsServer`

```js
server.listen(port, host) → Promise<{address, port}>
server.address()
server.close() → Promise
server.sessions          // Map<"ip:port", DtlsSocket>
server.stats             // { accepted, rejected, rateLimited, handshakeFailures }
```

Olaylar:

| Olay | Argümanlar | Ne zaman |
|---|---|---|
| `listening` | `addr` | soket bağlandı |
| `connection` | `sock` | handshake **başlamadan önce** (log/metrik için) |
| `secureConnection` / `session` | `sock` | handshake tamamlandı |
| `sessionError` | `err, sock` | bir oturum başarısız oldu (sunucu ayakta) |
| `unhandled` | `dg, rinfo` | DTLS olmayan datagram (ICE/STUN vb.) |
| `ratelimit` / `overload` | `rinfo` | kaynak koruması devreye girdi |
| `error` | `err` | soket seviyesi hata |
| `log` | `level, msg, meta` | tanılama |

### `dtls.connect(options) → Promise<DtlsSocket>`

Handshake tamamlanınca çözülür, başarısızsa reddedilir.

> DTLS 1.3'te istemci, kendi Finished'ini gönderdiği anda handshake'i tamamlanmış
> sayar (TLS 1.3 ile aynı semantik). Sunucu istemci sertifikasını sonradan
> reddederse bu, `connect()` çözüldükten sonra `'close'` olayı olarak gelir.

### `DtlsSocket`

```js
sock.send(data[, opts]) → Promise      // opts: { reliable, ordered, streamId }
sock.write(data)                       // send() takma adı
sock.close() → Promise                 // close_notify gönderir
sock.destroy(err)

sock.sendMedia(rtpPacket)              // yalnızca SRTP kipinde
sock.sendRtcp(rtcpPacket)
sock.requestKeyUpdate(requestPeer)     // yalnızca DTLS 1.3
sock.exportKeyingMaterial(label, context, length)   // RFC 5705 / RFC 8446 §7.5

sock.protocol            // 'DTLSv1.3' | 'DTLSv1.2'
sock.cipher              // 'TLS_AES_128_GCM_SHA256' ...
sock.srtpProfile         // 'SRTP_AEAD_AES_128_GCM' | null
sock.alpnProtocol
sock.servername
sock.authorized / sock.authorizationError
sock.peerCertificateChain    // karşı tarafın gönderdiği zincir
sock.peerCertificatePath     // doğrulanmış yol: leaf → ara CA'lar → güven çıpası
sock.peerRevocation          // { ok, error, results: [{ method, status, ... }] }
sock.peerOcspStaple          // zımbalanmış ham OCSP yanıtı (DER) | null
sock.remoteAddress / sock.remotePort
sock.getInfo()
```

Olaylar: `connect`, `data`, `media`, `rtcp`, `alert`, `error`, `close`,
`peer-certificate`, `srtp`, `secrets`, `log`.

### Seçenekler

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| `cert`, `key`, `passphrase` | — | PEM/DER sertifika **demeti**; sıra önemsizdir, leaf başa alınır |
| `ca` | — | Güven çıpaları (PEM/DER, çoklu blok olabilir); kök olmak zorunda değil |
| `requestCert` | `false` | Sunucu: CertificateRequest gönder |
| `rejectUnauthorized` | `true` | Doğrulanamayan karşı tarafı reddet |
| `allowSelfSigned` | `false` | Kendinden imzalı leaf'i kabul et |
| `peerFingerprint` | — | Parmak izi tabanlı güven |
| `verifyPeerCertificate` | — | Özel doğrulama kancası |
| `checkServerIdentity` | — | Özel hostname doğrulayıcı |
| `checkPurpose` | `true` | Leaf'te `serverAuth`/`clientAuth` EKU'sunu doğrula |
| `revocation` | `'off'` | OCSP/CRL iptal denetimi: `'soft-fail'` \| `'hard-fail'` \| nesne |
| `requestOCSP` | `revocation`'a bağlı | İstemci: `status_request` (zımbalama) gönder |
| `ocspResponse` | — | Sunucu: zımbalanacak OCSP yanıtı (Buffer veya fonksiyon) |
| `servername` / `sni` | host | SNI + hostname doğrulaması |
| `contexts`, `SNICallback` | — | Sunucuda hostname başına sertifika |
| `minVersion`, `maxVersion` | `DTLSv1.2` / `DTLSv1.3` | Sürüm aralığı |
| `cipherSuites` / `cipher` | `'balanced'` | Politika adı (`balanced`, `aes128`, `aes256`, `aes`, `chacha20`, `mobile`) **veya** isim/ID listesi |
| `groups` | `X25519, SECP256R1` | ECDHE eğrileri |
| `sigSchemes` | ECDSA/PSS/Ed25519 | İmza şemaları |
| `alpn` | — | Protokol listesi |
| `srtp` | `false` | `true` veya `{ profiles, replayProtection, demux }` |
| `reliable` | `false` | `true` veya `{ ordered, congestionControl, maxRetransmits, ... }` |
| `extendedMasterSecret` | `true` | RFC 7627 (DTLS 1.2) |
| `cookie` | `true` | HelloRetryRequest / HelloVerifyRequest ile DoS koruması |
| `mtu` | `1200` | Datagram bütçesi; handshake buna göre parçalanır |
| `handshakeTimeout` | `30000` | ms |
| `idleTimeout` | `300000` | Sunucu: sessiz oturumları düşürme süresi |
| `maxSessions` | `10000` | Sunucu: eşzamanlı oturum sınırı |
| `rateLimitBurst` / `rateLimitPerSec` | `30` / `15` | Sunucu: kaynak başına yeni oturum hızı |
| `keylogFile` | `SSLKEYLOGFILE` | Wireshark için NSS anahtar günlüğü |

---

## Şifreleme paketi seçimi

Suite listesini elle yazmak, DTLS 1.3 ve 1.2 karşılıklarını da elle eşlemek
demektir; birini unutmak "el sıkışma başarısız" olarak geri döner ve sebebi
görünmez. **Politika adı** bu eşlemeyi tek yerde yapar:

```js
// Tek kelime: hem 1.3 hem 1.2 karşılıkları, doğru sırayla kurulur.
await dtls.connect({ host, port, ca, cipher: 'chacha20' });

// Açık liste de kabul edilir — verilen SIRA tercih sırasıdır.
dtls.createServer({ cert, key, cipherSuites: [
  'TLS_AES_256_GCM_SHA384',
  'TLS_AES_128_GCM_SHA256',
]});

// Politikalar birleştirilebilir.
await dtls.connect({ host, port, ca, cipher: ['chacha20', 'aes128'] });
```

| Politika | İçerik | Ne zaman |
|---|---|---|
| `balanced` *(varsayılan)* | AES-128 → AES-256 → ChaCha20 | AES-NI olan her makine — yani 2010 sonrası hemen her sunucu/masaüstü |
| `aes128` / `aes256` / `aes` | yalnızca AES-GCM | Uzun anahtar isteyen kurumsal politikalar; ChaCha20 **FIPS 140-3 onaylı değildir** |
| `chacha20` | yalnızca ChaCha20-Poly1305 | AES donanım hızlandırması **olmayan** uçlar: ARM Cortex-A (eski Raspberry Pi), gömülü yönlendiriciler, düşük seviye mobil yongalar |
| `mobile` | ChaCha20 → AES | Karışık istemci parkı — hızlı ucun seçimi yavaş uca dayatılmasın |

Takma adlar da çalışır: `chacha`, `aes-128`, `strong`, `arm`, `embedded`, `fips`.

> AES-128'in kırıldığına dair bir bulgu **yoktur**; `aes256` bir uyum tercihidir,
> güvenlik yükseltmesi değil. Gerçek fark, AES hızlandırması olmayan bir uçta
> ChaCha20'ye geçmektir — orada kazanç kat cinsindendir.

Yalnızca AEAD suite'leri desteklenir. CBC / MAC-then-encrypt (Lucky13, POODLE)
bilinçli olarak **yoktur**.

---

## Desteklenen algoritmalar

**DTLS 1.3**
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`

**DTLS 1.2** (yalnızca AEAD — CBC suite'leri bilinçli olarak yok)
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `..._AES_256_GCM_SHA384`,
`..._CHACHA20_POLY1305_SHA256` ve `TLS_ECDHE_RSA_*` karşılıkları

**Anahtar takası:** X25519, secp256r1 (P-256)
**İmza:** ECDSA P-256/P-384, RSA-PSS, RSA-PKCS#1 (yalnızca 1.2), Ed25519

---

## Güvenlik notları

* **Sadece AEAD.** CBC + MAC-then-encrypt suite'leri hiç uygulanmadı (Lucky13, POODLE).
* **Downgrade koruması.** İstemci `supported_versions` gönderir; sunucunun seçtiği
  sürüm istemcinin izin verdiği aralığın dışındaysa handshake kesilir.
* **Extended Master Secret.** DTLS 1.2'de varsayılan olarak açık (RFC 7627),
  triple-handshake saldırısına karşı.
* **Cookie takası.** Her iki sürümde de varsayılan açık; ECDHE ve imza maliyetine
  girmeden önce kaynak adresi doğrulanır.
* **Hız sınırı + oturum sınırı.** Kaynak başına token bucket ve `maxSessions` ile
  handshake seli sınırlandırılır.
* **Replay koruması.** Epoch başına 64 genişliğinde kayan pencere; SRTP'de SSRC
  başına ayrı pencere.
* **Alıcı bellek tavanı.** Güvenilir kanalda birleştirme belleği, gönderenin
  bildirdiği parça sayısına bırakılmaz: hem tek mesaj (`maxMessageBytes`) hem
  tüm eşzamanlı birleştirmelerin toplamı (`maxReassemblyBytes`) ayrı ayrı
  sınırlıdır. Tavan aşıldığında bağlantı düşmez, en eski yarım mesaj atılır.
* **Sabit hata mesajları.** AEAD başarısızlıkları hangi aşamada olduğunu
  sızdırmayan tek bir mesaj döndürür.
* **Anahtar materyali loglanmaz.** Tanılama günlükleri hiçbir seviyede gizli
  anahtar, traffic secret veya IV yazmaz. Wireshark ile çözümleme gerekiyorsa
  `keylogFile` / `SSLKEYLOGFILE` bilinçli olarak açılmalıdır.
* **Renegotiation yok.** DTLS 1.2 `HelloRequest`'e `no_renegotiation` uyarısıyla
  cevap verilir.

### Kapsam dışı

Bilinçli olarak uygulanmayanlar: 0-RTT / early data, oturum devamı
(NewSessionTicket / PSK), post-handshake authentication, Connection ID müzakeresi
(RFC 9146 — kayıt katmanı destekler ama uzantı müzakere edilmez), CRL/OCSP
(bunun yerine `verifyPeerCertificate` kancası kullanılır).

---

## Örnekler

```bash
npm run certs

node examples/echo-server.js         # düz DTLS + mTLS echo sunucusu
node examples/echo-client.js "selam"

node examples/srtp-media.js          # DTLS-SRTP medya akışı
node examples/reliable-transfer.js   # 1 MB güvenilir aktarım

# mTLS + iptal denetimi — OCSP responder ve CRL sunucusu dahil, tek süreçte
node examples/mtls-revocation.js             # geçerli sertifika  → kabul
node examples/mtls-revocation.js --revoke    # iptal edilmiş      → RED
node examples/mtls-revocation.js --crl --revoke   # aynı senaryo, CRL üzerinden
node examples/mtls-revocation.js --staple    # sunucu OCSP yanıtını zımbalar
```

---

## Testler

```bash
npm run certs           # test PKI'sı: kök CA → ara CA → leaf + istemci sertifikaları
npm run certs:force     # tutarsız/eski certs/ dizinini baştan üret
npm test                # tüm paketler

npm run test:kat        # RFC 5869 HKDF + RFC 8448 TLS 1.3 anahtar programı vektörleri
npm run test:unit       # kayıt katmanı, çerçeveleme, kripto, SRTP, reliable, PKI
npm run test:e2e        # uçtan uca: DTLS 1.3 + 1.2 + sürüm müzakeresi
npm run test:mtls       # mTLS, sertifika zincirleri, doğrulama (her iki sürümde)
npm run test:revocation # OCSP + CRL (gerçek HTTP responder ile)
npm run test:srtp       # DTLS-SRTP (her iki sürümde, 4 profil)
npm run test:reliable   # güvenilir kanal, %50'ye varan yapay kayıpla
npm run test:bbr        # BBRv3 — deterministik hat benzetimi (kayıp, tampon, RTT)
npm run test:retransmit # uçuş yeniden gönderimi
npm run test:robust     # bozuk girdi, replay, kaynak sınırları
```

Tanılama:

```bash
DTLS_LOG_LEVEL=DEBUG node examples/echo-server.js
SSLKEYLOGFILE=/tmp/keys.log node examples/echo-client.js   # Wireshark için
```

---

## Mimari

```
index.js                     public API: createServer / connect
src/
  options.js                 seçenek normalizasyonu + doğrulaması (tek kapı)
  api/server.js              DtlsServer — soket, oturum tablosu, kaynak koruması
  api/client.js              connect()
  session/
    session.js               ortak çekirdek: kayıt katmanı, uçuşlar, alarmlar, eklentiler
    negotiate.js             sürüm müzakeresi, ClientHello, SNI, ALPN, use_srtp
    handshake.js             DTLS 1.3 + 1.2 handshake makineleri (tek dosya)
    verify.js                karşı taraf doğrulama politikası + iptal denetimi kancası
  record/
    plaintext.js             DTLSPlaintext
    protected.js             kayıt koruması — 1.3 unified header + 1.2 AEAD (tek dosya)
    srtp.js                  SRTP/SRTCP (RFC 3711 + RFC 7714) + RFC 7983 demux
    replay-window.js, ack.js
  handshake/
    framing.js, extensions.js
    messages.js              1.3 + 1.2 mesajları ve ortak imza katmanı (tek dosya)
    transcript.js            1.3 ve 1.2 transcript kuralları
    reassembler.js, cookie.js
  crypto/
    hkdf.js
    key-schedule.js          1.3 HKDF ağacı + 1.2 PRF/key block (tek dosya)
    exporter.js              RFC 8446 §7.5 / RFC 5705 exporter
    aead.js, cipher-suite.js, ecdhe.js
    der.js                   minimal DER (X.690) okuyucu/yazıcı
    x509.js                  X.509 uzantı ayrıştırma (AIA, CDP, KU, EKU, BC) + CRL
    pki.js                   zincir kurma ve yol doğrulama
    revocation.js            OCSP (RFC 6960) + CRL (RFC 5280) istemcisi
  reliable/
    recovery.js              RFC 9002 kayıp tespiti + RTT tahmini + PTO
    congestion.js            takılabilir tıkanıklık denetimi: BBRv3 (varsayılan), NewReno
    pacing.js                jeton kovası hız şekillendirici (BBR için zorunlu)
    channel.js               çerçeveleme, akışlar, parçalama/birleştirme
  transport/udp.js, stun.js

tunnel/                      mTLS ters proxy uygulaması — bkz. tunnel/README.md
  src/protocol/              FTP v1 çerçeveleri ve ikili kodlayıcı
  src/common/mux.js          çoklama, kredi tabanlı akış denetimi, DRR
  src/server/                DTLS dinleyici, port havuzu, koruma, yönetim yüzeyi
  src/server/peers.js        genel yüzeye bağlanan uçlar: pasif gecikme ölçümü, at/engelle
  src/server/admin/          yönetim REST + sıkı CSP'li panel (satır içi script/stil YOK)
  src/client/                cihaz kodu girişi, CSR, yerel hedeflere bağlanma
  config.example.js          yapılandırma dosyası şablonu (config.js olarak kopyalayın)
```

### Neden sürüm başına ayrı dosya yok?

`*12.js` dosyaları (`proto12`, `messages12`, `protected12`, `key-schedule12`,
`prf12`) sürüm başına ayrılmıştı. Bu ayrım iki soruna yol açıyordu:

1. **Bağımlılık yönü tersine dönüyordu** — TLS 1.3'ün `CertificateVerify`'ı,
   TLS 1.2'nin `SignatureAndHashAlgorithm` kodlamasını aynen kullanır, bu yüzden
   `messages.js` `messages12.js`'ten `sign12` import etmek zorundaydı.
2. **Düzeltmeler tek tarafta kalıyordu** — `h13_applyPeerVerification` ve
   `h12_applyPeerVerification` neredeyse birebir aynıydı; birinde yapılan
   iyileştirme diğerine taşınmayı bekliyordu.

Artık her konu tek dosyada, sürüme göre bölümlenmiş durumda: iki şemanın farkı
(HKDF ağacı vs. P_hash, unified header vs. 13 baytlık başlık) yan yana okunur
ve ortak katman bir kez yazılır.

---

## Lisans

MIT — bkz. [LICENSE](LICENSE).
