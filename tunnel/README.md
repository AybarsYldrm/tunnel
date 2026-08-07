# fitfak tünel

**DTLS 1.3 + mTLS üzerine kurulu ters proxy.** Port açamayan bir istemci, yerel
ağındaki bir servisi bu sunucu üzerinden dış dünyaya yayınlar. Kimlik
`trust.fitfak.net`'in verdiği sertifikadan, yetki `session.fitfak.net`'ten gelir.

```
  dış istemci                sunucu                        tünel istemcisi
      │                        │                                  │
      │── TCP :24913 ─────────▶│                                  │
      │                        │── OPEN (akış 7) ────────────────▶│
      │                        │                                  │── TCP ─▶ 127.0.0.2:8080
      │◀────────── veri ──────▶│◀──── DTLS 1.3 / mTLS ───────────▶│◀─ veri ─▶
```

Cloudflare Tunnel'ın çalışma mantığı; farkı taşımanın DTLS olması, kimliğin
sertifikaya bağlanması ve iptal durumunun OCSP/CRL ile denetlenmesi.

---

## İçindekiler

1. [Neden bu tasarım](#neden-bu-tasarım)
2. [Hızlı başlangıç](#hızlı-başlangıç)
3. [Protokol](#protokol--ftp-v1)
4. [Hizmet sınıfı (QoS) ve öncelik](#hizmet-sınıfı-qos-ve-öncelik)
5. [Akış denetimi ve adil sıralama](#akış-denetimi-ve-adil-sıralama)
6. [Port havuzu](#port-havuzu)
7. [DoS / DDoS koruması](#dos--ddos-koruması)
8. [Sertleştirme](#sertleştirme)
9. [Kimlik ve güven zinciri](#kimlik-ve-güven-zinciri)
10. [Yönetim yüzeyi](#yönetim-yüzeyi)
11. [Kalıcılık](#kalıcılık)
12. [Yapılandırma](#yapılandırma)
13. [Testler](#testler)
14. [Kapsam dışı](#kapsam-dışı)

---

## Neden bu tasarım

Üç karar sistemin geri kalanını belirliyor.

### 1. Taşıma DTLS, çoklama bize ait

`node-dtls`'in güvenilir kanalı (`src/reliable/channel.js`) mesaj sınırı, akış
başına sıra, parçalama ve RFC 9002 kayıp kurtarma veriyor. Doğrudan ona yazmak
iki şeyi yanlış yapardı:

| Sorun | Neden olur | Çözüm |
|---|---|---|
| **Baş tıkanması** | Kanalın gönderim kuyruğu TEK bir FIFO'dur. 200 MB'lık bir aktarımı tek mesajda verirseniz arkasındaki SSH oturumu o bitene kadar tek bayt geçiremez. | Trafik 16 KiB'lik segmentlere bölünüp akışlar arasında **açık farklı sıralı dağıtımla (DRR)** veriliyor. |
| **Sınırsız bellek** | Tıkanıklık penceresi AĞIN kapasitesini söyler, ALICININ kapasitesini değil. 1 Gbit'ten 10 Mbit'lik bir servise pompalayınca fark süreç belleğinde birikir. | **Kredi tabanlı pencere**: alıcı yerel sokete yazamadıkça kredi yollamaz, kredi gelmeyince gönderen durur. |

### 2. OPEN, denetim akışında değil veri akışında

Bir bağlantının açıldığını denetim akışından (streamId 0) bildirseydik, aynı anda
gönderilen ilk veri baytları ondan **önce** varabilirdi — denetim akışı ile veri
akışı birbirinden bağımsız sıralanır. Alıcı henüz var olmayan bir akışa ait
çerçeveyi atardı ve HTTP'nin istek satırı ya da TLS'in ClientHello'su kaybolurdu.

Bunun bir bedeli var ve karşılanması gerekiyor: veri düzleminde giden `OPEN`,
aynı bandın hacimli verisinin arkasına düşebilir. Bant yükseltmek yanlış cevap
olurdu (açılış çerçevesi kredi kadar kritik değildir ve denetim düzlemini
kirletirdi); doğru cevap **kendi bandının başına geçmek** — bkz. "Yeni bağlantı,
aynı sınıftaki aktarımı bekler mi".

`OPEN`'ı veri akışının **ilk mesajı** yapmak bunu yapısal olarak imkânsız kılıyor
ve üstüne bir tur kazandırıyor: veri, açılışın onaylanmasını beklemeden akıyor.

### 3. Kimlik sertifikadan, yetki IdP'den

İstemcinin `HELLO`'da bildirdiği ad yalnızca panelde göstermek için. Hiçbir yetki
kararında kullanılmaz — kullanılsaydı istemcinin kendi kendini adlandırması yetki
iddia etmek olurdu. Yetkinin tek kaynağı `trust.fitfak.net`'in imzaladığı ve
iptal durumu doğrulanmış sertifikadır.

---

## Hızlı başlangıç

### Sunucu

```bash
export FITFAK_TUNNEL_CERT=/etc/fitfak/tunnel.crt      # trust.fitfak.net'ten
export FITFAK_TUNNEL_KEY=/etc/fitfak/tunnel.key
export FITFAK_TUNNEL_PUBLIC_HOSTNAME=edge.fitfak.net
export FITFAK_TUNNEL_OAUTH_CLIENT_ID=fitfak-tunnel-admin
export FITFAK_TUNNEL_OAUTH_CLIENT_SECRET=...
export FITFAK_TUNNEL_OAUTH_REDIRECT_URI=http://127.0.1.3/oauth/callback
export FITFAK_TUNNEL_ROOT_CA_FINGERPRINT=3ff9779aacf342aa58ad86598229d678fa9328d907ea6db2d25fd40f040ca648

npx fitfak-tunneld
```

Kök sertifika verilmezse `http://status.trust.fitfak.net/root.crt` adresinden
indirilir. **Parmak izini sabitleyin** — gerekçesi
[Kimlik ve güven zinciri](#kimlik-ve-güven-zinciri) bölümünde.

### İstemci

```bash
npx fitfak-tunnel \
  --server tunnel.fitfak.net:4443 \
  --client-id fitfak-tunnel-cli \
  --tcp 127.0.0.2:8080 \
  --udp 127.0.0.9:5353 --lossy
```

İlk çalıştırmada tarayıcıda oturum açmanız istenir:

```
  Tarayıcında şu adresi aç:  https://session.fitfak.net/device
  Kod:                       K7RM-P4WQ

  yayında  edge.fitfak.net:24913/tcp
  yayında  edge.fitfak.net:27104/udp
```

Alınan sertifika `~/.fitfak-tunnel/` altına yazılır (0600); sonraki
çalıştırmalarda giriş sorulmaz ve ömrünün 2/3'ünde kendiliğinden yenilenir.

#### Taşıma ayarı

```bash
fitfak-tunnel --server tunnel.fitfak.net:4443 \
  --cipher chacha20 \      # AES hızlandırması olmayan uçlarda kat kat hızlı
  --cc bbr3 \              # varsayılan; 'newreno' de seçilebilir
  --mtu 1200                # IPv6 asgari MTU'suna göre güvenli değer
```

`--print-config` çözümlenmiş yapılandırmayı yazar ve çıkar — "neden benim
ayarım tutmuyor" sorusunu tek komutla bitirir. Öncelik sırası her zaman
**komut satırı > ortam değişkeni > varsayılan**.

#### Servis/otomasyon altında çalıştırma

İlk çalıştırmada kimlik yoksa tarayıcı akışı başlar. Bu, insan kullanımı için
doğru varsayılan ama bir servisin altında süreç sessizce asılı kalır ve
yeniden başlatma döngüsüne girer. `--no-enroll` bunu açık bir hataya çevirir:

```bash
fitfak-tunnel --server ... --no-enroll --quiet --json
```

| Çıkış kodu | Anlamı |
|---|---|
| `0` | Düzgün kapanış |
| `1` | Çalışma zamanı hatası (bağlanılamadı, sertifika geçersiz…) |
| `2` | Kullanım hatası (eksik/geçersiz seçenek) |
| `3` | Kimlik yok ve `--no-enroll` verildi |

`--json` her olayı satır başına bir JSON nesnesi olarak yazar
(`{"event":"ready",...}`, `{"event":"bound",...}`); günlük toplayıcıya doğrudan
verilebilir.

### Kütüphane olarak

```js
const { startTunnelServer, startTunnelClient } = require('@fitfak/dtls/tunnel');

const server = await startTunnelServer();
const client = await startTunnelClient({
  host: 'tunnel.fitfak.net', port: 4443,
  binds: [{ proto: 1, localHost: '127.0.0.2', localPort: 8080 }],
});
```

---

## Protokol — FTP v1

Her şey DTLS `application_data`'nın içinde, güvenilir kanalın üstünde.

| Yol | Akış | Ne taşır |
|---|---|---|
| Denetim düzlemi | streamId 0, sıralı | HELLO, BIND, CREDIT, PING, CONFIG, APP_SYNC |
| Veri düzlemi | streamId 1…65534, sıralı | OPEN, BYTES, FIN, RST, OPEN_ACK |
| Datagram | akışsız, tek atım | UDP, UDP_NEW, UDP_CLOSE |

**Veri çerçevesinin başlığı tek bayttır.** Akış numarasını ve sırayı alt katman
zaten taşıyor; burada tekrar etmek onu iki kez ödemek olurdu.

Denetim mesajları sabit yerleşimli ikili kodlama kullanır (`src/protocol/codec.js`)
— JSON yalnızca seyrek ve yapısı değişken olanlarda (`APP_SYNC`, `STATS`,
`CONFIG`), orada da okunabilirlik birkaç mikrosaniyeden değerli olduğu için.

### Akış numarası yeniden kullanımı

Kapanan bir numara **karantinaya** alınır (30 sn), tıpkı TCP'nin `TIME_WAIT`'i
gibi: geciken bir çerçevenin yeni bir bağlantıya karışmaması için. Kanal bir
akışta sırayı zorla atlarsa (`gap`) o numara **kalıcı olarak** yakılır — o
akıştaki veri bütünlüğü artık kanıtlanamaz.

### UDP

Kayıp toleranslı kipte datagramlar tek atım gider ve yeni akış satır içi kurulur
(`UDP_NEW` kaynak adresini taşır) — yeni bir UDP akışı açmak **bir tur bile
gerektirmez**. Kayıpsız kipte aynı yol güvenilir bir akış üzerinden işler;
orada datagram sınırları 2 baytlık uzunluk önekiyle korunur, çünkü akış katmanı
yazıları bölüp birleştirebilir.

---

## Hizmet sınıfı (QoS) ve öncelik

Aynı tünelden bir dosya indirmesi ile bir oyun sunucusu birlikte aktığında,
**adil paylaşım doğru cevap değildir.** Bir oyun istemcisi saniyede ~50 kbit
üretir; 25 Mbit'lik bir hatta ona "yarısını" vermek anlamsızdır. İhtiyacı bant
genişliği değil **sırada beklememektir**.

Her uygulama bir sınıfa atanır (panelden, `Uygulamalar → Hizmet sınıfı`):

| Sınıf | Ne için | Varsayılan olarak |
|---|---|---|
| **gerçek zamanlı** | Oyun, ses, görüntü, uzak masaüstü | UDP + kayıp toleranslı uygulamalar |
| **etkileşimli** | Web, SSH, API — varsayılan | TCP uygulamaları |
| **hacimli** | Dosya aktarımı, yedekleme, medya | elle seçilir |

Sıralama iki katmanlıdır ve ikisi farklı soruyu yanıtlar:

* **Bantlar arası katı öncelik** — "kim önce". Gerçek zamanlı bandın verisi
  varsa önce o gider.
* **Bant içi DRR** — "aynı sınıftakiler arasında kim ne kadar". Tek bir indirme,
  aynı sınıftaki diğer bağlantıları aç bırakamaz.

Katı öncelik tek başına tehlikelidir: yanlış işaretlenmiş bir uygulama hattı
sahiplenebilir. **Açlık koruması** bunu bağlar — alt bant 50 ms'dir sıra
alamadıysa, üst bant dolu olsa bile bir kuantumluk hak alır.

Öncelik **kanal kuyruğuna kadar iner**. Yalnızca çoklayıcıda sıralamak yetmezdi:
adil sıralanmış segmentler alttaki tek FIFO'ya girip geliş sırasına göre
çıkardı. Denetim çerçeveleri (kredi, kalp atışı) en üst bandı kullanır —
kredi, serbest bırakacağı verinin arkasında beklerse akış denetimi kilitlenir.

### Yeni bağlantı, aynı sınıftaki aktarımı bekler mi

Hayır — ve bunun iki ayrı mekanizması var, çünkü sınıf ayrımı bu durumu
**çözmez**: süren bir indirme ile yeni açılan bir sekme aynı sınıftadır
(etkileşimli).

* **Açılış çerçevesi fast-track'i.** `OPEN` ve `OPEN_ACK`, kanalda kendi
  bandının **başına** girer — bandı atlamaz, yalnızca aynı sınıftaki hacimli
  verinin arkasında beklemez. Bu bir konfor değil doğruluk meselesi:
  `OPEN_ACK` gecikirse karşı taraf `OPEN_TIMEOUT_MS` dolduğu için akışı
  **düşürür**; yani yerel bağlantı kurulmuş olmasına rağmen ziyaretçi
  kapanmış bir soket görür. Ayrıcalık dört parçadan büyük mesajlarda yok
  sayılır, dolayısıyla veri taşımak için kullanılamaz.
* **Yeni akış, DRR sırasının başına girer.** Sıranın sonuna eklenen bir akış,
  önündeki her akışın 32 KiB'lik kuantumunu bekler. Yeni bir bağlantının
  ihtiyacı bant genişliği değil, **ilk turu kaçırmamaktır**. Ayrıcalık ömür
  boyu bir keredir (ilk bayt gidince biter) ve yeniler kendi aralarında
  FIFO'dur.

### Kuyruk derinliği zamanla ölçülür

Çoklayıcının kanala doldurduğu veri **süreyle** sınırlıdır (`limits.targetQueueMs`,
varsayılan 20 ms), baytla değil. Sabit bir bayt bütçesi hızlı bir hatta makul,
yavaş bir hatta felakettir: 5 Mbit'te 4 MiB kuyruk, kuyruğa yeni giren her
baytın **altı saniye** beklemesi demektir. Zamana bağlanınca hattın hızı ne
olursa olsun baş-tıkanması sabit bir üst sınırda kalır.

Gerçek zamanlı bant bu sınırın dört katını kullanır: kanalın kuyruğu da
öncelikli olduğu için oraya giren paket zaten en öne geçer; onu üst katmanda
bekletmek kazanılan şeyi geri vermek olurdu. Henüz tek bayt göndermemiş bir
akış iki katını kullanır — bir bağlantının ilk segmenti, süren bir aktarımın
doldurduğu kuyruğun arkasında beklememeli. Her iki ayrıcalık da
`maxOutstandingBytes` tavanının **altında** kalır: öncelik, alıcı belleğini
şişirme hakkı değildir.

**Sürenin bir taban baytı vardır.** Bütçe yalnızca zamandan türetilseydi, hız
düştükçe bütçe de düşer ve bir noktada **besleme biriminin altına** inerdi:
1 Mbit'te 20 ms ≈ 2.5 KB'dir, oysa bir akışa tek seferde verilen segment
16 KB'dir. Bütçe segmentten küçük olduğu anda hiçbir segment kuyruğa giremez,
kuyruk boş kaldığı için hiçbir şey ACK'lenmez, ACK gelmediği için bütçe hiç
serbest kalmaz — bu bir yavaşlama değil **kilitlenmedir** ve tam da hattın en
dar olduğu anda başlar. Taban bu yüzden bayt cinsindendir: bir segment + bir
MTU. Taban devreye girdiğinde kuyruk gecikmesi `targetQueueMs`'i aşar; bu
bilinçli bir takastır (ilerleyen ama biraz gecikmeli bir kuyruk, hiç
ilerlemeyenden iyidir) ve gecikmeye duyarlı yük zaten bu kuyruğun arkasında
beklemez.

```js
limits: {
  targetQueueMs: 20,     // 10-40 ms makul aralık
}
```

### Çekirdek gönderim tamponu

`sendBufferSize` (varsayılan: işletim sistemine dokunma) küçültülebilir. Sebep:
çekirdek tamponu **bizim göremediğimiz** bir kuyruktur. Hız şekillendirici
paketleri zamana yayar, ama tampon büyükse paketler orada yığılır ve öncelik
sıralaması etkisiz kalır — gerçek zamanlı bir paket bizim kuyruğumuzu atlar,
çekirdektekinin arkasına düşer. Yavaş yükleme hatlarında (≤50 Mbit) 256 KB iyi
bir başlangıçtır.

---

## Akış denetimi ve adil sıralama

```
                    ┌──────────── tıkanıklık bütçesi (cwnd × 2) ─────────────┐
 akış A ──┐         │                                                        │
 akış B ──┼── DRR ──┼──▶ 16 KiB segmentler ──▶ ReliableChannel ──▶ DTLS ────▶│
 akış C ──┘  32 KiB │         ▲                                              │
             kuantum│         │ jeton kovası (uygulama/tünel hız sınırı)     │
                    └─────────┴──────────────────────────────────────────────┘
```

- **Akış başına pencere** 256 KiB, **tünel geneli** 8 MiB. Aşan taraf protokol
  ihlali sayılıp düşürülür — tolere etmek pencerenin bellek tavanı olma
  özelliğini tamamen ortadan kaldırırdı.
- **Kredi, veri sokete YAZILDIKTAN sonra** verilir. Alır almaz vermek pencereyi
  anlamsızlaştırırdı: gönderene "yetişiyorum" demiş olurduk, oysa henüz kimseye
  teslim etmedik.
- **Kanala aynı anda verilen bayt** tıkanıklık penceresinin iki katıyla sınırlı:
  bir pencere yolda, bir pencere kuyrukta. Daha fazlası yeni bir akışın ilk
  baytını geciktirir.
- **Bant genişliği sınırı** ek tampon gerektirmez. Gelen yön için kaynak soket
  duraklatılır; giden yön için **kredi, jeton kovasının hızında** serbest
  bırakılır — sınırlama veriyi biriktirerek değil *istemeyerek* uygulanır.

Testte doğrulanan davranış: 8 MB'lık bir indirme sürerken açılan küçük bir
bağlantı, indirme bitmeden yanıtlanıyor.

---

## Port havuzu

Varsayılan `20000–30000`. Port **rastgele** seçilir; sıradaki boş port değil.
Sıralı dağıtım, ilk kez bağlanan bir istemcinin alacağı portu dışarıdan tahmin
edilebilir kılar ve tarama yapana kolaylık sağlardı.

**Linger.** Tünel koptuğunda port hemen serbest bırakılmaz (varsayılan 20 sn).
Bir kopma çoğu zaman geçicidir; portu hemen bırakmak, dönen istemcinin farklı
bir adresle açılmasına ve dışarıdaki her yapılandırmanın (DNS kaydı, güvenlik
duvarı kuralı) bozulmasına yol açardı. Linger'daki port **yalnızca eski
sahibine** geri verilir.

`sticky: true` verilen bir uygulama portunu tünel gitse de elinde tutar.

---

## DoS / DDoS koruması

| Katman | Kapattığı senaryo |
|---|---|
| DTLS cookie takası | ECDHE ve imza maliyetine girmeden önce kaynak adresi doğrulanır |
| El sıkışma hız sınırı | Tek kaynaktan handshake seli |
| Kabul hızı (IP + genel) | Saniyede binlerce bağlantı açıp kapatmak |
| Eşzamanlılık (IP / uygulama / genel) | Bağlantı açıp hiç kapatmayarak akış tablosunu doldurmak |
| İlk bayt süresi | Slowloris — iki yönden de iptal olur, sunucu-önce konuşan protokoller kırılmaz |
| UDP paket/bayt hızı | Sahte kaynaklı UDP seli |
| **Yükseltme oranı** | Akış "kurulmuş" sayılana kadar çıkan bayt, gelenin katıyla sınırlı — sunucunun bir saldırı silahına çevrilmesini engeller |
| Üstel yasaklama | Israrlı kaynak; ceza her tekrarda uzuyor ve sessizce sönümleniyor |

Yasak bittiğinde **ihlal geçmişi silinmez** (varsayılan 1 saat hatırlanır).
Silinseydi üstel yasak diye bir şey olmazdı: saldırgan kısa yasağın bitmesini
bekler, aynı şeyi yapar, yine aynı kısa yasağı yerdi.

---

## Sertleştirme

Yukarıdaki tablo hacim saldırılarını kapatıyor. Bu bölüm onun altındaki katmanı
anlatıyor: **korunduğunu sandığın halde korunmadığın** durumları. Hepsi bu
depoda gerçekten bulunmuş ve kapatılmış açıklar; sıraları "ne kadar sessizce
başarısız oluyordu"ya göre.

### 1. Adres kanonikleştirme — sessizce çalışmayan engel

Node, çift yığınlı bir soketten gelen IPv4 bağlantısını `::ffff:203.0.113.7`,
tek yığınlıdan geleni `203.0.113.7` olarak verir. IPv6 gösterimi ayrıca
sıkıştırılabilir ve büyük/küçük harf serbesttir — `2001:DB8:0:0:0:0:0:1` ile
`2001:db8::1` aynı adrestir.

Engelleme, yasaklama ve kaynak başına sayaçların tamamı **dize karşılaştırması**
yapıyor. Yönetici panelde `203.0.113.7` yazıyor, kayıt öyle saklanıyor, gelen
bağlantı `::ffff:203.0.113.7` görünüyor, eşleşme olmuyordu. Engel hata
vermiyordu — **hiçbir şey yapmıyordu.** Aynı ayrışma hız sayaçlarını da ikiye
bölüp kaynak başına sınırları etkisizleştiriyordu.

`canonicalIp()` (`protocol/codec.js`) adresi ikiliye çevirip RFC 5952 metnine
geri yazıyor. Adres alan **her** yol — `Guard`'ın tüm metotları, `PeerRegistry`,
engel listesi — girdiyi önce oradan geçiriyor.

### 2. IP ayrıştırmada `Number()` gevşekliği

`Number('')` sıfır verir. Yani `'203.0.113.'` dört parçaya bölünüp dördüncüsü
sıfır sayılıyor, adres **geçerli** görünüyordu. `Number('0x10')` on altı,
`Number(' 7 ')` yedi verir. Bu fonksiyon aynı zamanda "bu bir IP mi" sorusunun
tek yanıtlayıcısı: engel listesi girdisini o doğruluyor. Yazım hatası içeren bir
kaydı kabul etmek, **engellenmiş görünen ama hiçbir şeyi engellemeyen** bir
kural üretiyordu. Artık her parça `/^\d{1,3}$/` ile sınanıyor.

### 3. Alıcı belleği gönderenin elinde

Bir DATA çerçevesi `count` alanında 65535 parça bildirebilir ve her parça MTU
kadar olabilir: tek mesajda ~78 MB, eşzamanlı mesajlarla gigabaytlar. Parça
sayısını sınırlamak yetmiyor, gelen baytları da saymak gerekiyor; ikisi ayrı
ayrı aşılabilir. Kanal artık her ikisini de tutuyor (`maxMessageBytes`,
`maxReassemblyBytes`) ve tavana değdiğinde bağlantıyı düşürmek yerine en eski
yarım mesajı atıyor.

Tünel bu tavanları kendi gerçek kullanımına çekiyor — kanala segment boyutundan
(16 KiB) büyük bir mesaj vermiyor, en büyüğü 256 KiB'lık APP_SYNC:

```js
maxMessageBytes: 1024 * 1024,         // kütüphane varsayılanı 16 MiB
maxReassemblyBytes: 8 * 1024 * 1024,  // kütüphane varsayılanı 64 MiB
```

> Bu iki alan bir süre **hiç uygulanmıyordu.** `normalizeOptions` güvenilir
> kanal seçenekleri için bir beyaz liste üretiyor ve listede yoktular; sessizce
> düşüyor, kanal kütüphane varsayılanına dönüyordu. Yapılandırma dosyası 1 MiB
> diyor, çalışan sistem 16 MiB kullanıyordu. Sessizce gevşeyen bir güvenlik
> sınırı hiç olmayanından beterdir — bakan kişi korunduğunu sanır.
> `tests/test-unit.js` içindeki gerileme testi tavanın kanala ulaştığını
> doğruluyor.

### 4. Kimlik doğrulamadan önce büyüyen tablolar

`/login` kimlik doğrulaması gerektirmiyor — gerektiremez de, giriş akışını o
başlatıyor. Her çağrı bir PKCE akış kaydı üretiyordu ve kayıt yalnızca akış
tamamlanınca ya da zaman aşımıyla siliniyordu. Hiç tamamlamayan bir istemci
tabloyu istediği kadar büyütebiliyordu. Aynı şey SSE bağlantıları için de
geçerli: her açık istemci bir olay kuyruğu tutuyor.

| Sınır | Değer | Kapattığı |
|---|---|---|
| `MAX_PENDING_FLOWS` | 512 | Tamamlanmayan giriş akışlarıyla bellek şişirme |
| `MAX_SESSIONS` | 256 | Oturum tablosunun sınırsız büyümesi |
| `MAX_SSE_CLIENTS` | 64 | Olay akışı bağlantılarıyla kuyruk biriktirme |

Tavana değildiğinde **en eski kayıt düşürülür**, yeni istek reddedilmez.
Reddetmek, saldırganın tabloyu doldurup meşru girişleri kilitlemesine izin
verirdi — yani bir DoS'u kapatırken başkasını açardı.

### 5. CSP yapılandırmayla gevşetilemez

`buildCsp()` politikayı kurarken `'unsafe-inline'`, `'unsafe-eval'` ve
`'unsafe-hashes'` anahtarlarını **yapılandırmadan gelseler bile** eliyor.
Panelde tek bir satıriçi `style="..."` ya da `<script>` yok; dinamik stiller
CSSOM üzerinden (`element.style.setProperty`) veriliyor — CSSOM `style-src`
kapsamı dışındadır, satıriçi `style` özniteliği değildir. Ayrıntı ve Cloudflare
beacon'ın nasıl açılacağı için bkz. [İçerik güvenliği
politikası](#i̇çerik-güvenliği-politikası).

---

## Kimlik ve güven zinciri

```
  1. kök sertifika     http://status.trust.fitfak.net/root.crt   (düz HTTP)
  2. cihaz kodu        session.fitfak.net  — RFC 8628
  3. anahtar + CSR     yerel P-256, özel anahtar ağa ÇIKMAZ
  4. imzalama          trust.fitfak.net/device/certificate
  5. mTLS              tünel sunucusuna bağlan
  6. yenileme          ömrün 2/3'ünde, HER SEFERİNDE yeni anahtar
```

**Kök neden düz HTTP?** Aksi bir döngüdür: bir sertifikayı doğrulamak için
gereken kökü HTTPS ile indirmek, o indirmeyi doğrulamak için başka bir köke
ihtiyaç duymaktır. RFC 5280 bu yüzden AIA/CDP uçlarını düz HTTP tanımlar.
Taşımaya değil, **içeriğe** güveniliyor — ve içeriğe güvenmenin yolu
`--root-ca-fingerprint` ile sabitlemektir. Sabitleme yoksa indirme "ilk
kullanımda güven"dir; bu açıkça istenmelidir ve yüksek sesle loglanır.

**Yenilemede neden yeni anahtar?** Aynı anahtarı yeniden sertifikalandırmak,
geçmişte olmuş olabilecek bir sızıntıyı bir ömür daha ileri taşımaktır.

CSR üretimi `src/client/csr.js`'te sıfırdan yazıldı (`node:crypto` CSR üretemez,
openssl alt süreci ise bu istemcinin çalışacağı yerlerde — küçük konteynerler,
gömülü cihazlar — güvenilir bir varsayım değil). Üretilen istek openssl ile
doğrulanmıştır.

---

## Yönetim yüzeyi

`http://127.0.1.3:80` — düz HTTP ve bir geri döngü adresi. Ayrım `Host`
başlığıyla değil **soket seviyesinde** yapılır: `Host`, istemcinin yazdığı bir
dizedir, soketin hangi arayüze bağlandığının kanıtı değil. Dışarıdan erişim
isteniyorsa önüne TLS sonlandıran bir ters proxy konur.

> Adresin geri döngü olması **kimlik doğrulamanın yerine geçmez**: aynı
> makinedeki her süreç oraya ulaşabilir. Yetki tek yerden gelir — IdP'de
> yönetici olmak (`role: admin`, ya da yapılandırılmış ve **doğrulanmış** bir
> e-posta adresi).

Giriş OAuth 2.0 + PKCE ile `session.fitfak.net`'e yapılır. Panel kendi kullanıcı
listesini tutmaz: ayrı bir liste, ayrı bir parola politikası ve — en kötüsü —
birisi işten ayrıldığında unutulacak ayrı bir iptal noktası demek olurdu.

Panelde görülen ve ayarlanabilenler:

- **Tüneller** — sertifika konusu/seri/geçerlilik, iptal denetimi sonucu, RTT
  (ağ ve uygulama ayrı), tıkanıklık denetleyicisi ve model durumu, ölçülen
  bant genişliği, hedef gönderim hızı, tıkanıklık penceresi, kayıp oranı,
  yeniden gönderim, anlık ve toplam bant genişliği, açık akış sayısı
- **Ziyaretçiler** — genel portlara **dışarıdan** bağlanan uçlar (aşağıda)
- **Uygulamalar** — yerel hedef (`127.0.0.2:8080`), genel port (otomatik ya da
  sabit), TCP/UDP, **kayıpsız / kayıp toleranslı teslim**, **hizmet sınıfı
  (QoS)**, yön başına Mbit/s sınırı, eşzamanlı bağlantı tavanı, port sabitleme
- **Port havuzu** — hangi port kime, ne zamandan beri, linger'da mı
- **Koruma** — düşürülen trafik, yasaklı kaynaklar, yürürlükteki sınırlar
- **Denetim kaydı** — kim, ne zaman, neyi değiştirdi

### Ziyaretçiler — kim bağlı, gecikmesi ne, nasıl atılır

Tünelin iki ayrı "istemci" kavramı var ve karıştırılmaları pahalıya patlar:

| | **İstemci** (client) | **Ziyaretçi** (peer) |
|---|---|---|
| Kim | Tüneli kuran taraf | Yayınlanmış bir genel porta (örn. `25565`) dışarıdan bağlanan |
| Kimlik | Sertifika (kriptografik) | Yalnızca IP adresi |
| Engellemek | Kalıcı yetki kararı | Genel yüzeyden dışlama |

Ziyaretçi listesi her açık dış bağlantı için kaynak adres/port, hangi uygulama
ve genel port, süre, taşınan bayt ve **gecikme** gösterir. Her satırda iki
işlem var: **At** (yalnızca o bağlantıyı kapatır) ve **Engelle** (adresi
listeye alır ve o adrese ait tüm açık bağlantıları düşürür).

Engel listesi otomatik yasaklardan **ayrı** tutulur ve diske yazılır. Otomatik
yasak bir hız sınırı tepkisidir: saniyeler içinde doğar, üstel büyür ve
kendiliğinden sönümlenir. Elle konan engel bir **karardır** ve yalnızca yine
elle kalkar — aynı tabloda tutulsalardı temizlik döngüsü yöneticinin kararını
sessizce silerdi. Süreli engel de verilebilir (`ttlMs`).

> **Gecikme "ping" değildir.** Ziyaretçiye ICMP echo atmak ham soket (root)
> ister ve pek çok ağ onu düşürür; TCP'nin çekirdekteki RTT tahmini Node'dan
> görünmez; uygulama protokolünü bilmediğimiz için protokole özgü bir yankı
> paketi de üretemeyiz. Ölçülen şey **tur süresidir**: ziyaretçiye son baytı
> yazdığımız an ile ondan gelen bir sonraki bayt arasındaki fark. Tek bir örnek
> `ağ gecikmesi + karşı tarafın düşünme süresi` toplamıdır ve işe yaramaz — ama
> kayan pencereli **minimum** alındığında düşünme süresi terimi sıfıra
> yaklaşır: sürekli konuşan bir protokolde (oyun istemcisi, SSH, HTTP
> keep-alive) er ya da geç hemen yanıtlanan bir tur olur. Panel bu yüzden ölçüm
> sayısını da gösterir; iki örnekten çıkan bir sayıya güvenilmemeli.

### İçerik güvenliği politikası

Politika `default-src 'none'` ile başlar ve tek tek açılır. Panelde **tek bir**
satır içi `style="..."` özniteliği ya da gövdeli script etiketi yoktur; dinamik
ölçüler (sparkline genişlikleri) CSS özel özelliği olarak, CSSOM üzerinden
atanır — o yol CSP'nin `style-src` kapsamı dışındadır, satır içi öznitelik ise
kapsam içindedir. Konsol hiçbir yerde `innerHTML` kullanmaz; her metin
`textContent` ile yazılır.

Bu uyum sayesinde `require-trusted-types-for 'script'` açılabiliyor: tarayıcı
artık `innerHTML`'e yazmayı **kendisi** engelliyor, yani kural gelecekte
yanlışlıkla bile ihlal edilemiyor.

Üçüncü taraf betikler varsayılan olarak **engellidir**. Paneli Cloudflare'in
arkasına koyduysanız `beacon.min.js` engellenir (konsoldaki *"Loading the script
… violates CSP"* hatası budur). Açmak isterseniz:

```js
admin: { csp: { cloudflareInsights: true } }   // ya da başka kökenler için:
admin: { csp: { scriptSrc: ['https://cdn.example.com'] } }
```

Bu, **tek bir kökene** izin verir; `'unsafe-inline'` açmaz. Zaten açılamaz da:
yapılandırmaya `'unsafe-inline'` / `'unsafe-eval'` yazılsa bile süzülür —
elimizdeki tek gerçek XSS bariyerini bir yazım hatasına bağlamak istemiyoruz.

Gönderilen diğer başlıklar: `Permissions-Policy` (tüm güçlü özellikler kapalı),
`Cross-Origin-Opener/Resource/Embedder-Policy`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

### REST API

`/api/overview`, `/api/tunnels`, `/api/clients`, `/api/apps`, `/api/ports`,
`/api/guard`, `/api/events`, `/api/metrics`, `/api/stream` (SSE)

Ziyaretçi ve engel uçları:

| Uç | Yöntem | Ne yapar |
|---|---|---|
| `/api/peers` | GET | Açık dış bağlantılar (`?appId=`, `?address=` ile süzülür) |
| `/api/peers/:id/kick` | POST | Tek bir bağlantıyı kapatır — adres engellenmez |
| `/api/blocklist` | GET | Engelli adresler |
| `/api/blocklist` | POST | `{ address, ttlMs, reason }` — 0 = kalıcı |
| `/api/blocklist/:address` | DELETE | Engeli kaldırır |

---

## Kalıcılık

`@fitfak/database`'e mTLS + gRPC üzerinden. Yumurta-tavuk sorunu fitfak-idp'deki
desenle çözülür: bootstrap TLS → güven çıpaları → enrolment → mTLS'e yükselme →
yenileme (RFC 7030/EST semantiği).

Koleksiyonlar: `tunnel_clients`, `tunnel_apps`, `tunnel_sessions`,
`tunnel_reservations`, `tunnel_events`, `tunnel_metrics`, `tunnel_blocklist`.

`tunnel_blocklist` yalnızca **elle konan** engelleri taşır. Otomatik yasaklar
diske yazılmaz ve bu bilinçli: saniyeler içinde doğup sönümlenen binlerce kaydı
kalıcılaştırmak, bir sel altında veritabanını saldırının kendisi hâline
getirirdi.

İndeks seçimi neyin sızdığını belirliyor: aranabilir olması gereken alanlar
(`clientId`, `appId`) **körlemesine** indeksli, gezilebilir olması gerekenler
(`kind`, `state`) düz indeksli. Tersi, veritabanı sunucusuna hangi müşterinin
hangi uygulamaları olduğunu şifreyi hiç çözmeden okuma imkânı verirdi.

**Veritabanı yapılandırılmazsa** bellek-içi bir uygulama kullanılır. Bu bir "test
modu" değil, tek makinelik bir kurulum için bilinçli bir seçenek — ama kalıcılık
yoktur ve açılışta bu yüksek sesle söylenir.

---

## Yapılandırma

Üç katman, net bir öncelik sırasıyla (sonraki öncekini ezer):

1. koddaki varsayılanlar
2. **ortam değişkenleri** — kapsayıcı/systemd dünyasının dili
3. **yapılandırma dosyası** — elle yönetilen kurulumlar için

Dosya neden ortamın üstünde? Dosyayı yazan kişi onu bilerek yazmıştır; ortam
değişkeni ise kabuktan, kapsayıcı imajından ya da CI'dan sızmış olabilir.
"Dosyada ne yazıyorsa o çalışır" teşhis edilebilir tek davranıştır.

```bash
cp tunnel/config.example.js tunnel/config.js   # sonra düzenleyin
# ya da başka bir yol:
FITFAK_TUNNEL_CONFIG=/etc/fitfak/tunnel.js node tunnel/bin/fitfak-tunneld.js
```

Dosya kısmi olabilir — yalnızca değiştirmek istediğiniz alanları yazın. `chmod
600` verin: OAuth `clientSecret` ve veritabanı anahtarı orada duruyor.
`tunnel/config.js` sürüm kontrolünde **yok sayılır**.

Ortam değişkenlerinin tamamı; ayrıntısı `src/server/config.js`'te.

| Değişken | Varsayılan | Ne yapar |
|---|---|---|
| `FITFAK_TUNNEL_HOST` / `_PORT` | `0.0.0.0` / `4443` | DTLS dinleyicisi |
| `FITFAK_TUNNEL_CERT` / `_KEY` | — | **zorunlu** — sunucu sertifikası |
| `FITFAK_TUNNEL_CA` | — | Kök CA dosyası (yoksa indirilir) |
| `FITFAK_TUNNEL_ROOT_CA_URL` | `http://status.trust.fitfak.net/root.crt` | Kök yayın adresi |
| `FITFAK_TUNNEL_ROOT_CA_FINGERPRINT` | — | **sabitleyin** |
| `FITFAK_TUNNEL_REVOCATION` | `hard-fail` | `off` \| `soft-fail` \| `hard-fail` |
| `FITFAK_TUNNEL_CIPHER` | `balanced` | `balanced` \| `aes128` \| `aes256` \| `aes` \| `chacha20` \| `mobile` |
| `FITFAK_TUNNEL_CONGESTION_CONTROL` | `bbr3` | `bbr3` \| `newreno` — tıkanıklık denetimi |
| `FITFAK_TUNNEL_MTU` | `1200` | Datagram yükü tavanı |
| `FITFAK_TUNNEL_CONFIG` | — | Yapılandırma dosyası yolu |
| `FITFAK_TUNNEL_PUBLIC_HOST` / `_HOSTNAME` | `0.0.0.0` / — | Bağlama adresi / gösterilen ad |
| `FITFAK_TUNNEL_PORT_MIN` / `_MAX` | `20000` / `30000` | Genel port havuzu |
| `FITFAK_TUNNEL_PORT_LINGER_MS` | `20000` | Kopmadan sonra portu tutma süresi |
| `FITFAK_TUNNEL_ALLOW_CLIENT_BINDS` | `1` | İstemci kendi uygulamasını tanımlayabilir mi |
| `FITFAK_TUNNEL_ALLOW_CLIENT_PORT_CHOICE` | `0` | İstemci sabit genel port isteyebilir mi |
| `FITFAK_TUNNEL_ADMIN_HOST` / `_PORT` | `127.0.1.3` / `80` | Yönetim yüzeyi |
| `FITFAK_TUNNEL_OAUTH_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI` | — | **zorunlu** (yönetim açıkken) |
| `FITFAK_TUNNEL_ADMIN_EMAIL` | — | İkinci kabul yolu |
| `FITFAK_TUNNEL_ADMIN_CSP_CLOUDFLARE` | `0` | Cloudflare beacon'ına izin ver |
| `FITFAK_TUNNEL_ADMIN_CSP_SCRIPT_SRC` | — | Ek betik kökenleri (boşlukla ayrık) |
| `FITFAK_TUNNEL_ADMIN_CSP_TRUSTED_TYPES` | `1` | Trusted Types zorunluluğu |
| `FITFAK_TUNNEL_DB_TARGET` | — | Verilmezse bellek-içi |
| `FITFAK_TUNNEL_SEGMENT_BYTES` | `16384` | DRR segment boyutu |
| `FITFAK_TUNNEL_STREAM_WINDOW` | `262144` | Akış başına pencere |
| `FITFAK_TUNNEL_CONNECTION_WINDOW` | `8388608` | Tünel geneli pencere |
| `FITFAK_TUNNEL_TARGET_QUEUE_MS` | `20` | Kanal kuyruğunda izin verilen gecikme |
| `FITFAK_TUNNEL_SEND_BUFFER` | `0` | UDP gönderim tamponu (0 = OS varsayılanı) |
| `FITFAK_TUNNEL_RECV_BUFFER` | `1048576` | UDP alım tamponu |
| `FITFAK_TUNNEL_LOG_LEVEL` | `INFO` | `TRACE`…`ERROR` |

---

## Testler

```bash
npm run certs               # test PKI'sı (kök CA + sunucu + istemci)
npm run test:tunnel-qos     # hizmet sınıfı, öncelikli zamanlayıcı, kuyruk derinliği
npm run test:tunnel         # uçtan uca: gerçek DTLS, gerçek TCP/UDP soketleri
npm run test:tunnel-protocol
npm run test:tunnel-admin   # gerçek HTTP + gerçek OAuth 2.0 + PKCE akışı
npm test                    # DTLS yığını + tünel, hepsi
```

Sahte taşıma katmanı kullanılmıyor. Bu tünelin çözdüğü sorunların çoğu — baş
tıkanması, geri basınç, port yaşam döngüsü — yalnızca gerçek soketler ve gerçek
zamanlama altında ortaya çıkar; bellek-içi bir kanal üzerinde hepsi "çalışıyor"
görünürdü.

**Geliştirme sırasında bulunup düzeltilen gerçek hatalar** (halının altına
süpürülmedi):

1. **Kayıpsız UDP, TCP soketi açıyordu.** İstemci `OPEN` gelince koşulsuz
   `net.connect` çağırıyordu; UDP uygulaması güvenilir kipte seçildiğinde
   yanlış soket türü açılıyor ve akış sessizce ölüyordu.
2. **Akış sınırı korunmuyordu.** Kayıpsız UDP'de datagramlar doğrudan akışa
   yazılıyordu; çoklayıcı bir bayt akışı sunduğu için iki datagram tek pakette
   birleşebiliyordu. Uzunluk önekiyle çözüldü.
3. **Saat geriye giderse hız şekillendirme kalıcı olarak kilitleniyordu.** Bir
   NTP düzeltmesi ya da sanal makine duraklaması `elapsed`'i negatif yapıyor,
   jeton kovası damgayı güncellemeden dönüyor ve bir daha ASLA dolmuyordu.
4. **Üstel yasak üstel değildi.** Yasak bitince kayıt siliniyordu; saldırgan
   kısa yasağın bitmesini bekleyip aynı şeyi yapınca ceza hiç büyümüyordu.
5. **Girdi hatası 500 dönüyordu.** Panelden gelen geçersiz bir port numarası
   sunucu arızası gibi loglanıyor ve yığın izi basıyordu.

---

## Kapsam dışı

Bilinçli olarak yapılmayanlar:

- **HTTP-farkındalığı yok.** Bu bir L4 tünelidir; `Host` başlığına göre
  yönlendirme, TLS sonlandırma ve sanal host yapmaz. Onlar tünelin ucundaki
  servisin ya da önündeki proxy'nin işi.
- **Tek sunucu.** Port rezervasyonları ve akış tabloları süreç içidir. Yatay
  ölçekleme, portu hangi düğümün tuttuğunu bilen bir dağıtıcı gerektirir.
- **Rate-limiter sayaçları örnek başına.** Kaba bir maliyet-yükseltme
  sezgiseli olarak tasarlandı; tam tutarlılık isteniyorsa kenar katmanında
  (Cloudflare Rate Limiting vb.) ele alınmalı.
- **İstemci başlatmalı akış yok.** Dış dünyayla konuşan taraf sunucu olduğu
  için akışları yalnızca o açar.
