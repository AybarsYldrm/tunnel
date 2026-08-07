'use strict';
// Güvenilir kanalın ZAMAN TABANI — tek bir monotonik saat.
//
// Kayıp kurtarma, tıkanıklık denetimi ve hız şekillendirmesinin tamamı zaman
// FARKLARI üzerine kurulu: RTT örneği, teslim hızı aralığı, jeton dolumu,
// PTO. `Date.now()` bu işlerin hiçbiri için doğru araç değil ve iki ayrı
// nedenden dolayı ölçülebilir zarar veriyordu.
//
// 1. ÇÖZÜNÜRLÜK. `Date.now()` TAM SAYI milisaniye döner. Teslim hızı örneği
//
//        teslim_hızı = teslim_edilen_bayt / max(gönderim_aralığı, ack_aralığı)
//
//    biçiminde hesaplanır ve paydadaki aralık tipik olarak birkaç
//    milisaniyedir. 3 ms'lik gerçek bir aralık 2 ya da 3 olarak okunduğunda
//    hız tahmini ±%33 sapar. Bu gürültü masum değil: bant genişliği tahmini
//    PENCERELİ MAKSİMUM olduğu için sapmanın sistematik olarak POZİTİF ucunu
//    seçer, yani model hattı olduğundan hızlı sanır, kuyruk oluşturur ve
//    ProbeBW döngüsü bunu her turda yeniden öğrenmek zorunda kalır.
//    `performance.now()` mikrosaniye altı çözünürlükte bir kayan sayı döner;
//    aynı ölçüm ±%0.03 sapar.
//
// 2. MONOTONLUK. `Date.now()` DUVAR SAATİDİR: NTP düzeltmesiyle, yaz saati
//    geçişiyle ya da sanal makinenin geri alınmasıyla GERİYE gidebilir. Geriye
//    giden bir duvar saati bu katmanda negatif RTT örneği, negatif jeton
//    dolumu ve geçmişte kalmış bir kayıp-tespiti zamanlayıcısı üretir —
//    hepsi de "ağ bozuldu" gibi görünen, aslında saatten gelen arızalar.
//    `performance.now()` süreç başlangıcından beri geçen süredir ve TANIM
//    GEREĞİ geriye gitmez.
//
// KURAL: bu katmandaki HER zaman damgası buradan gelir. Karıştırmak, iki farklı
// eksende ölçüm yapmak demektir — `Date.now()` ile alınmış bir damgadan
// `performance.now()` damgası çıkarılırsa sonuç, iki saatin başlangıç farkı
// kadar (tipik olarak milyarlarca milisaniye) anlamsız çıkar.
//
// Damgalar DIŞARI ÇIKARKEN süreye çevrilir: telde giden tek zaman alanı ACK
// gecikmesidir ve o bir FARKtır, damga değil. Süreler saat tabanından
// bağımsızdır, dolayısıyla karşı tarafın hangi saati kullandığı önemsizdir.

const { performance } = require('node:perf_hooks');

/** @returns {number} süreç başlangıcından beri geçen ms (kayan, monotonik) */
function now() { return performance.now(); }

module.exports = { now };
