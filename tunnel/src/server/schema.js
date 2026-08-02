'use strict';
// @fitfak/database koleksiyon şemaları.
//
// Alan NUMARASI kimliktir, adı değil: diske yazılan odur. Bu yüzden bir alanı
// yeniden adlandırmak serbesttir (aynı numarayla) ama numarasını değiştirmek
// ya da tipini değiştirmek yasaktır — motor bunu tanım anında reddeder, ilk
// bozuk okumada değil.
//
// İndeks seçimleri neyin SIZDIĞINI belirliyor (bkz. @fitfak/database README §9):
//
//   index      : sunucu düz değeri görür, sıralanabilir/taranabilir
//   blindIndex : sunucu yalnızca "bu değere sahip kayıt var mı" sorusunu
//                yanıtlayabilir; değeri göremez, listeleyemez
//
// Buna göre: aranabilir olması gereken (clientId, appId) körlemesine indeksli,
// GEZİLEBİLİR olması gereken (kind, state) düz indeksli. Tersini yapmak —
// örneğin appId'yi düz indekslemek — veritabanı sunucusuna, hangi müşterinin
// hangi uygulamaları olduğunu şifreyi hiç çözmeden okuma imkânı verirdi.

module.exports = {
  /** Sertifikasıyla tanınan tünel istemcileri. */
  tunnel_clients: {
    fields: [
      { no: 2, name: 'clientId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'commonName', type: 'string' },
      { no: 4, name: 'displayName', type: 'string' },
      { no: 5, name: 'email', type: 'string' },
      { no: 6, name: 'organization', type: 'string' },
      { no: 7, name: 'firstSeenAt', type: 'uint64' },
      { no: 8, name: 'lastSeenAt', type: 'uint64' },
      { no: 9, name: 'lastAddress', type: 'string' },
      { no: 10, name: 'certSerial', type: 'string' },
      { no: 11, name: 'certNotAfter', type: 'uint64' },
      { no: 12, name: 'note', type: 'string' },
      // Sertifika hâlâ geçerliyken bile bağlanmayı reddetmenin yolu. İptal
      // (OCSP/CRL) daha güçlüdür ama yayılması zaman alır; bu, anında etki
      // eden yerel bir kapıdır.
      { no: 13, name: 'blocked', type: 'bool' },
      { no: 14, name: 'ownerUserId', type: 'string' },
    ],
  },

  /** Yerel bir servisi dış dünyaya açan kural. */
  tunnel_apps: {
    fields: [
      { no: 2, name: 'appId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'clientId', type: 'string', index: true, required: true },
      { no: 4, name: 'name', type: 'string' },
      { no: 5, name: 'proto', type: 'int32' },
      { no: 6, name: 'delivery', type: 'int32' },
      { no: 7, name: 'ordered', type: 'bool' },
      { no: 8, name: 'localHost', type: 'string' },
      { no: 9, name: 'localPort', type: 'int32' },
      { no: 10, name: 'publicPort', type: 'int32' },
      { no: 11, name: 'sticky', type: 'bool' },
      { no: 12, name: 'enabled', type: 'bool' },
      { no: 13, name: 'rateInBps', type: 'int64' },
      { no: 14, name: 'rateOutBps', type: 'int64' },
      { no: 15, name: 'maxConns', type: 'int32' },
      { no: 16, name: 'idleMs', type: 'int64' },
      { no: 17, name: 'source', type: 'string' },
      { no: 18, name: 'createdBy', type: 'string' },
      { no: 19, name: 'createdAt', type: 'uint64' },
      { no: 20, name: 'updatedAt', type: 'uint64' },
    ],
  },

  /** Her tünel bağlantısı bir oturumdur — kimin ne zaman ne kadar taşıdığı. */
  tunnel_sessions: {
    fields: [
      { no: 2, name: 'tunnelId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'clientId', type: 'string', index: true, required: true },
      { no: 4, name: 'remoteAddress', type: 'string' },
      { no: 5, name: 'startedAt', type: 'uint64' },
      { no: 6, name: 'endedAt', type: 'uint64' },
      { no: 7, name: 'bytesIn', type: 'int64' },
      { no: 8, name: 'bytesOut', type: 'int64' },
      { no: 9, name: 'protocol', type: 'string' },
      { no: 10, name: 'cipher', type: 'string' },
      { no: 11, name: 'certSerial', type: 'string' },
      { no: 12, name: 'closeReason', type: 'string' },
      { no: 13, name: 'streamsOpened', type: 'int64' },
    ],
  },

  /** Port rezervasyonları — hangi portun kime, ne zamandan beri ayrıldığı. */
  tunnel_reservations: {
    fields: [
      { no: 2, name: 'key', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'proto', type: 'int32' },
      { no: 4, name: 'port', type: 'int32' },
      { no: 5, name: 'appId', type: 'string', index: true },
      { no: 6, name: 'clientId', type: 'string', index: true },
      { no: 7, name: 'acquiredAt', type: 'uint64' },
      { no: 8, name: 'releasedAt', type: 'uint64' },
      { no: 9, name: 'state', type: 'string', index: true },
    ],
  },

  /** Yönetim işlemlerinin denetim kaydı. */
  tunnel_events: {
    fields: [
      { no: 2, name: 'eventId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'kind', type: 'string', index: true },
      { no: 4, name: 'actor', type: 'string' },
      { no: 5, name: 'subject', type: 'string' },
      { no: 6, name: 'detail', type: 'string' },
      // Gün kovalı aralık sorgusu: sunucu hangi GÜN olduğunu görür, tam anı
      // değil. "Son 7 günün olayları" için yeterli, zaman analizi için değil.
      { no: 7, name: 'at', type: 'uint64', rangeBucket: { width: 86400000 } },
    ],
  },

  /** Panelin grafiklerini besleyen periyodik örnekler. */
  tunnel_metrics: {
    fields: [
      { no: 2, name: 'sampleId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'clientId', type: 'string', index: true },
      { no: 4, name: 'appId', type: 'string', index: true },
      { no: 5, name: 'at', type: 'uint64', rangeBucket: { width: 3600000 } },
      { no: 6, name: 'bytesIn', type: 'int64' },
      { no: 7, name: 'bytesOut', type: 'int64' },
      { no: 8, name: 'rateIn', type: 'int64' },
      { no: 9, name: 'rateOut', type: 'int64' },
      { no: 10, name: 'rttMs', type: 'int32' },
      { no: 11, name: 'connections', type: 'int32' },
      { no: 12, name: 'lossPpm', type: 'int32' },
    ],
  },
};
