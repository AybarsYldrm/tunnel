'use strict';
// Yönetim konsolu.
//
// Çerçeve yok, derleme adımı yok, bağımlılık yok — sunucunun kendisi de öyle.
//
// TEK BİR `innerHTML` ATAMASI YOK ve bu bilinçli bir kural.
//
// Bu sayfadaki verilerin çoğu DIŞARIDAN geliyor: istemcinin kendi bildirdiği
// ad, sertifika konusu, dışarıdan bağlanan bir ucun IP'si, hata mesajları.
// Önceki sürüm bunları bir `esc()` yardımcısından geçirip dize birleştirmeyle
// HTML üretiyordu. O yaklaşım iki nedenle terk edildi:
//
//   1. TEK BİR UNUTMA YETER. `esc()` çağrısı atlanmış bir yer, tünel istemcisi
//      olan HERKESE yönetim panelinde kod çalıştırma imkânı verir. Doğruluğu
//      "her çağrı noktasında dikkatli olmak"a bağlı bir savunma, savunma
//      değildir.
//   2. CSP'Yİ GERÇEK KILAR. `require-trusted-types-for 'script'` başlığı
//      innerHTML'e yazmayı tarayıcı seviyesinde yasaklar. Ancak sayfa zaten
//      hiç kullanmıyorsa açılabilir — ve açıldığında bu kural bir daha asla
//      ihlal edilemez hâle gelir.
//
// Yerine geçen şey `el()`: düğüm ağacını doğrudan kurar, metni daima
// `textContent` ile yazar. Metin ile biçimlendirme hiçbir noktada aynı dizede
// buluşmaz, dolayısıyla kaçırılacak bir şey de kalmaz.
//
// Dinamik ölçüler (sparkline genişliği) CSS ÖZEL ÖZELLİĞİ olarak atanır:
// CSSOM üzerinden stil yazmak CSP'nin `style-src` kapsamı dışındadır, satır içi
// `style="..."` özniteliği ise kapsam içindedir. Aradaki fark, panelin
// `'unsafe-inline'` olmadan çalışabilmesidir.

(function () {
  // ======================================================================
  // DOM yardımcıları
  // ======================================================================
  function $(id) { return document.getElementById(id); }

  function append(node, children) {
    if (children === null || children === undefined) return node;
    var list = Array.isArray(children) ? children : [children];
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (c === null || c === undefined || c === false) continue;
      node.appendChild(
        (typeof c === 'string' || typeof c === 'number')
          ? document.createTextNode(String(c))
          : c,
      );
    }
    return node;
  }

  /**
   * @param {string} tag
   * @param {object} [o] { class, text, id, attrs, on, props, vars }
   * @param {*} [children] düğüm, dize ya da bunların dizisi
   */
  function el(tag, o, children) {
    var node = document.createElement(tag);
    if (o) {
      if (o.class) node.className = o.class;
      if (o.id) node.id = o.id;
      // Metin DAİMA textContent ile: burada bir HTML ayrıştırıcısı yok.
      if (o.text !== undefined && o.text !== null) node.textContent = String(o.text);
      if (o.attrs) Object.keys(o.attrs).forEach(function (k) { node.setAttribute(k, o.attrs[k]); });
      if (o.props) Object.keys(o.props).forEach(function (k) { node[k] = o.props[k]; });
      if (o.on) Object.keys(o.on).forEach(function (k) { node.addEventListener(k, o.on[k]); });
      // CSS özel özellikleri — CSSOM yolu, satır içi `style` özniteliği değil.
      if (o.vars) Object.keys(o.vars).forEach(function (k) { node.style.setProperty(k, o.vars[k]); });
    }
    return append(node, children);
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function replace(node, children) { clear(node); return append(node, children); }

  // ---------- biçimlendirme ----------
  function bytes(n) {
    n = Number(n) || 0;
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + ' ' + units[i];
  }

  function bits(bytesPerSec) {
    var b = (Number(bytesPerSec) || 0) * 8;
    var units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
    var i = 0;
    while (b >= 1000 && i < units.length - 1) { b /= 1000; i++; }
    return (i === 0 ? Math.round(b) : b.toFixed(b < 10 ? 2 : 1)) + ' ' + units[i];
  }

  // Logaritmik: 10 kbit ile 100 Mbit aynı çubukta okunabilsin diye.
  function sparkPercent(bytesPerSec) {
    var b = (Number(bytesPerSec) || 0) * 8;
    if (b <= 0) return 0;
    return Math.max(2, Math.min(100, Math.round((Math.log10(b) / Math.log10(1e9)) * 100)));
  }

  function ms(v) { return v === null || v === undefined ? '—' : Math.round(v) + ' ms'; }

  function date(v) { return v ? new Date(Number(v)).toLocaleString('tr-TR') : '—'; }

  function duration(v) {
    if (!v) return '—';
    var s = Math.floor(v / 1000);
    if (s < 60) return s + ' sn';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' dk';
    var h = Math.floor(m / 60);
    if (h < 24) return h + ' sa ' + (m % 60) + ' dk';
    return Math.floor(h / 24) + ' gün ' + (h % 24) + ' sa';
  }

  function short(s, n) {
    s = String(s === null || s === undefined ? '' : s);
    var max = n || 16;
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  // ---------- yeniden kullanılan parçalar ----------
  function badge(text, kind) {
    return el('span', { class: 'badge badge-' + (kind || 'neutral'), text: text });
  }

  function mono(text, cls) {
    return el('span', { class: cls ? 'mono ' + cls : 'mono', text: text });
  }

  function sub(text) { return el('div', { class: 'cell-sub', text: text }); }

  function subMono(text) { return el('div', { class: 'cell-sub mono', text: text }); }

  function strongCell(text) { return el('div', { class: 'cell-strong', text: text }); }

  function statCard(label, value, note) {
    var big = String(value).length > 9;
    return el('div', { class: 'stat' }, [
      el('div', { class: 'stat-label', text: label }),
      el('div', { class: 'stat-value' + (big ? ' sm' : ''), text: value }),
      el('div', { class: 'stat-note', text: note === undefined ? '' : note }),
    ]);
  }

  function renderStats(hostId, rows) {
    replace($(hostId), rows.map(function (x) { return statCard(x[0], x[1], x[2]); }));
  }

  /** Bant genişliği çubuğu. Genişlik CSS değişkeniyle veriliyor. */
  function spark(bytesPerSec, down) {
    return el('div', { class: down ? 'spark down' : 'spark' }, [
      el('i', { vars: { '--spark-fill': sparkPercent(bytesPerSec) + '%' } }),
    ]);
  }

  function btn(label, cls, onClick) {
    return el('button', {
      class: 'btn btn-sm' + (cls ? ' ' + cls : ''),
      text: label,
      attrs: { type: 'button' },
      on: { click: onClick },
    });
  }

  function btnRow(buttons) { return el('div', { class: 'btn-row' }, buttons); }

  function td(row, content, cls) {
    var cell = row.insertCell();
    if (cls) cell.className = cls;
    append(cell, content);
    return cell;
  }

  function emptyRow(tbody, cols, text) {
    clear(tbody);
    var cell = tbody.insertRow().insertCell();
    cell.colSpan = cols;
    cell.className = 'empty';
    cell.textContent = text;
  }

  function section(title, rows) {
    var dl = el('dl', { class: 'kv' });
    rows.forEach(function (r) {
      append(dl, [el('dt', { text: r[0] }), el('dd', { text: r[1] })]);
    });
    return el('div', null, [el('div', { class: 'stat-label', text: title }), dl]);
  }

  // ---------- form alanları ----------
  function labelFor(id, text) { return el('label', { attrs: { for: id }, text: text }); }

  function input(id, type, value, attrs) {
    var a = { type: type, id: id };
    if (attrs) Object.keys(attrs).forEach(function (k) { a[k] = attrs[k]; });
    var node = el('input', { id: id, attrs: a });
    if (value !== undefined && value !== null) node.value = String(value);
    return node;
  }

  function select(id, options, selected) {
    return el('select', { id: id, attrs: { id: id } }, options.map(function (o) {
      var opt = el('option', { text: o.label, attrs: { value: o.value } });
      if (o.value === selected) opt.selected = true;
      return opt;
    }));
  }

  function checkbox(id, label, checked) {
    var box = el('input', { id: id, attrs: { type: 'checkbox', id: id } });
    box.checked = !!checked;
    return el('div', { class: 'check-row' }, [box, labelFor(id, label)]);
  }

  function hint(text, cls) {
    return el('div', { class: cls ? 'field-hint ' + cls : 'field-hint', text: text });
  }

  function fieldRow(cells) { return el('div', { class: 'field-row' }, cells); }

  function field(id, label, node) { return el('div', null, [labelFor(id, label), node]); }

  // ======================================================================
  // Durum ve API
  // ======================================================================
  var state = {
    overview: null, tunnels: [], clients: [], apps: [], peers: [], blocklist: [],
  };

  function showErr(m) {
    $('ok').classList.remove('show');
    var e = $('err');
    e.textContent = m;
    e.classList.add('show');
  }

  function showOk(m) {
    $('err').classList.remove('show');
    var e = $('ok');
    e.textContent = m;
    e.classList.add('show');
    setTimeout(function () { e.classList.remove('show'); }, 4000);
  }

  function clearBanners() {
    $('err').classList.remove('show');
    $('ok').classList.remove('show');
  }

  function api(path, opts) {
    opts = opts || {};
    return fetch(path, {
      method: opts.method || 'GET',
      credentials: 'same-origin',
      headers: opts.body ? { 'content-type': 'application/json' } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    }).then(function (res) {
      if (res.status === 401) { window.location.href = '/login'; throw new Error('oturum gerekli'); }
      return res.json().catch(function () { return null; }).then(function (data) {
        if (!res.ok) throw new Error((data && (data.message || data.error)) || ('HTTP ' + res.status));
        return data;
      });
    });
  }

  function fail(e) { showErr(e.message); }

  // ======================================================================
  // Navigasyon
  // ======================================================================
  var LOADERS = {};

  function activeView() {
    var active = document.querySelector('.nav-item.active');
    return active ? active.dataset.view : null;
  }

  Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (button) {
    button.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (b) {
        b.classList.remove('active');
      });
      button.classList.add('active');
      Array.prototype.forEach.call(document.querySelectorAll('.view'), function (v) {
        v.classList.remove('active');
      });
      $('view-' + button.dataset.view).classList.add('active');
      clearBanners();
      if (LOADERS[button.dataset.view]) LOADERS[button.dataset.view]();
    });
  });

  // ======================================================================
  // Kip (modal)
  // ======================================================================
  var modalSave = null;

  /** @param {Node|Node[]} body — dize değil DÜĞÜM; HTML ayrıştırma yok. */
  function openModal(title, body, onSave, saveLabel) {
    $('modal-title').textContent = title;
    replace($('modal-body'), body);
    modalSave = onSave;
    $('modal-save').textContent = saveLabel || 'Kaydet';
    $('modal-save').hidden = !onSave;
    $('modal-backdrop').classList.add('open');
  }

  function closeModal() {
    $('modal-backdrop').classList.remove('open');
    modalSave = null;
  }

  $('modal-cancel').addEventListener('click', closeModal);
  $('modal-backdrop').addEventListener('click', function (e) {
    if (e.target === $('modal-backdrop')) closeModal();
  });
  $('modal-save').addEventListener('click', function () {
    if (!modalSave) return;
    var button = this;
    button.disabled = true;
    Promise.resolve(modalSave())
      .then(closeModal)
      .catch(fail)
      .finally(function () { button.disabled = false; });
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });

  /** Onay kipi — silme/kapatma gibi geri alınamayan işlemler için. */
  function confirmModal(title, body, action, label) {
    openModal(title, body, action, label);
  }

  // ======================================================================
  // GENEL BAKIŞ
  // ======================================================================
  function renderOverview(o) {
    if (!o) return;
    state.overview = o;
    $('listener').textContent = o.listener
      ? 'dtls ' + o.listener.address + ':' + o.listener.port
      : 'dinlemiyor';
    $('count-tunnels').textContent = o.tunnels.online;
    $('count-apps').textContent = o.apps.total;
    if (o.peers) $('count-peers').textContent = o.peers.active;

    renderStats('overview-stats', [
      ['Bağlı tünel', o.tunnels.online, o.apps.published + ' uygulama yayında'],
      ['Trafik ↓ / ↑', bits(o.traffic.rateIn) + ' / ' + bits(o.traffic.rateOut),
        bytes(o.traffic.bytesIn) + ' / ' + bytes(o.traffic.bytesOut) + ' toplam'],
      ['Ortalama RTT', o.link.avgRttMs === null ? '—' : o.link.avgRttMs + ' ms',
        o.link.congestionControl ? o.link.congestionControl + ' · yumuşatılmış' : 'RFC 9002 yumuşatılmış'],
      ['Açık akış', o.streams, 'mantıksal bağlantı'],
      ['Ziyaretçi', o.peers ? o.peers.active : '—',
        o.peers ? (o.peers.total + ' toplam · ' + o.peers.blocked + ' engelli') : 'genel yüzey'],
      ['Port havuzu', o.ports.free + ' boş',
        o.ports.active + ' kullanımda · ' + o.ports.linger + ' beklemede'],
      ['Reddedilen', o.guard.refused, o.guard.bannedIps + ' yasaklı kaynak'],
      ['Çalışma süresi', duration(o.uptimeMs), 'kalıcılık: ' + o.persistence],
    ]);
  }

  function tunnelHealthBadge(t) {
    if (t.state !== 'ready') return badge(t.state, 'warn');
    if (t.revocation && !t.revocation.ok) return badge('iptal denetimi', 'bad');
    if (t.link.lossRate > 0.05) return badge('kayıp %' + (t.link.lossRate * 100).toFixed(1), 'warn');
    return badge('sağlıklı', 'ok');
  }

  function renderOverviewTunnels() {
    var tb = $('overview-tunnels');
    if (!state.tunnels.length) { emptyRow(tb, 7, 'Bağlı tünel yok.'); return; }
    clear(tb);
    state.tunnels.forEach(function (t) {
      var tr = tb.insertRow();
      td(tr, [strongCell(t.name), subMono(short(t.clientId, 20))]);
      td(tr, [mono(t.remoteAddress + ':' + t.remotePort), sub(t.transport.protocol || '—')]);
      td(tr, [ms(t.link.rttMs), sub('min ' + ms(t.link.minRttMs))], 'num');
      td(tr, [
        '↓ ' + bits(t.traffic.rateIn), spark(t.traffic.rateIn, true),
        '↑ ' + bits(t.traffic.rateOut), spark(t.traffic.rateOut, false),
      ], 'num');
      td(tr, [bytes(t.traffic.bytesIn + t.traffic.bytesOut), sub(t.streams.open + ' akış')], 'num');
      td(tr, String(t.apps.length), 'num');
      td(tr, tunnelHealthBadge(t));
    });
  }

  LOADERS.overview = function () {
    return Promise.all([api('/api/overview'), api('/api/tunnels')]).then(function (res) {
      renderOverview(res[0]);
      state.tunnels = res[1].tunnels;
      renderOverviewTunnels();
      replace($('whoami'), ['Oturum: ', el('strong', { text: res[0].me.username })]);
    }).catch(fail);
  };

  // ======================================================================
  // TÜNELLER
  // ======================================================================
  function tunnelCard(t) {
    var wrap = el('div', { class: 'table-wrap' });

    var head = el('div', { class: 'table-head' }, [
      el('h2', null, [
        t.name, ' ',
        badge(t.transport.protocol || '—', 'neutral'), ' ',
        tunnelHealthBadge(t),
      ]),
      btnRow([
        btn('Bant sınırı', null, function () { openTunnelLimitModal(t); }),
        btn('Uygulama ekle', null, function () { openAppModal(null, t.clientId); }),
        btn('Bağlantıyı kes', 'btn-danger', function () {
          confirmModal('Tüneli kapat', [
            el('p', null, [
              '“' + t.name + '” tüneli kapatılacak. Yayındaki ',
              el('strong', { text: t.apps.length + ' uygulama' }),
              ' anında erişilemez olur; portlar kısa bir süre bu istemci için ayrılmış kalır.',
            ]),
          ], function () {
            return api('/api/tunnels/' + encodeURIComponent(t.tunnelId) + '/disconnect', {
              method: 'POST', body: {},
            }).then(function () { showOk('Tünel kapatıldı.'); return LOADERS.tunnels(); });
          }, 'Kapat');
        }),
      ]),
    ]);
    append(wrap, head);

    var cert = t.certificate || {};
    var rev = t.revocation;
    var link = t.link;
    append(wrap, el('div', { class: 'card-body' }, [
      section('Bağlantı', [
        ['Adres', t.remoteAddress + ':' + t.remotePort],
        ['Şifre', t.transport.cipher || '—'],
        ['Çalışma süresi', duration(t.uptimeMs)],
        ['Tünel kimliği', t.tunnelId],
      ]),
      section('Bağlantı kalitesi', [
        ['Tıkanıklık denetimi', link.congestionControl || '—'],
        ['RTT (ağ)', ms(link.rttMs) + ' · min ' + ms(link.minRttMs)],
        ['RTT (uygulama)', ms(link.appRttMs)],
        ['Tahmini bant genişliği', link.bandwidthBps ? bits(link.bandwidthBps) : '—'],
        ['Hedef gönderim hızı', link.pacingRateBps ? bits(link.pacingRateBps) : 'şekillendirme yok'],
        ['Tıkanıklık penceresi', bytes(link.congestionWindow) + ' · uçuşta ' + bytes(link.bytesInFlight)],
        ['Model durumu', link.ccState || '—'],
        ['Kayıp', (link.lossRate * 100).toFixed(3) + '% · ' + link.retransmits + ' yeniden gönderim'],
        ['Kuyruk (kanal)', bytes(link.channelQueuedBytes || 0) + ' / ' + bytes(link.queueAllowanceBytes || 0)],
        // Sapma milisaniyenin altında anlamlıdır: 1.2 ms ile 15.6 ms arasındaki
        // fark, hattın tamamı ile onda biri arasındaki farktır.
        ['Patlama payı', link.pacingBurstBytes
          ? bytes(link.pacingBurstBytes) + ' · ' + Number(link.pacingBurstMs).toFixed(1) + ' ms'
          : '—'],
        ['Zamanlayıcı sapması', link.timerLagMs == null
          ? '—'
          : Number(link.timerLagMs).toFixed(1) + ' ms'],
        ['Sırada (sınıfa göre)', (link.queuedByBand || []).join(' · ') || '—'],
      ]),
      section('Trafik', [
        ['Anlık', '↓ ' + bits(t.traffic.rateIn) + ' / ↑ ' + bits(t.traffic.rateOut)],
        ['Toplam', bytes(t.traffic.bytesIn) + ' / ' + bytes(t.traffic.bytesOut)],
        ['Çıkış sınırı', t.traffic.egressLimitBps ? bits(t.traffic.egressLimitBps) : 'sınırsız'],
        ['Akışlar', t.streams.open + ' açık · ' + t.streams.opened + ' toplam · ' + t.streams.resets + ' reset'],
        ['Datagram', t.datagrams.in + ' ↓ / ' + t.datagrams.out + ' ↑ · ' + t.datagrams.dropped + ' düşen'],
      ]),
      section('Sertifika', [
        ['Konu', cert.commonName || '—'],
        ['Veren', cert.issuer || '—'],
        ['Seri', cert.serialNumber || '—'],
        ['Geçerlilik', (cert.validFrom || '—') + ' → ' + (cert.validTo || '—')],
        ['Parmak izi', short(cert.fingerprint256, 32)],
        ['İptal denetimi', rev ? (rev.ok ? 'geçerli' : ('BAŞARISIZ: ' + rev.error)) : 'kapalı'],
      ]),
    ]));

    if (t.apps.length) {
      var tbody = el('tbody');
      t.apps.forEach(function (a) {
        var tr = tbody.insertRow();
        td(tr, [strongCell(a.name), sub(a.protocol + ' · ' + a.delivery)]);
        td(tr, mono(a.local));
        td(tr, a.publicPort
          ? el('span', { class: 'chip', text: (a.publicHost || '') + ':' + a.publicPort })
          : badge('bağlı değil', 'warn'));
        td(tr, a.live ? (a.live.activeConnections + ' / ' + a.live.totalConnections) : '—', 'num');
        td(tr, a.live ? (bytes(a.live.bytesIn) + ' ↓ / ' + bytes(a.live.bytesOut) + ' ↑') : '—', 'num');
        td(tr, a.enabled ? badge('açık', 'ok') : badge('kapalı', 'neutral'));
      });

      append(wrap, el('div', { class: 'table-scroll card-table' }, [
        el('table', null, [
          el('thead', null, [
            el('tr', null, ['Uygulama', 'Yerel', 'Genel', 'Bağlantı', 'Trafik', 'Durum']
              .map(function (h) { return el('th', { text: h }); })),
          ]),
          tbody,
        ]),
      ]));
    }
    return wrap;
  }

  function openTunnelLimitModal(t) {
    var current = t.traffic.egressLimitBps ? (t.traffic.egressLimitBps * 8 / 1e6) : 0;
    openModal('Bant sınırı — ' + t.name, [
      hint('Tünelin TOPLAM çıkış hızı (sunucudan istemciye). 0 = sınırsız. '
           + 'Sınır, uygulama başına verilen sınırların üstünde bir tavandır.', 'modal-hint-top'),
      labelFor('egress', 'Çıkış (Mbit/s)'),
      input('egress', 'number', current, { min: '0', step: '0.1' }),
    ], function () {
      return api('/api/tunnels/' + encodeURIComponent(t.tunnelId) + '/limits', {
        method: 'POST', body: { egressMbit: Number($('egress').value) || 0 },
      }).then(function () { showOk('Sınır uygulandı.'); return LOADERS.tunnels(); });
    });
  }

  LOADERS.tunnels = function () {
    return api('/api/tunnels').then(function (res) {
      state.tunnels = res.tunnels;
      var host = $('tunnel-cards');
      if (!res.tunnels.length) {
        replace(host, el('div', { class: 'table-wrap' }, [
          el('div', { class: 'empty', text: 'Bağlı tünel yok.' }),
        ]));
        return;
      }
      replace(host, res.tunnels.map(tunnelCard));
    }).catch(fail);
  };

  // ======================================================================
  // İSTEMCİLER
  // ======================================================================
  function renderClients() {
    var q = ($('client-filter').value || '').toLowerCase();
    var rows = state.clients.filter(function (c) {
      return !q || [c.commonName, c.displayName, c.email, c.clientId].some(function (v) {
        return String(v || '').toLowerCase().indexOf(q) >= 0;
      });
    });
    $('count-clients').textContent = state.clients.length;

    var tb = $('clients-body');
    if (!rows.length) { emptyRow(tb, 5, 'Kayıtlı istemci yok.'); return; }
    clear(tb);
    rows.forEach(function (c) {
      var tr = tb.insertRow();
      td(tr, [
        strongCell(c.displayName || c.commonName || '—'),
        sub(c.email || ''),
        subMono(short(c.clientId, 24)),
      ]);
      td(tr, [subMono(c.certSerial || '—'), sub('bitiş: ' + date(c.certNotAfter))]);
      td(tr, [date(c.lastSeenAt), subMono(c.lastAddress || '')]);
      td(tr, c.blocked
        ? badge('engelli', 'bad')
        : (c.online ? badge('çevrimiçi', 'ok') : badge('çevrimdışı', 'neutral')));
      td(tr, btnRow([
        btn('Uygulama ekle', null, function () { openAppModal(null, c.clientId); }),
        btn(c.blocked ? 'Engeli kaldır' : 'Engelle', c.blocked ? null : 'btn-danger', function () {
          api('/api/clients/' + encodeURIComponent(c.clientId) + '/block', {
            method: 'POST', body: { blocked: !c.blocked },
          }).then(function () {
            showOk(c.blocked ? 'Engel kaldırıldı.' : 'İstemci engellendi.');
            return LOADERS.clients();
          }).catch(fail);
        }),
      ]));
    });
  }

  $('client-filter').addEventListener('input', renderClients);

  LOADERS.clients = function () {
    return api('/api/clients').then(function (res) {
      state.clients = res.clients;
      renderClients();
    }).catch(fail);
  };

  // ======================================================================
  // ZİYARETÇİLER — genel yüzeye dışarıdan bağlananlar
  // ======================================================================
  /**
   * Gecikme PASİF ölçümdür (bkz. server/peers.js): son yazdığımız bayt ile
   * uçtan gelen bir sonraki bayt arasındaki en küçük fark. Kullanıcıya bunun
   * bir "ping" olmadığı, ölçüm yöntemi rozetle söyleniyor.
   */
  function rttCell(p) {
    if (p.rttMs === null || p.rttMs === undefined) {
      return el('span', { class: 'rtt rtt-unknown', text: '—' });
    }
    var cls = p.rttMs < 60 ? 'rtt-good' : (p.rttMs < 150 ? 'rtt-fair' : 'rtt-poor');
    return el('span', { class: 'rtt ' + cls, text: Math.round(p.rttMs) + ' ms' });
  }

  function renderPeers() {
    var q = ($('peer-filter').value || '').toLowerCase();
    var rows = state.peers.filter(function (p) {
      return !q || [p.address, String(p.port), p.appName, String(p.publicPort)].some(function (v) {
        return String(v || '').toLowerCase().indexOf(q) >= 0;
      });
    });
    $('count-peers').textContent = state.peers.length;

    var tb = $('peers-body');
    if (!rows.length) { emptyRow(tb, 7, 'Açık bağlantı yok.'); return; }
    clear(tb);
    rows.forEach(function (p) {
      var tr = tb.insertRow();
      td(tr, [mono(p.address), sub('kaynak port ' + p.port)]);
      td(tr, [strongCell(p.appName || '—'), sub(p.protocol + ' · ' + (p.tunnelName || '—'))]);
      td(tr, mono(String(p.publicPort || '—')), 'num');
      td(tr, [
        rttCell(p),
        sub(p.samples
          ? (p.samples + ' ölçüm · son ' + (p.lastRttMs === null ? '—' : Math.round(p.lastRttMs) + ' ms'))
          : 'ölçülmedi'),
      ], 'num');
      td(tr, duration(p.uptimeMs), 'num');
      td(tr, [
        bytes(p.bytesIn + p.bytesOut),
        sub('↓ ' + bytes(p.bytesIn) + ' / ↑ ' + bytes(p.bytesOut)),
      ], 'num');
      td(tr, btnRow([
        btn('At', null, function () {
          api('/api/peers/' + encodeURIComponent(p.id) + '/kick', { method: 'POST', body: {} })
            .then(function () { showOk('Bağlantı kapatıldı.'); return LOADERS.peers(); })
            .catch(fail);
        }),
        btn('Engelle', 'btn-danger', function () { openBlockModal(p.address); }),
      ]));
    });
  }

  function renderBlocklist() {
    var tb = $('blocklist-body');
    if (!state.blocklist.length) { emptyRow(tb, 5, 'Engelli adres yok.'); return; }
    clear(tb);
    state.blocklist.forEach(function (b) {
      var tr = tb.insertRow();
      td(tr, mono(b.address));
      td(tr, b.reason || '—');
      td(tr, sub(b.actor || '—'));
      td(tr, b.expiresAt ? duration(b.expiresAt - Date.now()) : badge('kalıcı', 'dark'), 'num');
      td(tr, btn('Kaldır', null, function () {
        api('/api/blocklist/' + encodeURIComponent(b.address), { method: 'DELETE' })
          .then(function () { showOk('Engel kaldırıldı.'); return LOADERS.peers(); })
          .catch(fail);
      }));
    });
  }

  function openBlockModal(address) {
    openModal('Adresi engelle', [
      hint('Engellenen adres genel portlara BAĞLANAMAZ ve o adrese ait açık '
           + 'bağlantılar hemen kapatılır. Süre boş bırakılırsa engel kalıcıdır.',
           'modal-hint-top'),
      labelFor('blk-addr', 'IP adresi'),
      input('blk-addr', 'text', address || '', { placeholder: '203.0.113.10' }),
      fieldRow([
        field('blk-ttl', 'Süre (dakika, 0 = kalıcı)', input('blk-ttl', 'number', 0, { min: '0' })),
        field('blk-reason', 'Sebep', input('blk-reason', 'text', '', { maxlength: '120' })),
      ]),
    ], function () {
      var addr = $('blk-addr').value.trim();
      if (!addr) return Promise.reject(new Error('IP adresi gerekli'));
      var minutes = Number($('blk-ttl').value) || 0;
      return api('/api/blocklist', {
        method: 'POST',
        body: {
          address: addr,
          ttlMs: minutes > 0 ? minutes * 60_000 : 0,
          reason: $('blk-reason').value.trim(),
        },
      }).then(function () { showOk('Adres engellendi.'); return LOADERS.peers(); });
    }, 'Engelle');
  }

  $('peer-filter').addEventListener('input', renderPeers);
  $('btn-peers-refresh').addEventListener('click', function () {
    clearBanners();
    LOADERS.peers().then(function () { showOk('Yenilendi.'); });
  });
  $('btn-block-add').addEventListener('click', function () { openBlockModal(''); });

  LOADERS.peers = function () {
    return Promise.all([api('/api/peers'), api('/api/blocklist')]).then(function (res) {
      state.peers = res[0].peers;
      state.blocklist = res[1].blocklist;
      var s = res[0].stats;
      renderStats('peer-stats', [
        ['Açık bağlantı', s.active, s.distinctAddresses + ' farklı adres'],
        ['Toplam', s.total, s.kicked + ' atıldı'],
        ['Ortalama gecikme', s.avgRttMs === null ? '—' : s.avgRttMs + ' ms', 'pasif ölçüm'],
        ['Engelli adres', state.blocklist.length, s.blockedRejections + ' istek reddedildi'],
      ]);
      renderPeers();
      renderBlocklist();
    }).catch(fail);
  };

  // ======================================================================
  // UYGULAMALAR
  // ======================================================================
  /**
   * Hizmet sınıfı rozeti. Renk kodu bilinçli: gerçek zamanlı olan "iyi" değil,
   * ÖNCELİKLİ demek — panelde bunun bir performans göstergesi değil bir
   * yapılandırma seçimi olduğu görünmeli.
   */
  var QOS_LABEL = {
    realtime: 'gerçek zamanlı',
    interactive: 'etkileşimli',
    bulk: 'hacimli',
  };
  var QOS_KIND = { realtime: 'ok', interactive: 'neutral', bulk: 'dark' };

  function qosBadge(qos) {
    var key = QOS_LABEL[qos] ? qos : 'interactive';
    return badge(QOS_LABEL[key], QOS_KIND[key]);
  }

  function appStatusBadge(a) {
    if (!a.enabled) return badge('kapalı', 'neutral');
    if (a.live && a.live.bound) return badge('yayında', 'ok');
    return a.lastError ? badge('hata', 'bad') : badge('çevrimdışı', 'warn');
  }

  function renderApps() {
    var q = ($('app-filter').value || '').toLowerCase();
    var rows = state.apps.filter(function (a) {
      return !q || [a.name, a.local, String(a.publicPort), a.clientId].some(function (v) {
        return String(v || '').toLowerCase().indexOf(q) >= 0;
      });
    });
    $('count-apps').textContent = state.apps.length;

    var tb = $('apps-body');
    if (!rows.length) { emptyRow(tb, 8, 'Tanımlı uygulama yok.'); return; }
    clear(tb);
    rows.forEach(function (a) {
      var tr = tb.insertRow();
      td(tr, [
        strongCell(a.name),
        sub(a.protocol + (a.sticky ? ' · sabit port' : '')),
        subMono(short(a.clientId, 18)),
      ]);
      td(tr, mono(a.local));
      td(tr, a.publicPort
        ? el('span', { class: 'chip', text: (a.publicHost || '') + ':' + a.publicPort })
        : (a.requestedPublicPort
          ? badge('istenen ' + a.requestedPublicPort, 'warn')
          : badge('otomatik', 'neutral')));
      td(tr, [badge(a.delivery, 'neutral'), ' ', qosBadge(a.qos)]);
      td(tr, [
        (a.rateInBps ? bits(a.rateInBps) : '∞') + ' ↑',
        sub((a.rateOutBps ? bits(a.rateOutBps) : '∞') + ' ↓'),
      ], 'num');
      td(tr, a.live
        ? [bytes(a.live.bytesIn + a.live.bytesOut), sub(a.live.activeConnections + ' bağlantı')]
        : '—', 'num');
      td(tr, appStatusBadge(a));
      td(tr, btnRow([
        btn('Düzenle', null, function () { openAppModal(a, a.clientId); }),
        btn(a.enabled ? 'Kapat' : 'Aç', null, function () {
          api('/api/apps/' + encodeURIComponent(a.appId), {
            method: 'PATCH', body: { enabled: !a.enabled },
          }).then(function () { showOk('Uygulama güncellendi.'); return LOADERS.apps(); })
            .catch(fail);
        }),
        btn('Sil', 'btn-danger', function () {
          confirmModal('Uygulamayı sil', [
            el('p', null, [
              '“' + a.name + '” silinecek. Genel port ',
              el('strong', { text: 'anında serbest bırakılır' }),
              ' ve başka bir uygulamaya verilebilir.',
            ]),
          ], function () {
            return api('/api/apps/' + encodeURIComponent(a.appId), { method: 'DELETE' })
              .then(function () { showOk('Uygulama silindi.'); return LOADERS.apps(); });
          }, 'Sil');
        }),
      ]));
    });
  }

  $('app-filter').addEventListener('input', renderApps);

  function openAppModal(existing, clientId) {
    var e = existing || {};
    var isEdit = !!existing;
    var target = e.clientId || clientId;

    var clientOptions = state.clients.map(function (c) {
      return {
        value: c.clientId,
        label: (c.displayName || c.commonName || short(c.clientId, 16)) + (c.online ? ' (çevrimiçi)' : ''),
      };
    });

    var body = [];
    if (!isEdit) {
      body.push(labelFor('f-client', 'İstemci'), select('f-client', clientOptions, target));
    }
    body.push(
      labelFor('f-name', 'Ad'),
      input('f-name', 'text', e.name || '', { placeholder: 'web' }),
      fieldRow([
        field('f-host', 'Yerel adres',
              input('f-host', 'text', e.localHost || '127.0.0.2', { placeholder: '127.0.0.2' })),
        field('f-port', 'Yerel port',
              input('f-port', 'number', e.localPort || '', { min: '1', max: '65535', placeholder: '8080' })),
      ]),
      hint('İstemcinin KENDİ ağında bağlanacağı adres. Örn. 127.0.0.2:8080 ya da 127.0.0.9:5432.'),
      fieldRow([
        field('f-proto', 'Protokol', select('f-proto', [
          { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' },
        ], e.protocol === 'udp' ? 'udp' : 'tcp')),
        field('f-delivery', 'Teslim', select('f-delivery', [
          { value: 'reliable', label: 'Kayıpsız' },
          { value: 'unreliable', label: 'Kayıp toleranslı' },
        ], e.delivery === 'unreliable' ? 'unreliable' : 'reliable')),
      ]),
      hint('TCP her zaman kayıpsızdır. UDP\'de kayıp toleranslı teslim, gecikmeye duyarlı '
           + 'yükler (ses, video, oyun) için doğru olandır: geciken bir paket, düşen bir '
           + 'paketten kötüdür.'),
      labelFor('f-qos', 'Hizmet sınıfı (QoS)'),
      select('f-qos', [
        { value: 'realtime', label: 'Gerçek zamanlı — oyun, ses, görüntü' },
        { value: 'interactive', label: 'Etkileşimli — web, SSH, API (varsayılan)' },
        { value: 'bulk', label: 'Hacimli — dosya aktarımı, yedekleme' },
      ], e.qos || 'interactive'),
      hint('Sınıf BANT GENİŞLİĞİ PAYI DEĞİLDİR; “kim önce” sorusunu yanıtlar. Aynı tünelde '
           + 'bir dosya indirmesi sürerken oyun paketlerinin sırada beklememesini sağlayan '
           + 'şey budur. Gerçek zamanlı sınıf küçük ve sık paketler varsayar — hacimli bir '
           + 'aktarımı oraya koymak, koruduğu şeyi bozar.'),
      fieldRow([
        field('f-public', 'İstenen genel port',
              input('f-public', 'number', e.requestedPublicPort || 0, { min: '0', max: '65535' })),
        field('f-maxconns', 'Azami eşzamanlı bağlantı',
              input('f-maxconns', 'number', e.maxConns || 0, { min: '0' })),
      ]),
      hint('0 = havuzdan rastgele bir port. Rastgele seçim bilinçlidir: sıralı dağıtım, '
           + 'dışarıdan tahmin edilebilir olurdu.'),
      fieldRow([
        field('f-ratein', 'Yükleme sınırı (Mbit/s)',
              input('f-ratein', 'number', e.rateInBps ? (e.rateInBps * 8 / 1e6) : 0, { min: '0', step: '0.1' })),
        field('f-rateout', 'İndirme sınırı (Mbit/s)',
              input('f-rateout', 'number', e.rateOutBps ? (e.rateOutBps * 8 / 1e6) : 0, { min: '0', step: '0.1' })),
      ]),
      checkbox('f-sticky', 'Portu bu uygulamaya sabitle (tünel gitse de ayrılı kalır)', e.sticky),
      checkbox('f-enabled', 'Etkin', e.enabled !== false),
    );

    openModal(isEdit ? ('Uygulamayı düzenle — ' + e.name) : 'Uygulama ekle', body, function () {
      var payload = {
        name: $('f-name').value.trim(),
        localHost: $('f-host').value.trim(),
        localPort: Number($('f-port').value),
        protocol: $('f-proto').value,
        delivery: $('f-delivery').value,
        qos: $('f-qos').value,
        publicPort: Number($('f-public').value) || 0,
        maxConns: Number($('f-maxconns').value) || 0,
        rateInMbit: Number($('f-ratein').value) || 0,
        rateOutMbit: Number($('f-rateout').value) || 0,
        sticky: $('f-sticky').checked,
        enabled: $('f-enabled').checked,
      };
      if (!payload.localPort) return Promise.reject(new Error('Yerel port gerekli'));

      if (isEdit) {
        return api('/api/apps/' + encodeURIComponent(e.appId), { method: 'PATCH', body: payload })
          .then(function () { showOk('Uygulama güncellendi.'); return LOADERS.apps(); });
      }
      payload.clientId = $('f-client') ? $('f-client').value : clientId;
      if (!payload.clientId) return Promise.reject(new Error('İstemci seçin'));
      return api('/api/apps', { method: 'POST', body: payload }).then(function (created) {
        showOk(created && created.publicPort
          ? ('Uygulama yayında: ' + (created.publicHost || '') + ':' + created.publicPort)
          : 'Uygulama kaydedildi; istemci bağlandığında yayına alınacak.');
        return LOADERS.apps();
      });
    }, isEdit ? 'Güncelle' : 'Oluştur');
  }

  $('btn-new-app').addEventListener('click', function () { openAppModal(null, null); });

  LOADERS.apps = function () {
    return Promise.all([
      api('/api/apps'),
      state.clients.length ? Promise.resolve(null) : api('/api/clients'),
    ]).then(function (res) {
      state.apps = res[0].apps;
      if (res[1]) state.clients = res[1].clients;
      renderApps();
    }).catch(fail);
  };

  // ======================================================================
  // PORT HAVUZU
  // ======================================================================
  LOADERS.ports = function () {
    return api('/api/ports').then(function (res) {
      var s = res.stats;
      renderStats('port-stats', [
        ['Havuz', s.poolMin + '–' + s.poolMax, s.poolSize + ' port'],
        ['Kullanımda', s.active, 'canlı tünellere ayrılmış'],
        ['Beklemede', s.linger, 'kopan tünel için tutuluyor'],
        ['Boş', s.free, s.unusable + ' kullanılamaz'],
      ]);

      var tb = $('ports-body');
      if (!res.reservations.length) { emptyRow(tb, 6, 'Rezervasyon yok.'); return; }
      clear(tb);
      res.reservations.sort(function (a, b) { return a.port - b.port; }).forEach(function (p) {
        var tr = tb.insertRow();
        td(tr, mono(String(p.port)), 'num');
        td(tr, badge(p.proto, 'neutral'));
        td(tr, mono(short(p.appId, 20), 'cell-sub'));
        td(tr, mono(short(p.tunnelId, 20), 'cell-sub'));
        td(tr, p.state === 'active'
          ? badge('etkin', 'ok')
          : [badge('bekliyor', 'warn'), p.sticky ? ' ' : null, p.sticky ? badge('sabit', 'dark') : null]);
        td(tr, date(p.since));
      });
    }).catch(fail);
  };

  // ======================================================================
  // KORUMA
  // ======================================================================
  LOADERS.guard = function () {
    return api('/api/guard').then(function (res) {
      var g = res.stats;
      $('count-bans').textContent = g.bannedIps;
      renderStats('guard-stats', [
        ['Kabul edilen', g.accepted, g.connectionsGlobal + ' açık bağlantı'],
        ['Reddedilen', g.refused, g.distinctSourceIps + ' farklı kaynak'],
        ['Yasaklı', g.bannedIps, g.watchedIps + ' izlenen'],
        ['UDP', g.udpAccepted, g.udpDropped + ' düşürülen · ' + g.udpFlows + ' akış'],
        ['Yükseltme engeli', g.amplificationBlocked, 'doğrulanmamış kaynağa yanıt'],
        ['Slowloris', g.slowlorisKilled, 'ilk bayt beklenmeden düşürüldü'],
      ]);

      var tb = $('bans-body');
      if (!res.bans.length) {
        emptyRow(tb, 4, 'Yasaklı kaynak yok.');
      } else {
        clear(tb);
        res.bans.forEach(function (b) {
          var tr = tb.insertRow();
          td(tr, mono(b.ip));
          td(tr, String(b.offences), 'num');
          td(tr, duration(b.remainingMs), 'num');
          td(tr, btn('Yasağı kaldır', null, function () {
            api('/api/guard/bans/' + encodeURIComponent(b.ip), { method: 'DELETE' })
              .then(function () { showOk('Yasak kaldırıldı.'); return LOADERS.guard(); })
              .catch(fail);
          }));
        });
      }

      var lt = $('guard-limits');
      clear(lt);
      Object.keys(res.limits).sort().forEach(function (k) {
        var tr = lt.insertRow();
        td(tr, mono(k));
        td(tr, String(res.limits[k]), 'num');
      });
    }).catch(fail);
  };

  // ======================================================================
  // DENETİM
  // ======================================================================
  LOADERS.events = function () {
    return api('/api/events?limit=200').then(function (res) {
      var tb = $('events-body');
      if (!res.events.length) { emptyRow(tb, 5, 'Kayıt yok.'); return; }
      clear(tb);
      res.events.forEach(function (ev) {
        var tr = tb.insertRow();
        td(tr, date(ev.at), 'num');
        td(tr, badge(ev.kind, 'neutral'));
        td(tr, ev.actor || '—');
        td(tr, mono(short(ev.subject, 24), 'cell-sub'));
        td(tr, mono(short(ev.detail, 90), 'cell-sub'));
      });
    }).catch(fail);
  };

  // ======================================================================
  // Canlı akış + başlangıç
  // ======================================================================
  $('btn-refresh').addEventListener('click', function () {
    clearBanners();
    LOADERS.overview().then(function () { showOk('Yenilendi.'); });
  });

  $('btn-logout').addEventListener('click', function () {
    fetch('/logout', { method: 'POST', credentials: 'same-origin' })
      .then(function () { window.location.href = '/login'; });
  });

  function connectStream() {
    var es = new EventSource('/api/stream');
    es.addEventListener('open', function () {
      $('live').classList.add('on');
      $('live-text').textContent = 'canlı';
    });
    es.addEventListener('overview', function (e) {
      try { renderOverview(JSON.parse(e.data)); } catch (err) { /* bozuk kare */ }
    });
    es.addEventListener('tunnel', function () {
      // Tünel açıldı/kapandı: yalnızca AÇIK olan görünümü tazele. Hepsini
      // yenilemek, on tünelin aynı anda bağlandığı bir anda paneli kendi
      // kendine yük üreten bir şeye çevirirdi.
      var view = activeView();
      if (view && LOADERS[view]) LOADERS[view]();
    });
    es.addEventListener('error', function () {
      $('live').classList.remove('on');
      $('live-text').textContent = 'bağlantı koptu';
    });
  }

  // Tünel ve ziyaretçi görünümleri canlı veriye dayanıyor: açıkken tazele.
  setInterval(function () {
    var view = activeView();
    if (view === 'tunnels') LOADERS.tunnels();
    else if (view === 'peers' && $('peer-auto').checked) LOADERS.peers();
  }, 5000);

  LOADERS.clients().then(LOADERS.overview).then(connectStream);
}());
