'use strict';
// Yönetim konsolu.
//
// Çerçeve yok, derleme adımı yok, bağımlılık yok — sunucunun kendisi de öyle.
// DOM'a yazarken her yerde `textContent` ya da kaçırılmış dize kullanılıyor:
// bu sayfadaki verilerin çoğu (istemcinin bildirdiği ad, sertifika konusu,
// hata mesajları) DIŞARIDAN geliyor ve `innerHTML`'e ham konsaydı, tünel
// istemcisi olan herkes yönetim panelinde kod çalıştırabilirdi.

(function () {
  var $ = function (id) { return document.getElementById(id); };
  var state = {
    overview: null, tunnels: [], clients: [], apps: [], ports: null, guard: null, events: [],
  };

  // ---------- yardımcılar ----------
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

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
  function sparkWidth(bytesPerSec) {
    var b = (Number(bytesPerSec) || 0) * 8;
    if (b <= 0) return 0;
    var pct = (Math.log10(b) / Math.log10(1e9)) * 100;
    return Math.max(2, Math.min(100, Math.round(pct)));
  }

  function ms(v) { return v == null ? '—' : Math.round(v) + ' ms'; }

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

  function short(s, n) { s = String(s || ''); return s.length > (n || 16) ? s.slice(0, n || 16) + '…' : s; }

  function showErr(m) { $('ok').classList.remove('show'); var e = $('err'); e.textContent = m; e.classList.add('show'); }
  function showOk(m) {
    $('err').classList.remove('show');
    var e = $('ok'); e.textContent = m; e.classList.add('show');
    setTimeout(function () { e.classList.remove('show'); }, 4000);
  }
  function clearBanners() { $('err').classList.remove('show'); $('ok').classList.remove('show'); }

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

  function td(row, html, cls) {
    var cell = row.insertCell();
    if (cls) cell.className = cls;
    cell.innerHTML = html;
    return cell;
  }

  function emptyRow(tbody, cols, text) {
    tbody.innerHTML = '';
    var tr = tbody.insertRow();
    var cell = tr.insertCell();
    cell.colSpan = cols;
    cell.className = 'empty';
    cell.textContent = text;
  }

  // ---------- navigasyon ----------
  var LOADERS = {};
  Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (btn) {
    btn.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      Array.prototype.forEach.call(document.querySelectorAll('.view'), function (v) { v.classList.remove('active'); });
      $('view-' + btn.dataset.view).classList.add('active');
      clearBanners();
      if (LOADERS[btn.dataset.view]) LOADERS[btn.dataset.view]();
    });
  });

  // ---------- kip ----------
  var modalSave = null;
  function openModal(title, bodyHtml, onSave, saveLabel) {
    $('modal-title').textContent = title;
    $('modal-body').innerHTML = bodyHtml;
    modalSave = onSave;
    $('modal-save').textContent = saveLabel || 'Kaydet';
    $('modal-save').style.display = onSave ? '' : 'none';
    $('modal-backdrop').classList.add('open');
  }
  function closeModal() { $('modal-backdrop').classList.remove('open'); modalSave = null; }
  $('modal-cancel').addEventListener('click', closeModal);
  $('modal-backdrop').addEventListener('click', function (e) { if (e.target === $('modal-backdrop')) closeModal(); });
  $('modal-save').addEventListener('click', function () {
    if (!modalSave) return;
    var btn = this;
    btn.disabled = true;
    Promise.resolve(modalSave())
      .then(closeModal)
      .catch(function (e) { showErr(e.message); })
      .finally(function () { btn.disabled = false; });
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });

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

    var s = [
      ['Bağlı tünel', o.tunnels.online, o.apps.published + ' uygulama yayında'],
      ['Trafik ↓ / ↑', bits(o.traffic.rateIn) + ' / ' + bits(o.traffic.rateOut),
        bytes(o.traffic.bytesIn) + ' / ' + bytes(o.traffic.bytesOut) + ' toplam'],
      ['Ortalama RTT', o.link.avgRttMs == null ? '—' : o.link.avgRttMs + ' ms', 'RFC 9002 yumuşatılmış'],
      ['Açık akış', o.streams, 'mantıksal bağlantı'],
      ['Port havuzu', o.ports.free + ' boş', o.ports.active + ' kullanımda · ' + o.ports.linger + ' beklemede'],
      ['Reddedilen', o.guard.refused, o.guard.bannedIps + ' yasaklı kaynak'],
      ['Çalışma süresi', duration(o.uptimeMs), 'kalıcılık: ' + o.persistence],
      ['El sıkışma hatası', o.tunnels.handshakeFailures, o.tunnels.accepted + ' kabul edildi'],
    ];
    $('overview-stats').innerHTML = s.map(function (x) {
      var big = String(x[1]).length > 9;
      return '<div class="stat"><div class="stat-label">' + esc(x[0]) + '</div>'
        + '<div class="stat-value' + (big ? ' sm' : '') + '">' + esc(x[1]) + '</div>'
        + '<div class="stat-note">' + esc(x[2]) + '</div></div>';
    }).join('');
  }

  function renderOverviewTunnels() {
    var tb = $('overview-tunnels');
    if (!state.tunnels.length) { emptyRow(tb, 7, 'Bağlı tünel yok.'); return; }
    tb.innerHTML = '';
    state.tunnels.forEach(function (t) {
      var tr = tb.insertRow();
      td(tr, '<div class="cell-strong">' + esc(t.name) + '</div>'
        + '<div class="cell-sub mono">' + esc(short(t.clientId, 20)) + '</div>');
      td(tr, '<span class="mono">' + esc(t.remoteAddress) + ':' + esc(t.remotePort) + '</span>'
        + '<div class="cell-sub">' + esc(t.transport.protocol || '—') + '</div>');
      td(tr, ms(t.link.rttMs) + '<div class="cell-sub">min ' + ms(t.link.minRttMs) + '</div>', 'num');
      td(tr, '↓ ' + bits(t.traffic.rateIn) + '<div class="spark down"><i style="width:' + sparkWidth(t.traffic.rateIn) + '%"></i></div>'
        + '↑ ' + bits(t.traffic.rateOut) + '<div class="spark"><i style="width:' + sparkWidth(t.traffic.rateOut) + '%"></i></div>', 'num');
      td(tr, bytes(t.traffic.bytesIn + t.traffic.bytesOut)
        + '<div class="cell-sub">' + t.streams.open + ' akış</div>', 'num');
      td(tr, String(t.apps.length), 'num');
      td(tr, tunnelHealthBadge(t));
    });
  }

  function tunnelHealthBadge(t) {
    if (t.state !== 'ready') return '<span class="badge badge-warn">' + esc(t.state) + '</span>';
    if (t.revocation && !t.revocation.ok) return '<span class="badge badge-bad">iptal denetimi</span>';
    if (t.link.lossRate > 0.05) return '<span class="badge badge-warn">kayıp %' + (t.link.lossRate * 100).toFixed(1) + '</span>';
    return '<span class="badge badge-ok">sağlıklı</span>';
  }

  LOADERS.overview = function () {
    return Promise.all([api('/api/overview'), api('/api/tunnels')]).then(function (r) {
      renderOverview(r[0]);
      state.tunnels = r[1].tunnels;
      renderOverviewTunnels();
      $('whoami').innerHTML = 'Oturum: <strong>' + esc(r[0].me.username) + '</strong>';
    }).catch(function (e) { showErr(e.message); });
  };

  // ======================================================================
  // TÜNELLER
  // ======================================================================
  LOADERS.tunnels = function () {
    return api('/api/tunnels').then(function (r) {
      state.tunnels = r.tunnels;
      var host = $('tunnel-cards');
      host.innerHTML = '';
      if (!r.tunnels.length) {
        host.innerHTML = '<div class="table-wrap"><div class="empty">Bağlı tünel yok.</div></div>';
        return;
      }
      r.tunnels.forEach(function (t) { host.appendChild(tunnelCard(t)); });
    }).catch(function (e) { showErr(e.message); });
  };

  function tunnelCard(t) {
    var wrap = document.createElement('div');
    wrap.className = 'table-wrap';

    var head = document.createElement('div');
    head.className = 'table-head';
    head.innerHTML = '<h2>' + esc(t.name) + ' <span class="badge badge-neutral">' + esc(t.transport.protocol || '') + '</span> '
      + tunnelHealthBadge(t) + '</h2>';
    var actions = document.createElement('div');
    actions.className = 'btn-row';

    var limitBtn = document.createElement('button');
    limitBtn.className = 'btn btn-sm';
    limitBtn.textContent = 'Bant sınırı';
    limitBtn.addEventListener('click', function () { openTunnelLimitModal(t); });
    actions.appendChild(limitBtn);

    var appBtn = document.createElement('button');
    appBtn.className = 'btn btn-sm';
    appBtn.textContent = 'Uygulama ekle';
    appBtn.addEventListener('click', function () { openAppModal(null, t.clientId); });
    actions.appendChild(appBtn);

    var kick = document.createElement('button');
    kick.className = 'btn btn-sm btn-danger';
    kick.textContent = 'Bağlantıyı kes';
    kick.addEventListener('click', function () {
      openModal('Tüneli kapat', '<p>“' + esc(t.name) + '” tüneli kapatılacak. '
        + 'Yayındaki <strong>' + t.apps.length + ' uygulama</strong> anında erişilemez olur; '
        + 'portlar kısa bir süre bu istemci için ayrılmış kalır.</p>', function () {
        return api('/api/tunnels/' + encodeURIComponent(t.tunnelId) + '/disconnect', { method: 'POST', body: {} })
          .then(function () { showOk('Tünel kapatıldı.'); return LOADERS.tunnels(); });
      }, 'Kapat');
    });
    actions.appendChild(kick);
    head.appendChild(actions);
    wrap.appendChild(head);

    var body = document.createElement('div');
    body.style.padding = '16px';
    body.style.display = 'grid';
    body.style.gridTemplateColumns = 'repeat(auto-fit, minmax(260px, 1fr))';
    body.style.gap = '18px';

    var cert = t.certificate || {};
    var rev = t.revocation;
    body.innerHTML = ''
      + section('Bağlantı', [
        ['Adres', t.remoteAddress + ':' + t.remotePort],
        ['Şifre', t.transport.cipher || '—'],
        ['Çalışma süresi', duration(t.uptimeMs)],
        ['Tünel kimliği', t.tunnelId],
      ])
      + section('Bağlantı kalitesi', [
        ['RTT (ağ)', ms(t.link.rttMs) + ' · min ' + ms(t.link.minRttMs)],
        ['RTT (uygulama)', ms(t.link.appRttMs)],
        ['Tıkanıklık penceresi', bytes(t.link.congestionWindow) + ' · uçuşta ' + bytes(t.link.bytesInFlight)],
        ['Kayıp', (t.link.lossRate * 100).toFixed(3) + '% · ' + t.link.retransmits + ' yeniden gönderim'],
        ['Tıkanıklık olayı', String(t.link.congestionEvents)],
      ])
      + section('Trafik', [
        ['Anlık', '↓ ' + bits(t.traffic.rateIn) + ' / ↑ ' + bits(t.traffic.rateOut)],
        ['Toplam', bytes(t.traffic.bytesIn) + ' / ' + bytes(t.traffic.bytesOut)],
        ['Çıkış sınırı', t.traffic.egressLimitBps ? bits(t.traffic.egressLimitBps) : 'sınırsız'],
        ['Akışlar', t.streams.open + ' açık · ' + t.streams.opened + ' toplam · ' + t.streams.resets + ' reset'],
        ['Datagram', t.datagrams.in + ' ↓ / ' + t.datagrams.out + ' ↑ · ' + t.datagrams.dropped + ' düşen'],
      ])
      + section('Sertifika', [
        ['Konu', cert.commonName || '—'],
        ['Veren', cert.issuer || '—'],
        ['Seri', cert.serialNumber || '—'],
        ['Geçerlilik', (cert.validFrom || '—') + ' → ' + (cert.validTo || '—')],
        ['Parmak izi', short(cert.fingerprint256, 32)],
        ['İptal denetimi', rev ? (rev.ok ? 'geçerli' : ('BAŞARISIZ: ' + rev.error)) : 'kapalı'],
      ]);

    wrap.appendChild(body);

    if (t.apps.length) {
      var tableWrap = document.createElement('div');
      tableWrap.className = 'table-scroll';
      tableWrap.style.borderTop = '1px solid var(--line)';
      var table = document.createElement('table');
      table.innerHTML = '<thead><tr><th>Uygulama</th><th>Yerel</th><th>Genel</th><th>Bağlantı</th><th>Trafik</th><th>Durum</th></tr></thead>';
      var tb = document.createElement('tbody');
      t.apps.forEach(function (a) {
        var tr = tb.insertRow();
        td(tr, '<div class="cell-strong">' + esc(a.name) + '</div><div class="cell-sub">' + esc(a.protocol) + ' · ' + esc(a.delivery) + '</div>');
        td(tr, '<span class="mono">' + esc(a.local) + '</span>');
        td(tr, a.publicPort ? '<span class="chip">' + esc(a.publicHost || '') + ':' + a.publicPort + '</span>' : '<span class="badge badge-warn">bağlı değil</span>');
        td(tr, a.live ? (a.live.activeConnections + ' / ' + a.live.totalConnections) : '—', 'num');
        td(tr, a.live ? (bytes(a.live.bytesIn) + ' ↓ / ' + bytes(a.live.bytesOut) + ' ↑') : '—', 'num');
        td(tr, a.enabled ? '<span class="badge badge-ok">açık</span>' : '<span class="badge badge-neutral">kapalı</span>');
      });
      table.appendChild(tb);
      tableWrap.appendChild(table);
      wrap.appendChild(tableWrap);
    }
    return wrap;
  }

  function section(title, rows) {
    return '<div><div class="stat-label">' + esc(title) + '</div><dl class="kv">'
      + rows.map(function (r) {
        return '<dt>' + esc(r[0]) + '</dt><dd>' + esc(r[1]) + '</dd>';
      }).join('')
      + '</dl></div>';
  }

  function openTunnelLimitModal(t) {
    var current = t.traffic.egressLimitBps ? (t.traffic.egressLimitBps * 8 / 1e6) : 0;
    openModal('Bant sınırı — ' + t.name,
      '<p class="field-hint" style="margin-top:0">Tünelin TOPLAM çıkış hızı (sunucudan istemciye). '
      + '0 = sınırsız. Sınır, uygulama başına verilen sınırların üstünde bir tavandır.</p>'
      + '<label for="egress">Çıkış (Mbit/s)</label>'
      + '<input type="number" id="egress" min="0" step="0.1" value="' + current + '">',
      function () {
        return api('/api/tunnels/' + encodeURIComponent(t.tunnelId) + '/limits', {
          method: 'POST', body: { egressMbit: Number($('egress').value) || 0 },
        }).then(function () { showOk('Sınır uygulandı.'); return LOADERS.tunnels(); });
      });
  }

  // ======================================================================
  // İSTEMCİLER
  // ======================================================================
  function renderClients() {
    var q = ($('client-filter').value || '').toLowerCase();
    var rows = state.clients.filter(function (c) {
      return !q || [c.commonName, c.displayName, c.email, c.clientId]
        .some(function (v) { return String(v || '').toLowerCase().indexOf(q) >= 0; });
    });
    $('count-clients').textContent = state.clients.length;
    var tb = $('clients-body');
    if (!rows.length) { emptyRow(tb, 5, 'Kayıtlı istemci yok.'); return; }
    tb.innerHTML = '';
    rows.forEach(function (c) {
      var tr = tb.insertRow();
      td(tr, '<div class="cell-strong">' + esc(c.displayName || c.commonName || '—') + '</div>'
        + '<div class="cell-sub">' + esc(c.email || '') + '</div>'
        + '<div class="cell-sub mono">' + esc(short(c.clientId, 24)) + '</div>');
      td(tr, '<div class="cell-sub mono">' + esc(c.certSerial || '—') + '</div>'
        + '<div class="cell-sub">bitiş: ' + date(c.certNotAfter) + '</div>');
      td(tr, date(c.lastSeenAt) + '<div class="cell-sub mono">' + esc(c.lastAddress || '') + '</div>');
      td(tr, c.blocked
        ? '<span class="badge badge-bad">engelli</span>'
        : (c.online ? '<span class="badge badge-ok">çevrimiçi</span>' : '<span class="badge badge-neutral">çevrimdışı</span>'));

      var cell = tr.insertCell();
      var row = document.createElement('div');
      row.className = 'btn-row';

      var addApp = document.createElement('button');
      addApp.className = 'btn btn-sm';
      addApp.textContent = 'Uygulama ekle';
      addApp.addEventListener('click', function () { openAppModal(null, c.clientId); });
      row.appendChild(addApp);

      var block = document.createElement('button');
      block.className = 'btn btn-sm' + (c.blocked ? '' : ' btn-danger');
      block.textContent = c.blocked ? 'Engeli kaldır' : 'Engelle';
      block.addEventListener('click', function () {
        api('/api/clients/' + encodeURIComponent(c.clientId) + '/block', {
          method: 'POST', body: { blocked: !c.blocked },
        }).then(function () { showOk(c.blocked ? 'Engel kaldırıldı.' : 'İstemci engellendi.'); return LOADERS.clients(); })
          .catch(function (e) { showErr(e.message); });
      });
      row.appendChild(block);
      cell.appendChild(row);
    });
  }
  $('client-filter').addEventListener('input', renderClients);

  LOADERS.clients = function () {
    return api('/api/clients').then(function (r) { state.clients = r.clients; renderClients(); })
      .catch(function (e) { showErr(e.message); });
  };

  // ======================================================================
  // UYGULAMALAR
  // ======================================================================
  function renderApps() {
    var q = ($('app-filter').value || '').toLowerCase();
    var rows = state.apps.filter(function (a) {
      return !q || [a.name, a.local, String(a.publicPort), a.clientId]
        .some(function (v) { return String(v || '').toLowerCase().indexOf(q) >= 0; });
    });
    $('count-apps').textContent = state.apps.length;
    var tb = $('apps-body');
    if (!rows.length) { emptyRow(tb, 8, 'Tanımlı uygulama yok.'); return; }
    tb.innerHTML = '';
    rows.forEach(function (a) {
      var tr = tb.insertRow();
      td(tr, '<div class="cell-strong">' + esc(a.name) + '</div>'
        + '<div class="cell-sub">' + esc(a.protocol) + (a.sticky ? ' · sabit port' : '') + '</div>'
        + '<div class="cell-sub mono">' + esc(short(a.clientId, 18)) + '</div>');
      td(tr, '<span class="mono">' + esc(a.local) + '</span>');
      td(tr, a.publicPort
        ? '<span class="chip">' + esc(a.publicHost || '') + ':' + a.publicPort + '</span>'
        : (a.requestedPublicPort
          ? '<span class="badge badge-warn">istenen ' + a.requestedPublicPort + '</span>'
          : '<span class="badge badge-neutral">otomatik</span>'));
      td(tr, '<span class="badge badge-neutral">' + esc(a.delivery) + '</span>');
      td(tr, (a.rateInBps ? bits(a.rateInBps) : '∞') + ' ↑<div class="cell-sub">'
        + (a.rateOutBps ? bits(a.rateOutBps) : '∞') + ' ↓</div>', 'num');
      td(tr, a.live
        ? (bytes(a.live.bytesIn + a.live.bytesOut) + '<div class="cell-sub">' + a.live.activeConnections + ' bağlantı</div>')
        : '—', 'num');
      td(tr, !a.enabled ? '<span class="badge badge-neutral">kapalı</span>'
        : (a.live && a.live.bound ? '<span class="badge badge-ok">yayında</span>'
          : (a.lastError ? '<span class="badge badge-bad">hata</span>' : '<span class="badge badge-warn">çevrimdışı</span>')));

      var cell = tr.insertCell();
      var row = document.createElement('div');
      row.className = 'btn-row';

      var edit = document.createElement('button');
      edit.className = 'btn btn-sm';
      edit.textContent = 'Düzenle';
      edit.addEventListener('click', function () { openAppModal(a, a.clientId); });
      row.appendChild(edit);

      var toggle = document.createElement('button');
      toggle.className = 'btn btn-sm';
      toggle.textContent = a.enabled ? 'Kapat' : 'Aç';
      toggle.addEventListener('click', function () {
        api('/api/apps/' + encodeURIComponent(a.appId), { method: 'PATCH', body: { enabled: !a.enabled } })
          .then(function () { showOk('Uygulama güncellendi.'); return LOADERS.apps(); })
          .catch(function (e) { showErr(e.message); });
      });
      row.appendChild(toggle);

      var del = document.createElement('button');
      del.className = 'btn btn-sm btn-danger';
      del.textContent = 'Sil';
      del.addEventListener('click', function () {
        openModal('Uygulamayı sil', '<p>“' + esc(a.name) + '” silinecek. '
          + 'Genel port <strong>anında serbest bırakılır</strong> ve başka bir uygulamaya verilebilir.</p>', function () {
          return api('/api/apps/' + encodeURIComponent(a.appId), { method: 'DELETE' })
            .then(function () { showOk('Uygulama silindi.'); return LOADERS.apps(); });
        }, 'Sil');
      });
      row.appendChild(del);
      cell.appendChild(row);
    });
  }
  $('app-filter').addEventListener('input', renderApps);

  function openAppModal(existing, clientId) {
    var e = existing || {};
    var isEdit = !!existing;
    var clientOptions = state.clients.map(function (c) {
      var sel = (c.clientId === (e.clientId || clientId)) ? ' selected' : '';
      return '<option value="' + esc(c.clientId) + '"' + sel + '>'
        + esc((c.displayName || c.commonName || short(c.clientId, 16)) + (c.online ? ' (çevrimiçi)' : ''))
        + '</option>';
    }).join('');

    var html = ''
      + (isEdit ? '' : '<label for="f-client">İstemci</label><select id="f-client">' + clientOptions + '</select>')
      + '<label for="f-name">Ad</label><input type="text" id="f-name" value="' + esc(e.name || '') + '" placeholder="web">'
      + '<div class="field-row">'
      + '<div><label for="f-host">Yerel adres</label><input type="text" id="f-host" value="' + esc(e.localHost || '127.0.0.2') + '" placeholder="127.0.0.2"></div>'
      + '<div><label for="f-port">Yerel port</label><input type="number" id="f-port" min="1" max="65535" value="' + esc(e.localPort || '') + '" placeholder="8080"></div>'
      + '</div>'
      + '<div class="field-hint">İstemcinin KENDİ ağında bağlanacağı adres. Örn. 127.0.0.2:8080 ya da 127.0.0.9:5432.</div>'
      + '<div class="field-row">'
      + '<div><label for="f-proto">Protokol</label><select id="f-proto">'
      + '<option value="tcp"' + (e.protocol === 'udp' ? '' : ' selected') + '>TCP</option>'
      + '<option value="udp"' + (e.protocol === 'udp' ? ' selected' : '') + '>UDP</option></select></div>'
      + '<div><label for="f-delivery">Teslim</label><select id="f-delivery">'
      + '<option value="reliable"' + (e.delivery === 'unreliable' ? '' : ' selected') + '>Kayıpsız</option>'
      + '<option value="unreliable"' + (e.delivery === 'unreliable' ? ' selected' : '') + '>Kayıp toleranslı</option></select></div>'
      + '</div>'
      + '<div class="field-hint">TCP her zaman kayıpsızdır. UDP\'de kayıp toleranslı teslim, gecikmeye duyarlı yükler '
      + '(ses, video, oyun) için doğru olandır: geciken bir paket, düşen bir paketten kötüdür.</div>'
      + '<div class="field-row">'
      + '<div><label for="f-public">İstenen genel port</label><input type="number" id="f-public" min="0" max="65535" value="' + esc(e.requestedPublicPort || 0) + '"></div>'
      + '<div><label for="f-maxconns">Azami eşzamanlı bağlantı</label><input type="number" id="f-maxconns" min="0" value="' + esc(e.maxConns || 0) + '"></div>'
      + '</div>'
      + '<div class="field-hint">0 = havuzdan rastgele bir port. Rastgele seçim bilinçlidir: sıralı dağıtım, dışarıdan tahmin edilebilir olurdu.</div>'
      + '<div class="field-row">'
      + '<div><label for="f-ratein">Yükleme sınırı (Mbit/s)</label><input type="number" id="f-ratein" min="0" step="0.1" value="' + (e.rateInBps ? (e.rateInBps * 8 / 1e6) : 0) + '"></div>'
      + '<div><label for="f-rateout">İndirme sınırı (Mbit/s)</label><input type="number" id="f-rateout" min="0" step="0.1" value="' + (e.rateOutBps ? (e.rateOutBps * 8 / 1e6) : 0) + '"></div>'
      + '</div>'
      + '<div class="check-row"><input type="checkbox" id="f-sticky"' + (e.sticky ? ' checked' : '') + '><label for="f-sticky">Portu bu uygulamaya sabitle (tünel gitse de ayrılı kalır)</label></div>'
      + '<div class="check-row"><input type="checkbox" id="f-enabled"' + (e.enabled === false ? '' : ' checked') + '><label for="f-enabled">Etkin</label></div>';

    openModal(isEdit ? ('Uygulamayı düzenle — ' + e.name) : 'Uygulama ekle', html, function () {
      var payload = {
        name: $('f-name').value.trim(),
        localHost: $('f-host').value.trim(),
        localPort: Number($('f-port').value),
        protocol: $('f-proto').value,
        delivery: $('f-delivery').value,
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
      return api('/api/apps', { method: 'POST', body: payload })
        .then(function (created) {
          showOk(created && created.publicPort
            ? ('Uygulama yayında: ' + (created.publicHost || '') + ':' + created.publicPort)
            : 'Uygulama kaydedildi; istemci bağlandığında yayına alınacak.');
          return LOADERS.apps();
        });
    }, isEdit ? 'Güncelle' : 'Oluştur');
  }
  $('btn-new-app').addEventListener('click', function () { openAppModal(null, null); });

  LOADERS.apps = function () {
    return Promise.all([api('/api/apps'), state.clients.length ? Promise.resolve(null) : api('/api/clients')])
      .then(function (r) {
        state.apps = r[0].apps;
        if (r[1]) state.clients = r[1].clients;
        renderApps();
      }).catch(function (e) { showErr(e.message); });
  };

  // ======================================================================
  // PORT HAVUZU
  // ======================================================================
  LOADERS.ports = function () {
    return api('/api/ports').then(function (r) {
      var s = r.stats;
      $('port-stats').innerHTML = [
        ['Havuz', s.poolMin + '–' + s.poolMax, s.poolSize + ' port'],
        ['Kullanımda', s.active, 'canlı tünellere ayrılmış'],
        ['Beklemede', s.linger, 'kopan tünel için tutuluyor'],
        ['Boş', s.free, s.unusable + ' kullanılamaz'],
      ].map(function (x) {
        return '<div class="stat"><div class="stat-label">' + esc(x[0]) + '</div>'
          + '<div class="stat-value' + (String(x[1]).length > 9 ? ' sm' : '') + '">' + esc(x[1]) + '</div>'
          + '<div class="stat-note">' + esc(x[2]) + '</div></div>';
      }).join('');

      var tb = $('ports-body');
      if (!r.reservations.length) { emptyRow(tb, 6, 'Rezervasyon yok.'); return; }
      tb.innerHTML = '';
      r.reservations.sort(function (a, b) { return a.port - b.port; }).forEach(function (p) {
        var tr = tb.insertRow();
        td(tr, '<span class="mono">' + p.port + '</span>', 'num');
        td(tr, '<span class="badge badge-neutral">' + esc(p.proto) + '</span>');
        td(tr, '<span class="mono cell-sub">' + esc(short(p.appId, 20)) + '</span>');
        td(tr, '<span class="mono cell-sub">' + esc(short(p.tunnelId, 20)) + '</span>');
        td(tr, p.state === 'active'
          ? '<span class="badge badge-ok">etkin</span>'
          : '<span class="badge badge-warn">bekliyor</span>' + (p.sticky ? ' <span class="badge badge-dark">sabit</span>' : ''));
        td(tr, date(p.since));
      });
    }).catch(function (e) { showErr(e.message); });
  };

  // ======================================================================
  // KORUMA
  // ======================================================================
  LOADERS.guard = function () {
    return api('/api/guard').then(function (r) {
      var g = r.stats;
      $('count-bans').textContent = g.bannedIps;
      $('guard-stats').innerHTML = [
        ['Kabul edilen', g.accepted, g.connectionsGlobal + ' açık bağlantı'],
        ['Reddedilen', g.refused, g.distinctSourceIps + ' farklı kaynak'],
        ['Yasaklı', g.bannedIps, g.watchedIps + ' izlenen'],
        ['UDP', g.udpAccepted, g.udpDropped + ' düşürülen · ' + g.udpFlows + ' akış'],
        ['Yükseltme engeli', g.amplificationBlocked, 'doğrulanmamış kaynağa yanıt'],
        ['Slowloris', g.slowlorisKilled, 'ilk bayt beklenmeden düşürüldü'],
      ].map(function (x) {
        return '<div class="stat"><div class="stat-label">' + esc(x[0]) + '</div>'
          + '<div class="stat-value">' + esc(x[1]) + '</div>'
          + '<div class="stat-note">' + esc(x[2]) + '</div></div>';
      }).join('');

      var tb = $('bans-body');
      if (!r.bans.length) { emptyRow(tb, 4, 'Yasaklı kaynak yok.'); } else {
        tb.innerHTML = '';
        r.bans.forEach(function (b) {
          var tr = tb.insertRow();
          td(tr, '<span class="mono">' + esc(b.ip) + '</span>');
          td(tr, String(b.offences), 'num');
          td(tr, duration(b.remainingMs), 'num');
          var cell = tr.insertCell();
          var btn = document.createElement('button');
          btn.className = 'btn btn-sm';
          btn.textContent = 'Yasağı kaldır';
          btn.addEventListener('click', function () {
            api('/api/guard/bans/' + encodeURIComponent(b.ip), { method: 'DELETE' })
              .then(function () { showOk('Yasak kaldırıldı.'); return LOADERS.guard(); })
              .catch(function (err) { showErr(err.message); });
          });
          cell.appendChild(btn);
        });
      }

      var lt = $('guard-limits');
      lt.innerHTML = '';
      Object.keys(r.limits).sort().forEach(function (k) {
        var tr = lt.insertRow();
        td(tr, '<span class="mono">' + esc(k) + '</span>');
        td(tr, esc(r.limits[k]), 'num');
      });
    }).catch(function (e) { showErr(e.message); });
  };

  // ======================================================================
  // DENETİM
  // ======================================================================
  LOADERS.events = function () {
    return api('/api/events?limit=200').then(function (r) {
      var tb = $('events-body');
      if (!r.events.length) { emptyRow(tb, 5, 'Kayıt yok.'); return; }
      tb.innerHTML = '';
      r.events.forEach(function (ev) {
        var tr = tb.insertRow();
        td(tr, date(ev.at), 'num');
        td(tr, '<span class="badge badge-neutral">' + esc(ev.kind) + '</span>');
        td(tr, esc(ev.actor || '—'));
        td(tr, '<span class="mono cell-sub">' + esc(short(ev.subject, 24)) + '</span>');
        td(tr, '<span class="cell-sub mono">' + esc(short(ev.detail, 90)) + '</span>');
      });
    }).catch(function (e) { showErr(e.message); });
  };

  // ======================================================================
  // canlı akış + başlangıç
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
      var active = document.querySelector('.nav-item.active');
      if (active && LOADERS[active.dataset.view]) LOADERS[active.dataset.view]();
    });
    es.addEventListener('error', function () {
      $('live').classList.remove('on');
      $('live-text').textContent = 'bağlantı koptu';
    });
  }

  // Tüneller görünümü canlı veriye dayanıyor: açıkken periyodik tazeleme.
  setInterval(function () {
    var active = document.querySelector('.nav-item.active');
    if (active && active.dataset.view === 'tunnels') LOADERS.tunnels();
  }, 5000);

  LOADERS.clients().then(LOADERS.overview).then(connectStream);
}());
