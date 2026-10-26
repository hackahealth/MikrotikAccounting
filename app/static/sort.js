/* مرتب‌سازی همهٔ جدول‌ها با کلیک روی سرستون (بار دوم: برعکس). عدد، حجم (MB/GB)، مدت (۰۲:۱۵ / ۱ روز ...)، درصد و
   تاریخ شمسی تشخیص داده می‌شود. جدولی با کلاس nosort یا heat مرتب نمی‌شود. */
(function () {
  var FA = '۰۱۲۳۴۵۶۷۸۹', AR = '٠١٢٣٤٥٦٧٨٩';
  var UNIT = {b: 1, kb: 1024, mb: 1048576, gb: 1073741824, tb: 1099511627776,
              bps: 1, kbps: 1e3, mbps: 1e6, gbps: 1e9};
  function norm(s) {
    return s.replace(/[۰-۹]/g, function (d) { return FA.indexOf(d); })
            .replace(/[٠-٩]/g, function (d) { return AR.indexOf(d); })
            .replace(/٫/g, '.').replace(/[٬,]/g, '').replace(/‌/g, ' ').trim();
  }
  function key(cell) {
    var raw = cell.getAttribute('data-sort');
    if (raw !== null) { var n = parseFloat(raw); return isNaN(n) ? [1, raw] : [0, n]; }
    var t = norm(cell.textContent || '');
    if (!t || t === '-' || t === '—') return [2, ''];
    var m = t.match(/^(-?[\d.]+)\s*(b|kb|mb|gb|tb|bps|kbps|mbps|gbps)$/i);
    if (m) return [0, parseFloat(m[1]) * UNIT[m[2].toLowerCase()]];
    if (/^\d{4}\/\d{1,2}\/\d{1,2}/.test(t)) return [1, t.replace(/\b(\d)\b/g, '0$1')];
    m = t.match(/^(?:(\d+)\s*روز\s*)?(\d+(?::\d+)+)\s*(s)?$/);
    if (m) {
      var v = 0;
      m[2].split(':').forEach(function (p) { v = v * 60 + parseInt(p, 10); });
      return [0, (m[1] ? parseInt(m[1], 10) * 1440 : 0) + v];
    }
    m = t.match(/^(-?\d+(?:\.\d+)?)\s*(?:s|%|٪)?(?:\s|$)/);
    if (m) return [0, parseFloat(m[1])];
    return [1, t];
  }
  function cmp(a, b) {
    if (a[0] !== b[0]) return a[0] - b[0];
    if (a[0] === 0) return a[1] - b[1];
    return String(a[1]).localeCompare(String(b[1]), 'fa');
  }
  function setup(table) {
    if (table.classList.contains('nosort') || table.classList.contains('heat') || table.dataset.sortReady) return;
    var rows = Array.prototype.slice.call(table.rows);
    var head = null;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].querySelector('th') && !rows[i].querySelector('td')) { head = rows[i]; break; }
    }
    if (!head || head.querySelector('[rowspan],[colspan]')) return;
    table.dataset.sortReady = '1';
    Array.prototype.forEach.call(head.cells, function (th, col) {
      if (!th.textContent.trim()) return;
      th.classList.add('sortable');
      th.title = 'مرتب‌سازی';
      th.addEventListener('click', function () {
        var all = Array.prototype.slice.call(table.rows);
        var start = all.indexOf(head) + 1;
        var body = all.slice(start).filter(function (r) { return r.cells.length === head.cells.length; });
        if (body.length < 2) return;
        var dir = th.classList.contains('asc') ? -1 : 1;
        Array.prototype.forEach.call(head.cells, function (h) { h.classList.remove('asc', 'desc'); });
        th.classList.add(dir === 1 ? 'asc' : 'desc');
        var parent = body[0].parentNode, after = body[body.length - 1].nextSibling;
        body.map(function (r, i) { return {r: r, k: key(r.cells[col]), i: i}; })
            .sort(function (a, b) { return dir * cmp(a.k, b.k) || a.i - b.i; })
            .forEach(function (x) { parent.insertBefore(x.r, after); });
      });
    });
  }
  function all() { document.querySelectorAll('main table').forEach(setup); }
  window.TableSort = {setup: setup, all: all};
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', all); else all();
})();
