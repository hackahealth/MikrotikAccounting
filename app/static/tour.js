/* آموزش مرحله‌ای: هر مرحله یک بخش صفحه را روشن می‌کند و توضیح می‌دهد. Tour.init({steps, auto, done}) */
(function () {
  var T = window.Tour = {all: [], steps: [], i: 0, opts: {}, nodes: null, sent: false};
  var FA = '۰۱۲۳۴۵۶۷۸۹';
  function fa(n) { return String(n).replace(/\d/g, function (d) { return FA[d]; }); }
  function target(sel) {
    if (!sel) return null;
    var e = document.querySelector(sel);
    if (!e) return null;
    var d = e.closest && e.closest('details');
    if (d && !d.open) d.open = true;            // a menu item inside a closed group
    var r = e.getBoundingClientRect();
    return r.width || r.height ? e : null;
  }
  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }
  T.init = function (opts) {
    T.opts = opts || {};
    T.all = T.opts.steps || [];
    if (T.opts.auto && T.all.length) setTimeout(T.start, 350);
  };
  T.start = function () {
    T.steps = T.all.filter(function (s) { return !s.el || target(s.el); });
    if (!T.steps.length) return;
    T.close(true);
    var mask = h('div', 'tour-mask'), spot = h('div', 'tour-spot'), pop = h('div', 'tour-pop');
    pop.setAttribute('role', 'dialog');
    pop.innerHTML = '<h4></h4><p></p><div class="tf"><button type="button" class="btn s skip">رد شدن</button>' +
      '<span class="n"></span><button type="button" class="btn s prev">قبلی</button>' +
      '<button type="button" class="btn s p next">بعدی</button></div>';
    pop.querySelector('.skip').onclick = function () { T.close(); };
    pop.querySelector('.prev').onclick = function () { T.go(T.i - 1); };
    pop.querySelector('.next').onclick = function () { T.go(T.i + 1); };
    document.body.appendChild(mask); document.body.appendChild(spot); document.body.appendChild(pop);
    T.nodes = {mask: mask, spot: spot, pop: pop};
    document.addEventListener('keydown', key);
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    T.go(0);
  };
  function key(e) {
    if (!T.nodes) return;
    if (e.key === 'Escape') T.close();
    else if (e.key === 'ArrowLeft' || e.key === 'Enter') { e.preventDefault(); T.go(T.i + 1); }
    else if (e.key === 'ArrowRight') T.go(T.i - 1);
  }
  T.go = function (i) {
    if (i < 0) return;
    if (i >= T.steps.length) return T.close();
    T.i = i;
    var s = T.steps[i], n = T.nodes, last = i === T.steps.length - 1;
    n.pop.querySelector('h4').textContent = s.title;
    n.pop.querySelector('p').textContent = s.text;
    n.pop.querySelector('.n').textContent = fa(i + 1) + ' از ' + fa(T.steps.length);
    n.pop.querySelector('.prev').style.visibility = i ? 'visible' : 'hidden';
    n.pop.querySelector('.next').textContent = last ? 'پایان' : 'بعدی';
    n.pop.querySelector('.skip').style.visibility = last ? 'hidden' : 'visible';
    var t = target(s.el);
    if (t && t.scrollIntoView) t.scrollIntoView({block: 'nearest', inline: 'nearest'});
    place();
    n.pop.querySelector('.next').focus({preventScroll: true});
  };
  function place() {
    if (!T.nodes) return;
    var n = T.nodes, s = T.steps[T.i], t = target(s.el), pop = n.pop;
    var W = window.innerWidth, H = window.innerHeight, pw = pop.offsetWidth, ph = pop.offsetHeight, gap = 18;
    if (!t) {
      n.mask.classList.add('full'); n.spot.style.display = 'none';
      pop.style.left = Math.max(12, (W - pw) / 2) + 'px'; pop.style.top = Math.max(12, (H - ph) / 2.4) + 'px';
      return;
    }
    n.mask.classList.remove('full'); n.spot.style.display = 'block';
    var r = t.getBoundingClientRect(), pad = 4;
    n.spot.style.left = (r.left - pad) + 'px'; n.spot.style.top = (r.top - pad) + 'px';
    n.spot.style.width = (r.width + 2 * pad) + 'px'; n.spot.style.height = (r.height + 2 * pad) + 'px';
    var clamp = function (v, lo, hi) { return Math.max(lo, Math.min(v, hi)); }, left, top;
    if (r.left - gap - pw >= 12 && r.width < W / 2) {             // beside (the menu is on the right)
      left = r.left - gap - pw; top = clamp(r.top + r.height / 2 - ph / 2, 12, H - ph - 12);
    } else if (r.right + gap + pw <= W - 12 && r.width < W / 2) {
      left = r.right + gap; top = clamp(r.top + r.height / 2 - ph / 2, 12, H - ph - 12);
    } else {
      left = clamp(r.left + r.width / 2 - pw / 2, 12, W - pw - 12);
      top = r.bottom + gap + ph <= H - 12 ? r.bottom + gap : Math.max(12, r.top - gap - ph);
    }
    pop.style.left = left + 'px'; pop.style.top = top + 'px';
  }
  T.close = function (silent) {
    if (T.nodes) {
      ['mask', 'spot', 'pop'].forEach(function (k) { T.nodes[k].remove(); });
      T.nodes = null;
      document.removeEventListener('keydown', key);
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    }
    if (!silent && !T.sent && T.opts.done) {        // seen once: not shown automatically again
      T.sent = true;
      fetch(T.opts.done, {method: 'POST', credentials: 'same-origin'}).catch(function () {});
    }
  };
})();
