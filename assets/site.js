(function(){
  const $ = (s, r=document) => r.querySelector(s), $$ = (s, r=document) => [...r.querySelectorAll(s)];

  /* theme */
  const tb = $('.theme');
  if (tb) tb.addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('fnl-theme', next); } catch(e) {}
  });

  /* mobile menu */
  const mb = $('.menu');
  if (mb) mb.addEventListener('click', () => { const o = document.body.classList.toggle('nav-open'); mb.setAttribute('aria-expanded', o); });
  $$('.side a').forEach(a => a.addEventListener('click', () => document.body.classList.remove('nav-open')));

  /* copy buttons */
  $$('.copy').forEach(b => b.addEventListener('click', () => {
    const src = b.dataset.copy ? document.getElementById(b.dataset.copy) : b.closest('.code').querySelector('code');
    const text = src.innerText;
    const done = () => { const t = b.textContent; b.textContent = b.closest('[lang="en"]') ? 'Copied' : 'تم النسخ'; b.classList.add('done'); setTimeout(() => { b.textContent = t; b.classList.remove('done'); }, 1600); };
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(done).catch(() => {
      const r = document.createRange(); r.selectNodeContents(src); const s = getSelection(); s.removeAllRanges(); s.addRange(r);
    });
  }));

  /* on-this-page highlight */
  const links = $$('.toc a');
  if (links.length && 'IntersectionObserver' in window) {
    const map = new Map(links.map(a => [a.getAttribute('href').slice(1), a]));
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (e.isIntersecting) { links.forEach(a => a.classList.remove('on')); const a = map.get(e.target.id); if (a) a.classList.add('on'); }
    }), { rootMargin: '-20% 0px -70% 0px' });
    $$('.sec').forEach(s => io.observe(s));
  }

  /* checklist memory (per viewer only) */
  $$('.checklist input').forEach(c => {
    try { c.checked = localStorage.getItem('fnl-' + c.id) === '1'; } catch(e) {}
    c.addEventListener('change', () => { try { localStorage.setItem('fnl-' + c.id, c.checked ? '1' : '0'); } catch(e) {} });
  });

  /* packet explorer */
  const XP = {};
  $$('.xp').forEach(root => {
    const data = JSON.parse(root.querySelector('.xp-data').textContent);
    const list = $('.xp-list', root), tree = $('.xp-tree', root), hex = $('.xp-hex', root), flt = $('input', root);
    const cap = root.dataset.cap;
    const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    function row(f) {
      const s = f.s, ep = s.src ? `${s.src}${s.sport ? ':' + s.sport : ''} → ${s.dst}${s.dport ? ':' + s.dport : ''}` : `${s.src_mac || ''} → ${s.dst_mac || ''}`;
      const proto = s.proto || s.ethertype || '?';
      return `<div class="xr" role="option" data-no="${s.no}" aria-selected="false" tabindex="-1"><span>${s.no}</span><span>${s.rt.toFixed(3)}</span><span>${esc(ep)}</span><span class="p p-${esc(proto)}">${esc(proto)}${s.vlan != null ? ' ·' + s.vlan : ''}</span><span class="i">${esc(s.info || '')}</span></div>`;
    }
    list.innerHTML = data.map(row).join('');
    function show(no) {
      const f = data[no - 1]; if (!f) return;
      $$('.xr', list).forEach(r => r.setAttribute('aria-selected', r.dataset.no == no));
      const b = f.h.match(/../g);
      // layer + field tree
      tree.innerHTML = f.l.map((ly, i) => `<details ${i < 4 ? 'open' : ''}><summary>${esc(ly.name)} <span class="mono muted">· ${ly.len} B</span></summary>` +
        ly.fields.map(fd => `<div class="fl" data-off="${fd.off}" data-len="${fd.len}"><span class="k">${esc(fd.name)}</span><span class="v">${esc(fd.value)}</span>${fd.note ? `<span class="nt">${esc(fd.note)}</span>` : ''}</div>`).join('') + '</details>').join('')
        + (f.s.payload_txt ? `<div class="xp-pl mono" dir="ltr">${esc(f.s.payload_txt)}</div>` : '');
      // hex dump
      let out = '';
      for (let r = 0; r < b.length; r += 16) {
        out += `<span class="o">${r.toString(16).padStart(4, '0')}</span>  ` + b.slice(r, r + 16).map((x, k) => `<b data-i="${r + k}">${x}</b>`).join(' ') + '\n';
      }
      hex.innerHTML = out;
      $$('.fl', tree).forEach(el => {
        const on = v => { const o = +el.dataset.off, n = +el.dataset.len; el.classList.toggle('on', v); for (let i = o; i < o + n; i++) { const c = hex.querySelector(`b[data-i="${i}"]`); if (c) c.classList.toggle('on', v); } };
        el.addEventListener('mouseenter', () => on(true)); el.addEventListener('mouseleave', () => on(false));
        el.addEventListener('click', () => { $$('.fl.on', tree).forEach(x => x.dispatchEvent(new Event('mouseleave'))); on(true); });
      });
    }
    list.addEventListener('click', e => { const r = e.target.closest('.xr'); if (r) show(+r.dataset.no); });
    list.addEventListener('keydown', e => {
      const cur = $('.xr[aria-selected="true"]', list); if (!cur) return;
      const sib = e.key === 'ArrowDown' ? cur.nextElementSibling : e.key === 'ArrowUp' ? cur.previousElementSibling : null;
      if (sib) { e.preventDefault(); show(+sib.dataset.no); sib.focus(); }
    });
    list.tabIndex = 0;
    flt.addEventListener('input', () => {
      const q = flt.value.trim().toLowerCase();
      $$('.xr', list).forEach(r => { r.hidden = q && !r.textContent.toLowerCase().includes(q); });
    });
    show(data.findIndex(f => f.s.proto === 'TCP' || f.s.proto === 'ICMP' || f.s.proto === 'ARP') + 1 || 1);
    XP[cap] = { root, show, list };
  });
  const firstCap = Object.keys(XP)[0];
  /* sequence diagrams: draw arrows as they come into view */
  if ('IntersectionObserver' in window && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const rows = $$('.fr'); const vh = innerHeight;
    rows.forEach((r, i) => { if (r.getBoundingClientRect().top > vh) r.classList.add('pre'); });
    const io2 = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.remove('pre'); io2.unobserve(e.target); } }), { rootMargin: '0px 0px -10% 0px' });
    rows.forEach(r => io2.observe(r));
  }
  $$('.fref, .fr[data-frame]').forEach(b => b.addEventListener('click', () => {
    const x = XP[b.dataset.cap || firstCap]; if (!x) return;
    x.show(+b.dataset.frame);
    const r = $(`.xr[data-no="${b.dataset.frame}"]`, x.list); if (r) { r.hidden = false; r.scrollIntoView({ block: 'nearest' }); }
    x.root.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    x.root.classList.remove('flash'); void x.root.offsetWidth; x.root.classList.add('flash');
  }));
})();
