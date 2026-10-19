import { generate, validateUsername, charClass, score, normalizeWord } from './generator.js';

const $ = s => document.querySelector(s);
const STORE = 'ttuf:v1';
const PAGE = 120;
const STATUS = {
  unverified: 'Unverified',
  notfound: 'No profile found',
  available: 'Confirmed available',
  taken: 'Taken',
  unknown: "Couldn't tell",
};
const profileUrl = u => `https://www.tiktok.com/@${encodeURIComponent(u)}`;

// One named tab is reused for every check, so lookups stay at human pace and tabs don't pile up.
// rel=noopener would force a new tab each time, so the opener link is cut by hand instead.
function openTikTok(u) {
  const w = window.open(profileUrl(u), 'tt-check');
  if (w) w.opener = null;
  else toast('Your browser blocked the new tab. Allow pop-ups for this page, or use the ↗ link.');
}

// Statuses and favorites are keyed by username so they survive a new batch that repeats a name.
const state = { items: [], status: {}, fav: new Set(), tab: 'all', shown: PAGE };

function load() {
  try {
    const d = JSON.parse(localStorage.getItem(STORE) || '{}');
    state.items = Array.isArray(d.items) ? d.items : [];
    state.status = d.status && typeof d.status === 'object' ? d.status : {};
    state.fav = new Set(Array.isArray(d.fav) ? d.fav : []);
    if (d.form) restoreForm(d.form);
  } catch { /* private mode or corrupt data: start empty */ }
}
function save() {
  try {
    localStorage.setItem(STORE, JSON.stringify({ items: state.items, status: state.status, fav: [...state.fav], form: readForm() }));
  } catch { toast('Could not save in this browser. Export your results to keep them.'); }
}

const statusOf = u => state.status[u]?.s || 'unverified';

function readForm() {
  const f = $('#gen');
  return {
    keywords: f.keywords.value, initials: f.initials.value, words: f.words.value,
    styles: [...f.querySelectorAll('[name=style]:checked')].map(i => i.value),
    length: f.querySelector('[name=length]:checked')?.value || 'any',
    allowNumbers: f.allowNumbers.checked, allowUnderscore: f.allowUnderscore.checked, allowPeriod: f.allowPeriod.checked,
    excludeChars: f.excludeChars.value, excludeWords: f.excludeWords.value,
    count: Math.max(20, Math.min(500, Number(f.count.value) || 120)),
  };
}
function restoreForm(v) {
  const f = $('#gen');
  for (const k of ['keywords', 'initials', 'words', 'excludeChars', 'excludeWords']) if (typeof v[k] === 'string') f[k].value = v[k];
  if (v.count) f.count.value = v.count;
  for (const k of ['allowNumbers', 'allowUnderscore', 'allowPeriod']) if (typeof v[k] === 'boolean') f[k].checked = v[k];
  if (Array.isArray(v.styles)) f.querySelectorAll('[name=style]').forEach(i => { i.checked = v.styles.includes(i.value); });
  const r = f.querySelector(`[name=length][value="${CSS.escape(v.length || '')}"]`);
  if (r) r.checked = true;
}

// ---------- generation ----------
$('#gen').addEventListener('submit', e => {
  e.preventDefault();
  const opts = readForm();
  const msg = $('#genMsg');
  msg.classList.remove('warn');
  if (!opts.styles.length) { msg.textContent = 'Pick at least one style.'; msg.classList.add('warn'); return; }
  if (opts.keywords && !normalizeWord(opts.keywords)) {
    msg.textContent = 'Keywords need Latin letters or numbers; TikTok usernames cannot contain other scripts.';
    msg.classList.add('warn');
    return;
  }
  let res;
  try {
    res = generate(opts);
  } catch (err) {
    console.error(err);
    msg.textContent = 'Something went wrong while generating. Try different keywords.';
    msg.classList.add('warn');
    return;
  }
  const append = $('#append').checked;
  const existing = new Set(append ? state.items.map(i => i.username) : []);
  const fresh = res.items.filter(i => !existing.has(i.username));
  state.items = append ? [...state.items, ...fresh] : fresh;
  state.items.forEach((it, n) => { it.order = n; });
  state.shown = PAGE;
  const short = res.stats.produced < res.stats.requested;
  msg.textContent = `${fresh.length} new suggestions${append ? ` added (${res.items.length - fresh.length} already in your list)` : ''}.`
    + (short ? ` Only ${res.stats.produced} of ${res.stats.requested} fit your rules; widen the length or allow more characters.` : '')
    + ' All start as Unverified.';
  msg.classList.toggle('warn', short);
  save();
  setTab('all');
  $('#results').scrollIntoView({ block: 'start' });
});

// ---------- filtering ----------
function inLen(n, v) {
  if (!v) return true;
  const [a, b] = v.split('-').map(Number);
  return n >= a && n <= b;
}
function view() {
  const q = $('#q').value.trim().toLowerCase().replace(/^@/, '');
  const fl = $('#fLen').value, fc = $('#fChars').value, fs = $('#fStyle').value, fst = $('#fStatus').value;
  const out = state.items.filter(it => {
    const st = statusOf(it.username);
    if (state.tab === 'available' && st !== 'available') return false;
    if (state.tab === 'todo' && !(st === 'unverified' || st === 'unknown')) return false;
    if (state.tab === 'notfound' && st !== 'notfound') return false;
    if (state.tab === 'taken' && st !== 'taken') return false;
    if (state.tab === 'fav' && !state.fav.has(it.username)) return false;
    if (q && !it.username.includes(q)) return false;
    if (!inLen(it.username.length, fl)) return false;
    if (fc === 'letters' && /[^a-z]/.test(it.username)) return false;
    if (fc === 'digits' && !it.digits) return false;
    if (fc === 'underscore' && !it.underscore) return false;
    if (fc === 'period' && !it.period) return false;
    if (fs && it.style !== fs) return false;
    if (fst && st !== fst) return false;
    return true;
  });
  const s = $('#sort').value;
  if (s === 'score') out.sort((a, b) => b.score - a.score);
  else if (s === 'az') out.sort((a, b) => a.username.localeCompare(b.username));
  else if (s === 'short') out.sort((a, b) => a.username.length - b.username.length || a.username.localeCompare(b.username));
  else out.sort((a, b) => a.order - b.order);
  return out;
}

// ---------- rendering ----------
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v);
  }
  n.append(...kids);
  return n;
}

function itemNode(it) {
  const u = it.username, st = statusOf(u), fav = state.fav.has(u);
  const sel = el('select', { class: `status-sel s-${st}`, 'data-act': 'status', 'aria-label': `Status of ${u}` });
  for (const [k, label] of Object.entries(STATUS)) {
    const o = el('option', { value: k, text: label });
    if (k === st) o.selected = true;
    sel.append(o);
  }
  return el('li', { class: `item is-${st}`, 'data-u': u },
    el('span', { class: 'name', text: `@${u}` }),
    el('div', { class: 'ops' },
      el('button', { class: 'icon', type: 'button', 'data-act': 'copy', 'aria-label': `Copy ${u}`, title: 'Copy', text: '⧉' }),
      el('button', { class: 'icon', type: 'button', 'data-act': 'fav', 'aria-pressed': String(fav), 'aria-label': `Favorite ${u}`, title: 'Favorite', text: fav ? '★' : '☆' }),
      el('a', { class: 'icon', href: profileUrl(u), target: 'tt-check', rel: 'noopener noreferrer', 'data-act': 'open', 'aria-label': `Open @${u} on TikTok`, title: 'Open on TikTok', text: '↗' })),
    el('div', { class: 'meta' },
      sel,
      el('span', { class: 'pill', text: `${u.length} chars` }),
      el('span', { class: 'pill', text: it.style === 'custom' ? 'added by you' : it.style })));
}

function render() {
  const v = view();
  const list = $('#list');
  list.replaceChildren(...v.slice(0, state.shown).map(itemNode));
  $('#more').hidden = v.length <= state.shown;
  $('#more').textContent = `Show more (${v.length - state.shown} hidden)`;
  $('#empty').hidden = state.items.length > 0;
  $('#listMsg').textContent = state.items.length && !v.length ? 'Nothing matches these filters.' : '';

  const counts = { all: state.items.length, available: 0, todo: 0, notfound: 0, taken: 0, fav: 0 };
  for (const it of state.items) {
    const st = statusOf(it.username);
    if (st === 'available') counts.available++;
    else if (st === 'notfound') counts.notfound++;
    else if (st === 'taken') counts.taken++;
    else counts.todo++;
    if (state.fav.has(it.username)) counts.fav++;
  }
  for (const [k, n] of Object.entries(counts)) $(`#c-${k}`).textContent = n;
  const checked = counts.all - counts.todo;
  $('#progLabel').textContent = `Checked ${checked} of ${counts.all}`;
  $('#progFill').style.width = counts.all ? `${(checked / counts.all) * 100}%` : '0';
  const bar = $('#progBar');
  bar.setAttribute('aria-valuemax', counts.all);
  bar.setAttribute('aria-valuenow', checked);
  $('#checkMode').disabled = !v.length;
}

function setTab(t) {
  state.tab = t;
  state.shown = PAGE;
  document.querySelectorAll('[role=tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === t)));
  render();
}
document.querySelector('.tabs').addEventListener('click', e => {
  const b = e.target.closest('[role=tab]');
  if (b) setTab(b.dataset.tab);
});
document.querySelector('.tabs').addEventListener('keydown', e => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const tabs = [...document.querySelectorAll('[role=tab]')];
  const i = tabs.indexOf(document.activeElement);
  const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
  n.focus();
  setTab(n.dataset.tab);
});
for (const id of ['#fLen', '#fChars', '#fStyle', '#fStatus', '#sort']) $(id).addEventListener('change', () => { state.shown = PAGE; render(); });
$('#q').addEventListener('input', () => { state.shown = PAGE; render(); });
$('#more').addEventListener('click', () => { state.shown += PAGE; render(); });

// ---------- per-item actions ----------
function setStatus(u, s) {
  if (s === 'unverified') delete state.status[u];
  else state.status[u] = { s, at: new Date().toISOString() };
  save();
}
function toggleFav(u) {
  state.fav.has(u) ? state.fav.delete(u) : state.fav.add(u);
  save();
}
$('#list').addEventListener('click', e => {
  const t = e.target.closest('[data-act]');
  if (!t) return;
  const u = t.closest('[data-u]').dataset.u;
  if (t.dataset.act === 'open') { e.preventDefault(); openTikTok(u); }
  if (t.dataset.act === 'copy') copy(u);
  if (t.dataset.act === 'fav') { toggleFav(u); render(); }
});
$('#list').addEventListener('change', e => {
  if (e.target.dataset.act !== 'status') return;
  const u = e.target.closest('[data-u]').dataset.u;
  setStatus(u, e.target.value);
  toast(`@${u}: ${STATUS[e.target.value]}`);
  render();
});

// Search box doubles as "add a username I already have in mind".
$('#addForm').addEventListener('submit', e => {
  e.preventDefault();
  const u = $('#q').value.trim().toLowerCase().replace(/^@/, '');
  if (!u) return;
  const v = validateUsername(u);
  if (!v.ok) { toast(`Not a valid TikTok username: ${v.reason}.`); return; }
  if (state.items.some(i => i.username === u)) { toast(`@${u} is already in your list.`); return; }
  state.items.unshift({ username: u, length: u.length, style: 'custom', pattern: 'custom', score: score(u), ...charClass(u), order: -Date.now() });
  save();
  $('#q').value = '';
  setTab('all');
  toast(`Added @${u}. Open it to check.`);
});

// ---------- clipboard, toast, export ----------
async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el('textarea', { readonly: '' });
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    if (!ok) { toast('Copy failed. Select the name and copy it manually.'); return; }
  }
  toast(`Copied ${text}`);
}
let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('on');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('on'), 2200);
}

function download(name, type, body) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const csvCell = v => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
const stamp = () => new Date().toISOString().slice(0, 10);
$('#expTxt').addEventListener('click', () => {
  const v = view();
  if (!v.length) { toast('Nothing to export in this view.'); return; }
  download(`tiktok-usernames-${stamp()}.txt`, 'text/plain', v.map(i => i.username).join('\n') + '\n');
  toast(`Exported ${v.length} usernames`);
});
$('#expCsv').addEventListener('click', () => {
  const v = view();
  if (!v.length) { toast('Nothing to export in this view.'); return; }
  const rows = [['username', 'length', 'style', 'status', 'checked_at', 'favorite', 'profile_url']];
  for (const i of v) {
    rows.push([i.username, i.username.length, i.style, STATUS[statusOf(i.username)], state.status[i.username]?.at || '',
      state.fav.has(i.username) ? 'yes' : 'no', profileUrl(i.username)]);
  }
  download(`tiktok-usernames-${stamp()}.csv`, 'text/csv', rows.map(r => r.map(csvCell).join(',')).join('\n') + '\n');
  toast(`Exported ${v.length} rows`);
});
$('#clear').addEventListener('click', () => {
  const keep = state.items.filter(i => state.fav.has(i.username));
  if (!confirm(`Clear ${state.items.length - keep.length} results? Favorites (${keep.length}) are kept.`)) return;
  state.items = keep;
  save();
  render();
});

// ---------- checking mode ----------
// Walks the current view one name at a time. Links open in one named tab ("tt-check"),
// so checks happen at human pace and never pile up tabs or automated requests.
const ck = { queue: [], i: 0 };
const dlg = $('#checker');
function openChecker() {
  const v = view().map(i => i.username);
  const todo = v.filter(u => ['unverified', 'unknown'].includes(statusOf(u)));
  ck.queue = todo.length ? todo : v;
  ck.i = 0;
  if (!ck.queue.length) return;
  showCk();
  dlg.showModal();
}
function showCk() {
  const u = ck.queue[ck.i], st = statusOf(u);
  $('#ckPos').textContent = `${ck.i + 1} / ${ck.queue.length}`;
  $('#ckName').textContent = `@${u}`;
  $('#ckStatus').replaceChildren(el('span', { class: `tag s-${st}`, text: STATUS[st] }));
  $('#ckOpen').href = profileUrl(u);
  const fav = state.fav.has(u);
  $('#ckFav').setAttribute('aria-pressed', String(fav));
  $('#ckFav').firstChild.textContent = fav ? '★ Favorite ' : '☆ Favorite ';
  $('#ckPrev').disabled = ck.i === 0;
}
function step(d) {
  const n = ck.i + d;
  if (n >= ck.queue.length) { dlg.close(); toast('Reached the end of this list.'); return; }
  ck.i = Math.max(0, n);
  showCk();
}
function mark(s) {
  const u = ck.queue[ck.i];
  setStatus(u, s);
  if (s === 'available') { state.fav.add(u); save(); }
  render();
  step(1);
}
$('#checkMode').addEventListener('click', openChecker);
$('#ckClose').addEventListener('click', () => dlg.close());
$('#ckPrev').addEventListener('click', () => step(-1));
$('#ckNext').addEventListener('click', () => step(1));
$('#ckOpen').addEventListener('click', e => { e.preventDefault(); openTikTok(ck.queue[ck.i]); });
$('#ckCopy').addEventListener('click', () => copy(ck.queue[ck.i]));
$('#ckFav').addEventListener('click', () => { toggleFav(ck.queue[ck.i]); showCk(); render(); });
document.querySelector('.ck-marks').addEventListener('click', e => {
  const b = e.target.closest('[data-mark]');
  if (b) mark(b.dataset.mark);
});
dlg.addEventListener('keydown', e => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const k = e.key.toLowerCase();
  const marks = { t: 'taken', n: 'notfound', a: 'available', u: 'unknown' };
  if (marks[k]) { e.preventDefault(); mark(marks[k]); }
  else if (k === 's' || e.key === 'ArrowRight') { e.preventDefault(); step(1); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); step(-1); }
  else if (k === 'c') { e.preventDefault(); copy(ck.queue[ck.i]); }
  else if (k === 'f') { e.preventDefault(); $('#ckFav').click(); }
  else if (k === 'o') { e.preventDefault(); openTikTok(ck.queue[ck.i]); }
});

load();
render();
