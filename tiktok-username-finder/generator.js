// Username generation. Pure functions, no DOM, so Node tests can import it.
// Nothing here knows whether a name is free on TikTok; it only builds valid-looking candidates.

export const STYLES = ['minimal', 'aesthetic', 'professional', 'gaming', 'rare'];
export const LENGTHS = { '3-5': [3, 5], '6-8': [6, 8], '9-12': [9, 12], any: [3, 24] };

const VOWELS = 'aeiou';
const BANK = {
  minimalPre: ['the', 'its', 'im', 'just', 'by', 'hey', 'only'],
  aesthetic: ['moon', 'luna', 'velvet', 'haze', 'bloom', 'soft', 'dream', 'mist', 'petal', 'aura', 'glow', 'honey',
    'cloud', 'sage', 'lune', 'fleur', 'stella', 'noir', 'blush', 'ember', 'daisy', 'silk', 'halo', 'willow', 'iris', 'sol'],
  softEnd: ['ie', 'y', 'elle', 'a'],
  pro: ['hq', 'studio', 'media', 'creates', 'works', 'labs', 'co', 'digital', 'design', 'films', 'daily', 'online', 'team', 'tv', 'club'],
  proPre: ['the', 'meet', 'hey', 'by'],
  gamePre: ['its', 'xo', 'pro', 'dark', 'neo', 'ghost', 'nova', 'shadow', 'frost', 'venom', 'zero', 'hyper', 'rogue', 'ninja', 'blaze', 'viper', 'pixel'],
  gameEnd: ['gg', 'plays', 'fps', 'x', 'op', 'tv', 'clips', 'live', 'main', 'gaming'],
  onset: ['b', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z', 'x', 'q', 'ky', 'zy', 'kr', 'sh', 'th'],
  rareOnset: ['x', 'z', 'q', 'v', 'k', 'j'],
  coda: ['', '', '', 'n', 'x', 'r', 'k', 's', 'l', 'v'],
  vowel: ['a', 'e', 'i', 'o', 'u', 'y', 'ae', 'ai', 'io'],
};

// Subtle respellings: one swap per variant so the result still reads as the keyword.
const SWAPS = [[/ph/, 'f'], [/f(?!f)/, 'ph'], [/ck/, 'k'], [/c(?=[aou])/, 'k'], [/s$/, 'z'], [/i/, 'y'], [/y$/, 'ie'],
  [/ie$/, 'y'], [/er$/, 'r'], [/oo/, 'u'], [/ee/, 'i'], [/ight/, 'ite'], [/x/, 'ks'], [/qu/, 'kw'], [/a$/, 'ah'], [/o$/, 'oh']];
const LEET = { a: '4', e: '3', i: '1', o: '0' };

// Seeded PRNG so a batch can be reproduced in tests.
export function mulberry32(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function normalizeWord(s) {
  return String(s).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

// "fahad awad, coffee" -> [["fahad","awad"],["coffee"]]
export function parsePhrases(s) {
  return String(s || '').split(/[,;\n]+/)
    .map(p => p.trim().split(/\s+/).map(normalizeWord).filter(Boolean))
    .filter(p => p.length);
}

// TikTok's published rules: 2–24 characters; letters, numbers, underscores and periods; cannot end with a period.
// Leading periods, double periods and all-digit names are rejected too, to stay on the safe side.
export function validateUsername(u) {
  if (typeof u !== 'string' || !u) return { ok: false, reason: 'Empty username' };
  if (u.length < 2 || u.length > 24) return { ok: false, reason: 'Must be 2–24 characters' };
  if (!/^[a-z0-9._]+$/.test(u)) return { ok: false, reason: 'Only letters, numbers, _ and . are allowed' };
  if (u.endsWith('.')) return { ok: false, reason: 'Cannot end with a period' };
  if (u.startsWith('.')) return { ok: false, reason: 'Should not start with a period' };
  if (u.includes('..')) return { ok: false, reason: 'Avoid consecutive periods' };
  if (/^\d+$/.test(u)) return { ok: false, reason: 'Cannot be numbers only' };
  return { ok: true, reason: '' };
}

export function charClass(u) {
  return { digits: /\d/.test(u), underscore: u.includes('_'), period: u.includes('.') };
}

export function variations(w) {
  const out = new Set([w]);
  if (w.length > 4) {
    const dropped = w[0] + w.slice(1).replace(/[aeiou]/g, '');
    if (dropped.length >= 3) out.add(dropped);
  }
  for (const [re, rep] of SWAPS) {
    const v = w.replace(re, rep);
    if (v !== w && v.length >= 2) out.add(v);
  }
  if (w.length >= 3 && !VOWELS.includes(w.at(-1))) out.add(w + w.at(-1));
  return [...out];
}

function truncations(w) {
  const out = [];
  for (let n = 3; n <= 5; n++) if (w.length > n + 1) out.push(w.slice(0, n));
  return out;
}

// Readability score: penalises separators, digits, long consonant runs and triple letters.
export function score(u) {
  const s = u.replace(/[._]/g, '');
  let sc = 100 - (u.length - s.length) * 6;
  if (/\d/.test(u)) sc -= 8;
  sc -= 12 * (s.match(/[^aeiouy0-9]{4,}/g) || []).length;
  const vr = (s.match(/[aeiouy]/g) || []).length / Math.max(1, s.length);
  if (vr < 0.2) sc -= 10;
  if (/(.)\1\1/.test(s)) sc -= 30;
  return sc - Math.abs(s.length - 7);
}

export function generate(opts = {}) {
  const o = {
    keywords: '', initials: '', words: '', styles: STYLES, length: 'any', count: 120,
    allowNumbers: false, allowUnderscore: true, allowPeriod: true, excludeChars: '', excludeWords: '',
    seed: Date.now(), ...opts,
  };
  const rng = mulberry32(o.seed >>> 0);
  const pick = a => a[Math.floor(rng() * a.length)];
  const sample = (a, n) => [...a].sort(() => rng() - 0.5).slice(0, n);
  const [minLen, maxLen] = LENGTHS[o.length] || LENGTHS.any;
  const styles = (o.styles && o.styles.length ? o.styles : STYLES).filter(s => STYLES.includes(s));
  const count = Math.max(1, Math.min(1000, Number(o.count) || 120));
  const exChars = [...new Set(String(o.excludeChars).toLowerCase().replace(/\s|,/g, ''))];
  const exWords = String(o.excludeWords).split(/[,;\s]+/).map(normalizeWord).filter(Boolean);

  const strip = w => (o.allowNumbers ? w : w.replace(/\d/g, ''));
  const phrases = parsePhrases(o.keywords).map(p => p.map(strip).filter(Boolean)).filter(p => p.length);
  const keywords = [...new Set(phrases.flat())];
  const prefs = [...new Set(parsePhrases(o.words).flat().map(strip).filter(Boolean))];
  // "Fahad Awad" -> "fa"; "fw" stays "fw".
  const inits = [...new Set(parsePhrases(o.initials).map(p => strip(p.length > 1 ? p.map(x => x[0]).join('') : p[0])).filter(Boolean))];

  // Pairs: words of one phrase ("fahad awad"), then cross-keyword pairs.
  const pairs = [];
  for (const p of phrases) if (p.length > 1) pairs.push([p[0], p.at(-1)]);
  for (const a of keywords.slice(0, 6)) for (const b of keywords.slice(0, 6)) if (a !== b) pairs.push([a, b]);
  for (const a of keywords.slice(0, 6)) for (const b of prefs.slice(0, 8)) pairs.push([a, b], [b, a]);

  const roots = [];
  for (const k of keywords) for (const v of variations(k)) roots.push({ r: v, w: v === k ? 18 : 12 });
  for (const p of prefs) roots.push({ r: p, w: 10 });

  const pool = new Map();
  let rejected = 0;
  const finalize = u => {
    if (!o.allowPeriod) u = u.replace(/\./g, o.allowUnderscore ? '_' : '');
    if (!o.allowUnderscore) u = u.replace(/_/g, o.allowPeriod ? '.' : '');
    u = u.replace(/\.{2,}/g, '.').replace(/^[._]+(?=[._])/, '').replace(/\.$/, '');
    return u;
  };
  const add = (raw, style, pattern, weight = 0) => {
    const u = finalize(raw);
    const bare = u.replace(/[._]/g, '');
    if (!validateUsername(u).ok || u.length < minLen || u.length > maxLen
      || (!o.allowNumbers && /\d/.test(u))
      || exChars.some(c => u.includes(c))
      || exWords.some(w => bare.includes(w))) { rejected++; return; }
    const sc = score(u) + weight;
    const prev = pool.get(u);
    if (!prev || prev.score < sc) pool.set(u, { username: u, length: u.length, style, pattern, score: sc, ...charClass(u) });
  };

  const syllable = (rare = false) => (rare && rng() < 0.5 ? pick(BANK.rareOnset) : pick(BANK.onset)) + pick(BANK.vowel);
  const coined = (rare = false, target = 5) => {
    let s = '';
    while (s.length < target - 1) s += syllable(rare);
    return s + pick(BANK.coda);
  };
  const leet = w => {
    const i = [...w].findIndex(c => LEET[c]);
    return i < 0 ? w : w.slice(0, i) + LEET[w[i]] + w.slice(i + 1);
  };

  const build = {
    minimal() {
      for (const { r, w } of roots) {
        add(r, 'minimal', 'keyword', w);
        for (const t of truncations(r)) add(t, 'minimal', 'short', w - 4);
        for (const p of BANK.minimalPre) add(p + r, 'minimal', 'prefix', w - 8);
        for (const i of inits) add(i + r, 'minimal', 'initials', w - 2);
      }
      for (const [a, b] of pairs) { add(a + b, 'minimal', 'combo', 10); add(a[0] + b, 'minimal', 'initial+word', 6); }
      for (const i of inits) for (const p of prefs) add(i + p, 'minimal', 'initials', 4);
    },
    aesthetic() {
      const words = [...prefs, ...BANK.aesthetic];
      for (const { r, w } of roots) {
        for (const a of sample(words, 10)) {
          add(`${r}.${a}`, 'aesthetic', 'word.word', w);
          add(`${a}.${r}`, 'aesthetic', 'word.word', w - 2);
          add(`${r}_${a}`, 'aesthetic', 'word_word', w - 4);
          add(a + r, 'aesthetic', 'blend', w - 4);
        }
        if (!VOWELS.includes(r.at(-1))) for (const e of BANK.softEnd) add(r + e, 'aesthetic', 'soft', w - 2);
      }
      for (const [a, b] of pairs) add(`${a}.${b}`, 'aesthetic', 'word.word', 8);
      for (const i of inits) for (const a of sample(words, 6)) add(`${i}.${a}`, 'aesthetic', 'initials', 2);
    },
    professional() {
      for (const { r, w } of roots) {
        for (const s of BANK.pro) { add(r + s, 'professional', 'brand', w - 2); add(`${r}.${s}`, 'professional', 'brand', w - 4); }
        for (const p of BANK.proPre) add(p + r, 'professional', 'prefix', w - 6);
      }
      for (const [a, b] of pairs) {
        add(`${a}.${b}`, 'professional', 'first.last', 14);
        add(a + b, 'professional', 'firstlast', 12);
        add(`${a[0]}${b}`, 'professional', 'initial+last', 10);
        add(`${a}.${b[0]}`, 'professional', 'first.initial', 6);
      }
      for (const i of inits) {
        for (const s of BANK.pro) add(i + s, 'professional', 'initials', 2);
        for (const { r } of roots) add(`${i}.${r}`, 'professional', 'initials', 6);
      }
    },
    gaming() {
      for (const { r, w } of roots) {
        for (const p of sample(BANK.gamePre, 8)) add(p + r, 'gaming', 'prefix', w - 4);
        for (const s of BANK.gameEnd) { add(r + s, 'gaming', 'suffix', w - 4); add(`${r}_${s}`, 'gaming', 'suffix', w - 8); }
        add(`x${r}x`, 'gaming', 'wrap', w - 10);
        if (o.allowNumbers) add(leet(r), 'gaming', 'leet', w - 6);
      }
      for (const [a, b] of pairs) add(a + b, 'gaming', 'combo', 6);
    },
    rare() {
      for (const { r, w } of roots) {
        for (const t of truncations(r)) for (let k = 0; k < 2; k++) add(t + syllable(true), 'rare', 'clipped', w - 6);
        add(`${r[0]}.${r.slice(1, 4)}`, 'rare', 'dotted', w - 8);
        add(r[0] + coined(true, 3), 'rare', 'coined', w - 8);
      }
      for (const i of inits) for (let k = 0; k < 4; k++) add(i + coined(true, 3), 'rare', 'initials', 0);
    },
  };
  for (const s of styles) build[s]();

  // Fill with pronounceable coined names (anchored to keywords when there are any) until the pool is big enough.
  const anchors = [...keywords, ...prefs, ...inits];
  const len = () => minLen + Math.floor(rng() * (maxLen - minLen + 1));
  for (let tries = 0; pool.size < count * 2 && tries < count * 60; tries++) {
    const s = pick(styles);
    const target = len();
    const a = anchors.length && rng() < 0.6 ? pick(anchors) : '';
    let pre = a ? a.slice(0, Math.max(2, Math.min(a.length, target - 3))) : '';
    let post = '';
    if (s === 'aesthetic' && rng() < 0.5) pre = `${pick(BANK.aesthetic)}.`;
    if (s === 'gaming' && !a && rng() < 0.5) pre = pick(BANK.gamePre);
    if (s === 'professional' && rng() < 0.5) post = pick(BANK.pro);
    const room = target - pre.length - post.length;
    if (room < 2) continue;
    const u = pre + coined(s === 'rare', room).slice(0, room) + post;
    add(u, s, a ? 'keyword+coined' : 'coined', a ? 2 : -6);
  }

  // Pick round-robin across (style, pattern) buckets so no single pattern floods the batch,
  // and skip names that only differ by a separator from one already picked ("a.b" vs "a_b").
  const buckets = new Map();
  for (const c of pool.values()) {
    const key = `${c.style}|${c.pattern}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(c);
  }
  const queues = [...buckets.values()].map(b => b.sort((x, y) => y.score - x.score));
  queues.sort((x, y) => y[0].score - x[0].score);
  const items = [];
  const seenBare = new Set();
  while (items.length < count && queues.some(q => q.length)) {
    for (const q of queues) {
      while (q.length) {
        const c = q.shift();
        const bare = c.username.replace(/[._]/g, '');
        if (seenBare.has(bare)) continue;
        seenBare.add(bare);
        items.push(c);
        break;
      }
      if (items.length >= count) break;
    }
  }
  return { items, stats: { requested: count, produced: items.length, candidates: pool.size, rejected } };
}
