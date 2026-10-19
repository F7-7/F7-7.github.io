// Run: node --test tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { generate, validateUsername, variations, LENGTHS, STYLES } from '../generator.js';

const base = { keywords: 'fahad awad, coffee', initials: 'fw', words: 'night', seed: 42 };

test('every result is a valid, in-range, unique username', () => {
  for (const length of Object.keys(LENGTHS)) {
    const { items } = generate({ ...base, length, count: 150 });
    const [min, max] = LENGTHS[length];
    assert.ok(items.length >= 100, `${length}: only ${items.length}`);
    assert.equal(new Set(items.map(i => i.username)).size, items.length);
    for (const { username: u } of items) {
      assert.ok(validateUsername(u).ok, `${u}: ${validateUsername(u).reason}`);
      assert.ok(u.length >= min && u.length <= max, `${u} outside ${length}`);
    }
  }
});

test('names that differ only by a separator are deduplicated', () => {
  const { items } = generate({ ...base, count: 300 });
  const bare = items.map(i => i.username.replace(/[._]/g, ''));
  assert.equal(new Set(bare).size, bare.length);
});

test('500 suggestions per batch without keywords', () => {
  const { items } = generate({ count: 500, seed: 7 });
  assert.equal(items.length, 500);
});

test('character toggles are respected', () => {
  const { items } = generate({ ...base, allowNumbers: false, allowPeriod: false, allowUnderscore: false, count: 200 });
  for (const { username: u } of items) assert.match(u, /^[a-z]+$/);
  const withNums = generate({ ...base, allowNumbers: true, styles: ['gaming'], count: 300 }).items;
  assert.ok(withNums.some(i => /\d/.test(i.username)), 'leet variants appear when numbers are allowed');
});

test('numbers stay rare even when allowed', () => {
  const { items } = generate({ ...base, allowNumbers: true, count: 200 });
  const share = items.filter(i => /\d/.test(i.username)).length / items.length;
  assert.ok(share < 0.15, `digits in ${(share * 100).toFixed(0)}% of names`);
});

test('excluded characters and words never appear', () => {
  const { items } = generate({ ...base, excludeChars: 'x z', excludeWords: 'coffee, moon', count: 200 });
  for (const { username: u } of items) {
    assert.ok(!/[xz]/.test(u), u);
    assert.ok(!u.replace(/[._]/g, '').includes('coffee') && !u.includes('moon'), u);
  }
});

test('style filter limits output styles', () => {
  const { items } = generate({ ...base, styles: ['professional'], count: 100 });
  assert.ok(items.every(i => i.style === 'professional'));
  assert.ok(STYLES.length === 5);
});

test('keyword-anchored ideas come first', () => {
  const { items } = generate({ ...base, length: '6-8', count: 120 });
  const top = items.slice(0, 20).filter(i => /fahad|fhd|awad|cof/.test(i.username)).length;
  assert.ok(top >= 15, `only ${top}/20 top results use a keyword`);
});

test('same seed gives the same batch', () => {
  assert.deepEqual(generate({ ...base, count: 50 }).items, generate({ ...base, count: 50 }).items);
});

test('validateUsername follows TikTok rules', () => {
  assert.ok(validateUsername('fahad.awad').ok);
  assert.ok(validateUsername('_fahad_').ok);
  assert.ok(!validateUsername('fahad.').ok);
  assert.ok(!validateUsername('a').ok);
  assert.ok(!validateUsername('x'.repeat(25)).ok);
  assert.ok(!validateUsername('fa-had').ok);
  assert.ok(!validateUsername('12345').ok);
});

test('variations include subtle respellings and a vowel-drop form', () => {
  const v = variations('coffee');
  assert.ok(v.includes('cffee') || v.includes('cff'));
  assert.ok(v.includes('cofphee') || v.includes('koffee'));
});
