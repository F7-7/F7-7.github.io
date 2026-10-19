// Browser test of the main flows. Needs Playwright and a local server:
//   python3 -m http.server 8765 --directory ..   (from this folder's parent)
//   node tests/e2e.mjs [http://localhost:8765/tiktok-username-finder/]
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const require = createRequire(import.meta.url);
let pw;
try { pw = require('playwright'); } catch { pw = require(process.env.PLAYWRIGHT_PATH || '/opt/node-tools/node_modules/playwright'); }

const URL = process.argv[2] || 'http://localhost:8765/tiktok-username-finder/';
const out = process.env.SHOTS || '';
const browser = await pw.chromium.launch();
const errors = [];
const log = m => console.log('✓', m);

async function run(viewport) {
  const ctx = await browser.newContext({ viewport, acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/fonts\.g/.test(m.text())) errors.push(m.text()); });
  // Block every request to TikTok: the app must never call it on its own.
  const tiktokCalls = [];
  await ctx.route(/tiktok\.com/, r => { tiktokCalls.push(r.request().url()); r.fulfill({ status: 200, body: 'stub' }); });
  await page.goto(URL);

  // Empty state, then generate.
  assert.ok(await page.isVisible('#empty'));
  await page.fill('#keywords', 'fahad awad, coffee');
  await page.fill('#initials', 'fw');
  await page.check('[name=length][value="6-8"]', { force: true });
  await page.click('#generate');
  await page.waitForSelector('#list .item');
  const n = Number(await page.textContent('#c-all'));
  assert.ok(n >= 100, `generated ${n}`);
  const names = await page.$$eval('#list .name', els => els.map(e => e.textContent.slice(1)));
  assert.ok(names.every(u => u.length >= 6 && u.length <= 8));
  assert.equal(await page.textContent('#c-available'), '0', 'nothing is available before a check');
  assert.equal(await page.textContent('#c-todo'), String(n));
  log(`${viewport.width}px: generated ${n} names, all Unverified`);
  if (out) await page.screenshot({ path: `${out}/gen-${viewport.width}.png`, fullPage: false });

  // Copy.
  const first = names[0];
  await page.click(`[data-u="${first}"] [data-act=copy]`);
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), first);
  log('copy button');

  // Favorite.
  await page.click(`[data-u="${first}"] [data-act=fav]`);
  assert.equal(await page.textContent('#c-fav'), '1');
  log('favorite');

  // Open link targets the profile in one reusable tab.
  const [popup] = await Promise.all([page.waitForEvent('popup'), page.click(`[data-u="${first}"] [data-act=open]`)]);
  assert.equal(popup.url(), `https://www.tiktok.com/@${first}`);
  await popup.close();
  log('open profile link');

  // Checking mode with keyboard marks.
  await page.click('#checkMode');
  assert.ok(await page.isVisible('#checker'));
  const ckName = (await page.textContent('#ckName')).slice(1);
  await page.keyboard.press('t');
  await page.keyboard.press('n');
  await page.keyboard.press('a');
  await page.keyboard.press('s');
  await page.keyboard.press('u');
  if (out) await page.screenshot({ path: `${out}/check-${viewport.width}.png` });
  await page.click('#ckClose');
  assert.equal(await page.textContent('#c-taken'), '1');
  assert.equal(await page.textContent('#c-notfound'), '1');
  assert.equal(await page.textContent('#c-available'), '1');
  assert.equal(await page.textContent('#progLabel'), `Checked 3 of ${n}`);
  assert.equal(await page.$eval(`[data-u="${ckName}"] select`, e => e.value), 'taken');
  log('checking mode: taken / no profile / available / skip / unknown');

  // Confirmed tab shows only confirmed names; available ones are auto-favorited.
  await page.click('[data-tab=available]');
  assert.equal(await page.$$eval('#list .item', e => e.length), 1);
  assert.equal(await page.textContent('#c-fav'), '2');
  await page.click('[data-tab=all]');
  log('confirmed tab separates verified results');

  // Status dropdown on a card.
  await page.selectOption(`[data-u="${names[10]}"] select`, 'taken');
  assert.equal(await page.textContent('#c-taken'), '2');
  log('manual status change');

  // Filters.
  await page.selectOption('#fChars', 'letters');
  assert.ok((await page.$$eval('#list .name', e => e.map(x => x.textContent.slice(1)))).every(u => /^[a-z]+$/.test(u)));
  await page.selectOption('#fChars', '');
  await page.selectOption('#fStyle', 'gaming');
  assert.ok((await page.$$eval('#list .meta span:nth-of-type(2)', e => e.map(x => x.textContent))).every(s => s === 'gaming'));
  await page.selectOption('#fStyle', '');
  await page.selectOption('#fStatus', 'taken');
  assert.equal(await page.$$eval('#list .item', e => e.length), 2);
  await page.selectOption('#fStatus', '');
  log('filters: characters, style, status');

  // Search + add a custom username, including invalid input.
  await page.fill('#q', 'bad.');
  await page.click('#addBtn');
  assert.match(await page.textContent('#toast'), /Cannot end with a period/);
  await page.fill('#q', '@my.own_name');
  await page.click('#addBtn');
  assert.equal(await page.textContent('#c-all'), String(n + 1));
  assert.ok(await page.isVisible('[data-u="my.own_name"]'));
  log('add custom username with validation');

  // Exports.
  await page.click('[data-tab=fav]');
  const [txt] = await Promise.all([page.waitForEvent('download'), page.click('#expTxt')]);
  const body = fs.readFileSync(await txt.path(), 'utf8').trim().split('\n');
  assert.equal(body.length, 2);
  await page.click('[data-tab=all]');
  const [csv] = await Promise.all([page.waitForEvent('download'), page.click('#expCsv')]);
  const rows = fs.readFileSync(await csv.path(), 'utf8').trim().split('\n');
  assert.equal(rows[0], 'username,length,style,status,checked_at,favorite,profile_url');
  assert.equal(rows.length, n + 2);
  log('export TXT (favorites) and CSV (all)');

  // Persistence across reload.
  await page.reload();
  await page.waitForSelector('#list .item');
  assert.equal(await page.textContent('#c-all'), String(n + 1));
  assert.equal(await page.textContent('#c-taken'), '2');
  log('state survives reload');

  // Append mode adds without duplicating.
  await page.click('.more summary');
  await page.check('#append');
  await page.click('#generate');
  await page.waitForFunction(m => Number(document.querySelector('#c-all').textContent) > m, n + 1);
  const all = await page.$$eval('#list .name', e => e.map(x => x.textContent));
  assert.equal(new Set(all).size, all.length);
  log('append batch without duplicates');

  // Arabic-only keyword is explained, not silently dropped.
  await page.fill('#keywords', 'فهد');
  await page.click('#generate');
  assert.match(await page.textContent('#genMsg'), /Latin letters/);
  log('non-Latin keyword warning');

  // No horizontal scroll.
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  log('no horizontal overflow');
  if (out) await page.screenshot({ path: `${out}/full-${viewport.width}.png`, fullPage: true });

  assert.deepEqual(tiktokCalls.filter(u => !u.startsWith('https://www.tiktok.com/@')), [], 'no background calls to TikTok');
  await ctx.close();
}

await run({ width: 1280, height: 900 });
await run({ width: 375, height: 780 });
await browser.close();
assert.deepEqual(errors, [], 'console errors');
console.log('All browser flows passed.');
