// Hadhar evaluation harness.
//   node eval/run-eval.mjs [--sets hand,sms,urls] [--split dev|test|all] [--errors] [--write]
// Every item is assigned to "dev" or "test" by a hash of its id. Rules were tuned
// on dev only; report numbers from --split test.
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { MESSAGES } from './data/messages.js';
import { buildResult, registrableDomain } from '../src/engine.js';
import { analyzeMessage, domainAgeDays } from '../src/net.js';
import { nodeHttp } from '../src/http-node.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CACHE = join(HERE, 'cache');
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf('--' + name); return i === -1 ? def : (args[i + 1]?.startsWith('--') || args[i + 1] === undefined ? true : args[i + 1]); };
const SETS = String(opt('sets', 'hand,sms,urls')).split(',');
const SPLIT = opt('split', 'dev');
const SHOW = args.includes('--errors');

function fnv(str) { let h = 2166136261; for (const c of str) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }
const splitOf = (id) => (fnv(id) % 2 === 0 ? 'dev' : 'test');
function mulberry32(a) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function shuffle(arr, seed) { const r = mulberry32(seed); const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }
const offline = async () => { throw new Error('offline'); };

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

// ------------------------------------------------------------------ datasets
async function loadHand() {
  return MESSAGES.map(([label, lang, text], i) => ({ id: `hand:${i}`, label, lang, text, kind: 'message' }));
}
async function loadSms() {
  const f = join(CACHE, 'SMSSpamCollection');
  if (!existsSync(f)) throw new Error('missing eval/cache/SMSSpamCollection (see eval/README.md)');
  const rows = readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => { const t = l.indexOf('\t'); return { label: l.slice(0, t) === 'spam' ? 'scam' : 'benign', text: l.slice(t + 1) }; });
  const pick = (label, n) => shuffle(rows.filter((r) => r.label === label), 7).slice(0, n);
  return [...pick('scam', 300), ...pick('benign', 300)].map((r, i) => ({ id: `sms:${i}`, ...r, lang: 'en', kind: 'message' }));
}
async function loadUrls() {
  const phishFile = join(CACHE, 'openphish.txt');
  const trancoFile = join(CACHE, 'top-1m.csv');
  if (!existsSync(phishFile) || !existsSync(trancoFile)) throw new Error('missing eval/cache/openphish.txt or top-1m.csv (see eval/README.md)');
  const phish = readFileSync(phishFile, 'utf8').split('\n').map((l) => l.trim()).filter((l) => /^https?:\/\//.test(l));
  const seenDom = new Set(); const phishPick = [];
  for (const u of shuffle(phish, 11)) { let h; try { h = new URL(u).hostname; } catch { continue; } const d = registrableDomain(h).domain; if (seenDom.has(d)) continue; seenDom.add(d); phishPick.push(u); if (phishPick.length === 150) break; }
  const tranco = readFileSync(trancoFile, 'utf8').split('\n').filter(Boolean).map((l) => l.split(',')[1]?.trim()).filter(Boolean);
  const top = shuffle(tranco.slice(0, 1000), 13).slice(0, 75);
  const tail = shuffle(tranco.slice(50000, 100000), 17).slice(0, 75);
  return [
    ...phishPick.map((u, i) => ({ id: `url:p${i}`, label: 'scam', text: u, url: u, kind: 'url', group: 'openphish' })),
    ...top.map((d, i) => ({ id: `url:t${i}`, label: 'benign', text: `https://${d}/`, url: `https://${d}/`, kind: 'url', group: 'tranco-top1k' })),
    ...tail.map((d, i) => ({ id: `url:l${i}`, label: 'benign', text: `https://${d}/`, url: `https://${d}/`, kind: 'url', group: 'tranco-50k-100k' })),
  ];
}

// -------------------------------------------------------------------- running
const rdapCacheFile = join(CACHE, 'rdap.json');
const rdapCache = existsSync(rdapCacheFile) ? JSON.parse(readFileSync(rdapCacheFile, 'utf8')) : {};
async function ageFor(url) {
  const host = new URL(url).hostname; const dom = registrableDomain(host).domain;
  if (dom in rdapCache) return rdapCache[dom];
  let age = null;
  for (let attempt = 0; attempt < 2 && age === null; attempt++) { age = await domainAgeDays(host, nodeHttp, Date.now(), { timeout: 12000 }); if (age === null) await new Promise((r) => setTimeout(r, 300)); }
  rdapCache[dom] = age; return age;
}

async function run(item) {
  if (item.kind === 'url') { // URL-only: structure + domain age (RDAP). The live blocklist is excluded on purpose (ground truth would leak in).
    const ageDays = await ageFor(item.url);
    return buildResult(item.text, [{ url: item.url, ageDays }]);
  }
  return analyzeMessage(item.text, { http: offline, blockIndex: null });
}

const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(1)}%` : 'n/a');
function summarize(rows) {
  const scam = rows.filter((r) => r.label === 'scam'); const ben = rows.filter((r) => r.label === 'benign');
  const flag = (r) => r.verdict !== 'green'; const red = (r) => r.verdict === 'red';
  return { n: rows.length, scam: scam.length, benign: ben.length,
    scamFlagged: scam.filter(flag).length, scamRed: scam.filter(red).length,
    benignFlagged: ben.filter(flag).length, benignRed: ben.filter(red).length };
}
function line(name, s) {
  return `${name.padEnd(26)} scams ${String(s.scam).padStart(3)}  caught(amber+red) ${pct(s.scamFlagged, s.scam).padStart(6)}  caught(red) ${pct(s.scamRed, s.scam).padStart(6)} | safe ${String(s.benign).padStart(3)}  false alarm(red) ${pct(s.benignRed, s.benign).padStart(6)}  any alarm ${pct(s.benignFlagged, s.benign).padStart(6)}`;
}

const loaders = { hand: loadHand, sms: loadSms, urls: loadUrls };
const report = { split: SPLIT, generatedAt: new Date().toISOString(), sets: {} };
for (const set of SETS) {
  const all = await loaders[set]();
  const items = all.filter((it) => SPLIT === 'all' || splitOf(it.id) === SPLIT);
  const rows = await pool(items, set === 'urls' ? 3 : 8, async (it) => { const r = await run(it); return { id: it.id, label: it.label, lang: it.lang, group: it.group, text: it.text, verdict: r.verdict, score: r.score, signals: r.signals.map((s) => s.id) }; });
  if (set === 'urls') writeFileSync(rdapCacheFile, JSON.stringify(rdapCache));
  const groups = { all: summarize(rows) };
  if (set === 'hand') for (const l of ['en', 'ar']) groups[l] = summarize(rows.filter((r) => r.lang === l));
  if (set === 'urls') {
    const ph = summarize(rows.filter((r) => r.group === 'openphish'));
    const known = rows.filter((r) => r.label === 'benign' && r.group === 'tranco-top1k'); const tail = rows.filter((r) => r.group === 'tranco-50k-100k');
    groups.phish = summarize(rows.filter((r) => r.group === 'openphish' || r.group === 'tranco-top1k' || r.group === 'tranco-50k-100k')); delete groups.phish;
    groups['vs top-1k'] = summarize([...rows.filter((r) => r.group === 'openphish'), ...known]);
    groups['vs 50k-100k'] = summarize([...rows.filter((r) => r.group === 'openphish'), ...tail]);
    void ph;
  }
  report.sets[set] = { groups, rows };
  console.log(`\n== ${set} (${SPLIT}) ==`);
  for (const [name, s] of Object.entries(groups)) console.log(line(name, s));
  if (SHOW) {
    for (const r of rows) {
      if (r.label === 'scam' && r.verdict === 'green') console.log(`  MISS  [${r.score}] ${r.text.slice(0, 110)}`);
      if (r.label === 'benign' && r.verdict === 'red') console.log(`  FALSE-RED [${r.score}] ${r.text.slice(0, 110)} {${r.signals.join(',')}}`);
    }
  }
}
if (args.includes('--write')) {
  mkdirSync(join(HERE, 'results'), { recursive: true });
  const slim = { ...report, sets: Object.fromEntries(Object.entries(report.sets).map(([k, v]) => [k, { groups: v.groups }])) };
  writeFileSync(join(HERE, 'results', `${SPLIT}.json`), JSON.stringify(slim, null, 2));
}
