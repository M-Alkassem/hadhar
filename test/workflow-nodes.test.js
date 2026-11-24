// Runs the REAL generated Code-node scripts inside a sandbox that mimics n8n's globals,
// so bundling mistakes are caught in milliseconds, long before n8n is started.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildWorkflow } from '../scripts/build-workflow.mjs';

const wf = buildWorkflow();
const nodeCode = (name) => wf.nodes.find((n) => n.name === name).parameters.jsCode;

async function runNode(name, { items = [], env = {}, store = {}, helpers = {}, scans = [] } = {}) {
  const sandbox = {
    $input: { all: () => items.map((json) => ({ json })) },
    $getWorkflowStaticData: () => store,
    $env: env,
    $: (n) => ({ all: () => (n === 'Scan message' ? scans.map((json) => ({ json })) : []) }),
    // NOTE: deliberately NO URL / URLSearchParams / fetch: n8n's Code-node sandbox does not provide them.
    console, Date, Math, JSON, Promise, Array, Object, String, Number, Set, Map, RegExp, Error, Intl, TextEncoder, Buffer, setTimeout,
  };
  const ctx = vm.createContext(sandbox);
  // n8n exposes `$('Node')` as a function; mirror that name too
  const fn = vm.runInContext(`(async function () {\n${nodeCode(name)}\n})`, ctx, { filename: name });
  return (await fn.call({ helpers })).map((i) => i.json);
}

const NOW_DAYS_AGO = (d) => new Date(Date.now() - d * 86400000).toISOString();
function fakeInternet(routes) {
  return { httpRequest: async (o) => { const r = routes[o.url] ?? routes[`${o.method} ${o.url}`]; if (!r) throw new Error('no route ' + o.url); return r; } };
}

test('the committed workflow file is up to date with src/ (run `npm run build`)', () => {
  const onDisk = readFileSync(fileURLToPath(new URL('../workflow/hadhar.workflow.json', import.meta.url)), 'utf8');
  assert.equal(onDisk, JSON.stringify(wf, null, 2) + '\n');
});

test('every connection points at a node that exists', () => {
  const names = new Set(wf.nodes.map((n) => n.name));
  for (const [from, c] of Object.entries(wf.connections)) {
    assert.ok(names.has(from), from);
    for (const branch of c.main) for (const t of branch) assert.ok(names.has(t.node), `${from} -> ${t.node}`);
  }
});

test('Route message: /family creates a code, a normal message passes through', async () => {
  const store = {};
  const [cmd] = await runNode('Route message', { store, items: [{ source: 'webhook', chatId: 'g1', name: 'Sam', text: '/family' }] });
  assert.equal(cmd.isCommand, true);
  assert.match(cmd.messages[0].text, /\/join [A-Z0-9]{6}/);
  assert.equal(cmd.messages[0].deliver, 'respond');
  const [pass] = await runNode('Route message', { store, items: [{ source: 'telegram', chatId: '5', text: 'hello http://x.top' }] });
  assert.equal(pass.isCommand, false);
});

test('Route message: Arabic users get Arabic command replies; empty text gets guidance; rejected requests get 401', async () => {
  const [ar] = await runNode('Route message', { items: [{ source: 'telegram', chatId: '1', langCode: 'ar', text: '/start' }] });
  assert.match(ar.messages[0].text, /الاحتيال/);
  const [empty] = await runNode('Route message', { items: [{ source: 'telegram', chatId: '1', text: '', unsupported: true }] });
  assert.match(empty.messages[0].text, /Send me the text/);
  const [rej] = await runNode('Route message', { items: [{ source: 'webhook', reject: true }] });
  assert.equal(rej.messages[0].status, 401);
});

test('Normalize webhook enforces the shared secret only when one is configured', async () => {
  const req = (headers) => [{ body: { chatId: 9, text: 'hi' }, headers }];
  assert.equal((await runNode('Normalize webhook', { items: req({}), env: {} }))[0].reject, undefined);
  assert.equal((await runNode('Normalize webhook', { items: req({}), env: { HADHAR_WEBHOOK_TOKEN: 's' } }))[0].reject, true);
  assert.equal((await runNode('Normalize webhook', { items: req({ 'x-hadhar-token': 's' }), env: { HADHAR_WEBHOOK_TOKEN: 's' } }))[0].reject, undefined);
  assert.equal((await runNode('Normalize webhook', { items: req({}) }))[0].chatId, '9');
});

test('Poll Telegram: idle without a token; with one it parses updates and advances the offset', async () => {
  assert.equal((await runNode('Poll Telegram', { env: {} })).length, 0);
  const store = {};
  const helpers = { httpRequest: async (o) => ({ result: [{ update_id: 41, message: { chat: { id: 7 }, from: { first_name: 'Mum', language_code: 'ar' }, text: 'hi' } }, { update_id: 42, message: { chat: { id: 7 }, from: { first_name: 'Mum' } } }] }) };
  const out = await runNode('Poll Telegram', { env: { TELEGRAM_BOT_TOKEN: 't' }, store, helpers });
  assert.equal(out.length, 2);
  assert.equal(out[0].chatId, '7');
  assert.equal(out[0].langCode, 'ar');
  assert.equal(out[1].unsupported, true);
  assert.equal(store.tgOffset, 43);
  assert.equal((await runNode('Poll Telegram', { env: { TELEGRAM_BOT_TOKEN: 't' }, store, helpers: { httpRequest: async () => { throw new Error('offline'); } } })).length, 0);
});

test('Scan + Build: a phishing message ends red, with a guardian alert that hides digits', async () => {
  const text = 'Your PayPal account is suspended, verify within 24 hours: http://paypal-secure.top/login and send code 123456';
  const helpers = fakeInternet({
    'https://openphish.com/feed.txt': { statusCode: 200, headers: {}, body: 'https://other-bad.top/\n' },
    'HEAD http://paypal-secure.top/login': { statusCode: 200, headers: {} },
    'https://rdap.org/domain/paypal-secure.top': { statusCode: 200, headers: {}, body: { events: [{ eventAction: 'registration', eventDate: NOW_DAYS_AGO(2) }] } },
  });
  const store = {};
  // set up family link: guardian g1 watches chat m1 (named Mum)
  await runNode('Route message', { store, items: [{ source: 'webhook', chatId: 'g1', text: '/family' }] });
  const code = Object.keys(store.family.invites)[0];
  await runNode('Route message', { store, items: [{ source: 'webhook', chatId: 'm1', name: 'Mum', text: `/join ${code} Mum` }] });

  const scanned = await runNode('Scan message', { store, helpers, items: [{ source: 'telegram', chatId: 'm1', name: 'Mum', text }] });
  assert.equal(scanned[0].result.verdict, 'red');
  assert.ok(scanned[0].llmRequest.messages[0].content.includes('untrusted'));
  const built = await runNode('Build replies', { store, scans: scanned, items: scanned });
  assert.equal(built.length, 2);
  assert.equal(built[0].chat, 'm1');
  assert.match(built[0].text, /^🔴/);
  assert.equal(built[1].chat, 'g1');
  assert.match(built[1].text, /Mum/);
  assert.doesNotMatch(built[1].text, /123456/);
});

test('Scan: a private-address link is never requested', async () => {
  const seen = [];
  const helpers = { httpRequest: async (o) => { seen.push(o.url); if (o.url.includes('openphish')) return { statusCode: 200, headers: {}, body: '' }; throw new Error('should not be called: ' + o.url); } };
  const [r] = await runNode('Scan message', { helpers, items: [{ source: 'webhook', chatId: 'x', text: 'pay here http://169.254.169.254/latest/meta-data' }] });
  assert.equal(r.result.inspected[0].error, 'private-host');
  assert.equal(seen.length, 1);
  assert.equal(seen[0], 'https://openphish.com/feed.txt');
});

test('Build replies: the model opinion is merged and cannot lower a verdict', async () => {
  const mkScan = (verdict, score) => ({ source: 'webhook', chatId: 'c', text: 't', result: { verdict, score, lang: 'en', signals: [], urls: [], inspected: [] } });
  const llm = (scam) => ({ content: [{ type: 'text', text: JSON.stringify({ scam, explanation: 'because' }) }] });
  const up = await runNode('Build replies', { scans: [mkScan('amber', 25)], items: [llm(true)] });
  assert.equal(up[0].body.verdict, 'red');
  const down = await runNode('Build replies', { scans: [mkScan('red', 80)], items: [llm(false)] });
  assert.equal(down[0].body.verdict, 'red');
  const none = await runNode('Build replies', { scans: [mkScan('amber', 25)], items: [{ error: 'boom' }] });
  assert.equal(none[0].body.verdict, 'amber');
  assert.equal(none[0].body.llm, null);
});
