import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveChain, domainAgeDays, refreshBlocklist, buildBlocklistIndex, isBlocklisted, inspectUrl, analyzeMessage } from '../src/net.js';

// A tiny fake internet: map url -> response (or a function).
function fakeNet(routes, calls = []) {
  return async (opts) => {
    calls.push(`${opts.method} ${opts.url}`);
    const r = routes[opts.url] ?? routes[`${opts.method} ${opts.url}`];
    if (!r) throw new Error('no route ' + opts.url);
    return typeof r === 'function' ? r(opts) : r;
  };
}
const redirect = (to) => ({ status: 302, headers: { location: to } });
const ok = { status: 200, headers: {} };

test('resolveChain follows redirects and records every hop', async () => {
  const http = fakeNet({ 'http://a.com/': redirect('https://b.com/x'), 'https://b.com/x': redirect('/y'), 'https://b.com/y': ok });
  const r = await resolveChain('http://a.com/', http);
  assert.deepEqual(r.chain, ['http://a.com/', 'https://b.com/x', 'https://b.com/y']);
  assert.equal(r.status, 200);
});

test('resolveChain never requests a private address, even mid-chain', async () => {
  const calls = [];
  const http = fakeNet({ 'http://a.com/': redirect('http://169.254.169.254/latest/meta-data') }, calls);
  const r = await resolveChain('http://a.com/', http);
  assert.equal(r.blocked, true);
  assert.equal(r.error, 'private-host');
  assert.deepEqual(calls, ['HEAD http://a.com/']); // metadata endpoint was never contacted
});

test('resolveChain refuses a private start URL without any request', async () => {
  const calls = [];
  const r = await resolveChain('http://localhost:8080/admin', fakeNet({}, calls));
  assert.equal(r.blocked, true);
  assert.equal(calls.length, 0);
});

test('resolveChain detects loops and caps hops', async () => {
  const loop = fakeNet({ 'http://a.com/': redirect('http://b.com/'), 'http://b.com/': redirect('http://a.com/') });
  assert.equal((await resolveChain('http://a.com/', loop)).error, 'redirect-loop');
  const long = fakeNet(Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`http://h${i}.com/`, redirect(`http://h${i + 1}.com/`)])));
  const r = await resolveChain('http://h0.com/', long, { maxHops: 5 });
  assert.equal(r.error, 'too-many-redirects');
  assert.equal(r.chain.length, 6);
});

test('resolveChain falls back to GET when HEAD is refused', async () => {
  const calls = [];
  const http = fakeNet({ 'HEAD http://a.com/': { status: 405, headers: {} }, 'GET http://a.com/': ok }, calls);
  const r = await resolveChain('http://a.com/', http);
  assert.equal(r.status, 200);
  assert.deepEqual(calls, ['HEAD http://a.com/', 'GET http://a.com/']);
});

test('resolveChain survives a network failure', async () => {
  const r = await resolveChain('http://down.example.com/', fakeNet({}));
  assert.equal(r.error, 'fetch-failed');
  assert.deepEqual(r.chain, ['http://down.example.com/']);
});

test('domainAgeDays reads the RDAP registration date', async () => {
  const now = Date.parse('2026-11-24T00:00:00Z');
  const http = fakeNet({ 'https://rdap.org/domain/new-site.top': { status: 200, headers: {}, body: { events: [{ eventAction: 'registration', eventDate: '2026-11-21T00:00:00Z' }] } } });
  assert.equal(Math.round(await domainAgeDays('login.new-site.top', http, now)), 3);
});

test('domainAgeDays returns null for unknown, IPs, free hosting and errors', async () => {
  const http = fakeNet({ 'https://rdap.org/domain/x.example': { status: 404, headers: {} } });
  assert.equal(await domainAgeDays('x.example', http), null);
  assert.equal(await domainAgeDays('1.2.3.4', http), null);
  assert.equal(await domainAgeDays('me.github.io', http), null);
  assert.equal(await domainAgeDays('nowhere.test', fakeNet({})), null);
});

test('blocklist: refresh caches for the ttl, matches exact urls and domain-level entries', async () => {
  let fetches = 0;
  const http = async () => { fetches++; return { status: 200, headers: {}, body: 'https://evil.top/\nhttps://legit.com/wp/phish.html\nnot a url\n' }; };
  const c1 = await refreshBlocklist(http, null, 1000);
  const c2 = await refreshBlocklist(http, c1, 2000);
  assert.equal(fetches, 1);
  assert.equal(c2.urls.length, 2);
  const idx = buildBlocklistIndex(c2.urls);
  assert.equal(isBlocklisted('https://evil.top/anything', idx), true); // domain-level entry
  assert.equal(isBlocklisted('https://legit.com/wp/phish.html?x=1', idx), true); // exact path
  assert.equal(isBlocklisted('https://legit.com/about', idx), false); // compromised host is not condemned
});

test('blocklist: a failed refresh keeps the previous cache', async () => {
  const old = { fetchedAt: 1, urls: ['https://a.top/'] };
  const r = await refreshBlocklist(async () => { throw new Error('down'); }, old, 99999999999);
  assert.equal(r, old);
});

test('analyzeMessage: end to end on a fake phishing site -> red, with the evidence listed', async () => {
  const now = Date.parse('2026-11-24T00:00:00Z');
  const http = fakeNet({
    'http://bit.ly/3x': redirect('https://paypal-verify.top/login'),
    'https://paypal-verify.top/login': ok,
    'https://rdap.org/domain/paypal-verify.top': { status: 200, headers: {}, body: { events: [{ eventAction: 'registration', eventDate: '2026-11-22T00:00:00Z' }] } },
  });
  const r = await analyzeMessage('Your PayPal account is suspended, verify now: http://bit.ly/3x', { http, blockIndex: buildBlocklistIndex([]), now });
  assert.equal(r.verdict, 'red');
  const sigIds = r.signals.map((s) => s.id);
  for (const id of ['brand_lookalike', 'domain_new', 'shortener']) assert.ok(sigIds.includes(id), id);
  assert.equal(r.inspected[0].hops, 1);
});

test('analyzeMessage: a text-only scam still scores without any network call', async () => {
  const r = await analyzeMessage('Hi mum, I lost my phone, new number. Please send money urgently, buy gift cards', { http: fakeNet({}), blockIndex: null });
  assert.notEqual(r.verdict, 'green');
});

test('analyzeMessage inspects at most three links', async () => {
  const calls = [];
  const http = fakeNet({}, calls);
  await analyzeMessage('http://a1.com http://a2.com http://a3.com http://a4.com http://a5.com', { http, blockIndex: null });
  assert.ok(calls.filter((c) => c.startsWith('HEAD')).length <= 3);
});

test('a bare link (no scheme in the message) is not called "unencrypted", an explicit http link is', async () => {
  const http = fakeNet({});
  const bare = await analyzeMessage('go to aramex-pay.click/track', { http, blockIndex: null });
  assert.ok(!bare.signals.some((s) => s.id === 'no_https'));
  const explicit = await analyzeMessage('go to http://aramex-pay.click/track', { http, blockIndex: null });
  assert.ok(explicit.signals.some((s) => s.id === 'no_https'));
});
