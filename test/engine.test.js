import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeText, detectLang, extractUrls, parseUrl, normalizeIPv4, resolveRelative, registrableDomain, isPrivateHost,
  brandLookalike, urlSignals, textSignals, buildResult, formatReply, familyAlert, snippet,
} from '../src/engine.js';

const ids = (signals) => signals.map((s) => s.id);

test('normalizeText folds Arabic variants and digits', () => {
  assert.equal(normalizeText('إيقاف حسابك ٢٤ ساعة'), 'ايقاف حسابك 24 ساعه');
  assert.equal(normalizeText('كلمةُ المرور'), 'كلمه المرور');
});

test('detectLang picks Arabic only when mostly Arabic', () => {
  assert.equal(detectLang('تم إيقاف حسابك http://x.top'), 'ar');
  assert.equal(detectLang('Your account is locked'), 'en');
  assert.equal(detectLang('12345 !!!'), 'en');
});

test('extractUrls finds full, www and bare links and skips emails', () => {
  const urls = extractUrls('Visit https://a.example.com/x?y=1, or www.test.org. Mail me at bob@gmail.com or go to secure-login.top/verify now');
  assert.deepEqual(urls, ['https://a.example.com/x?y=1', 'www.test.org', 'secure-login.top/verify']);
});

test('extractUrls handles Arabic text around a link', () => {
  const urls = extractUrls('تم تعليق حسابك، اضغط: http://bank-verify.top/login، شكراً');
  assert.deepEqual(urls, ['http://bank-verify.top/login']);
});

test('extractUrls de-duplicates', () => {
  assert.equal(extractUrls('http://a.com http://a.com').length, 1);
});

test('parseUrl guesses the scheme and flags non-ASCII hosts', () => {
  const p = parseUrl('www.example.com/a');
  assert.equal(p.schemeGuessed, true);
  assert.equal(p.host, 'www.example.com');
  assert.equal(parseUrl('http://аpple.com').unicodeHost, true);
  assert.equal(parseUrl('ftp://x.com'), null);
});

test('registrableDomain handles two-part and free-hosting suffixes', () => {
  assert.equal(registrableDomain('a.b.example.co.uk').domain, 'example.co.uk');
  assert.equal(registrableDomain('login.paypal.com').domain, 'paypal.com');
  const g = registrableDomain('my-bank.github.io');
  assert.equal(g.domain, 'my-bank.github.io');
  assert.equal(g.freeHosting, true);
});

test('isPrivateHost blocks internal targets (SSRF guard)', () => {
  for (const h of ['localhost', '127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '0.0.0.0', 'intranet', 'printer.local', '::1', 'fd00::1', '100.64.0.1', '[::ffff:7f00:1]']) {
    assert.equal(isPrivateHost(h), true, h);
  }
  for (const h of ['example.com', '8.8.8.8', '172.32.0.1', '93.184.216.34']) {
    assert.equal(isPrivateHost(h), false, h);
  }
});

test('decimal and hex IP tricks are normalised before the SSRF check', () => {
  assert.equal(isPrivateHost(parseUrl('http://2130706433/').host), true);
  assert.equal(isPrivateHost(parseUrl('http://0x7f000001/').host), true);
});

test('brandLookalike flags imitations but not the real sites', () => {
  assert.equal(brandLookalike('secure-paypal-login.com')?.brand, 'paypal');
  assert.equal(brandLookalike('paypal.com.verify-id.top')?.brand, 'paypal');
  assert.equal(brandLookalike('paypa1.com')?.kind, 'typosquat');
  assert.equal(brandLookalike('netfiix.com')?.kind, 'typosquat');
  assert.equal(brandLookalike('www.paypal.com'), null);
  assert.equal(brandLookalike('support.apple.com'), null);
  assert.equal(brandLookalike('accounts.google.com'), null);
  assert.equal(brandLookalike('googleusercontent.com'), null);
});

test('brandLookalike catches digit-for-letter typosquats', () => {
  assert.equal(brandLookalike('netf1ix.com')?.brand, 'netflix');
  assert.equal(brandLookalike('arnazon.com'), null); // documented limit: "rn" for "m" needs distance 2
});

test('urlSignals: young look-alike on a risky TLD is loud', () => {
  const s = urlSignals({ url: 'http://paypal-secure.top/login', ageDays: 2 });
  assert.deepEqual(ids(s).sort(), ['brand_lookalike', 'domain_new', 'no_https', 'risky_tld'].sort());
});

test('urlSignals: a blocklisted url is flagged', () => {
  assert.ok(ids(urlSignals({ url: 'https://evil.example.net/a', blocklisted: true })).includes('blocklisted'));
});

test('urlSignals: shortener + redirect chain', () => {
  const s = urlSignals({ url: 'https://bit.ly/abc', chain: ['https://bit.ly/abc', 'https://t.co/x', 'https://a-promo.xyz/y', 'https://a-promo.xyz/z'] });
  const got = ids(s);
  assert.ok(got.includes('shortener'));
  assert.ok(got.includes('many_redirects'));
  assert.ok(got.includes('risky_tld'));
});

test('urlSignals: ip host, userinfo, punycode', () => {
  assert.ok(ids(urlSignals({ url: 'http://185.12.9.4/pay' })).includes('ip_host'));
  assert.ok(ids(urlSignals({ url: 'https://google.com@evil.example.org/' })).includes('userinfo'));
  assert.ok(ids(urlSignals({ url: 'http://аррle.com/' })).includes('punycode'));
});

test('urlSignals: an old, normal site gets nothing', () => {
  assert.deepEqual(urlSignals({ url: 'https://www.wikipedia.org/wiki/Cat', ageDays: 9000 }), []);
});

test('urlSignals: a bare link does not get penalised for missing https', () => {
  assert.ok(!ids(urlSignals({ url: 'example.com/a' })).includes('no_https'));
  assert.ok(ids(urlSignals({ url: 'http://example.com/a' })).includes('no_https'));
});

test('textSignals: credential request fires, but a normal OTP message does not', () => {
  assert.ok(ids(textSignals('Please reply with your OTP to confirm')).includes('credential_ask'));
  assert.ok(!ids(textSignals('Your verification code is 482913. Do not share it with anyone.')).includes('credential_ask'));
  assert.ok(ids(textSignals('الرجاء ارسال رمز التحقق الذي وصلك')).includes('credential_ask'));
  assert.ok(!ids(textSignals('رمز التحقق الخاص بك 4821. لا تشاركه مع أحد')).includes('credential_ask'));
});

test('textSignals: Arabic delivery-fee and urgency', () => {
  const got = ids(textSignals('شحنتك معلقة، سدد رسوم التوصيل خلال 24 ساعة', { hasUrl: true }));
  assert.ok(got.includes('delivery_fee'));
  assert.ok(got.includes('urgency_threat'));
});

test('textSignals: family impersonation and untraceable payment', () => {
  assert.ok(ids(textSignals('Hi mum, I lost my phone, this is my new number. Can you send money urgently?')).includes('family_impersonation'));
  assert.ok(ids(textSignals('Buy two Google Play gift cards and send me the codes')).includes('untraceable_payment'));
});

test('buildResult: a classic phishing text is red and bilingual evidence is present', () => {
  const r = buildResult('Your PayPal account has been suspended. Verify now: http://paypal-secure.top/login', [
    { url: 'http://paypal-secure.top/login', ageDays: 3 },
  ]);
  assert.equal(r.verdict, 'red');
  assert.ok(r.signals.every((s) => s.en && s.ar));
});

test('buildResult: an ordinary chat is green', () => {
  const r = buildResult('See you at dinner at 8, I will bring the cake', []);
  assert.equal(r.verdict, 'green');
  assert.equal(r.score, 0);
});

test('buildResult: a legitimate parcel link on an old domain stays below red', () => {
  const r = buildResult('Your order has shipped. Track it here: https://www.amazon.com/gp/css/order', [
    { url: 'https://www.amazon.com/gp/css/order', ageDays: 11000 },
  ]);
  assert.notEqual(r.verdict, 'red');
});

test('buildResult de-duplicates repeated signals across links', () => {
  const r = buildResult('x', [
    { url: 'https://a.top/1', ageDays: 2 },
    { url: 'https://b.top/2', ageDays: 2 },
  ]);
  assert.equal(r.signals.filter((s) => s.id === 'domain_new').length, 1);
});

test('formatReply answers in the message language and caps evidence at four lines', () => {
  const r = buildResult('تم تعليق حسابك البنكي. اضغط http://bank-verify.top خلال 24 ساعة وأرسل رمز التحقق', [
    { url: 'http://bank-verify.top', ageDays: 1 },
  ]);
  const out = formatReply(r);
  assert.match(out, /^🔴/);
  assert.match(out, /السبب:/);
  assert.ok(out.split('\n').filter((l) => l.startsWith('• ')).length <= 4 + 3);
  assert.match(formatReply(r, 'en'), /Why:/);
});

test('snippet masks long digit runs and truncates', () => {
  assert.match(snippet('my card is 4111111111111111 ok'), /•{16}/);
  assert.ok(snippet('a'.repeat(500)).length <= 160);
});

test('familyAlert names the relative and never includes raw codes', () => {
  const r = buildResult('Send me the code 123456 and your password', []);
  const msg = familyAlert(r, 'Mum', 'Send me the code 123456 and your password', 'en');
  assert.match(msg, /Mum/);
  assert.doesNotMatch(msg, /123456/);
});

test('own-brand domains under normal TLDs are not look-alikes, but .top/.shop ones are', () => {
  assert.equal(brandLookalike('www.amazon.co.jp'), null);
  assert.equal(brandLookalike('paypal.de'), null);
  assert.ok(brandLookalike('paypal.top'));
  assert.ok(brandLookalike('amazon.shop'));
});

test('short brand names are not typosquat-matched by plain edit distance (apply.com is not apple)', () => {
  assert.equal(brandLookalike('apply.com'), null);
  assert.equal(brandLookalike('chose.com'), null);
});

test('brand_in_path fires only on low-reputation hosts', () => {
  assert.ok(ids(urlSignals({ url: 'https://sia0126.github.io/Netflix/' })).includes('brand_in_path'));
  assert.ok(ids(urlSignals({ url: 'https://flyn.top/www-roblox-login' })).includes('brand_in_path'));
  assert.ok(!ids(urlSignals({ url: 'https://en.wikipedia.org/wiki/Netflix' })).includes('brand_in_path'));
});

test('random_host catches machine-generated free-hosting names but not ordinary ones', () => {
  assert.ok(ids(urlSignals({ url: 'http://uuzce-s1g-gyur-43mm8-30-09-2026-aa.pages.dev/' })).includes('random_host'));
  assert.ok(ids(urlSignals({ url: 'http://sp28ct11-vemkaro-biz-lazruni.pages.dev/' })).includes('random_host'));
  assert.ok(!ids(urlSignals({ url: 'https://my-portfolio.pages.dev/' })).includes('random_host'));
  assert.ok(!ids(urlSignals({ url: 'https://www.wikipedia.org/' })).includes('random_host'));
});

test('brand-owned TLDs and extra official domains are not look-alikes', () => {
  assert.equal(brandLookalike('static.microsoft'), null);
  assert.equal(brandLookalike('apple-dns.net'), null);
  assert.ok(brandLookalike('apple-dns.top'));
});

test('numeric host tricks all normalise to the real address', () => {
  assert.equal(normalizeIPv4('2130706433'), '127.0.0.1');
  assert.equal(normalizeIPv4('0x7f000001'), '127.0.0.1');
  assert.equal(normalizeIPv4('0177.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIPv4('127.1'), '127.0.0.1');
  assert.equal(normalizeIPv4('169.254.169.254'), '169.254.169.254');
  assert.equal(normalizeIPv4('example.com'), null);
  assert.equal(normalizeIPv4('256.1.1.1'), null);
  assert.equal(normalizeIPv4('1.2.3.4.5'), null);
});

test('parseUrl: ports, userinfo, IPv6, fragments, bad input', () => {
  const p = parseUrl('https://user:pw@Example.COM:8443/a/b?x=1#frag');
  assert.equal(p.host, 'example.com');
  assert.equal(p.hasUserinfo, true);
  assert.equal(p.path, '/a/b?x=1');
  assert.equal(p.href, 'https://user:pw@example.com:8443/a/b?x=1');
  assert.equal(parseUrl('http://[::1]:8080/x').host, '::1');
  assert.equal(parseUrl('http://example.com:99999x/'), null);
  assert.equal(parseUrl('javascript://x'), null);
  assert.equal(parseUrl('http://'), null);
});

test('resolveRelative handles absolute, protocol-relative, root, query and dot-segment redirects', () => {
  const base = 'https://a.com/x/y/page?q=1';
  assert.equal(resolveRelative('https://b.com/z', base), 'https://b.com/z');
  assert.equal(resolveRelative('//c.com/p', base), 'https://c.com/p');
  assert.equal(resolveRelative('/root', base), 'https://a.com/root');
  assert.equal(resolveRelative('?n=2', base), 'https://a.com/x/y/page?n=2');
  assert.equal(resolveRelative('../up', base), 'https://a.com/x/up');
  assert.equal(resolveRelative('sibling', base), 'https://a.com/x/y/sibling');
  assert.equal(resolveRelative('javascript:alert(1)', base), null);
  assert.equal(resolveRelative('', base), null);
});
