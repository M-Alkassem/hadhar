// Hadhar network layer. All I/O goes through an injected `http` function so the
// logic is testable with a fake and runs unchanged inside n8n Code nodes.
//
//   http({ url, method, headers, timeout, followRedirects }) ->
//        Promise<{ status:number, headers:Record<string,string>, body?:any }>
//
// Needs from engine.js: parseUrl, isPrivateHost, registrableDomain,
// extractUrls, buildResult.

import { parseUrl, resolveRelative, isPrivateHost, registrableDomain, extractUrls, buildResult } from './engine.js'; // stripped when bundled into n8n

const MAX_URLS = 3;

// Follows redirects by hand so every hop can be checked against the SSRF guard
// before a single request is made to it.
export async function resolveChain(startUrl, http, opts = {}) {
  const maxHops = opts.maxHops ?? 5;
  const timeout = opts.timeout ?? 6000;
  const first = parseUrl(startUrl);
  if (!first) return { chain: [], error: 'invalid-url' };
  const chain = [first.href];
  let current = first.href;
  for (let hop = 0; hop <= maxHops; hop++) {
    const p = parseUrl(current);
    if (!p || isPrivateHost(p.host)) return { chain, blocked: true, error: 'private-host' };
    if (hop === maxHops) return { chain, error: 'too-many-redirects' };
    let res;
    try {
      res = await http({ url: current, method: 'HEAD', timeout, followRedirects: false });
      if ([400, 403, 405, 501].includes(res.status)) {
        res = await http({ url: current, method: 'GET', headers: { Range: 'bytes=0-0' }, timeout, followRedirects: false });
      }
    } catch {
      return { chain, error: 'fetch-failed' };
    }
    const loc = res.headers && (res.headers.location || res.headers.Location);
    if (res.status >= 300 && res.status < 400 && loc) {
      const next = resolveRelative(loc, current);
      if (!next) return { chain, error: 'bad-location' };
      if (chain.includes(next)) return { chain, error: 'redirect-loop' };
      chain.push(next);
      current = next;
      continue;
    }
    return { chain, status: res.status };
  }
  return { chain, error: 'too-many-redirects' };
}

// Domain age from RDAP (the free, structured successor to WHOIS).
// Returns whole days, or null when unknown (free hosting, IPs, no RDAP server).
export async function domainAgeDays(host, http, now = Date.now(), opts = {}) {
  const reg = registrableDomain(host);
  if (reg.ip || reg.freeHosting || isPrivateHost(host)) return null;
  try {
    const res = await http({ url: `https://rdap.org/domain/${reg.domain}`, method: 'GET', timeout: opts.timeout ?? 6000, followRedirects: true, headers: { Accept: 'application/rdap+json' } });
    if (res.status !== 200) return null;
    const body = typeof res.body === 'string' ? JSON.parse(res.body) : res.body;
    const ev = (body.events || []).find((e) => e.eventAction === 'registration');
    if (!ev || !ev.eventDate) return null;
    const t = Date.parse(ev.eventDate);
    if (Number.isNaN(t)) return null;
    return Math.max(0, (now - t) / 86400000);
  } catch {
    return null;
  }
}

// ---- blocklist (OpenPhish community feed: one URL per line) -----------------

export const BLOCKLIST_URL = 'https://openphish.com/feed.txt';

export async function refreshBlocklist(http, cache, now = Date.now(), ttlMs = 6 * 3600 * 1000) {
  if (cache && cache.fetchedAt && now - cache.fetchedAt < ttlMs && Array.isArray(cache.urls)) return cache;
  try {
    const res = await http({ url: BLOCKLIST_URL, method: 'GET', timeout: 10000, followRedirects: true });
    if (res.status !== 200) return cache || { fetchedAt: 0, urls: [] };
    const text = typeof res.body === 'string' ? res.body : String(res.body ?? '');
    const urls = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^https?:\/\//i.test(l)).slice(0, 20000);
    return { fetchedAt: now, urls };
  } catch {
    return cache || { fetchedAt: 0, urls: [] };
  }
}

function normForMatch(href) {
  const p = parseUrl(href);
  if (!p) return null;
  return p.host + p.path.split('?')[0].replace(/\/+$/, '');
}

export function buildBlocklistIndex(urls = []) {
  const exact = new Set();
  const hosts = new Set();
  for (const u of urls) {
    const p = parseUrl(u);
    if (!p) continue;
    exact.add(normForMatch(u));
    // a domain-level entry (no path) condemns the whole host
    if ((p.path === '/' || p.path === '') && !registrableDomain(p.host).freeHosting) hosts.add(p.host);
  }
  return { exact, hosts };
}

export function isBlocklisted(href, index) {
  if (!index) return false;
  const p = parseUrl(href);
  if (!p) return false;
  return index.exact.has(normForMatch(href)) || index.hosts.has(p.host);
}

// ---- orchestration ----------------------------------------------------------

export async function inspectUrl(url, deps) {
  const { http, blockIndex, now } = deps;
  const r = await resolveChain(url, http, deps.chainOpts);
  const info = { url, chain: r.chain, blocklisted: false, ageDays: null };
  if (r.error) info.error = r.error;
  if (!r.chain.length) return info;
  info.blocklisted = r.chain.some((h) => isBlocklisted(h, blockIndex));
  const finalHost = parseUrl(r.chain[r.chain.length - 1])?.host;
  if (finalHost && !r.blocked) info.ageDays = await domainAgeDays(finalHost, http, now ?? Date.now());
  return info;
}

export async function analyzeMessage(text, deps) {
  const urls = extractUrls(text).slice(0, MAX_URLS);
  const infos = await Promise.all(urls.map((u) => inspectUrl(u, deps)));
  const result = buildResult(text, infos);
  result.inspected = infos.map((i) => ({ url: i.url, hops: Math.max(0, i.chain.length - 1), ageDays: i.ageDays === null ? null : Math.floor(i.ageDays), blocklisted: i.blocklisted, error: i.error || null }));
  return result;
}
