// Node adapter for the `http` contract used by net.js (used by the CLI, the
// evaluation harness and tests that hit the real network). Not used inside n8n.

export async function nodeHttp({ url, method = 'GET', headers = {}, timeout = 6000, followRedirects = false }) {
  const res = await fetch(url, {
    method,
    headers: { 'User-Agent': 'Hadhar/0.1 (+https://github.com/M-Alkassem/hadhar)', ...headers },
    redirect: followRedirects ? 'follow' : 'manual',
    signal: AbortSignal.timeout(timeout),
  });
  const hdrs = {};
  res.headers.forEach((v, k) => (hdrs[k.toLowerCase()] = v));
  let body;
  if (method !== 'HEAD' && res.status < 300) body = await res.text();
  else await res.body?.cancel?.().catch(() => {});
  return { status: res.status, headers: hdrs, body };
}
