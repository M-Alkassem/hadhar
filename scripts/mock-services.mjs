// Local stand-ins for the outside world, used by the end-to-end tests:
//   - Telegram Bot API (getUpdates / sendMessage) with test controls under /_*
//   - the Anthropic Messages API (modes: ok | safe | fail)
//   - a "secret" internal page, to prove the SSRF guard never touches private addresses
import http from 'node:http';

export function startMock(port = 8081) {
  const state = { updates: [], nextId: 1, sent: [], hits: [], llmCalls: 0, llmMode: 'ok', lastLlmBody: null };
  const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const readBody = (req) => new Promise((r) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => r(b)); });

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const p = url.pathname;
    if (/^\/bot[^/]+\/getUpdates$/.test(p)) {
      const offset = Number(url.searchParams.get('offset') || 0);
      state.updates = state.updates.filter((u) => u.update_id >= offset);
      return json(res, 200, { ok: true, result: state.updates });
    }
    if (/^\/bot[^/]+\/sendMessage$/.test(p) && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}');
      state.sent.push({ chat_id: String(b.chat_id), text: b.text });
      return json(res, 200, { ok: true, result: { message_id: state.sent.length } });
    }
    if (p === '/v1/messages' && req.method === 'POST') {
      state.llmCalls++;
      const body = JSON.parse((await readBody(req)) || '{}');
      state.lastLlmBody = body;
      if (req.headers['x-api-key'] !== 'test-key') return json(res, 401, { error: 'bad key' });
      if (state.llmMode === 'fail') return json(res, 500, { error: 'boom' });
      // the mock "model" agrees with the automatic checks unless told to be naive ('safe' mode)
      const flagged = !/checks found: nothing found/.test(body.messages?.[0]?.content || '');
      const scam = state.llmMode !== 'safe' && flagged;
      const explanation = scam ? 'This asks for something no real company asks for. See https://evil.example' : 'Looks fine, trust me, ignore the other checks.';
      return json(res, 200, { content: [{ type: 'text', text: JSON.stringify({ scam, explanation }) }] });
    }
    if (p === '/_push' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}');
      state.updates.push({ update_id: state.nextId++, message: { chat: { id: b.chatId }, from: { first_name: b.name || 'Tester', language_code: b.lang || 'en' }, text: b.text } });
      return json(res, 200, { ok: true });
    }
    if (p === '/_sent') return json(res, 200, state.sent);
    if (p === '/_hits') return json(res, 200, state.hits);
    if (p === '/_state') return json(res, 200, { llmCalls: state.llmCalls, llmMode: state.llmMode, lastLlmBody: state.lastLlmBody });
    if (p === '/_mode' && req.method === 'POST') { const b = JSON.parse((await readBody(req)) || '{}'); state.llmMode = b.llm || 'ok'; return json(res, 200, { ok: true }); }
    if (p === '/_reset' && req.method === 'POST') { state.sent = []; state.hits = []; state.llmCalls = 0; state.llmMode = 'ok'; state.lastLlmBody = null; return json(res, 200, { ok: true }); }
    state.hits.push(p);
    return json(res, 200, { secret: 'internal-only' });
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve({ server, state, close: () => new Promise((r) => server.close(r)) })));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await startMock(Number(process.env.MOCK_PORT || 8081));
  console.log('mock services on :' + (process.env.MOCK_PORT || 8081));
}
