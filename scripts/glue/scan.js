// Scan message: follow links safely, look up domain age and the phishing blocklist,
// then score everything. All network I/O goes through this one adapter.
const state = $getWorkflowStaticData('global');

const http = async (o) => {
  const r = await this.helpers.httpRequest({
    url: o.url,
    method: o.method || 'GET',
    headers: o.headers || {},
    timeout: o.timeout || 6000,
    returnFullResponse: true,
    ignoreHttpStatusCode: true,
    disableFollowRedirect: !o.followRedirects,
  });
  const headers = {};
  for (const [k, v] of Object.entries(r.headers || {})) headers[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
  return { status: r.statusCode, headers, body: r.body };
};

state.blocklist = await refreshBlocklist(http, state.blocklist, Date.now());
const blockIndex = buildBlocklistIndex(state.blocklist.urls);

const out = [];
for (const it of $input.all()) {
  const result = await analyzeMessage(it.json.text, { http, blockIndex, now: Date.now() });
  out.push({
    json: {
      ...it.json,
      result,
      llmRequest: buildLlmRequest(it.json.text, result, { model: $env.HADHAR_LLM_MODEL || undefined }),
    },
  });
}
return out;
