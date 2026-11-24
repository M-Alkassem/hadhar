// Build replies: merge the optional model opinion, write the answer in the
// message's language, and alert family guardians when a relative gets a red verdict.
const scans = $('Scan message').all();
const state = $getWorkflowStaticData('global');
if (!state.family) state.family = newState();

const out = [];
$input.all().forEach((it, i) => {
  const scan = scans[i].json;
  const llm = it.json && it.json.content ? parseLlmReply(it.json) : null; // absent when the model step is off or failed
  const result = applyLlm(scan.result, llm);
  const reply = formatReply(result);
  const channel = scan.source === 'webhook' ? 'respond' : 'telegram';
  out.push({
    json: {
      deliver: channel,
      chat: scan.chatId,
      text: reply,
      body: {
        verdict: result.verdict,
        score: result.score,
        lang: result.lang,
        signals: result.signals.map((s) => ({ id: s.id, weight: s.weight, en: s.en, ar: s.ar })),
        inspected: result.inspected,
        llm: result.llm,
        reply,
      },
    },
  });
  if (result.verdict === 'red') {
    const fam = guardiansOf(state.family, scan.chatId);
    for (const g of fam.guardians) {
      out.push({ json: { deliver: 'telegram', chat: g, text: familyAlert(result, fam.name || scan.name, scan.text, result.lang) } });
    }
  }
});
return out;
