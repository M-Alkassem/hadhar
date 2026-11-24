// Normalise the test webhook into the same item shape the Telegram poller produces.
// If HADHAR_WEBHOOK_TOKEN is set, callers must send it in the x-hadhar-token header.
const secret = $env.HADHAR_WEBHOOK_TOKEN;
return $input.all().map((it) => {
  const body = it.json.body || {};
  const headers = it.json.headers || {};
  if (secret && headers['x-hadhar-token'] !== secret) {
    return { json: { source: 'webhook', reject: true, text: '', chatId: '', name: '' } };
  }
  return {
    json: {
      source: 'webhook',
      chatId: String(body.chatId || 'web'),
      name: String(body.name || ''),
      langCode: String(body.lang || ''),
      text: String(body.text || ''),
    },
  };
});
