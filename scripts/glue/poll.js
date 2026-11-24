// Poll Telegram (long-polling replacement that needs no public URL).
// Keeps the update offset in workflow static data so no message is handled twice.
const base = $env.TELEGRAM_API_BASE || 'https://api.telegram.org';
const token = $env.TELEGRAM_BOT_TOKEN;
if (!token) return []; // polling stays idle until a bot token is configured

const state = $getWorkflowStaticData('global');
let res;
try {
  res = await this.helpers.httpRequest({
    url: `${base}/bot${token}/getUpdates`,
    method: 'GET',
    qs: { offset: state.tgOffset || 0, timeout: 0, allowed_updates: JSON.stringify(['message']) },
    json: true,
    timeout: 10000,
  });
} catch (e) {
  return []; // network blip: try again on the next tick
}

const out = [];
for (const u of res.result || []) {
  state.tgOffset = u.update_id + 1;
  const m = u.message;
  if (!m || !m.chat) continue;
  const text = m.text || m.caption || '';
  out.push({
    json: {
      source: 'telegram',
      chatId: String(m.chat.id),
      name: (m.from && m.from.first_name) || '',
      langCode: (m.from && m.from.language_code) || '',
      text,
      unsupported: !text,
    },
  });
}
return out;
