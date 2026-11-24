// Route message: bot commands (/start, /family, /join, /leave) are handled here;
// everything else is passed on to be scanned.
const state = $getWorkflowStaticData('global');
if (!state.family) state.family = newState();

const NO_TEXT = {
  en: 'Send me the text of the suspicious message, or paste the link. (Screenshots are not supported yet.)',
  ar: 'أرسل لي نص الرسالة المشبوهة أو الصق الرابط. (لا ندعم الصور بعد.)',
};

const out = [];
for (const it of $input.all()) {
  const j = it.json;
  const channel = j.source === 'webhook' ? 'respond' : 'telegram';
  if (j.reject) {
    out.push({ json: { ...j, isCommand: true, messages: [{ deliver: 'respond', status: 401, body: { error: 'unauthorized' } }] } });
    continue;
  }
  const lang = String(j.langCode || '').startsWith('ar') || detectLang(j.text) === 'ar' ? 'ar' : 'en';
  if (!j.text || !j.text.trim()) {
    out.push({ json: { ...j, isCommand: true, messages: [{ deliver: channel, chat: j.chatId, text: NO_TEXT[lang], body: { type: 'help', reply: NO_TEXT[lang] } }] } });
    continue;
  }
  const cmd = handleCommand(j.text, { state: state.family, chatId: j.chatId, name: j.name, lang, now: Date.now() });
  if (!cmd.handled) {
    out.push({ json: { ...j, isCommand: false } });
    continue;
  }
  const messages = [{ deliver: channel, chat: j.chatId, text: cmd.reply, body: { type: 'command', reply: cmd.reply } }];
  for (const n of cmd.notify || []) messages.push({ deliver: 'telegram', chat: n.chat, text: n.text });
  out.push({ json: { ...j, isCommand: true, messages } });
}
return out;
