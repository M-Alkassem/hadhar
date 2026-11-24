// Family mode: a guardian creates a one-time code, a relative joins with it,
// and risky verdicts for that relative are also sent to the guardian.
// State is a plain JSON object (n8n keeps it in workflow static data).

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
const INVITE_TTL_MS = 24 * 3600 * 1000;
const MAX_GUARDIANS = 3;

export function newState() {
  return { v: 1, invites: {}, links: {} };
}

function pruneInvites(state, now) {
  for (const [code, inv] of Object.entries(state.invites)) {
    if (now - inv.createdAt > INVITE_TTL_MS) delete state.invites[code];
  }
}

export function createInvite(state, guardianChat, now = Date.now(), rand = Math.random) {
  pruneInvites(state, now);
  // one live invite per guardian
  for (const [code, inv] of Object.entries(state.invites)) if (inv.guardianChat === String(guardianChat)) delete state.invites[code];
  let code;
  do {
    code = Array.from({ length: 6 }, () => CODE_ALPHABET[Math.floor(rand() * CODE_ALPHABET.length)]).join('');
  } while (state.invites[code]);
  state.invites[code] = { guardianChat: String(guardianChat), createdAt: now };
  return code;
}

export function joinWithCode(state, rawCode, chatId, name, now = Date.now()) {
  pruneInvites(state, now);
  const code = String(rawCode || '').trim().toUpperCase();
  const inv = state.invites[code];
  if (!inv) return { ok: false, reason: 'invalid' };
  if (inv.guardianChat === String(chatId)) return { ok: false, reason: 'self' };
  const link = state.links[chatId] || { name: name || '', guardians: [] };
  if (name) link.name = name;
  if (!link.guardians.includes(inv.guardianChat)) {
    if (link.guardians.length >= MAX_GUARDIANS) return { ok: false, reason: 'full' };
    link.guardians.push(inv.guardianChat);
  }
  state.links[chatId] = link;
  delete state.invites[code]; // single use
  return { ok: true, guardianChat: inv.guardianChat };
}

export function guardiansOf(state, chatId) {
  const l = state.links[chatId];
  return l ? { name: l.name, guardians: l.guardians.slice() } : { name: '', guardians: [] };
}

export function leave(state, chatId) {
  const had = Boolean(state.links[chatId]);
  delete state.links[chatId];
  return had;
}

const MSG = {
  en: {
    welcome: 'Hi! I check messages for scams.\n\nJust forward or paste anything suspicious: a text, a link, a WhatsApp message. I will tell you in seconds if it looks like a scam and what to do.\n\nFamily mode: /family lets someone you trust get an alert when a relative receives a scam.',
    invite: (c) => `Your invite code is ${c}.\nAsk your relative to open this bot and send:\n/join ${c} Name\n\nThe code works once and expires in 24 hours. After that, you get an alert whenever a very risky message reaches them.`,
    joined: 'Done. If something very risky reaches you, someone you trust will be told too. Send /leave to stop this at any time.',
    joinedGuardian: (n) => `${n || 'A relative'} joined your family list. You will get an alert when a risky message reaches them.`,
    invalid: 'That code is not valid or has expired. Ask for a new one with /family.',
    self: 'You cannot join your own code. Send it to the person you want to protect.',
    full: 'This chat already has the maximum of 3 people watching.',
    left: 'Done. Nobody will be alerted about your messages any more.',
    notLinked: 'You were not in family mode.',
    usage: 'Send: /join CODE Name',
  },
  ar: {
    welcome: 'أهلاً! أنا أفحص الرسائل بحثاً عن الاحتيال.\n\nأرسل لي أي شيء مشبوه: رسالة أو رابطاً أو محادثة واتساب، وسأخبرك خلال ثوانٍ إن كان احتيالاً وماذا تفعل.\n\nوضع العائلة: الأمر /family يتيح لشخص تثق به أن يصله تنبيه عندما تصل رسالة احتيال لأحد أقاربك.',
    invite: (c) => `رمز الدعوة: ${c}\nاطلب من قريبك أن يفتح هذا البوت ويرسل:\n/join ${c} الاسم\n\nالرمز يعمل مرة واحدة وينتهي خلال 24 ساعة. بعدها يصلك تنبيه كلما وصلته رسالة شديدة الخطورة.`,
    joined: 'تم. إذا وصلتك رسالة شديدة الخطورة فسيُبلَّغ بها شخص تثق به. أرسل /leave لإيقاف ذلك في أي وقت.',
    joinedGuardian: (n) => `${n || 'أحد الأقارب'} انضم إلى قائمتك. سيصلك تنبيه عند وصول رسالة خطيرة إليه.`,
    invalid: 'الرمز غير صالح أو انتهت صلاحيته. اطلب رمزاً جديداً بالأمر /family.',
    self: 'لا يمكنك استخدام رمزك بنفسك. أرسله للشخص الذي تريد حمايته.',
    full: 'هذه المحادثة وصلت للحد الأقصى: 3 أشخاص يراقبونها.',
    left: 'تم. لن يُبلَّغ أحد برسائلك بعد الآن.',
    notLinked: 'لم تكن في وضع العائلة.',
    usage: 'أرسل: /join الرمز الاسم',
  },
};

// Returns { handled, reply, notify?:[{chat,text}] }. Mutates ctx.state.
export function handleCommand(text, ctx) {
  const { state, chatId, name = '', lang = 'en', now = Date.now(), rand = Math.random } = ctx;
  const M = MSG[lang] || MSG.en;
  const m = String(text || '').trim().match(/^\/(\w+)(?:@\w+)?(?:\s+([\s\S]*))?$/);
  if (!m) return { handled: false };
  const cmd = m[1].toLowerCase();
  const arg = (m[2] || '').trim();
  if (cmd === 'start' || cmd === 'help') return { handled: true, reply: M.welcome };
  if (cmd === 'family') return { handled: true, reply: M.invite(createInvite(state, chatId, now, rand)) };
  if (cmd === 'join') {
    const [code, ...rest] = arg.split(/\s+/);
    if (!code) return { handled: true, reply: M.usage };
    const who = rest.join(' ') || name;
    const r = joinWithCode(state, code, chatId, who, now);
    if (!r.ok) return { handled: true, reply: M[r.reason] };
    return { handled: true, reply: M.joined, notify: [{ chat: r.guardianChat, text: MSG.en.joinedGuardian(who) }] };
  }
  if (cmd === 'leave') return { handled: true, reply: leave(state, chatId) ? M.left : M.notLinked };
  return { handled: true, reply: M.welcome };
}
