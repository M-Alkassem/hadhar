import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newState, createInvite, joinWithCode, guardiansOf, leave, handleCommand } from '../src/family.js';

const seq = (n = 0) => () => ((n = (n + 0.137) % 1), n);

test('invite codes are 6 chars, avoid look-alike characters, and are unique', () => {
  const s = newState();
  const a = createInvite(s, 1, 0, seq());
  const b = createInvite(s, 2, 0, seq(0.5));
  assert.match(a, /^[A-HJ-NP-Z2-9]{6}$/);
  assert.notEqual(a, b);
});

test('a guardian has one live invite at a time', () => {
  const s = newState();
  const a = createInvite(s, 1, 0, seq());
  const b = createInvite(s, 1, 10, seq(0.3));
  assert.equal(joinWithCode(s, a, 9, 'Mum', 20).ok, false);
  assert.equal(joinWithCode(s, b, 9, 'Mum', 20).ok, true);
});

test('join links the relative, is single use and case-insensitive', () => {
  const s = newState();
  const code = createInvite(s, 100, 0);
  const r = joinWithCode(s, code.toLowerCase(), 200, 'Mum', 1000);
  assert.deepEqual(r, { ok: true, guardianChat: '100' });
  assert.deepEqual(guardiansOf(s, 200), { name: 'Mum', guardians: ['100'] });
  assert.equal(joinWithCode(s, code, 300, 'Dad', 2000).reason, 'invalid');
});

test('invites expire after 24 hours', () => {
  const s = newState();
  const code = createInvite(s, 100, 0);
  assert.equal(joinWithCode(s, code, 200, 'Mum', 25 * 3600 * 1000).reason, 'invalid');
});

test('you cannot join your own code, and at most 3 guardians', () => {
  const s = newState();
  const c = createInvite(s, 1, 0);
  assert.equal(joinWithCode(s, c, 1, 'x', 1).reason, 'self');
  for (const g of [11, 12, 13]) joinWithCode(s, createInvite(s, g, 0), 200, 'Mum', 1);
  assert.equal(guardiansOf(s, 200).guardians.length, 3);
  assert.equal(joinWithCode(s, createInvite(s, 14, 0), 200, 'Mum', 1).reason, 'full');
});

test('leave removes the link', () => {
  const s = newState();
  joinWithCode(s, createInvite(s, 1, 0), 2, 'Mum', 1);
  assert.equal(leave(s, 2), true);
  assert.equal(leave(s, 2), false);
  assert.deepEqual(guardiansOf(s, 2).guardians, []);
});

test('handleCommand: full flow, bilingual replies, guardian notified', () => {
  const state = newState();
  const inv = handleCommand('/family', { state, chatId: 1, lang: 'en', now: 0 });
  const code = inv.reply.match(/\/join ([A-Z0-9]{6})/)[1];
  const j = handleCommand(`/join ${code} أمي`, { state, chatId: 2, lang: 'ar', now: 5 });
  assert.match(j.reply, /تم/);
  assert.equal(j.notify[0].chat, '1');
  assert.match(j.notify[0].text, /أمي/);
  assert.equal(handleCommand('hello there', { state, chatId: 2 }).handled, false);
  assert.match(handleCommand('/join', { state, chatId: 2 }).reply, /CODE/);
  assert.match(handleCommand('/start@HadharBot', { state, chatId: 2 }).reply, /scams/);
  assert.match(handleCommand('/leave', { state, chatId: 2 }).reply, /Nobody/);
});
