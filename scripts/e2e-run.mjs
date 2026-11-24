// Orchestrates the end-to-end tests: boots a fresh n8n with the real workflow, runs
// scripts/e2e.test.mjs against it, and always shuts n8n down again.
//   node scripts/e2e-run.mjs [local|full|all]
import { spawn } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MODES = {
  local: { HADHAR_WEBHOOK_TOKEN: '', HADHAR_LLM_KEY: '', HADHAR_LLM_BASE: '' },
  full: { HADHAR_WEBHOOK_TOKEN: 'e2e-secret', HADHAR_LLM_KEY: 'test-key', HADHAR_LLM_BASE: 'http://127.0.0.1:8081' },
};
const want = process.argv[2] || 'all';
const modes = want === 'all' ? ['local', 'full'] : [want];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runMode(name) {
  const folder = join(ROOT, `.n8n-e2e-${name}`);
  rmSync(folder, { recursive: true, force: true });
  const env = {
    ...process.env, ...MODES[name],
    N8N_USER_FOLDER: folder, N8N_PORT: '5678',
    TELEGRAM_API_BASE: 'http://127.0.0.1:8081', TELEGRAM_BOT_TOKEN: 'testtoken',
  };
  console.log(`\n=== e2e: ${name} ===`);
  const n8n = spawn(join(ROOT, 'scripts/run-n8n.sh'), [], { env, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let log = '';
  n8n.stdout.on('data', (d) => (log += d));
  n8n.stderr.on('data', (d) => (log += d));
  const stop = () => { try { process.kill(-n8n.pid, 'SIGTERM'); } catch {} };
  try {
    let ready = false;
    for (let i = 0; i < 90 && !ready; i++) {
      await sleep(1000);
      try { const r = await fetch('http://127.0.0.1:5678/webhook/check', { method: 'POST', headers: { 'content-type': 'application/json', ...(env.HADHAR_WEBHOOK_TOKEN ? { 'x-hadhar-token': env.HADHAR_WEBHOOK_TOKEN } : {}) }, body: '{"text":"ping","chatId":"warmup"}' }); ready = r.status === 200; } catch {}
    }
    if (!ready) { console.error('n8n did not become ready:\n' + log.slice(-3000)); return 1; }
    const t = spawn(process.execPath, ['--test', join(ROOT, 'scripts/e2e.test.mjs')], { env, stdio: 'inherit' });
    return await new Promise((r) => t.on('exit', (c) => r(c ?? 1)));
  } finally {
    stop();
    await sleep(1500);
    rmSync(folder, { recursive: true, force: true });
  }
}

let code = 0;
for (const m of modes) code = (await runMode(m)) || code;
process.exit(code);
