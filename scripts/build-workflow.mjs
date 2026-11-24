// Generates workflow/hadhar.workflow.json. The Code nodes embed the SAME source files that
// the unit tests cover (src/*.js), so what is tested is exactly what runs inside n8n.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');

function bundle(files) {
  return files
    .map((f) => {
      const body = read(f)
        .split('\n')
        .filter((l) => !/^import .* from .*;/.test(l.trim()))
        .map((l) => l.replace(/^export (async function|function|const|let)/, '$1'))
        .join('\n');
      return `// ---- ${f} (generated, edit the file in src/, not here) ----\n${body}`;
    })
    .join('\n');
}
const LIB = bundle(['src/engine.js', 'src/net.js', 'src/family.js', 'src/llm.js']);
const glue = (name) => read(`scripts/glue/${name}.js`);
const withLib = (name) => `${LIB}\n\n// ---- node logic ----\n${glue(name)}`;

function checkSyntax(label, code) {
  try {
    new vm.Script(`(async function () {\n${code}\n})`, { filename: label });
  } catch (e) {
    throw new Error(`Syntax error in ${label}: ${e.message}`);
  }
}

const code = (id, name, x, y, js, notes) => {
  checkSyntax(name, js);
  return { id, name, type: 'n8n-nodes-base.code', typeVersion: 2, position: [x, y], parameters: { mode: 'runOnceForAllItems', language: 'javaScript', jsCode: js }, ...(notes ? { notes } : {}) };
};
const ifNode = (id, name, x, y, leftValue, operator, rightValue = '') => ({
  id, name, type: 'n8n-nodes-base.if', typeVersion: 2.2, position: [x, y],
  parameters: { conditions: { options: { caseSensitive: true, leftValue: '', typeValidation: 'strict', version: 2 }, conditions: [{ id: `${id}-c`, leftValue, rightValue, operator }], combinator: 'and' }, options: {} },
});
const sticky = (id, x, y, w, h, color, content) => ({ id, name: `Note ${id}`, type: 'n8n-nodes-base.stickyNote', typeVersion: 1, position: [x, y], parameters: { content, width: w, height: h, color } });

export function buildWorkflow() {
  const nodes = [
    { id: 'poll-trigger', name: 'Every 3 seconds', type: 'n8n-nodes-base.scheduleTrigger', typeVersion: 1.2, position: [0, 0], parameters: { rule: { interval: [{ field: 'seconds', secondsInterval: 3 }] } } },
    code('poll', 'Poll Telegram', 220, 0, glue('poll'), 'Reads new chat messages. Idle until TELEGRAM_BOT_TOKEN is set.'),
    { id: 'webhook', name: 'Test webhook', type: 'n8n-nodes-base.webhook', typeVersion: 2, position: [0, 220], webhookId: 'hadhar-check', parameters: { httpMethod: 'POST', path: 'check', responseMode: 'responseNode', options: {} } },
    code('normalize', 'Normalize webhook', 220, 220, glue('normalize'), 'Optional shared secret: set HADHAR_WEBHOOK_TOKEN.'),
    code('route', 'Route message', 460, 110, withLib('route'), 'Handles /start /family /join /leave. Everything else is scanned.'),
    ifNode('is-command', 'Is command?', 700, 110, '={{ $json.isCommand }}', { type: 'boolean', operation: 'true', singleValue: true }),
    code('expand', 'Expand messages', 940, 20, glue('expand')),
    code('scan', 'Scan message', 940, 220, withLib('scan'), 'Safe redirect following, domain age, blocklist, scoring.'),
    ifNode('llm-on', 'Model opinion on?', 1180, 220, '={{ !!$env.HADHAR_LLM_KEY }}', { type: 'boolean', operation: 'true', singleValue: true }),
    {
      id: 'ask-claude', name: 'Ask Claude (optional)', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [1420, 140], onError: 'continueRegularOutput',
      parameters: {
        method: 'POST', url: "={{ ($env.HADHAR_LLM_BASE || 'https://api.anthropic.com') + '/v1/messages' }}",
        sendHeaders: true, headerParameters: { parameters: [{ name: 'x-api-key', value: '={{ $env.HADHAR_LLM_KEY }}' }, { name: 'anthropic-version', value: '2023-06-01' }] },
        sendBody: true, specifyBody: 'json', jsonBody: '={{ JSON.stringify($json.llmRequest) }}', options: { timeout: 8000 },
      },
    },
    code('build', 'Build replies', 1660, 220, withLib('build'), 'Merges the optional model opinion; alerts guardians on red.'),
    ifNode('respond-or-send', 'Reply to webhook?', 1900, 110, '={{ $json.deliver }}', { type: 'string', operation: 'equals' }, 'respond'),
    { id: 'respond', name: 'Respond to webhook', type: 'n8n-nodes-base.respondToWebhook', typeVersion: 1.1, position: [2140, 20], parameters: { respondWith: 'json', responseBody: '={{ $json.body || { reply: $json.text } }}', options: { responseCode: '={{ $json.status || 200 }}' } } },
    {
      id: 'send', name: 'Send Telegram message', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [2140, 220], onError: 'continueRegularOutput',
      parameters: {
        method: 'POST', url: "={{ ($env.TELEGRAM_API_BASE || 'https://api.telegram.org') + '/bot' + $env.TELEGRAM_BOT_TOKEN + '/sendMessage' }}",
        sendBody: true, specifyBody: 'json', jsonBody: '={{ JSON.stringify({ chat_id: $json.chat, text: $json.text }) }}', options: { timeout: 10000 },
      },
    },
    sticky('s1', -40, -120, 520, 90, 5, '## Hadhar (حذار)\nForward any suspicious message or link. The workflow follows links safely, checks domain age and a phishing blocklist, scores every signal, and answers in the sender\'s language. Family mode alerts a trusted person on red verdicts.'),
    sticky('s2', 930, 360, 520, 130, 3, '## Safety notes\nThe bot fetches links that strangers send it, so every hop is checked against a private-address guard (no localhost, LAN or cloud-metadata targets) before any request is made. Executions are not saved: messages stay private.'),
  ];

  const wire = (from, ...to) => ({ main: [to.map((t) => ({ node: t, type: 'main', index: 0 }))] });
  const connections = {
    'Every 3 seconds': wire('', 'Poll Telegram'),
    'Poll Telegram': wire('', 'Route message'),
    'Test webhook': wire('', 'Normalize webhook'),
    'Normalize webhook': wire('', 'Route message'),
    'Route message': wire('', 'Is command?'),
    'Is command?': { main: [[{ node: 'Expand messages', type: 'main', index: 0 }], [{ node: 'Scan message', type: 'main', index: 0 }]] },
    'Expand messages': wire('', 'Reply to webhook?'),
    'Scan message': wire('', 'Model opinion on?'),
    'Model opinion on?': { main: [[{ node: 'Ask Claude (optional)', type: 'main', index: 0 }], [{ node: 'Build replies', type: 'main', index: 0 }]] },
    'Ask Claude (optional)': wire('', 'Build replies'),
    'Build replies': wire('', 'Reply to webhook?'),
    'Reply to webhook?': { main: [[{ node: 'Respond to webhook', type: 'main', index: 0 }], [{ node: 'Send Telegram message', type: 'main', index: 0 }]] },
  };

  const workflow = {
    id: 'HadharScamCheck1',
    name: 'Hadhar - is this a scam?',
    nodes,
    connections,
    settings: { executionOrder: 'v1', saveDataSuccessExecution: 'none', saveDataErrorExecution: 'none', saveManualExecutions: false, executionTimeout: 90 },
    active: false,
    pinData: {},
  };

  return workflow;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const workflow = buildWorkflow();
  writeFileSync(join(ROOT, 'workflow/hadhar.workflow.json'), JSON.stringify(workflow, null, 2) + '\n');
  console.log(`wrote workflow/hadhar.workflow.json (${workflow.nodes.length} nodes, ${(JSON.stringify(workflow).length / 1024).toFixed(0)} KB)`);
}
