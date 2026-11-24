// Renders docs/demo.svg from REAL engine output (offline run: no simulated domain ages).
//   node scripts/make-demo-svg.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyzeMessage } from '../src/net.js';
import { formatReply } from '../src/engine.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const offline = async () => { throw new Error('offline'); };
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function wrap(text, width) {
  const out = [];
  for (const para of text.split('\n')) {
    if (!para) { out.push(''); continue; }
    const lead = /^[•🤖]\s/u.test(para) ? '  ' : '';
    let line = '';
    for (const w of para.split(' ')) {
      if ((line + ' ' + w).trim().length > width) { out.push(line); line = lead + w; }
      else line = (line ? line + ' ' : '') + w;
    }
    out.push(line);
  }
  return out;
}

const CASES = [
  { lang: 'en', msg: 'Your PayPal account has been suspended. Verify within 24 hours: http://paypal-secure.top/login and send the code we text you' },
  { lang: 'ar', msg: 'شحنتك معلقة في الجمارك. سدد رسوم التوصيل 15 ريال خلال 24 ساعة: aramex-pay.click/track' },
];

const COL_W = 440, PAD = 28, LH = 21;
let cols = '';
let maxY = 0;
for (let i = 0; i < CASES.length; i++) {
  const c = CASES[i];
  const result = await analyzeMessage(c.msg, { http: offline, blockIndex: null });
  const reply = formatReply(result);
  const x0 = 24 + i * (COL_W + 24);
  const rtl = c.lang === 'ar';
  const width = rtl ? 40 : 46;
  const tx = rtl ? x0 + COL_W - PAD : x0 + PAD;
  const anchor = 'start'; // in direction=rtl, "start" is the right edge
  const dir = rtl ? ' direction="rtl" unicode-bidi="plaintext"' : '';
  let y = 118;
  let svg = `<text x="${x0 + PAD}" y="92" class="cap">${rtl ? 'ARABIC · العربية' : 'ENGLISH'}</text>`;
  const inLines = wrap(c.msg, width);
  const inH = inLines.length * LH + 22;
  svg += `<rect x="${x0}" y="${y - 8}" width="${COL_W}" height="${inH}" rx="14" class="in"/>`;
  y += 10;
  for (const l of inLines) { svg += `<text x="${tx}" y="${y + 6}" text-anchor="${anchor}"${dir} class="m">${esc(l)}</text>`; y += LH; }
  y += 22;
  const outLines = wrap(reply, width);
  const outH = outLines.length * LH + 22;
  svg += `<rect x="${x0}" y="${y - 8}" width="${COL_W}" height="${outH}" rx="14" class="out"/>`;
  y += 10;
  for (const l of outLines) { svg += `<text x="${tx}" y="${y + 6}" text-anchor="${anchor}"${dir} class="${l.startsWith('🔴') || l.startsWith('🟠') || l.startsWith('🟢') ? 'v' : 'm'}">${esc(l)}</text>`; y += LH; }
  maxY = Math.max(maxY, y + outH - outLines.length * LH);
  cols += svg;
}
const H = Math.max(maxY, 560) + 56;
const total = 24 * 3 + COL_W * 2;
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${H}" role="img" aria-label="Two example chats: a phishing text in English and a delivery-fee scam in Arabic, each answered with a verdict, evidence and what to do">
<style>
text{font-family:-apple-system,"Segoe UI",Helvetica,Arial,"Noto Sans Arabic","Geeza Pro",sans-serif;fill:#e2e8f0}
.h{font-size:13px;font-weight:700;letter-spacing:.06em;fill:#7dd3fc}
.t{font-size:20px;font-weight:700}
.cap{font-size:11px;font-weight:600;letter-spacing:.1em;fill:#64748b}
.m{font-size:14px}.v{font-size:15px;font-weight:700}
.in{fill:#1e293b}.out{fill:#0b3a2e;stroke:#134e4a;stroke-width:1}
</style>
<rect width="${total}" height="${H}" rx="16" fill="#0f172a"/>
<text x="24" y="38" class="h">HADHAR · حذار</text>
<text x="24" y="64" class="t">Forward it. Know in seconds.</text>
${cols}
<text x="24" y="${H - 18}" style="font-size:12px;fill:#64748b">Real output of the engine, offline run (no domain-age lookup). With network, young domains and blocklist hits push these higher.</text>
</svg>
`;
writeFileSync(join(ROOT, 'docs/demo.svg'), svg);
console.log(`wrote docs/demo.svg (${total}x${H})`);
