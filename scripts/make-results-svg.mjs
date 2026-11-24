// Renders docs/results.svg from eval/results/test-after-fixes.json (held-out test half).
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const d = JSON.parse(readFileSync(join(ROOT, 'eval/results/test-after-fixes.json'), 'utf8')).sets;
const rows = [
  ['Real phishing URLs', 'OpenPhish vs Tranco domains', d.urls.groups.all],
  ['SMS spam', 'UCI collection, 150 + 150', d.sms.groups.all],
  ['Hand-written EN + AR', 'author-written, not independent', d.hand.groups.all],
];
const pct = (a, b) => (100 * a) / b;
const W = 960, X0 = 300, BW = 400, RH = 96;
let body = '';
rows.forEach(([name, sub, g], i) => {
  const y = 118 + i * RH;
  const caught = pct(g.scamFlagged, g.scam), red = pct(g.scamRed, g.scam);
  const fa = g.benignFlagged;
  body += `<text x="32" y="${y + 14}" class="t">${name}</text><text x="32" y="${y + 34}" class="s">${sub}</text>`;
  body += `<rect x="${X0}" y="${y}" width="${BW}" height="22" rx="6" class="track"/><rect x="${X0}" y="${y}" width="${(BW * caught) / 100}" height="22" rx="6" class="amber"/>`;
  body += `<text x="${X0 + BW + 12}" y="${y + 16}" class="v">${caught.toFixed(1)}%</text>`;
  body += `<rect x="${X0}" y="${y + 30}" width="${BW}" height="22" rx="6" class="track"/><rect x="${X0}" y="${y + 30}" width="${(BW * red) / 100}" height="22" rx="6" class="red"/>`;
  body += `<text x="${X0 + BW + 12}" y="${y + 46}" class="v">${red.toFixed(1)}%</text>`;
  body += `<text x="${X0 + BW + 76}" y="${y + 16}" class="s">false alarms:</text><text x="${X0 + BW + 76}" y="${y + 36}" class="ok">${fa} of ${g.benign}</text>`;
});
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} 440" role="img" aria-label="Held-out results: share of scams caught, caught as red, and false alarms on normal items for three test sets">
<style>
text{font-family:-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:#e2e8f0}
.h{font-size:13px;font-weight:700;letter-spacing:.06em;fill:#7dd3fc}.big{font-size:20px;font-weight:700}
.t{font-size:15px;font-weight:600}.s{font-size:12px;fill:#94a3b8}.v{font-size:14px;font-weight:700}.ok{font-size:15px;font-weight:700;fill:#4ade80}
.track{fill:#1e293b}.amber{fill:#f59e0b}.red{fill:#ef4444}
</style>
<rect width="${W}" height="440" rx="16" fill="#0f172a"/>
<text x="32" y="40" class="h">HELD-OUT TEST HALF</text>
<text x="32" y="66" class="big">How many scams does it catch?</text>
<rect x="${X0}" y="82" width="12" height="12" rx="3" class="amber"/><text x="${X0 + 18}" y="93" class="s">caught (amber or red)</text>
<rect x="${X0 + 170}" y="82" width="12" height="12" rx="3" class="red"/><text x="${X0 + 188}" y="93" class="s">caught as red (strongest verdict)</text>
${body}
<text x="32" y="418" class="s">Heuristics only: the live phishing blocklist is excluded so the feed can't grade itself. Samples are small (75 to 150 per class), roughly ±7 to ±10 points.</text>
</svg>
`;
writeFileSync(join(ROOT, 'docs/results.svg'), svg);
console.log('wrote docs/results.svg');
