# Evaluation

Run `eval/fetch-data.sh` once, then `npm run eval -- --sets hand,sms,urls --split test`.

| Set | What it is | Independent? | Network |
|---|---|---|---|
| `hand` | 128 hand-written EN/AR messages (64 scams, 64 normal, many hard negatives such as real OTP and delivery notices) | **No.** Written by the author who also wrote the rules. A regression suite, not evidence. | offline |
| `sms` | UCI SMS Spam Collection, 300 spam + 300 ham sampled with a fixed seed | Yes. Mostly UK premium-rate *spam*, which overlaps with but is not the same as phishing | offline |
| `urls` | 150 live phishing URLs from the OpenPhish feed vs 150 benign domains from Tranco (75 top-1k, 75 ranked 50k-100k) | Yes | real RDAP lookups |

**Method.** Every item is assigned to `dev` or `test` by a hash of its id. Rules and weights were tuned by looking at `dev` misses only; the `test` half was run once at the end. Numbers in the README come from `--split test`.

**What is deliberately left out.** For the URL set the phishing-blocklist lookup is disabled: the same feed is the ground truth, so it would score 100% by construction. The numbers show what the heuristics alone catch. In production the blocklist is an extra layer on top.

**Metrics.** *Caught (amber+red)* = scam that was not given a green verdict. *Caught (red)* = scam given the strongest verdict. *False alarm (red)* = normal item wrongly called red; *any alarm* = wrongly amber or red.
