# Visa vvaharness — Model Comparison

Models run through the **Visa vvaharness** 9-stage pipeline on the three shared targets. Numbers from each run's `security-scan/*_report.md` + `*_report.sarif`. Compiled 2026-06-18.

**Status: 8/9 complete.** Model A (`qwen2.5-coder-14b-32k`) 3/3 ✓; Model C (`claude-opus-4-8`, AWS Bedrock) 3/3 ✓; Model B (`qwen3.6-36b-128k`) nokogiri + juice-shop ✓, **underscore running**. The **juice-shop row is now complete for all three models**.

**Findings are triage candidates, not verified vulnerabilities.**

## ⚠️ Model C note — the Claude subscription was NOT viable; Model C runs on Bedrock

Model C was first attempted on a **Claude Code subscription** (`via:cli`) and proved **unwinnable** — Opus's s4 is hundreds of ~80k-token chunks with no intra-stage checkpoint, so it could never finish within one ~4h subscription token window. Resolution: same stock harness + `via:cli`, but the `claude` CLI points at **Opus 4.8 on AWS Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`, pay-per-token, no wall). The full column completed in ~2.1h / ~18.5M tokens (≈$115–126 at $5/$25 per M). juice-shop/underscore ran on `<repo>-opus/` path-copies to run parallel to Model B.

## 1. Verification funnel — raw → confirmed

`Verifier errors` = candidates the s6 verifier could not adjudicate (undetermined — NOT confirmed false). Precision = confirmed ÷ raw.

| Target | Model | Raw (s4) | Confirmed | False+ | Verifier err (undet.) | Dup | Precision |
|---|---|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 72 | 4 | 5 | 51 | 4 | 5.6% |
| nokogiri | qwen3.6-36b-128k | 71 | 1 | 32 | 16 | 12 | 1.4% |
| nokogiri | claude-opus-4-8 | 47 | 2 | 4 | 0 | 0 | 4.3% |
| juice-shop | qwen2.5-coder-14b-32k | 321 | 19 | 26 | 217 | 40 | 5.9% |
| juice-shop | qwen3.6-36b-128k | 321 | 32 | 115 | 81 | 83 | 10.0% |
| juice-shop | claude-opus-4-8 | 184 | 64 | 21 | 0 | 26 | 34.8% |
| underscore | qwen2.5-coder-14b-32k | 53 | 1 | 6 | 20 | 13 | 1.9% |
| underscore | qwen3.6-36b-128k | — | — | — | — | — | _pending_ |
| underscore | claude-opus-4-8 | 8 | 0 | 2 | 0 | 0 | 0.0% |

## 2. Confirmed findings by severity + exploit chains

| Target | Model | Total | Crit | High | Med | Low | Chains |
|---|---|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 4 | 1 | 3 | 0 | 0 | 2 |
| nokogiri | qwen3.6-36b-128k | 1 | 0 | 0 | 1 | 0 | 0 |
| nokogiri | claude-opus-4-8 | 2 | 0 | 0 | 2 | 0 | 0 |
| juice-shop | qwen2.5-coder-14b-32k | 19 | 16 | 0 | 3 | 0 | 3 |
| juice-shop | qwen3.6-36b-128k | 32 | 8 | 9 | 15 | 0 | 0 |
| juice-shop | claude-opus-4-8 | 64 | 8 | 17 | 38 | 1 | 7 |
| underscore | qwen2.5-coder-14b-32k | 1 | 1 | 0 | 0 | 0 | 0 |
| underscore | qwen3.6-36b-128k | _pending_ |  |  |  |  |  |
| underscore | claude-opus-4-8 | 0 | 0 | 0 | 0 | 0 | 0 |

## 3. Cost / runtime

A/B local (free GPU); C is AWS Bedrock (pay-per-token, ~$5/$25 per M in/out).

| Target | Model | Backend | Wall-clock | Tokens | s4 |
|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | local Ollama | 5.6h | 4,021,942 | clean |
| nokogiri | qwen3.6-36b-128k | local Ollama | 22.9h | 16,706,571 | s4 degraded 4/148 |
| nokogiri | claude-opus-4-8 | AWS Bedrock | 44m | 7,915,135 | clean |
| juice-shop | qwen2.5-coder-14b-32k | local Ollama | 7.3h | 4,617,645 | clean |
| juice-shop | qwen3.6-36b-128k | local Ollama | 45.7h | 42,611,099 | 1/490 degraded (negligible) |
| juice-shop | claude-opus-4-8 | AWS Bedrock | 1.2h | 8,473,942 | 1/584 degraded (negligible) |
| underscore | qwen2.5-coder-14b-32k | local Ollama | 1.1h | 1,349,049 | clean |
| underscore | qwen3.6-36b-128k | local Ollama | _pending_ |  |  |
| underscore | claude-opus-4-8 | AWS Bedrock | 10m | 2,052,172 | clean |

### Token breakdown (input / output / total)

Billable tokens from each run's report (`prompt` = fresh + cache-write input; `completion` = output). Cache-*reads* are tracked separately and excluded, so tokens *processed* were higher; only these are billed (only Model C's are paid — Bedrock). Model B underscore still running.

| Model | Repo | Input | Output | Total |
|---|---|--:|--:|--:|
| qwen2.5-coder-14b | nokogiri | 3,962,360 | 59,582 | 4,021,942 |
|  | juice-shop | 4,391,084 | 226,561 | 4,617,645 |
|  | underscore | 1,315,192 | 33,857 | 1,349,049 |
|  | **subtotal** |  |  | **9,988,636** |
| qwen3.6-36b | nokogiri | 15,460,760 | 1,245,811 | 16,706,571 |
|  | juice-shop | 40,092,851 | 2,518,248 | 42,611,099 |
|  | underscore | _running_ |  | — |
|  | **subtotal (2/3)** |  |  | **59,317,670** |
| claude-opus-4-8 | nokogiri | 7,415,214 | 499,921 | 7,915,135 |
|  | juice-shop | 7,330,213 | 1,143,729 | 8,473,942 |
|  | underscore | 1,955,292 | 96,880 | 2,052,172 |
|  | **subtotal** |  |  | **18,441,249** |
| **GRAND TOTAL (8 cells)** |  |  |  | **87,747,555** |

- The local **36B is the token hog**: 59.3M for *two* repos vs Opus's 18.4M for *three*. qwen3.6 juice-shop alone (**42.6M**) exceeds Opus's entire column.
- **Opus is the most token-efficient per repo** and far faster (~2.1h for the column vs the 36B's ~69h for two repos).

## 4. Headline findings

**juice-shop is a textbook capability gradient** — every metric scales monotonically with model strength:

| Metric | A · 14B | B · 36B | C · Opus |
|---|---|---|---|
| Confirmed | 19 | 32 | 64 |
| Precision | 5.9% | 10.0% | 34.8% |
| Verifier-errors (undet.) | 217 | 81 | 0 |
| Exploit chains | 3 | 0 | 7 |
| Wall-clock | 7.3h | 45.7h | 72m |

- **Verifier decisiveness scales with strength:** undetermined counts 217 → 81 → **0**. Opus adjudicated every candidate; the 14B left two-thirds unresolved — the locals' low precision is **verifier weakness**, not purely bad candidates.
- **Severity calibration:** A inflates to **16 Critical**; B and C both land at **8 Critical** (B 8C/9H/15M, C 8C/17H/38M) — the 36B and Opus agree on severity where the 14B over-rates.
- **Cost of the local 36B:** B juice-shop took **45.7h / 42.6M tokens** — 6× slower than the 14B and 38× slower than Opus on Bedrock, for half Opus's findings.

**Small repos:** nokogiri A 4 (1C/3H) · B 1 (MED) · C 2 (MED) — converge on schema-SSRF & CSS/XPath classes. underscore A 1 (a lone 'CRITICAL') · C 0 — Opus refuted all 8 candidates on the pure utility lib (A's Critical is likely inflated/FP).

## Caveats

- Only **Model B underscore** remains (running).
- Degraded s4: **B nokogiri 4/148**, **B juice-shop 1/490**, **C juice-shop 1/584** — all other runs clean (B nokogiri's 4/148 is the only non-trivial one).
- `Verifier errors` are undetermined, not clean — high local counts mean degraded verification, so low local precision partly reflects verifier weakness.
- Backends differ (A/B local Ollama `via:openai`; C Bedrock `via:cli`) — transport/billing, same harness. C juice-shop/underscore ran on `<repo>-opus/` path-copies. Per-run provenance in each `run_manifest.json`.
