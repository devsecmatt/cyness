# Visa vvaharness — Model Comparison

Models run through the **Visa vvaharness** 9-stage pipeline on the three shared targets. Numbers from each run's `security-scan/*_report.md` + `*_report.sarif`. Compiled 2026-06-17.

**Status:** Model A (`qwen2.5-coder-14b-32k`) 3/3 ✓. Model C (`claude-opus-4-8`, AWS Bedrock) **3/3 ✓**. Model B (`qwen3.6-36b-128k`) — nokogiri done; juice-shop running; underscore pending. Only Model B's last two cells remain.

**Findings are triage candidates, not verified vulnerabilities.**

## ⚠️ Model C note — the Claude subscription was NOT viable; Model C runs on Bedrock

Model C was first attempted on a **Claude Code subscription** (`via:cli`) and proved **unwinnable** — Opus's s4 is hundreds of ~80k-token chunks with no intra-stage checkpoint, so it could never complete within one ~4h subscription token window (best window did ~12/148 nokogiri chunks before the wall; `--resume` restarts s4). It only ever produced a 92%-degraded s4 the integrity gate refused to file.

**Resolution:** same stock harness and `via:cli` backend, but the `claude` CLI points at **Opus 4.8 on AWS Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`, pay-per-token, no wall). The full column then completed cleanly in **~2.1h / ~18.5M tokens** (≈$115–126 on Bedrock at $5/$25 per M). juice-shop/underscore ran on high-fidelity path-copies (`<repo>-opus/`) to run in parallel with Model B without the per-repo lock colliding.

## 1. Verification funnel — raw → confirmed

`Verifier errors` = candidates the s6 verifier could not adjudicate (undetermined — NOT confirmed false). Precision = confirmed ÷ raw.

| Target | Model | Raw (s4) | Confirmed | False+ | Verifier err (undet.) | Dup | Precision |
|---|---|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 72 | 4 | 5 | 51 | 4 | 5.6% |
| nokogiri | qwen3.6-36b-128k | 71 | 1 | 32 | 16 | 12 | 1.4% |
| nokogiri | claude-opus-4-8 | 47 | 2 | 4 | 0 | 0 | 4.3% |
| juice-shop | qwen2.5-coder-14b-32k | 321 | 19 | 26 | 217 | 40 | 5.9% |
| juice-shop | qwen3.6-36b-128k | — | — | — | — | — | _pending_ |
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
| juice-shop | qwen3.6-36b-128k | _pending_ |  |  |  |  |  |
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
| juice-shop | qwen3.6-36b-128k | local Ollama | _pending_ |  |  |
| juice-shop | claude-opus-4-8 | AWS Bedrock | 1.2h | 8,473,942 | 1/584 degraded (negligible) |
| underscore | qwen2.5-coder-14b-32k | local Ollama | 1.1h | 1,349,049 | clean |
| underscore | qwen3.6-36b-128k | local Ollama | _pending_ |  |  |
| underscore | claude-opus-4-8 | AWS Bedrock | 10m | 2,052,172 | clean |

Model C (Opus) column totals: **66 confirmed** (nokogiri 2 + juice-shop 64 + underscore 0), **0 verifier-errors** across all three, ~2.1h wall-clock, 18,441,249 tokens.

## 4. Headline findings

**Verifier decisiveness scales hard with model strength.** Total undetermined (verifier-error) counts across completed repos — A: **288**, B: 16 (nokogiri only), **C: 0**. Opus adjudicated *every* candidate on all three repos; the 14B left ~65% of its juice-shop candidates unresolved. The locals' rock-bottom precision is **verifier weakness**, not purely bad candidates.

**Opus finds more AND with far higher precision (juice-shop, A vs C):** confirmed **19 → 64** (3.4×); precision **5.9% → 34.8%**; chains **3 → 7**; severity A's skewed 16-Critical vs C's balanced 8C/17H/38M/1L (Opus rates fewer Criticals despite finding more — the **14B inflates severity**).

**Agreement on the small repos, divergence on the big app:**
- nokogiri: A 4 (1C/3H) · B 1 (MED) · C 2 (MED) — converge on schema-SSRF & CSS/XPath-injection *classes*, differ on count/severity.
- underscore: A **1** (a lone 'CRITICAL' circular-ref) · C **0** — Opus refuted all 8 candidates and confirmed nothing on this pure utility lib; A's single Critical is the kind of finding Opus's stricter verifier doesn't uphold (likely inflated/FP).
- juice-shop: A 19 · C **64** — the large attack surface is where model strength pays off most.

**Speed:** nokogiri A 5.6h / B 22.9h / C 44m; juice-shop A 7.3h / C 72m; underscore A 1.1h / C 10m. Bedrock Opus is fastest on every repo despite finding the most.

## Caveats

- Only Model B is incomplete (juice-shop running, underscore pending).
- **B nokogiri s4-degraded (4/148)**; **C juice-shop s4-degraded (1/584 — negligible)**; all other completed runs clean.
- `Verifier errors` are undetermined, not clean — high local counts mean degraded verification, so low local precision partly reflects verifier weakness.
- Backends differ (A/B local Ollama `via:openai`; C Bedrock `via:cli`) — transport/billing, same harness. C juice-shop/underscore ran on `<repo>-opus/` path-copies (identical content). Per-run provenance in each `run_manifest.json`.
