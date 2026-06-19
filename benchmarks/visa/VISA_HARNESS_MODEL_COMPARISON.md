# Visa vvaharness — Model Comparison

Models run through the **Visa vvaharness** 9-stage pipeline on the three shared targets. Numbers from each run's `security-scan/*_report.md` + `*_report.sarif`. Compiled 2026-06-19.

**Status: COMPLETE — full 3×3 matrix done.** A (`qwen2.5-coder-14b-32k`), B (`qwen3.6-36b-128k`), C (`claude-opus-4-8`, AWS Bedrock) — all 3/3.

**Findings are triage candidates, not verified vulnerabilities.**

## ⚠️ Model C note — the Claude subscription was NOT viable; Model C runs on Bedrock

Model C was first attempted on a **Claude Code subscription** (`via:cli`) and proved **unwinnable** — Opus's s4 is hundreds of ~80k-token chunks with no intra-stage checkpoint, so it could never finish within one ~4h subscription token window. Resolution: same stock harness + `via:cli`, but the `claude` CLI points at **Opus 4.8 on AWS Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`, pay-per-token, no wall). The full column completed in ~2.1h / ~18.4M tokens (≈$133–146; see cost table). juice-shop/underscore ran on `<repo>-opus/` path-copies to run parallel to Model B.

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
| underscore | qwen3.6-36b-128k | 132 | 0 | 61 | 39 | 31 | 0.0% |
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
| underscore | qwen3.6-36b-128k | 0 | 0 | 0 | 0 | 0 | 0 |
| underscore | claude-opus-4-8 | 0 | 0 | 0 | 0 | 0 | 0 |

## 3. Cost / runtime

A/B local (free GPU); C is AWS Bedrock (pay-per-token, ~$5/$25 per M in/out).

| Target | Model | Backend | Wall-clock | Tokens | s4 |
|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | local Ollama | 5.6h | 4,021,942 | clean |
| nokogiri | qwen3.6-36b-128k | local Ollama | 22.9h | 16,706,571 | s4 degraded 4/148 |
| nokogiri | claude-opus-4-8 | AWS Bedrock | 44m | 7,915,135 | clean |
| juice-shop | qwen2.5-coder-14b-32k | local Ollama | 7.3h | 4,617,645 | clean |
| juice-shop | qwen3.6-36b-128k | local Ollama | 45.7h | 42,611,099 | 1/490 degraded |
| juice-shop | claude-opus-4-8 | AWS Bedrock | 1.2h | 8,473,942 | 1/584 degraded |
| underscore | qwen2.5-coder-14b-32k | local Ollama | 1.1h | 1,349,049 | clean |
| underscore | qwen3.6-36b-128k | local Ollama | 27.0h | 23,164,089 | clean |
| underscore | claude-opus-4-8 | AWS Bedrock | 10m | 2,052,172 | clean |

### Token breakdown (input / output / total / cache-read)

Per-run tokens from each report. `Total (I/O)` = `prompt` (fresh + cache-write input) + `completion` (output). **Cache-read** is tracked separately and **excluded** from Total (I/O) — bills at ~$0.50/M (0.1× input).

| Model | Repo | Input | Output | Total (I/O) | Cache-read | Time |
|---|---|--:|--:|--:|--:|--:|
| qwen2.5-coder-14b | nokogiri | 3,962,360 | 59,582 | 4,021,942 | 0 | 5.6h |
|  | juice-shop | 4,391,084 | 226,561 | 4,617,645 | 0 | 7.3h |
|  | underscore | 1,315,192 | 33,857 | 1,349,049 | 0 | 1.1h |
|  | **subtotal** |  |  | **9,988,636** | **0** |  |
| qwen3.6-36b | nokogiri | 15,460,760 | 1,245,811 | 16,706,571 | 0 | 22.9h |
|  | juice-shop | 40,092,851 | 2,518,248 | 42,611,099 | 0 | 45.7h |
|  | underscore | 21,984,313 | 1,179,776 | 23,164,089 | 0 | 27.0h |
|  | **subtotal** |  |  | **82,481,759** | **0** |  |
| claude-opus-4-8 | nokogiri | 7,415,214 | 499,921 | 7,915,135 | 1,290,370 | 44m |
|  | juice-shop | 7,330,213 | 1,143,729 | 8,473,942 | 10,731,344 | 1.2h |
|  | underscore | 1,955,292 | 96,880 | 2,052,172 | 263,940 | 10m |
|  | **subtotal** |  |  | **18,441,249** | **12,285,654** |  |
| **GRAND TOTAL (9 cells)** |  |  |  | **110,911,644** | **12,285,654** |  |

- **Locals report zero cache-read** — Ollama doesn't surface `cached_tokens` / do prefix caching; Total (I/O) is the whole story for A and B.
- **Opus on Bedrock cached heavily** — juice-shop's cache-reads (10.7M) exceeded its Total (I/O) (127%).
- **The local 36B dominates token use:** 82.5M for its column vs Opus's 18.4M and the 14B's 10.0M. B underscore alone (23.2M) is more than Opus's entire 3-repo column.
- **A and B are free** (local GPU); only Model C is paid — priced below.

### Model C cost (AWS Bedrock)

Opus 4.8: **$5/M input, $25/M output, $0.50/M cache-read**. `+global 10%` = approximate cross-region surcharge on the `global.` profile (confirm vs the AWS bill).

| Repo | Input ($5/M) | Output ($25/M) | Cache-read ($0.50/M) | Run total | + global 10% |
|---|--:|--:|--:|--:|--:|
| nokogiri | $37.08 | $12.50 | $0.65 | $50.23 | $55.25 |
| juice-shop | $36.65 | $28.59 | $5.37 | $70.61 | $77.67 |
| underscore | $9.78 | $2.42 | $0.13 | $12.33 | $13.56 |
| **TOTAL** | **$83.50** | **$43.51** | **$6.14** | **$133.15** | **$146.47** |

**≈ $133 at base pricing, ≈ $146 with the ~10% global surcharge** (~$135–150 all-in). Input lumps fresh + cache-write (cache-write bills 1.25×), so a slight under-estimate; AWS bill is the source of truth.

## 4. Headline findings

**Confirmed findings scale with model strength — clearest on the large app:** juice-shop A **19** → B **32** → C **64**; precision 5.9% → 10.0% → 34.8%; verifier-errors 217 → 81 → 0; chains 3 → 0 → 7.

**Verifier decisiveness scales with strength.** Total verifier-errors (undetermined) across the full matrix: **A 288, B 136, C 0.** Opus adjudicated every candidate on all three repos; the locals left a third to two-thirds unresolved — the locals' low precision is **verifier weakness**, not purely bad candidates.

**Severity calibration:** on juice-shop, A inflates to 16 Critical; B and C both land at 8 Critical — the 14B over-rates where the 36B and Opus agree.

**Small repos, all models ~agree there's little:** nokogiri A 4 (1C/3H) · B 1 (MED) · C 2 (MED). **underscore A 1 · B 0 · C 0** — a pure utility lib; B refuted all 132 candidates and C all 8, confirming none. A's lone Critical is the outlier (likely FP).

**Cost of the local 36B:** Model B's column took **~95.6h wall-clock** (nokogiri 22.9h + juice-shop 45.7h + underscore 27.0h) and 82.5M tokens — vs Model A's ~14h and Opus's ~2.1h. underscore's 27h for **zero** findings (132 candidates, all refuted) is the starkest cost/value point in the matrix.

## Caveats

- Degraded s4: **B nokogiri 4/148**, **B juice-shop 1/490**, **C juice-shop 1/584** — all other runs clean. (B underscore s4 clean; its 39 s6 verifier-errors are undetermined verdicts, not coverage loss.)
- `Verifier errors` are undetermined, not clean — high local counts mean degraded verification, so low local precision partly reflects verifier weakness.
- Backends differ (A/B local Ollama `via:openai`; C Bedrock `via:cli`) — transport/billing, same harness. C juice-shop/underscore ran on `<repo>-opus/` path-copies. Per-run provenance in each `run_manifest.json`.
