# Visa vvaharness — Model Comparison

Comparison of the models run through the **Visa vvaharness** 9-stage pipeline against the three shared targets. Numbers are extracted from each run's `security-scan/*_report.md` (verification funnel) and `*_report.sarif` (final findings + severities). Compiled 2026-06-15.

**Status:** Model A (`qwen2.5-coder-14b-32k`) complete. Model B (`qwen3.6-36b-128k`) **in progress**; Model C (`claude-opus-4-8`) **not started** — their rows are placeholders to be filled when those runs finish.

**Findings are triage candidates, not verified vulnerabilities.** vvaharness emits many raw candidates at deep-dive (s4), then filters (s5) and adversarially verifies (s6); only s6-confirmed findings reach the report.

## 1. Verification funnel — raw → confirmed

`Verifier errors` = findings the s6 verifier could not adjudicate (undetermined — **not** confirmed false positives). Precision = confirmed ÷ raw.

| Target | Model | Raw (s4) | Confirmed (TP) | False+ (s6) | Verifier errors (undet.) | Duplicates | Precision |
|---|---|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 72 | 4 | 5 | 51 | 4 | 5.6% |
| juice-shop | qwen2.5-coder-14b-32k | 321 | 19 | 26 | 217 | 40 | 5.9% |
| underscore | qwen2.5-coder-14b-32k | 53 | 1 | 6 | 20 | 13 | 1.9% |
| nokogiri | qwen3.6-36b-128k | — | — | — | — | — | _pending_ |
| juice-shop | qwen3.6-36b-128k | — | — | — | — | — | _pending_ |
| underscore | qwen3.6-36b-128k | — | — | — | — | — | _pending_ |
| nokogiri | claude-opus-4-8 | — | — | — | — | — | _pending_ |
| juice-shop | claude-opus-4-8 | — | — | — | — | — | _pending_ |
| underscore | claude-opus-4-8 | — | — | — | — | — | _pending_ |

## 2. Confirmed findings by severity (final report)

| Target | Model | Total | Critical | High | Medium | Low | Exploit chains |
|---|---|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 4 | 1 | 3 | 0 | 0 | 2 |
| juice-shop | qwen2.5-coder-14b-32k | 19 | 16 | 0 | 3 | 0 | 3 |
| underscore | qwen2.5-coder-14b-32k | 1 | 1 | 0 | 0 | 0 | 0 |
| nokogiri | qwen3.6-36b-128k | _pending_ |  |  |  |  |  |
| juice-shop | qwen3.6-36b-128k | _pending_ |  |  |  |  |  |
| underscore | qwen3.6-36b-128k | _pending_ |  |  |  |  |  |
| nokogiri | claude-opus-4-8 | _pending_ |  |  |  |  |  |
| juice-shop | claude-opus-4-8 | _pending_ |  |  |  |  |  |
| underscore | claude-opus-4-8 | _pending_ |  |  |  |  |  |

## 3. Cost / runtime (local — wall-clock & tokens)

| Target | Model | Wall-clock | Total tokens |
|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 5.6h | 4,021,942 |
| juice-shop | qwen2.5-coder-14b-32k | 7.3h | 4,617,645 |
| underscore | qwen2.5-coder-14b-32k | 1.1h | 1,349,049 |
| nokogiri | qwen3.6-36b-128k | _pending_ |  |
| juice-shop | qwen3.6-36b-128k | _pending_ |  |
| underscore | qwen3.6-36b-128k | _pending_ |  |
| nokogiri | claude-opus-4-8 | _pending_ |  |
| juice-shop | claude-opus-4-8 | _pending_ |  |
| underscore | claude-opus-4-8 | _pending_ |  |

## 4. Model A totals

| Model | Raw (Σ) | Confirmed (Σ) | Verifier errors (Σ) | Final findings (Σ) | Chains (Σ) | Wall-clock (Σ) | Tokens (Σ) |
|---|---|---|---|---|---|---|---|
| qwen2.5-coder-14b-32k | 446 | 24 | 288 | 24 | 5 | 14.1h | 9,988,636 |

## 5. Observations (Model A — baseline)

- **High raw volume, low confirmation.** The 14B emitted **446 raw candidates** across the three repos but only **24** survived s6 verification (~5%). The dominant outcome was **verifier errors (288 undetermined)** — the agentic s6 verifier frequently could not adjudicate, so most candidates were dropped as unproven rather than confirmed false. This is the headline 14B limitation to watch when B/C land.
- **Severity skew to Critical.** Of 24 confirmed, 18 are Critical — consistent with the verifier only upholding the most clear-cut cases.
- **Cost.** ~14 hours wall-clock and ~10M tokens total on local GPU (free); compare against Model C's token spend once it runs.
- **underscore** confirmed just 1 finding (pure utility lib, low attack surface) — consistent with the Anthropic-harness result on the same repo.

## Caveats

- Only Model A is complete; B/C rows are placeholders.
- `Verifier errors` are undetermined, not clean — a high count means degraded verification (likely the 14B agentic verifier failing/timing out), so low precision here partly reflects verifier weakness, not just false candidates.
- Severity labels are vvaharness/CVSS-derived; not normalized against the Anthropic harness's labels (see the cross-harness doc).
- Per-run provenance (model, config, timing, tokens) is in each `security-scan/run_manifest.json` / report `Scan Metrics`.
