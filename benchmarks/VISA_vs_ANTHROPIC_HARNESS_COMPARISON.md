# Cross-Harness Comparison — Visa vvaharness vs Anthropic defending-code

The two SAST harnesses compared on the three shared targets. Visa numbers from `visa/.../security-scan/` reports; Anthropic from `anthropics/.../{VULN-FINDINGS,TRIAGE}.json`. Compiled 2026-06-17.

> ⚠️ **Still only partly model-matched.** The clean comparison is the *same model on both harnesses*. Anthropic ran `opus` + `qwen3.6`; Visa has `qwen2.5-coder-14b` (3/3) plus `qwen3.6` and `opus` on **nokogiri only** so far. So the **nokogiri column is now model-matchable** for opus and qwen3.6; juice-shop/underscore are not yet.

## 1. Methodology — why raw counts are NOT comparable

| Aspect | Visa vvaharness | Anthropic defending-code |
|---|---|---|
| Shape | 9-stage pipeline | 3 skill workflows (/threat-model → /vuln-scan → /triage) |
| "Raw" findings | Exhaustive s4 candidates — **hundreds**/repo | Curated model shortlist — **tens**/repo |
| Confirmation | Deterministic prefilter (s5) + adversarial verifier (s6) | /triage LLM verdict |
| "Confirmed" = | s6-verified true positives | /triage true-positives |

Only the **confirmed** endpoint is comparable, and even that is model-dependent.

## 2. Confirmed findings per repo, by (harness × model)

Visa = s6-verified TPs; Anthropic = /triage TPs.

| Target | Visa·qwen2.5-coder-14b | Visa·qwen3.6 | Visa·opus (Bedrock) | Anthropic·qwen3.6 | Anthropic·opus |
|---|---|---|---|---|---|
| nokogiri | 4 | 1 | 2 | 3 | 2 |
| juice-shop | 19 | _pending_ | _pending_ | 27 | 11 |
| underscore | 1 | _pending_ | _pending_ | 1 | 1 |

**nokogiri, now model-matchable:** on the *same model*, the two harnesses land close — Visa·opus **2** vs Anthropic·opus **2**; Visa·qwen3.6 **1** vs Anthropic·qwen3.6 **3**. Counts agree to within a couple of findings despite completely different pipelines, which is a meaningful cross-harness signal (the juice-shop/underscore cells will test whether it holds).

## 3. Raw-candidate volume (context only — NOT comparable)

| Target | Visa·qwen2.5-coder-14b (s4 raw) | Anthropic·qwen3.6 (/vuln-scan) | Anthropic·opus (/vuln-scan) |
|---|---|---|---|
| nokogiri | 72 | 11 | 4 |
| juice-shop | 321 | 30 | 14 |
| underscore | 53 | 10 | 6 |

Visa casts a wide net (72–321 raw) then filters hard; the Anthropic skills emit a focused list (4–30) up front.

## Caveats

- Model-matched only on **nokogiri** so far; juice-shop/underscore pending for Visa B/C.
- Raw counts not comparable across harnesses (different definitions).
- Both harnesses' 'confirmed' verdicts are model-generated (self-consistency, not a verified gold set).
- Visa·opus ran on **AWS Bedrock** (the Claude subscription was token-bound — see `visa/VISA_HARNESS_MODEL_COMPARISON.md`). Same harness/backend, different endpoint.
- Per-model detail: `anthropics/ANTHROPIC_HARNESS_MODEL_COMPARISON.md`, `visa/VISA_HARNESS_MODEL_COMPARISON.md`.
