# Cross-Harness Comparison — Visa vvaharness vs Anthropic defending-code

The two SAST harnesses on the three shared targets. Visa from `visa/.../security-scan/`; Anthropic from `anthropics/.../{VULN-FINDINGS,TRIAGE}.json`. Compiled 2026-06-17.

> **opus is now fully model-matched** across all three repos (Visa·opus complete). qwen3.6 is matched on nokogiri only (Visa·qwen3.6 juice-shop/underscore pending).

## 1. Methodology — why raw counts are NOT comparable

| Aspect | Visa vvaharness | Anthropic defending-code |
|---|---|---|
| Shape | 9-stage pipeline | 3 skill workflows (/threat-model → /vuln-scan → /triage) |
| "Raw" findings | Exhaustive s4 candidates — **hundreds**/repo | Curated model shortlist — **tens**/repo |
| Confirmation | Prefilter (s5) + adversarial verifier (s6) | /triage LLM verdict |
| "Confirmed" = | s6-verified TPs | /triage TPs |

## 2. Confirmed findings per repo, by (harness × model)

| Target | Visa·qwen2.5-14b | Visa·qwen3.6 | Visa·opus (Bedrock) | Anthropic·qwen3.6 | Anthropic·opus |
|---|---|---|---|---|---|
| nokogiri | 4 | 1 | 2 | 3 | 2 |
| juice-shop | 19 | _pending_ | 64 | 27 | 11 |
| underscore | 1 | _pending_ | 0 | 1 | 1 |

**The key cross-harness finding — agreement is repo-size dependent (now confirmed on the full opus row):**
- **Small repos: the two harnesses agree closely** on the same model. nokogiri: Visa·opus **2** vs Anthropic·opus **2**. underscore: Visa·opus **0** vs Anthropic·opus **1** — both essentially 'nothing exploitable here.'
- **Large app: they diverge ~6×** — juice-shop Visa·opus **64** vs Anthropic·opus **11**. Visa's exhaustive 9-stage decomposition scales with attack surface and surfaces far more confirmed issues; the Anthropic skills' curated `/vuln-scan` shortlist stays in the tens regardless of repo size. **On a big attack surface the pipeline design matters more than the model.**

## 3. Raw-candidate volume (context only — NOT comparable)

| Target | Visa·qwen2.5-14b (s4 raw) | Anthropic·qwen3.6 (/vuln-scan) | Anthropic·opus (/vuln-scan) |
|---|---|---|---|
| nokogiri | 72 | 11 | 4 |
| juice-shop | 321 | 30 | 14 |
| underscore | 53 | 10 | 6 |

## Caveats

- opus fully model-matched; qwen3.6 matched on nokogiri only (Visa B juice-shop/underscore pending).
- Raw counts not comparable across harnesses (different definitions).
- Both harnesses' 'confirmed' verdicts are model-generated (self-consistency, not a verified gold set).
- Visa·opus ran on **AWS Bedrock** (subscription was token-bound — see `visa/VISA_HARNESS_MODEL_COMPARISON.md`); juice-shop/underscore on path-copies to run parallel to Model B.
