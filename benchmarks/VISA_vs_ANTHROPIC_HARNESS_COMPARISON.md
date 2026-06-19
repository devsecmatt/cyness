# Cross-Harness Comparison — Visa vvaharness vs Anthropic defending-code

The two SAST harnesses on the three shared targets. Visa from `visa/.../security-scan/`; Anthropic from `anthropics/.../{VULN-FINDINGS,TRIAGE}.json`. Compiled 2026-06-19.

> **Fully model-matched now** — every Visa cell complete, so opus and qwen3.6 are both comparable across all three repos.

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
| juice-shop | 19 | 32 | 64 | 27 | 11 |
| underscore | 1 | 0 | 0 | 1 | 1 |

**Agreement depends on BOTH repo size and model strength:**
- **Small repos: the harnesses agree on every model.** nokogiri Visa·opus 2 vs Anth·opus 2 (Visa·qwen3.6 1 vs Anth·qwen3.6 3); underscore Visa·qwen3.6 **0** vs Anth·qwen3.6 1, Visa·opus **0** vs Anth·opus 1 — little surface, everyone lands near 0.
- **Large app (juice-shop): the gap tracks model strength.** Visa·qwen3.6 **32** vs Anth·qwen3.6 **27** (close); Visa·opus **64** vs Anth·opus **11** (~6×). The divergence is largest with the strongest model: Visa's exhaustive pipeline **plus a decisive Opus verifier** confirms far more than the curated shortlist; a weaker verifier (qwen3.6) upholds fewer candidates and lands near that shortlist. Exhaustive decomposition only pays off on a big attack surface when paired with a strong verifier.

## 3. Raw-candidate volume (context only — NOT comparable)

| Target | Visa·qwen2.5-14b (s4 raw) | Anthropic·qwen3.6 (/vuln-scan) | Anthropic·opus (/vuln-scan) |
|---|---|---|---|
| nokogiri | 72 | 11 | 4 |
| juice-shop | 321 | 30 | 14 |
| underscore | 53 | 10 | 6 |

## Caveats

- Fully model-matched, but counts are model-generated verdicts (self-consistency, not a verified gold set).
- Raw counts not comparable across harnesses (different definitions).
- Visa·opus ran on **AWS Bedrock** (subscription was token-bound); juice-shop/underscore on path-copies to run parallel to Model B.
