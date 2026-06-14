# Anthropic defending-code Harness — Model Comparison

Direct results comparison of the two models run through the Anthropic defending-code reference harness (`/vuln-scan` → `/triage`) against the three shared targets. Numbers are taken verbatim from the `summary` blocks of each `VULN-FINDINGS.json` / `TRIAGE.json` (cross-checked against the per-finding arrays — no mismatches). Compiled 2026-06-14.

**Findings are tool output, not ground truth.** `/vuln-scan` totals are raw candidates; `/triage` true-positive (TP) counts are the harness's own post-review verdicts, so "precision" here means **self-consistency** (share of its own raw findings a model upheld), not accuracy vs a verified gold set.

## 1. Raw findings — `/vuln-scan`

| Target | Model | Total | High | Medium | Low | Low-confidence |
|---|---|---|---|---|---|---|
| nokogiri | opus | 4 | 1 | 2 | 1 | 2 |
| nokogiri | qwen3.6 | 11 | 0 | 5 | 6 | 4 |
| juice-shop | opus | 14 | 7 | 6 | 1 | 0 |
| juice-shop | qwen3.6 | 30 | 10 | 18 | 2 | 0 |
| underscore | opus | 6 | 2 | 2 | 2 | 2 |
| underscore | qwen3.6 | 10 | 6 | 4 | 0 | 0 |

## 2. Triage outcomes — `/triage`

Precision = true-positives ÷ triage input.

| Target | Model | Input | True+ | False+ | Needs manual test | Duplicates | Precision |
|---|---|---|---|---|---|---|---|
| nokogiri | opus | 4 | 2 | 2 | 2 | 0 | 50% |
| nokogiri | qwen3.6 | 11 | 3 | 8 | 0 | 0 | 27% |
| juice-shop | opus | 14 | 11 | 3 | 2 | 0 | 79% |
| juice-shop | qwen3.6 | 30 | 27 | 2 | 0 | 1 | 90% |
| underscore | opus | 6 | 1 | 5 | 1 | 0 | 17% |
| underscore | qwen3.6 | 8 | 1 | 7 | 1 | 0 | 12% |

## 3. Triage true-positives by severity

| Target | Model | High | Medium | Low |
|---|---|---|---|---|
| nokogiri | opus | 0 | 2 | 0 |
| nokogiri | qwen3.6 | 2 | 1 | 0 |
| juice-shop | opus | 4 | 5 | 2 |
| juice-shop | qwen3.6 | 10 | 15 | 1 |
| underscore | opus | 0 | 1 | 0 |
| underscore | qwen3.6 | 0 | 0 | 1 |

## 4. Totals

| Model | Raw (Σ) | Triage input (Σ) | True+ (Σ) | False+ (Σ) | Needs manual (Σ) | Precision (Σ) | FP-rate (Σ) |
|---|---|---|---|---|---|---|---|
| opus | 24 | 24 | 14 | 10 | 5 | 58% | 42% |
| qwen3.6 | 51 | 49 | 31 | 17 | 1 | 63% | 35% |

## 5. Headline deltas (computed from the tables)

- **Volume:** qwen3.6 produced **51 raw findings vs opus's 24** (~2.1×) across the three targets.
- **Confirmed true-positives:** qwen3.6 **31** vs opus **14** (absolute) — more volume yielded more upheld findings.
- **Aggregate precision is close, and mixed by repo:** qwen3.6 63% vs opus 58% overall, but that total is dominated by juice-shop. Per-repo, opus had higher triage precision on **nokogiri, underscore**; qwen3.6 on **juice-shop**.
- **False positives:** qwen3.6 had more *absolute* FPs (17 vs 10) but a *lower* FP-rate (35% vs 42%) — its extra volume was not disproportionately noise.
- **Manual-test backlog:** opus flagged **5** findings as needs-manual-test vs qwen3.6's **1**; qwen3.6 returned firmer verdicts (fewer deferrals).

## 6. Finding overlap — shared vs unique

How much did the two models actually find *the same thing*? Cross-model finding identity is **fuzzy**: the same bug gets different line numbers and non-normalized category labels between models. So overlap is reported as a **locus match** — same file + line within ±10, matched greedily one-to-one — with the stricter exact `(file:line:category)` count alongside as a lower bound.

| Target | opus (raw) | qwen3.6 (raw) | Shared (locus ±10) | Unique opus | Unique qwen3.6 | Exact label match | Shared files |
|---|---|---|---|---|---|---|---|
| nokogiri | 4 | 11 | 0 | 4 | 11 | 0 | 3 |
| juice-shop | 14 | 30 | 11 | 3 | 19 | 5 | 7 |
| underscore | 6 | 10 | 4 | 2 | 6 | 3 | 4 |
| **Σ** | 24 | 51 | 15 | 9 | 36 | 8 | 14 |

**What this shows:**

- **15 of opus's 24 findings (~62%) coincide** with a qwen3.6 finding at the same locus; qwen3.6 surfaced **36 additional** findings opus did not. opus's set is largely a *subset* of qwen3.6's.
- **nokogiri: zero finding-level overlap** despite 3 shared files — the two models flagged *different bugs in the same files* (opus: XXE/XPath-injection/int-overflow; qwen3.6: null-derefs, memory leaks, OOB reads). No agreement on what's wrong there.
- **juice-shop: strongest agreement** — 11 shared loci spanning SQLi, XXE, SSRF, weak-crypto, open-redirect, path-traversal. Notably, only 5 of those 11 share an *exact* category label; the rest are the same locus under different names (`xxe`/`xxe-injection`, `code-injection`/`command-injection`, `dos`/`denial-of-service`).
- **Label divergence, not finding divergence:** across all repos only 8 of 15 locus-matches share an exact category string — so an exact-key comparison would *undercount* agreement by ~half.

## Caveats

- **Overlap is heuristic.** "Same finding" = same file + line within ±10 lines, greedy 1:1; categories are not normalized. Locus matches at Δline 4–5 (juice-shop `auth-bypass`, `path-traversal`; underscore `result.js`) could be co-location rather than true identity — confirm manually for rigor.
- Overlap is computed on **raw `/vuln-scan` findings**, not triaged true-positives.
- `/triage` verdicts are model-generated → precision measures self-consistency, not correctness vs a verified ground truth. A model can be "precise" about its own (possibly wrong) findings.
- Totals are skewed by **juice-shop**, which contributes the majority of both models' findings; weight the per-repo rows when comparing.
- Severity labels are each model's own and are **not normalized** between models.
- `qwen3.6/juice-shop/` is missing `TRIAGE.md`; its `TRIAGE.json` (used here) is present. See `README.md` known-gaps.
- For underscore, qwen3.6's triage input (8) is below its raw total (10) — some raw findings were dropped before triage; both numbers are shown so the gap is visible.
