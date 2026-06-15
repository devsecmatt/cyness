# Cross-Harness Comparison — Visa vvaharness vs Anthropic defending-code

Comparison of the **two SAST harnesses** themselves, using their results on the three shared targets. Visa numbers from `visa/.../security-scan/` reports; Anthropic numbers from `anthropics/.../{VULN-FINDINGS,TRIAGE}.json`. Compiled 2026-06-15.

> ⚠️ **Not model-matched yet.** The only clean cross-harness comparison is the **same model on both harnesses**. Anthropic ran `opus` + `qwen3.6`; Visa has so far completed only `qwen2.5-coder-14b`, with its `qwen3.6` run **in progress**. Until Visa's qwen3.6 (and opus) finish, the tables below pair *different models* and are **directional only** — read them as harness-behaviour signals, not a head-to-head model verdict.

## 1. Methodology — why raw counts are NOT comparable

| Aspect | Visa vvaharness | Anthropic defending-code |
|---|---|---|
| Shape | 9-stage pipeline (survey→threat-model→decompose→deep-dive→prefilter→verify→dedup→chain→SARIF) | 3 skill workflows: `/threat-model` → `/vuln-scan` → `/triage` |
| "Raw" findings | Exhaustive deep-dive candidates (s4) — **hundreds** per repo, pre-filter | Curated model shortlist from `/vuln-scan` — **tens** per repo |
| Confirmation | Deterministic prefilter (s5) + adversarial agentic verifier (s6) | `/triage` LLM review (true/false-positive verdict) |
| Output | Markdown report + SARIF 2.1.0 + exploit chains | THREAT_MODEL.md, VULN-FINDINGS.{md,json}, TRIAGE.{md,json} |
| "Confirmed" = | s6-verified true positives in final report | `/triage` true-positives |

Because each harness defines a *raw finding* completely differently (exhaustive candidates vs curated shortlist), **only the confirmed endpoint is comparable** — and even that is model-dependent.

## 2. Confirmed findings per repo, by (harness × model)

Visa = s6-verified TPs; Anthropic = `/triage` TPs.

| Target | Visa · qwen2.5-coder-14b | Visa · qwen3.6 | Visa · opus | Anthropic · qwen3.6 | Anthropic · opus |
|---|---|---|---|---|---|
| nokogiri | 4 | _pending_ | _pending_ | 3 | 2 |
| juice-shop | 19 | _pending_ | _pending_ | 27 | 11 |
| underscore | 1 | _pending_ | _pending_ | 1 | 1 |
| **Σ** | 24 | _pending_ | _pending_ | 31 | 14 |

## 3. Raw-candidate volume per repo (context, NOT comparable)

Shown only to illustrate the methodology gap — do not compare across harnesses.

| Target | Visa · qwen2.5-coder-14b (s4 raw) | Anthropic · qwen3.6 (/vuln-scan) | Anthropic · opus (/vuln-scan) |
|---|---|---|---|
| nokogiri | 72 | 11 | 4 |
| juice-shop | 321 | 30 | 14 |
| underscore | 53 | 10 | 6 |
| **Σ** | 446 | 51 | 24 |

## 4. Observations (preliminary — different models)

- **Volume philosophy is opposite.** Visa's pipeline generated **446 raw candidates** (14B) vs the Anthropic harness's curated **51** (qwen3.6) / **24** (opus). Visa casts a wide net then filters hard; the Anthropic skills emit a focused list up front.
- **Confirmed endpoint, with the model caveat:** Visa·14B confirmed **24** total; Anthropic·opus **14**, Anthropic·qwen3.6 **31**. The lower Visa number is confounded by (a) a weaker model (14B vs opus/qwen3.6-36B) and (b) its s6 verifier erroring out on most candidates — see the Visa model-comparison doc.
- **Agreement to test once model-matched:** the meaningful question — *does the same model find the same bugs through each harness?* — needs Visa's qwen3.6 run (in progress). The qwen3.6 row in §2 is the cell that will answer it.

## Caveats

- **Not model-matched** — the headline limitation; revisit once Visa qwen3.6 + opus complete.
- Raw-finding counts are **not comparable** across harnesses (different definitions).
- Visa 'confirmed' (s6-verified) and Anthropic 'triage TP' are both **model-generated verdicts**, i.e. self-consistency, not a verified gold set.
- Severity/category taxonomies are **not normalized** between harnesses.
- Anthropic per-model detail: see `anthropics/ANTHROPIC_HARNESS_MODEL_COMPARISON.md`; Visa per-model detail: `visa/VISA_HARNESS_MODEL_COMPARISON.md`.
