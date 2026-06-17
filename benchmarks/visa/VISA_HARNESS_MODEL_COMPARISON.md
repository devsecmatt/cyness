# Visa vvaharness — Model Comparison

Models run through the **Visa vvaharness** 9-stage pipeline on the three shared targets. Numbers from each run's `security-scan/*_report.md` + `*_report.sarif`. Compiled 2026-06-17.

**Status:** Model A (`qwen2.5-coder-14b-32k`) 3/3. Model B (`qwen3.6-36b-128k`) — nokogiri done; juice-shop running; underscore pending. Model C (`claude-opus-4-8`, AWS Bedrock) — nokogiri + juice-shop done; underscore next. `_pending_` cells fill in as runs finish.

**Findings are triage candidates, not verified vulnerabilities.**

## ⚠️ Model C note — the Claude subscription was NOT viable; Model C runs on Bedrock

Model C was first attempted on a **Claude Code subscription** (`via:cli`) and proved **unwinnable**: Opus's s4 is hundreds of ~80k-token chunks (shipped large budgets) and s4 has **no intra-stage checkpoint**, so it can only complete if one subscription token window covers the whole stage — it never could (best window finished ~12/148 nokogiri chunks before the ~4h wall; `--resume` restarts s4, so progress can't accumulate). Result was a 92%-degraded s4 the integrity gate refused to file.

**Resolution:** same stock harness and `via:cli` backend, but the `claude` CLI points at **Opus 4.8 on AWS Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`, pay-per-token, no wall). nokogiri then completed in 44 min, juice-shop in 72 min — the blocker was the subscription cap, not the model or harness. (juice-shop/underscore are scanned on high-fidelity path-copies — `<repo>-opus/` — so Opus runs in parallel with Model B without the per-repo lock colliding.)

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
| underscore | claude-opus-4-8 | — | — | — | — | — | _pending_ |

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
| underscore | claude-opus-4-8 | _pending_ |  |  |  |  |  |

## 3. Cost / runtime

A/B local (free GPU); C is AWS Bedrock (pay-per-token).

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
| underscore | claude-opus-4-8 | AWS Bedrock | _pending_ |  |  |

## 4. Headline findings

**Verifier decisiveness scales hard with model strength.** Undetermined (verifier-error) counts — nokogiri: A=51, B=16, **C=0**; juice-shop: A=**217**, **C=0**. The 14B left two-thirds of juice-shop candidates unresolved; Opus resolved every one. This is the clearest evidence the locals' rock-bottom precision is **verifier weakness**, not purely bad candidates.

**Opus finds more AND with far higher precision (juice-shop, model A vs C):**
- Confirmed: A **19** vs C **64** (3.4×); precision A 5.9% vs C **34.8%**; exploit chains A 3 vs C **7**.
- Severity: A skewed to **16 Critical** / 3 Medium; C balanced **8C / 17H / 38M / 1L** — Opus rating far fewer Criticals (despite finding more) supports the **14B severity-inflation** caveat.
- C's 64 span IDOR/auth-bypass (CWE-639 ×13), XSS (CWE-79 ×12), path traversal (CWE-22 ×6), NoSQL injection (CWE-943 ×4), code injection, SQLi, JWT/sig, brute force, missing-authz — the breadth a deliberately-vulnerable app should yield.

**Speed:** nokogiri A 5.6h / B 22.9h / **C 44m**; juice-shop A 7.3h / **C 72m** (Bedrock, no GPU bottleneck).

**nokogiri (complete 3-way):** A 4 (1C/3H) · B 1 (MED) · C 2 (MED). C's schema-guard finding is the same class as B's RelaxNG SSRF; C's CSS→XPath overlaps A/B's XPath-injection. Models converge on the bug *classes*, disagree on count/severity.

## Caveats

- B incomplete (nokogiri only); C underscore pending.
- **B nokogiri s4-degraded (4/148)**; **C juice-shop s4-degraded (1/584 — negligible)**; all other completed runs clean.
- `Verifier errors` are undetermined, not clean — high counts mean degraded verification (local agentic verifier failing), so low local precision partly reflects verifier weakness.
- Backends differ (A/B local Ollama `via:openai`; C Bedrock `via:cli`) — transport/billing, same harness. C juice-shop/underscore scanned on `<repo>-opus/` path-copies (identical content) to run parallel to B. Per-run provenance in each `run_manifest.json`.
