# Visa vvaharness — Model Comparison

Models run through the **Visa vvaharness** 9-stage pipeline on the three shared targets. Numbers from each run's `security-scan/*_report.md` (verification funnel, metrics) and `*_report.sarif` (final findings + severities). Compiled 2026-06-17.

**Status:** Model A (`qwen2.5-coder-14b-32k`) complete (3/3). Model B (`qwen3.6-36b-128k`) — nokogiri done; juice-shop running; underscore pending. Model C (`claude-opus-4-8`) — **nokogiri done via AWS Bedrock**; juice-shop/underscore pending. `_pending_` cells fill in as runs finish.

**Findings are triage candidates, not verified vulnerabilities.**

## ⚠️ Model C note — the Claude subscription was NOT viable; Model C runs on Bedrock

Model C was first attempted via the `claude` CLI on a **Claude Code subscription** (`via:cli`). It proved **unwinnable**: Opus's s4 (deep-dive) for nokogiri is ~148 chunks of ~80k-token prompts (the shipped large budgets), and s4 has **no intra-stage checkpoint** — so it can only complete if a single subscription token window covers the whole stage. It never could (best subscription window finished ~12/148 chunks before the ~4h usage wall; `--resume` restarts s4 from scratch, so progress can't accumulate across windows). After multiple sleep-and-resume cycles the run only ever produced a **92%-degraded s4 (0 findings)**, which the integrity gate correctly refused to file.

**Resolution:** Model C now runs the *same* stock harness and `via:cli` backend, but the `claude` CLI is pointed at **Opus 4.8 on AWS Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`, pay-per-token, no daily wall). The nokogiri run then completed cleanly in **44 minutes** — confirming the blocker was the subscription token cap, not the model or the harness.

## 1. Verification funnel — raw → confirmed

`Verifier errors` = candidates the s6 verifier could not adjudicate (undetermined — NOT confirmed false). Precision = confirmed ÷ raw.

| Target | Model | Raw (s4) | Confirmed | False+ | Verifier err (undet.) | Dup | Precision |
|---|---|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | 72 | 4 | 5 | 51 | 4 | 5.6% |
| nokogiri | qwen3.6-36b-128k | 71 | 1 | 32 | 16 | 12 | 1.4% |
| nokogiri | claude-opus-4-8 | 47 | 2 | 4 | 0 | 0 | 4.3% |
| juice-shop | qwen2.5-coder-14b-32k | 321 | 19 | 26 | 217 | 40 | 5.9% |
| juice-shop | qwen3.6-36b-128k | — | — | — | — | — | _pending_ |
| juice-shop | claude-opus-4-8 | — | — | — | — | — | _pending_ |
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
| juice-shop | claude-opus-4-8 | _pending_ |  |  |  |  |  |
| underscore | qwen2.5-coder-14b-32k | 1 | 1 | 0 | 0 | 0 | 0 |
| underscore | qwen3.6-36b-128k | _pending_ |  |  |  |  |  |
| underscore | claude-opus-4-8 | _pending_ |  |  |  |  |  |

## 3. Cost / runtime

Note the backends differ: A/B are local (free GPU time); C is AWS Bedrock (pay-per-token).

| Target | Model | Backend | Wall-clock | Tokens | s4 |
|---|---|---|---|---|---|
| nokogiri | qwen2.5-coder-14b-32k | local Ollama | 5.6h | 4,021,942 | clean |
| nokogiri | qwen3.6-36b-128k | local Ollama | 22.9h | 16,706,571 | s4 degraded 4/148 |
| nokogiri | claude-opus-4-8 | AWS Bedrock | 44m | 7,915,135 | clean |
| juice-shop | qwen2.5-coder-14b-32k | local Ollama | 7.3h | 4,617,645 | clean |
| juice-shop | qwen3.6-36b-128k | local Ollama | _pending_ |  |  |
| juice-shop | claude-opus-4-8 | AWS Bedrock | _pending_ |  |  |
| underscore | qwen2.5-coder-14b-32k | local Ollama | 1.1h | 1,349,049 | clean |
| underscore | qwen3.6-36b-128k | local Ollama | _pending_ |  |  |
| underscore | claude-opus-4-8 | AWS Bedrock | _pending_ |  |  |

## 4. nokogiri — complete 3-way head-to-head

The only fully-populated row, and the most informative:

- **Verifier decisiveness scales hard with model strength.** Undetermined (verifier-error) counts: **A=51, B=16, C=0**. The frontier model adjudicated *every* candidate; the 14B left 51 of 72 unresolved. This is the clearest signal that the locals' rock-bottom precision is **verifier weakness**, not purely bad candidates.
- **Speed inverts with model size locally, but Bedrock wins outright.** A=5.6h, B=22.9h (36B at 128k on the APU), **C=44 min** (Bedrock, no GPU bottleneck).
- **Severity sanity.** A claimed 1 Critical + 3 High; B and C each rated their findings **MEDIUM**. Opus rating the same bug-classes MEDIUM supports the earlier **14B severity-inflation** caveat.
- **What each confirmed (note the partial agreement):** A = path-manipulation, race, heap-overflow, unsafe deserialization (4). B = SSRF via external schema resolution in `RelaxNG.new` (1). C = NONET schema guard bypass (https/file/jar) + unescaped CSS id → XPath (2). C's schema-guard finding is the **same class** as B's RelaxNG SSRF; C's CSS→XPath overlaps A's & B's XPath-injection findings. The three models converge on the schema-SSRF and CSS/XPath-injection classes but disagree on count and severity.

## Caveats

- B/C are incomplete (nokogiri only for B-vs-A-vs-C; juice-shop/underscore pending).
- **B nokogiri was s4-degraded (4/148 chunks lost)** — a valid run but not fully clean; A and C nokogiri were clean.
- `Verifier errors` are undetermined, not clean — high counts mean degraded verification (the local agentic verifier failing), so low precision partly reflects verifier weakness.
- Severity labels are vvaharness/CVSS-derived, not normalized vs the Anthropic harness (see the cross-harness doc).
- Backends differ (A/B local Ollama `via:openai`; C Bedrock `via:cli`) — a transport/billing difference, same harness. Per-run provenance in each `run_manifest.json`.
