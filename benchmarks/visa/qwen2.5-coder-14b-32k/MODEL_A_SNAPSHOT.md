# Visa vvaharness — Model A snapshot (`qwen2.5-coder-14b-32k`)

Snapshot of the Model A run across all three targets. Numbers extracted from each
run's `security-scan/*_report.md` (verification funnel, metrics) and
`*_report.sarif` (final findings + severities). Compiled 2026-06-15.

## Verification funnel (raw → confirmed)

| Target | Raw (s4) | Confirmed | False+ | Verifier errors (undet.) | Dup | Precision |
|---|---|---|---|---|---|---|
| nokogiri | 72 | 4 | 5 | 51 | 4 | 5.6% |
| juice-shop | 321 | 19 | 26 | 217 | 40 | 5.9% |
| underscore | 53 | 1 | 6 | 20 | 13 | 1.9% |
| **Σ** | **446** | **24** | **37** | **288** | **57** | **~5%** |

`Verifier errors` = candidates the s6 verifier could not adjudicate
(undetermined — **not** confirmed false positives).

## Confirmed findings + cost

| Target | Confirmed (Crit/High/Med) | Exploit chains | Wall-clock | Tokens |
|---|---|---|---|---|
| nokogiri | 4 (1C / 3H) | 2 | 5.6h | 4,021,942 |
| juice-shop | 19 (16C / 0H / 3M) | 3 | 7.3h | 4,617,645 |
| underscore | 1 (1C) | 0 | 1.1h | 1,349,049 |
| **Σ** | **24 (18C / 3H / 3M)** | **5** | **~14h** | **9,988,636** |

## Confirmed findings (titles)

**nokogiri (4)**
1. [CRITICAL] File path manipulation via URL input in `ParserContext.setUrl`
2. [HIGH] Race condition in multiple error handlers
3. [HIGH] Heap overflow due to undersized buffer reallocation
4. [HIGH] Deserialization of untrusted input in zlib recipe configuration

Chains: `UAF → arb write → RCE`; `Directory traversal + arbitrary code execution`

**juice-shop (19 — mostly the app's planted bugs)**
1. [CRITICAL] Reentrancy allows unauthorized withdrawal of funds
2. [CRITICAL] Directory traversal in file path construction
3. [CRITICAL] XSS in NFT Unlock component
4. [CRITICAL] Authorization bypass through email modification
5. [CRITICAL] SQL injection via `JSON.parse` + unquoted string interpolation
6. [CRITICAL] Insecure deserialization of YAML
7. [CRITICAL] Unvalidated UserId parameter in `getPaymentMethods`
8. [CRITICAL] NoSQL injection in `updateProductReviews` route
9. [CRITICAL] Insecure handling of untrusted user input
10. [CRITICAL] CAPTCHA answer comparison vulnerable to timing attacks
11. [CRITICAL] JWT verification does not enforce algorithm / key-ID trust
12. [CRITICAL] Unfiltered user data exported in plain text
13. [CRITICAL] Lack of authorization checks on collections
14. [CRITICAL] Unvalidated user token update
15. [CRITICAL] Directory traversal via `req.params.key`
16. [CRITICAL] OAuth login with hardcoded secret
17. [MEDIUM] Open redirect in about-component gallery links
18. [MEDIUM] User-specific data exposure via `fields` query parameter
19. [MEDIUM] Shader material unsecured

Chains: `Reentrancy + unfiltered export → RCE + data exfiltration`;
`NoSQL injection + JWT forgery`; `Directory traversal + deserialization`

**underscore (1)**
1. [CRITICAL] Incorrectly handles circular references in objects (`isEqual`)

## Read with caution

- **Precision is not face-value.** The dominant funnel outcome was **288
  "verifier errors" (undetermined)**, not confirmed false positives — the 14B's
  agentic s6 verifier frequently could not adjudicate, so most candidates were
  dropped as *unproven* rather than refuted. The ~5% precision therefore reflects
  **verifier weakness as much as bad candidates**.
- **Possible severity inflation.** juice-shop returned 16 Criticals; juice-shop is
  deliberately vulnerable so many are genuine, but the skew warrants a skeptical
  pass.
- **underscore** confirmed just 1 finding (pure utility library, low attack
  surface) — consistent with the Anthropic-harness result on the same repo.
- Findings are **triage candidates, not verified vulnerabilities.**

This is the baseline the Model B (`qwen3.6-36b-128k`, running) and Model C
(`claude-opus-4-8`) columns will be read against — especially whether a stronger
model drives the verifier-error count down. See
`../VISA_HARNESS_MODEL_COMPARISON.md` for the full matrix.
