# Agentic SAST — underscore

## Summary
No findings survived adversarial verification.

## Scan Metrics

- Scan ID: 2026-06-17T12:03:07Z__underscore
- Module: underscore
- Start: 2026-06-17T12:03:07Z
- End: 2026-06-17T12:12:52Z
- Duration (sec): 585
- Files in scope: 190
- Files analyzed (unique): 185
- Coverage: 97.4%
- Chunks: 204 (risk=8, catch-all=65, specialist=131)
- Tokens (prompt): 1955292
- Tokens (completion): 96880
- Tokens (total): 2052172

- Folders scanned: 5
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s4-deepdive | 204 | 1,837,263 | 80,940 | 1,918,203 | 93.5 | 0 |
| s6-verify | 2 | 35,712 | 5,653 | 41,365 | 2.0 | 123,515 |
| s3-decompose | 1 | 31,608 | 3,213 | 34,821 | 1.7 | 0 |
| s1-preprocess | 1 | 20,155 | 4,048 | 24,203 | 1.2 | 140,425 |
| unlabeled | 1 | 19,887 | 4 | 19,891 | 1.0 | 0 |
| s2-threatmodel | 1 | 6,656 | 2,482 | 9,138 | 0.4 | 0 |
| s1-autoexclude | 1 | 4,011 | 540 | 4,551 | 0.2 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| javascript | 9972 | 9972 | 100.0 |
| other | 21814 | 278 | 1.3 |

## Threat Model

### System context

Underscore.js v1.13.8 is a widely-used functional-programming utility library for JavaScript, distributed as an npm/bower package and consumed both in Node.js servers and browsers. It provides collection, object, function, and type helpers, plus a micro-templating engine (_.template). It has NO network, IPC, socket, filesystem, or CLI entry points — it is purely a library invoked in-process by host application code. As such it has no independent privilege context: it runs with whatever trust the embedding application grants its inputs.

The security-relevant surfaces are therefore the public API functions whose behavior depends on caller-supplied data, and the module-load/global-detection bootstrap. The single dynamic-code sink is _.template, which compiles template text into a JS function via `new Function`. CVE-2021-23358 (variable-name injection) is already mitigated via a bareIdentifier regex check, but compiling untrusted template *body* text remains arbitrary JS execution by design (documented hazard).

The realistic attacker model is an upstream application that forwards untrusted input into Underscore APIs (template text, iteratee strings, deeply-nested objects, or regex-bearing settings), and the supply-chain risk of a compromised package being pulled into thousands of downstream builds.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| host process integrity | critical | The Node.js or browser execution context of the application embedding Underscore; arbitrary JS execution here means full compromise of that process. |
| service availability | medium | Responsiveness of the host application; library calls run synchronously in-process and can block the event loop. |
| downstream consumer integrity | critical | The thousands of packages/applications depending on Underscore via npm/bower; integrity of the published artifact protects them. |
| object/prototype integrity | high | Integrity of JS object prototypes and host-application data structures manipulated by object/collection helpers. |

### Trust boundaries

- **modules/template.js::template** — untrusted caller input (template text / settings regexes) → in-process dynamic code compilation → host process integrity, service availability, downstream consumer integrity
- **modules/index-all.js::(module exports)** — untrusted caller data → library API logic (iteratees, deep object keys, deep equality) → object/prototype integrity, service availability, host process integrity
- **modules/_setup.js::(module load)** — package registry / build pipeline → module load & global-object detection at import time → downstream consumer integrity, host process integrity

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | Arbitrary JavaScript execution in the host process when an application compiles attacker-controlled template text through _.template. | remote_unauth | modules/template.js::template | host process integrity | critical | likely | bareIdentifier regex blocks CVE-2021-23358 variable-injection vector; SECURITY.md documents that untrusted template input must never be passed; this is by-design behavior of the Function-constructor contract. |
| T2 | Malicious or compromised published artifact executes attacker code in every downstream build/runtime that installs the package (supply-chain compromise). | supply_chain | modules/_setup.js::(module load) | downstream consumer integrity | critical | rare | MIT-licensed, well-maintained project with documented security policy and supported-versions list; no install scripts in package.json; module load uses constant-string Function('return this') fallback, not user input. |
| T3 | Prototype pollution or unintended host-object mutation when object helpers (extend/defaults/keys assignment) process attacker-controlled key names from a parsed payload. | remote_unauth | modules/index-all.js::(module exports) | object/prototype integrity | high | possible | library does not deep-merge by default and uses own-property enumeration in most paths; behavior depends on how the embedding application feeds data. |
| T4 | Regular-expression / algorithmic-complexity denial of service when attacker-supplied custom template settings regexes or pathological inputs are evaluated, blocking the host event loop. | remote_unauth | modules/template.js::template | service availability | medium | possible | default escape/interpolate/evaluate regexes are fixed and non-catastrophic; custom settings regexes are caller-supplied. |
| T5 | Denial of service via algorithmic blowup in deep equality or recursive object traversal on large/cyclic attacker-supplied structures, stalling the synchronous library call. | remote_unauth | modules/index-all.js::(module exports) | service availability | medium | possible | isEqual implements cycle detection via traversal stacks; exposure depends on input size limits enforced by the host application. |
| T6 | Tampering of the global root object or shared prototypes detected at module load, allowing a hostile co-loaded module to shadow Underscore internals. | local_user | modules/_setup.js::(module load) | host process integrity | low | rare | root detection uses standard self/global/globalThis checks with a constant-string Function fallback; same-realm threat requires an already-compromised process. |

### Open questions

- Do any downstream applications pass externally-sourced strings (user input, DB, HTTP) directly into _.template as template text?
- Are custom template settings (interpolate/evaluate/escape regexes) ever derived from untrusted configuration?
- Do consumers feed attacker-controlled JSON/object key names into extend/defaults/assignment helpers without sanitization?
- What input-size or timeout limits does the embedding application enforce around synchronous Underscore calls?
- Is the npm publishing pipeline (maintainer credentials, 2FA, provenance/signing) hardened against artifact tampering?

## Verification
- Raw findings (pre-verification): 8
- True positives (verified): 0
- False positives (dropped): 2
- Verifier errors (excluded — undetermined, not confirmed clean): 0
- Duplicates collapsed (all passes): 0
- Verification precision: 0.0%

## Findings (0)

## Exploit Chains

No exploit chains were identified — the findings above are independent and do not combine into a multi-step path.


## Dropped Findings

- **[UNCONFIRMED]** `modules/_createAssigner.js:11` logic-flaw (chunk-03) — s4 confidence 0.35 < gate 0.60
- **[UNCONFIRMED]** `modules/isEqual.js:115` logic-flaw (chunk-04) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `underscore-esm.js:903` injection (catchall-05) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `underscore-umd.js:926` injection (catchall-07) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `underscore.js:926` injection (catchall-08) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/codeql-analysis.yml:48` logic-flaw (spec-iac-01) — s4 confidence 0.30 < gate 0.60
- **[FP]** `underscore-node-f.cjs:905` injection (catchall-06) — sink is real and correctly read, but it's a library API working as designed; no external/untrusted caller exists in this repo (only tests + demo), and the documented hazard belongs to consuming apps, not this code.
- **[FP]** `modules/template.js:52` injection (chunk-02) — `_.template` is a library API with no in-scope caller; compiling template text to code is its documented, intended function (working-as-designed), and the one real injection variant (CVE-2021-23358) is already mitigated by the bareIdentifier check.


---

## Appendix: Scan Scope

### Folders scanned (5)

- `./`
- `.github/`
- `.github/config/`
- `.github/workflows/`
- `modules/`

### Excluded from scan (239 files)

**Folders** (matched `exclude_dirs`):

- `docs/` — 179 files
- `.git/` — 28 files
- `test/` — 14 files
- `test-treeshake/` — 3 files
- `checkpoints/` — 1 files
- `patches/` — 1 files

**File types** (matched `exclude_exts`):

- `*.map` — 8 files
- `*.ico` — 1 files
- `*.html` — 1 files

**Patterns** (matched `exclude_globs`):

- `**/LICENSE` — 1 files
- `**/.gitignore` — 1 files
- `**/.editorconfig` — 1 files
