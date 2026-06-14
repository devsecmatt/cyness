# Triage Report

8 in -> 0 duplicates, 7 false positives, 1 confirmed (0 high / 0 med / 1 low), 1 need manual test.

Context: auto; environment = Library / SDK (caller is the trust boundary); scoring = Derived HIGH/MEDIUM/LOW from preconditions; 3-vote verification.

## Act on these

### [LOW] isEqual cycle-detection O(depth) scan -> O(n^2) on deeply nested structures now reachable after the stack-overflow fix  (f002)
`modules/isEqual.js:118` | algorithmic-complexity | claimed LOW (alignment +3) | confidence 7.0/10
**Owner:** top committer: Julian Gonggrijp (13/14 recent commits on modules/isEqual.js); no CODEOWNERS entry
**Verdict:** needs_manual_test, votes {true_positive: 3, false_positive: 0, cannot_verify: 0}
**Preconditions (4):**
- The application must actually call `_.isEqual(a, b)` on attacker-influenced data (the developer chooses to invoke it).
- At least one operand must be attacker-controlled (e.g. parsed JSON from a request body).
- The attacker-supplied operand must be a deeply-nested structure (deep linear chain); flat/shallow inputs do not trigger the quadratic path.
- Both operands must be structurally matching at each depth so the aStack accumulates rather than early-returning, and the depth must be large enough for n^2 CPU to be a meaningful DoS.
**Threat-model match:** none
**Why:** TRUE_POSITIVE by 3/3 verifiers. The per-node linear scan of `aStack` at isEqual.js:118-128 costs k at depth k; `aStack` holds the current traversal path (pushed at 133-134, unwound via the `true` sentinel at 29-33/136), so a depth-n linear chain sums to 1+2+...+n = O(n^2), with no depth/size bound in the file. The CVE-2026-27601 trampoline (line 20) moved traversal onto a heap `todo` array, removing the native call-stack ceiling that previously made deep inputs RangeError out early, so deep inputs now run to completion and reach the quadratic path. `_.isEqual` is a public API (index.js:41) whose operands are caller/attacker-controlled data; superlinear work from modest structured input is algorithmic complexity (kept in-scope, not excluded as volumetric DoS). Severity derived LOW: a pure CPU-burn DoS (no corruption, no data exposure) gated behind 3+ preconditions; the lower-of-columns rule confirms LOW even though access could be unauthenticated-remote. Scanner's LOW is well-justified (+3).
**Reachability evidence:** modules/index.js:41, modules/isEqual.js:118
> Recommend a human build a PoC; static reasoning hit its limit. Confirm whether realistic depths produce a wall-clock DoS before the quadratic factor stops mattering.

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f003 | Template body compiled into new Function -- RCE by design | modules/template.js:52 | false_positive: intentional_behavior (exclusion rule 3) -- documented eval-like caller contract; runtime data never reaches the sink as code; CVE-2021-23358 lever separately guarded |
| f004 | _.escape covers only 6 HTML chars; unsafe outside HTML body | modules/_escapeMap.js:2 | false_positive: intentional_behavior (exclusion rule 3) -- standard HTML-entity escaper; gap requires caller to use output in a context it never targeted (unquoted attr / URL / JS / CSS) |
| f001 | extend/extendOwn/defaults copy attacker __proto__ key onto destination | modules/_createAssigner.js:13 | false_positive: misread_code (exclusion rule 12) -- shallow assign; obj["__proto__"]=val rebinds only the single destination object's prototype, not global Object.prototype; no recursive descent |
| f005 | bareIdentifier guard on settings.variable -- no bypass found | modules/template.js:32 | false_positive: already_handled (exclusion rule 8) -- anchored regex admits only [\w$] runs; no bypass; settings.variable is template-author-trusted, same level as the template body |
| f006 | property/get path traversal reads prototype-chain members | modules/_deepGet.js:6 | false_positive: intentional_behavior / not_actionable (exclusion rule 13) -- read-only traversal; reads only intrinsics already reachable by the holder of obj; no write/pollution, no boundary crossed |
| f007 | _.invoke resolves a method by attacker path and applies it | modules/invoke.js:24 | false_positive: intentional_behavior (exclusion rule 3) -- documented dynamic-dispatch contract; property lookup + apply, never string-to-code eval; path fixed across items, not redirectable by data |
| f008 | _flatten trampoline has no cycle detection | modules/_flatten.js:23 | false_positive: implausible_trigger (exclusion rule 8) -- requires a caller-built cyclic array; JSON/deserialization cannot produce cycles; untrusted deep-nesting vector already defended by the trampoline; not a regression |
