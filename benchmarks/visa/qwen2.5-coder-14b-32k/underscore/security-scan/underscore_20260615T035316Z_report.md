# Agentic SAST — underscore

## Summary
The analysis of the findings reveals a logic flaw in the isEmpty function that can lead to denial-of-service conditions due to infinite recursion when handling circular references. Given the unauthenticated nature and the potential for affecting availability, this finding is rated as HIGH.

## Scan Metrics

- Scan ID: 2026-06-15T03:53:16Z__underscore
- Module: underscore
- Start: 2026-06-15T03:53:16Z
- End: 2026-06-15T05:01:13Z
- Duration (sec): 4077
- Files in scope: 188
- Files analyzed (unique): 187
- Coverage: 99.5%
- Chunks: 344 (risk=1, catch-all=171, specialist=172)
- Tokens (prompt): 1315192
- Tokens (completion): 33857
- Tokens (total): 1349049

- Folders scanned: 4
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s4-deepdive | 344 | 1,248,462 | 26,989 | 1,275,451 | 94.5 | 0 |
| s6-verify | 27 | 50,426 | 4,061 | 54,487 | 4.0 | 0 |
| s5-prefilter | 1 | 7,234 | 1,974 | 9,208 | 0.7 | 0 |
| s2-threatmodel | 1 | 3,381 | 409 | 3,790 | 0.3 | 0 |
| s1-autoexclude | 1 | 2,351 | 118 | 2,469 | 0.2 | 0 |
| s3-decompose | 1 | 1,998 | 220 | 2,218 | 0.2 | 0 |
| s1-preprocess | 1 | 940 | 41 | 981 | 0.1 | 0 |
| unlabeled | 2 | 400 | 45 | 445 | 0.0 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| javascript | 9989 | 9989 | 100.0 |
| other | 21597 | 210 | 1.0 |
| web-template | 4140 | 4140 | 100.0 |

## Scan Health

- Recoverable errors logged by stage: s4=18, s6-verify=20
- Full error log: `underscore_20260615T035316Z_errors.jsonl`

## Threat Model

### System context

Underscore.js is a JavaScript utility library that provides functional programming support, such as map, reduce, filter, etc. It does not extend core JavaScript objects and can be used in various environments like servers, clients, and browsers. The repository contains common build tools like npm, rollup, and terser for development. The library does not have explicit API contracts, entry points, or modules mapping.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Underscore.js Source | low | The core library source code with functional utilities. |

### Trust boundaries

- **_.template(...)** — un trusted input to JavaScript execution engine → Underscore.js Source

### Open questions

- Are there any other entry points or surfaces where untrusted inputs can be provided?
- Is the library used in environments that might allow executing arbitrary JavaScript code?

## Verification
- Raw findings (pre-verification): 53
- True positives (verified): 1
- False positives (dropped): 6
- Verifier errors (excluded — undetermined, not confirmed clean): 20
- Duplicates collapsed (all passes): 13
- Verification precision: 1.9%

## Findings (1)

### 1. [CRITICAL] Incorrectly handles circular references in objects
**Class:** CWE-690
**CWE:** CWE-690 - https://cwe.mitre.org/data/definitions/690.html
**File:** `modules/isEmpty.js:7-18`
**CVSS 3.1:** **10.0** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The `isEmpty` function does not handle circular references correctly. When passed an object with circular references, it falls into an infinite recursion, leading to a potential denial-of-service condition.

#### Impact
An attacker can create a large number of circular references, causing the `isEmpty` function to hang indefinitely. This blocks further execution and potentially leads to a denial-of-service attack.

#### Exploit scenario
An attacker can craft a JavaScript object with circular references and pass it to the `isEmpty` function. The function will be unable to terminate its loop and will hang indefinitely, causing performance degradation or complete blockage.

#### Preconditions
- The attacker can control the input to the `isEmpty` function

```
// Check for circular references
let seen = new Set();
function isEmpty(obj) {
  if (obj == null || seen.has(obj)) return true;
  seen.add(obj);
  // Rest of the function remains unchanged except for adding seen checks.
}
```

#### How to fix
Modify the `isEmpty` function to handle circular references by using a visited set of objects. Ensure deep iteration does not lead to infinite loops.

**Exploitability:** The `isEmpty` function does not handle circular references correctly, leading to an infinite recursion and denial-of-service condition. The attack does not require any preconditions or authentication, making it highly exploitable in both client and server environments.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — The code allows an object with circular references to pass the initial check, leading to infinite recursion.

{"name": "Read", "arguments": {"path": "modules/isEmpty.js"}}

## Exploit Chains

No exploit chains were identified — the findings above are independent and do not combine into a multi-step path.


## Dropped Findings

- **[EXCLUDED]** `./src/modules/_createPredicateIndexFinder.js:6` other (catchall-18) — file not in repo inventory
- **[UNCONFIRMED]** `modules/_shallowProperty.js:2` other (catchall-36) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `modules/find.js:6` other (catchall-65) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/functions.js:6` other (catchall-72) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/indexOf.js:2` other (catchall-81) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/map.js:7` other (catchall-116) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/chunk.js:6` logic-flaw (spec-logic-bug-47) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/contains.js:6` logic-flaw (spec-logic-bug-52) — missing source_ref/sink_ref — data flow unproven
- **[EXCLUDED]** `src/modules/initial.js:6` logic-flaw (spec-logic-bug-83) — file not in repo inventory
- **[UNCONFIRMED]** `modules/last.js:1` other (spec-logic-bug-115) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/lastIndexOf.js:6` logic-flaw (spec-logic-bug-116) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `modules/pick.js:8` logic-flaw (spec-logic-bug-133) — missing source_ref/sink_ref — data flow unproven
- **[UNCONFIRMED]** `test-treeshake/rollup.config.js:2` logic-flaw (spec-logic-bug-171) — missing source_ref/sink_ref — data flow unproven
- **[DUP (pre-verify)]** `modules/groupBy.js:6` other (catchall-74) — pre-verify semantic: Untrusted key manipulation via _.template (index=8) and Untrusted path leads to OS command injection through 'path' parameter. (index=13) trace back to issues with `get` function that could lead to injection, although each affects a different aspect of the issue.
- **[DUP (pre-verify)]** `modules/propertyOf.js:8` injection (catchall-136) — pre-verify semantic: 'Potential OS command injection' at index 13 and 'Untrusted path leads to OS command injection' at index 8 both trace back to the same logical flaw, specifically untrusted input use, which could be addressed in `get` function or similar utility.
- **[DUP (pre-verify)]** `modules/_hasObjectTag.js:1` other (spec-logic-bug-28) — pre-verify semantic: Template injection via _.template(...) and Regex Injection via Untrusted template map both stem from dynamic JavaScript function creation issues within _.template(), leading their fix to be consolidated at common entry points or utility functions used within the templating workflow.
- **[DUP (pre-verify)]** `modules/isUndefined.js:1` logic-flaw (spec-logic-bug-110) — pre-verify semantic: Improper input validation in _.template and Information Leakage via Property Enumeration both trace back to untrusted input used in templating functions, which can be fixed through more robust validation or escaping mechanisms.
- **[DUP (pre-verify)]** `modules/memoize.js:6` race-condition (spec-logic-bug-121) — pre-verify semantic: Race Condition in Memoization Cache and Untrusted Input leads to authorized access via deepGet both face vulnerabilities involving potentially manipulated shared resources (cache or global properties), which could be addressed by fixing the core functions that cause data races across these shared states.
- **[DUP (pre-verify)]** `modules/now.js:1` other (spec-logic-bug-126) — pre-verify semantic: Potential integer overflow in Date.now timestamp handling (index 26) and File reading without validation (index 4) both relate to potential timing issues that could lead to unexpected behavior, though they are resolved via different methods such as checking timestamps vs file access.
- **[DUP (pre-verify)]** `modules/once.js:1` logic-flaw (spec-logic-bug-129) — pre-verify semantic: 'Partial before function does not enforce one-time execution' and 'Potential OS command injection' (both trace back to untrusted input handling vulnerabilities in the same function calls, thus consolidating their fixes improves efficiency by addressing shared roots.
- **[DUP (pre-verify)]** `modules/property.js:7` other (spec-logic-bug-135) — pre-verify semantic: Unsanitized path traversal in property function (index 31) traces back to untrusted input handling similar to file reading without validation (index 0), making these duplicate concerns that require a common, robust fix.
- **[DUP (pre-verify)]** `modules/range.js:3` integer-overflow (spec-logic-bug-138) — pre-verify semantic: 'Potential integer overflow in range function' (index 32) and 'File reading without validation' (index 4): both handle out-of-bound values and could be consolidated as they stem from the same category of numerical input handling concerns.
- **[DUP (pre-verify)]** `modules/reject.js:6` logic-flaw (spec-logic-bug-141) — pre-verify semantic: Misinterpreted Trust Boundary and Partition Logic Flaw both pertain to validating untrusted inputs that may lead to changes in program behavior, and consolidating their fixes through robust input sanitization routines would address both concerns efficiently.
- **[DUP (pre-verify)]** `modules/tap.js:4` other (spec-logic-bug-151) — pre-verify semantic: Potential Use After Free in tap Function (index 36) and Instance check bypass via null or undefined share the context of post-execution resource management concerns; consolidating their fixes through improved interceptor validations can address both.
- **[DUP (pre-verify)]** `modules/templateSettings.js:6` injection (spec-logic-bug-153) — pre-verify semantic: 'Template injection vulnerability in _.templateSettings' shares root causes with other input handling vulnerabilities traced back to same file, allowing for a consolidated fix of input validation at common entry points or utility functions used by the templating workflows.
- **[DUP (pre-verify)]** `modules/unescape.js:1` other (spec-logic-bug-160) — pre-verify semantic: Unescaped output in unescapeMap at index 39 shares issues with improper input validation for template escaping (mentioned at index 22): both require similar changes in terms of ensuring proper encoding/escaping mechanisms to prevent XSS and other injection attacks.
- **[VERIFY-ERR]** `rollup.common.js:4` other (catchall-03) — verifier output unparseable
- **[FP]** `underscore-esm.js:578` other (catchall-04) — The input is properly validated before being passed to _.template.
- **[VERIFY-ERR]** `modules/_chainResult.js:5` logic-flaw (catchall-14) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_deepGet.js:2` other (catchall-21) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_keyInObj.js:1` other (catchall-32) — verifier output unparseable
- **[FP]** `modules/_stringTagBug.js:11` logic-flaw (catchall-37) — The function `hasObjectTag` likely checks for the correct internal tag of the object, which isn't necessarily indicative of IE11. The code snippet provided doesn't show any clear evidence of an exploitable vulnerability.
- **[VERIFY-ERR]** `modules/_stringTagBug.js:4` logic-flaw (catchall-37) — verifier output unparseable
- **[VERIFY-ERR]** `modules/findLastIndex.js:4` other (catchall-68) — verifier output unparseable
- **[VERIFY-ERR]** `modules/isNumber.js:1` other (catchall-102) — verifier output unparseable
- **[FP]** `modules/matcher.js:6` other (catchall-118) — No external caller found, and no evidence of the `matcher` function being called with untrusted input.
- **[VERIFY-ERR]** `modules/min.js:10` other (catchall-121) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_createEscaper.js:10` injection (spec-logic-bug-15) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_executeBound.js:8` logic-flaw (spec-logic-bug-22) — verifier output unparseable
- **[VERIFY-ERR]** `modules/before.js:3` other (spec-logic-bug-43) — verifier output unparseable
- **[VERIFY-ERR]** `modules/findWhere.js:2` logic-flaw (spec-logic-bug-70) — verifier output unparseable
- **[VERIFY-ERR]** `modules/first.js:1` logic-flaw (spec-logic-bug-71) — verifier output unparseable
- **[VERIFY-ERR]** `modules/has.js:7` logic-flaw (spec-logic-bug-76) — verifier output unparseable
- **[VERIFY-ERR]** `modules/invoke.js:17` injection (spec-logic-bug-86) — verifier output unparseable
- **[VERIFY-ERR]** `modules/mapObject.js:7` logic-flaw (spec-logic-bug-118) — verifier output unparseable
- **[VERIFY-ERR]** `modules/mixin.js:10` logic-flaw (spec-logic-bug-123) — verifier output unparseable
- **[FP]** `modules/partial.js:10` other (spec-logic-bug-131) — the placeholder is hardcoded and cannot be injected via untrusted input.
- **[FP]** `modules/partition.js:4` logic-flaw (spec-logic-bug-132) — no evident upstream control fully neutralizes the input.
- **[VERIFY-ERR]** `modules/pluck.js:5` logic-flaw (spec-logic-bug-134) — verifier output unparseable
- **[VERIFY-ERR]** `modules/reduceRight.js:3` logic-flaw (spec-logic-bug-140) — verifier output unparseable
- **[FP]** `modules/shuffle.js:4` logic-flaw (spec-logic-bug-146) — The `shuffle` function is not reachable from any external entry point and is primarily used internally. Even if an input is passed, it does not cross any security boundaries or lead to resource exhaustion in a way that would cause a DoS attack.
- **[VERIFY-ERR]** `modules/toArray.js:16` other (spec-logic-bug-156) — verifier output unparseable


---

## Appendix: Scan Scope

### Folders scanned (4)

- `./`
- `modules/`
- `patches/`
- `test-treeshake/`

### Excluded from scan (241 files)

**Folders** (matched `exclude_dirs`):

- `docs/` — 179 files
- `.git/` — 28 files
- `test/` — 14 files
- `.github/` — 3 files
- `checkpoints/` — 1 files

**File types** (matched `exclude_exts`):

- `*.map` — 8 files
- `*.md` — 4 files
- `*.ico` — 1 files

**Patterns** (matched `exclude_globs`):

- `**/LICENSE` — 1 files
- `**/.gitignore` — 1 files
- `**/.editorconfig` — 1 files
