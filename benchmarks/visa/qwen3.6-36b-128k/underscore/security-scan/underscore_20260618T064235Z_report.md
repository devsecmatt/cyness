# Agentic SAST — underscore

## Summary
No findings survived adversarial verification.

## Scan Metrics

- Scan ID: 2026-06-18T06:42:35Z__underscore
- Module: underscore
- Start: 2026-06-18T06:42:35Z
- End: 2026-06-19T09:43:59Z
- Duration (sec): 97284
- Files in scope: 188
- Files analyzed (unique): 183
- Coverage: 97.3%
- Chunks: 484 (risk=3, catch-all=153, specialist=328)
- Tokens (prompt): 21984313
- Tokens (completion): 1179776
- Tokens (total): 23164089

- Folders scanned: 2
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s6-verify | 1018 | 17,530,145 | 1,054,784 | 18,584,929 | 80.2 | 0 |
| s4-deepdive | 484 | 4,333,568 | 95,315 | 4,428,883 | 19.1 | 0 |
| s1-preprocess | 6 | 78,898 | 1,568 | 80,466 | 0.3 | 0 |
| s5-prefilter | 1 | 32,602 | 13,747 | 46,349 | 0.2 | 0 |
| s2-threatmodel | 1 | 3,567 | 5,301 | 8,868 | 0.0 | 0 |
| s3-decompose | 1 | 2,506 | 5,099 | 7,605 | 0.0 | 0 |
| s1-autoexclude | 1 | 2,466 | 3,179 | 5,645 | 0.0 | 0 |
| unlabeled | 2 | 561 | 783 | 1,344 | 0.0 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| javascript | 9972 | 9972 | 100.0 |
| other | 21737 | 201 | 0.9 |
| web-template | 4140 | 4140 | 100.0 |

## Scan Health

- Recoverable errors logged by stage: s6-verify=39
- Full error log: `underscore_20260618T064235Z_errors.jsonl`

## Threat Model

### System context

Underscore.js is a widely deployed, general-purpose functional programming utility library for JavaScript. It runs in client-side browsers, server-side Node.js, and AMD/CommonJS module environments without extending core prototypes. The library provides helper functions for collection/array manipulation, function binding, object utilities, templating, and chaining. It is consumed as a transitive or direct dependency in countless web applications, data-pipelines, and build tooling, acting as a foundational runtime helper rather than a standalone networked service or CLI tool.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Runtime Execution Environment | medium | The JavaScript VM (V8/SpiderMonkey/Chakra) of the host application where Underscore executes and may modify heap state or invoke functions. |
| Template Output Strings | high | Generated HTML or JavaScript strings rendered by _.template, often injected into DOM or eval contexts by host applications. |
| Library Package Integrity | medium | The integrity and provenance of the Underscore npm package, its version resolution, and transitive dependency tree. |

### Trust boundaries

- **_.template(string, data, settings)** — Untrusted host-context data → Template Compilation & Code Generation → Runtime Execution Environment, Template Output Strings
- **_.defaults / _.extend / _.merge** — Untrusted object properties → Internal prototype chain & object state mutation → Runtime Execution Environment
- **_.each / _.map / _.reduce** — Untrusted collections or iterables → Functional iteration & transformation → Runtime Execution Environment
- **npm require / ES module import** — Package registry & module resolution → Runtime code execution path → Library Package Integrity, Runtime Execution Environment

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | Arbitrary JavaScript execution via untrusted context data passed to _.template | local_user | _.template(string, data, settings) | Runtime Execution Environment | critical | likely | none (documented as consumer responsibility) |
| T2 | Client-side Cross-Site Scripting (XSS) via unescaped _.template output injected into DOM | remote_unauth | _.template(string, data, settings) | Template Output Strings | high | likely | none (relies on host application encoding) |
| T3 | Prototype pollution via malicious keys (e.g., __proto__, constructor, toString) in object-merging utilities | remote_unauth | _.defaults / _.extend / _.merge | Runtime Execution Environment | critical | possible | none |
| T4 | Denial of Service via deeply nested or circular data structures crashing functional iteration or cloning | remote_unauth | _.each / _.map / _.reduce | Runtime Execution Environment | medium | possible | none |
| T5 | Supply chain compromise or dependency confusion via npm registry aliasing or version mismatch | supply_chain | npm require / ES module import | Library Package Integrity | existential | rare | lockfiles, integrity hashes, pinned versions |

### Open questions

- Does the host application run _.template output through eval(), innerHTML, or raw DOM insertion without sanitization?
- What version range of Underscore is enforced across the ecosystem, and are legacy versions (pre-1.13.x) still deployed?
- Are there custom _.templateSettings overrides that disable auto-escaping or inject custom template functions?
- How does the host sandbox or CSP policy handle execution contexts where Underscore operates?
- Does the library's CJS/UMD/ESM dual-packaging introduce module resolution ambiguities that could be exploited for type confusion or code injection?

## Verification
- Raw findings (pre-verification): 132
- True positives (verified): 0
- False positives (dropped): 61
- Verifier errors (excluded — undetermined, not confirmed clean): 39
- Duplicates collapsed (all passes): 31
- Verification precision: 0.0%

## Findings (0)

## Exploit Chains

No exploit chains were identified — the findings above are independent and do not combine into a multi-step path.


## Dropped Findings

- **[UNCONFIRMED]** `modules/_tagTester.js:4` logic-flaw (spec-logic-bug-32) — s4 confidence 0.50 < gate 0.60
- **[DUP (pre-verify)]** `modules/_flatten.js:13` logic-flaw (spec-logic-bug-18) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `modules/invoke.js:19` logic-flaw (spec-access-control-81) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `modules/isEqual.js:16` logic-flaw (spec-access-control-90) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `modules/range.js:4` other (spec-access-control-133) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `modules/template.js:40` injection (spec-access-control-147) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `underscore-esm.js:903` injection (spec-logic-bug-02) — pre-verify semantic: Same `_.template` RCE defect reported in a different ES module file; merged with primary finding.
- **[DUP (pre-verify)]** `modules/_collectNonEnumProps.js:9` logic-flaw (spec-logic-bug-08) — pre-verify semantic: Same file and line reporting hash collision logic flaw; merged with primary `emulatedSet` finding.
- **[DUP (pre-verify)]** `modules/_createAssigner.js:9` injection (spec-logic-bug-09) — pre-verify semantic: Same file and adjacent line reporting missing key validation; covered by primary `_createAssigner` finding.
- **[DUP (pre-verify)]** `modules/_createIndexFinder.js:15` logic-flaw (spec-logic-bug-11) — pre-verify semantic: Same file reporting start index constraint drop; covered by primary `_createIndexFinder` finding.
- **[DUP (pre-verify)]** `modules/_group.js:7` logic-flaw (spec-logic-bug-21) — pre-verify semantic: Same file and line reporting missing partition invariant validation; covered by primary `_group` finding.
- **[DUP (pre-verify)]** `modules/bindAll.js:8` logic-flaw (spec-logic-bug-40) — pre-verify semantic: Same file reporting unfiltered key assignment prototype pollution; covered by primary `bindAll` finding.
- **[DUP (pre-verify)]** `modules/countBy.js:7` logic-flaw (spec-logic-bug-48) — pre-verify semantic: Same file and line reporting incorrect grouping key logic flaw; covered by primary `countBy` finding.
- **[DUP (pre-verify)]** `modules/flatten.js:5` logic-flaw (spec-logic-bug-67) — pre-verify semantic: Same file reporting boolean-to-depth conversion logic flaw; covered by primary `flatten` finding.
- **[DUP (pre-verify)]** `modules/get.js:9` logic-flaw (spec-logic-bug-69) — pre-verify semantic: Same file and line reporting undefined check logic flaw; covered by primary `get` finding.
- **[DUP (pre-verify)]** `modules/groupBy.js:7` other (spec-logic-bug-70) — pre-verify semantic: Same file and line reporting unchecked iteration key assignment; covered by primary `groupBy` finding.
- **[DUP (pre-verify)]** `modules/invert.js:8` logic-flaw (spec-logic-bug-80) — pre-verify semantic: Same file reporting unvalidated value coercion logic flaw; covered by primary `invert` finding.
- **[DUP (pre-verify)]** `modules/invoke.js:8` type-confusion (spec-logic-bug-81) — pre-verify semantic: Same file and line reporting primitive value bypass logic flaw; covered by primary `invoke` finding.
- **[DUP (pre-verify)]** `modules/isEqual.js:107` logic-flaw (spec-logic-bug-90) — pre-verify semantic: Same file reporting flawed constructor and key-count checks; covered by primary `isEqual` finding.
- **[DUP (pre-verify)]** `modules/iteratee.js:7` logic-flaw (spec-logic-bug-108) — pre-verify semantic: Same file and line reporting unfiltered iteratee keys; covered by primary `iteratee` finding.
- **[DUP (pre-verify)]** `modules/mapObject.js:6` logic-flaw (spec-logic-bug-113) — pre-verify semantic: Same file reporting unvalidated prototype-key injection; covered by primary `mapObject` finding.
- **[DUP (pre-verify)]** `modules/memoize.js:4` logic-flaw (spec-logic-bug-116) — pre-verify semantic: Same file reporting cache key collision logic flaw; covered by primary `memoize` finding.
- **[DUP (pre-verify)]** `modules/pick.js:9` logic-flaw (spec-logic-bug-128) — pre-verify semantic: Same file reporting unfiltered __proto__ logic flaw; covered by primary `pick` finding.
- **[DUP (pre-verify)]** `modules/range.js:4` logic-flaw (spec-logic-bug-133) — pre-verify semantic: Same file reporting unbounded array allocation logic flaw; covered by primary `range` finding.
- **[DUP (pre-verify)]** `modules/sortedIndex.js:12` logic-flaw (spec-logic-bug-145) — pre-verify semantic: Same file reporting malformed iteratee logic flaw; covered by primary `sortedIndex` finding.
- **[DUP (pre-verify)]** `modules/times.js:5` logic-flaw (spec-logic-bug-150) — pre-verify semantic: Same file reporting float truncation logic flaw; covered by primary `times` finding.
- **[DUP (pre-verify)]** `modules/toPath.js:7` logic-flaw (spec-logic-bug-152) — pre-verify semantic: Same file reporting mutable reference escape logic flaw; covered by primary `toPath` finding.
- **[DUP (pre-verify)]** `modules/uniqueId.js:4` logic-flaw (spec-logic-bug-158) — pre-verify semantic: Same file reporting unvalidated prefix parameter logic flaw; covered by primary `uniqueId` finding.
- **[DUP (pre-verify)]** `underscore.js:912` injection (spec-access-control-03) — pre-verify semantic: Same `_.template` RCE defect reported in bundled JS; merged with primary template finding.
- **[DUP (pre-verify)]** `modules/clone.js:6` injection (spec-access-control-43) — pre-verify semantic: Same file and line reporting unvalidated key copy; covered by primary `clone` finding.
- **[DUP (pre-verify)]** `modules/create.js:9` other (spec-access-control-49) — pre-verify semantic: Same file reporting missing property filtering logic flaw; covered by primary `create` finding.
- **[DUP (pre-verify)]** `modules/pick.js:9` other (spec-access-control-128) — pre-verify semantic: Same file reporting unsanitized enumerable keys; covered by primary `pick` finding.
- **[FP]** `modules/template.js:38` injection (spec-logic-bug-147) — The function `modules/template.js:38` is a generic templating utility in the Underscore.js library. While the `text` parameter acts as a "sink" for dynamic code execution via `new Function`, this repository contains no external entry points (e.g., HTTP handlers, routes) that pass untrusted or user-controlled input to `_.template()`. All callers within the repository are unit tests (`test/utility.js`) and static documentation, which pass hardcoded, developer-controlled strings. The vulnerability is a design property of the library that becomes exploitable only if a *consuming application* blindly passes user data to it; it is not a reachable vulnerability within this repository's source code boundary.
- **[FP]** `modules/_createAssigner.js:11` other (chunk-02) — Third-party library utility code (Underscore.js v1.13.8) with no in-application callers exposed to untrusted I/O; vendor dependency findings belong to the SCA pipeline.
- **[FP]** `modules/_flatten.js:7` logic-flaw (chunk-03) — Underscore.js is a client-side utility library with no external attack surface; cyclic arrays cannot arise from JSON deserialization, and reaching the sink requires the host application to construct a cyclic graph
- **[FP]** `underscore-esm-min.js:1` type-confusion (catchall-01) — third-party library code; scope is application code, not dependencies (handled by SCA)
- **[FP]** `modules/_baseIteratee.js:12` logic-flaw (catchall-05) — the "prototype pollution" affects only a locally-scoped object inside a closure that is never exposed to callers; no shared Object.prototype is modified and no downstream code can exploit it.
- **[VERIFY-ERR]** `modules/_collectNonEnumProps.js:9` injection (catchall-08) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_createIndexFinder.js:7` other (catchall-09) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_deepGet.js:2` logic-flaw (catchall-13) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_group.js:7` injection (catchall-18) — verifier output unparseable
- **[FP]** `modules/bindAll.js:14` other (catchall-36) — The scanner confuses setting an instance's [[Prototype]] (obj.__proto__) with mutating the global Object.prototype. These are distinct operations in JavaScript; the former does not pollute the global prototype chain.
- **[FP]** `modules/countBy.js:7` injection (catchall-43) — Scanner's core claim that result['__proto__'] = 1 pollutes Object.prototype is technically wrong for ES5+ engines; __proto__ is an accessor that sets the target object's prototype, not a property on Object.prototype.
- **[VERIFY-ERR]** `modules/create.js:7` injection (catchall-44) — verifier output unparseable
- **[FP]** `modules/every.js:6` logic-flaw (spec-logic-bug-57) — (no reason given)
- **[FP]** `modules/flatten.js:5` other (catchall-58) — The scanner misread the code; `_flatten` uses an explicit iterative stack (array), not recursion, so deep nesting causes heap growth not stack exhaustion.
- **[FP]** `modules/get.js:9` info-leak (catchall-60) — utility library with no network entry point; Object.prototype is already publicly accessible in all JS environments; the "information disclosure" describes standard JavaScript object behavior, not a vulnerability in context
- **[FP]** `modules/groupBy.js:7` injection (catchall-61) — Scanner incorrectly claims `result['__proto__'] = [value]` modifies `Object.prototype`; in ES2015+ it only sets the target object's own prototype (no global pollution). Additionally, this is a pure library (underscore.js) with no application-level HTTP routes to reach it.
- **[FP]** `modules/index-default.js:20` injection (catchall-65) — mixin() filters via functions()/isFunction() which excludes __proto__/constructor; line 23 uses a static import (allExports), not external input; even if user data reaches _.mixin, the functions() guard and the fact that only function-named keys are assigned to _.prototype prevent prototype pollution
- **[FP]** `modules/indexBy.js:5` logic-flaw (catchall-67) — Scanner misreads JS `__proto__` assignment behavior (creates own property, not prototype mutation in modern engines); code is third-party library with no production callers
- **[FP]** `modules/invert.js:5` injection (catchall-71) — The only caller in the codebase passes a hardcoded safe object (`escapeMap`) with no `__proto__`/`constructor`/`hasOwnProperty` values; additionally, modern JS engines no longer permit prototype pollution via `__proto__` assignment on plain objects.
- **[FP]** `modules/invoke.js:8` logic-flaw (catchall-72) — pure utility library with no server-side code, no external entry point to invoke()
- **[FP]** `modules/isEqual.js:20` other (catchall-81) — pure utility library with no network entry points or server code; exploit scenario describes application-layer misconfiguration, not a library vulnerability
- **[FP]** `modules/iteratee.js:7` injection (catchall-99) — scanner misread `__proto__` assignment semantics; it sets a temporary object's prototype, not Object.prototype globally
- **[VERIFY-ERR]** `modules/map.js:5` logic-flaw (catchall-103) — verifier output unparseable
- **[VERIFY-ERR]** `modules/mapObject.js:8` other (catchall-104) — verifier output unparseable
- **[VERIFY-ERR]** `modules/matcher.js:7` injection (catchall-105) — verifier output unparseable
- **[FP]** `modules/max.js:10` logic-flaw (catchall-106) — **
- **[VERIFY-ERR]** `modules/memoize.js:7` other (catchall-107) — verifier output unparseable
- **[VERIFY-ERR]** `modules/mixin.js:8` injection (catchall-109) — verifier output unparseable
- **[VERIFY-ERR]** `modules/object.js:6` injection (spec-logic-bug-122) — verifier output unparseable
- **[FP]** `modules/omit.js:10` other (catchall-114) — Scanner misreads JavaScript semantics: `__proto__` assignment sets the object's [[Prototype]], not Object.prototype; no global prototype pollution occurs. No external caller chain exists in this standalone library.
- **[VERIFY-ERR]** `modules/pick.js:23` injection (catchall-120) — verifier output unparseable
- **[FP]** `modules/random.js:7` logic-flaw (spec-logic-bug-132) — This is the Underscore.js utility library; `random()` is used exclusively for benign `sample()`/`shuffle()` data manipulation, not for tokens, OTPs, or any security-adjacent purpose. The vulnerability narrative requires a usage context (security token generation) that does not exist in this codebase.
- **[FP]** `modules/range.js:13` other (catchall-125) — Library utility function with no internal attack surface; V8 enforces a hard `RangeError` cap on array length preventing unbounded allocation; input validation is the caller's responsibility.
- **[FP]** `modules/sortedIndex.js:6` injection (catchall-136) — `sortedIndex` is a function within the Underscore.js utility library that intentionally accepts arbitrary functions as the `iteratee` parameter. Passing a function callback in JavaScript is the standard API pattern and not an injection flaw; the code simply invokes the provided function via `call`/`apply` rather than `eval`-ing text. An attacker supplying a function to be passed as a callback is functionally no different from having code execution already.
- **[FP]** `modules/times.js:5` other (catchall-139) — No production caller of times() exists in this repo; the exploit scenario (req.query → _.times) is fabricated with no code to support it. This is a utility library, not a server.
- **[FP]** `modules/toPath.js:6` injection (catchall-141) — underscore.js has no _.set() function; toPath is only consumed by read-only functions (get, has, property, result), so there is no path through the codebase that can mutate objects via array paths
- **[VERIFY-ERR]** `modules/uniqueId.js:4` other (catchall-147) — verifier output unparseable
- **[FP]** `underscore.js:1060` logic-flaw (spec-logic-bug-03) — underscore.js is a pure utility library with no server endpoints or external entry points; the described attack scenario requires a consuming application to pass untrusted data to _.flatten()
- **[FP]** `modules/_createEscaper.js:10` injection (spec-logic-bug-10) — Both callers of createEscaper use statically-defined, hardcoded entity maps that contain no regex metacharacters; the function is not exposed for dynamic configuration and there is no external code path to influence the map parameter.
- **[VERIFY-ERR]** `modules/_createPredicateIndexFinder.js:9` logic-flaw (spec-logic-bug-12) — verifier output unparseable
- **[FP]** `modules/_createReduce.js:12` logic-flaw (spec-logic-bug-13) — The "leaked" value is merely the caller's own input property reused as the initial accumulator on an empty traversal; it is a functional logic bug with zero security boundary violation or privilege escalation.
- **[VERIFY-ERR]** `modules/_createSizePropertyCheck.js:1` logic-flaw (spec-logic-bug-14) — verifier output unparseable
- **[VERIFY-ERR]** `modules/_executeBound.js:7` logic-flaw (spec-logic-bug-17) — verifier output unparseable
- **[FP]** `modules/_getByteLength.js:4` logic-flaw (spec-logic-bug-19) — _getByteLength is an internal, non-exported helper with type guards on all call sites; no public API enables spoofed input, and no downstream code allocates memory or exposes data based on its return value.
- **[FP]** `modules/_isBufferLike.js:6` logic-flaw (spec-logic-bug-25) — the scanner misread the guard's semantics: it correctly fails-safe (returns false) for all edge cases (NaN, Infinity, undefined) rather than being "neutralized"; _isBufferLike is also unreachable as a guard because modern runtimes use native ArrayBuffer.isView; and isTypedArray is used for data comparison, not security enforcement
- **[FP]** `modules/_keyInObj.js:3` logic-flaw (spec-logic-bug-26) — The scanner's exploit scenario fabricates a call chain (`defaults`/`extend` → `keyInObj`) that does not exist; `keyInObj` is only called by `pick.js` as a callback predicate where `value` is the standard iteratee `obj[key]` argument, not a security context, and no prototype pollution is achievable.
- **[VERIFY-ERR]** `modules/_methodFingerprint.js:9` logic-flaw (spec-logic-bug-27) — verifier output unparseable
- **[FP]** `modules/_optimizeCb.js:4` logic-flaw (spec-logic-bug-28) — no external caller can inject user-controlled argCount through the public API; the module is a private internal helper with no exploitable path
- **[FP]** `modules/_toBufferView.js:5` logic-flaw (spec-logic-bug-33) — Scanner's core factual claim that DataView lacks byteLength is incorrect per the ECMAScript spec (ES6+); data loss does not occur, and even if it did, the sole caller (isEqual) is a general-purpose deep-comparison utility with no security boundary.
- **[VERIFY-ERR]** `modules/after.js:2` logic-flaw (spec-logic-bug-36) — verifier output unparseable
- **[FP]** `modules/before.js:3` logic-flaw (spec-logic-bug-38) — The "off-by-one" is the documented semantics of _.before(n); times=1 intentionally fires 0 times, no external caller is forced into this path, and the function is a pure functional combinator with no attack surface.
- **[VERIFY-ERR]** `modules/bind.js:7` logic-flaw (spec-logic-bug-39) — verifier output unparseable
- **[FP]** `modules/chunk.js:5` logic-flaw (spec-logic-bug-42) — No external entry point; chunk() is only called by internal tests with hardcoded integer literals; the repo is a pure utility library with no server/API surface.
- **[FP]** `modules/clone.js:6` logic-flaw (spec-logic-bug-43) — Scanner misread isObject's function check; primitives are value types (inherently unclonable) by design, not a bypass; clone is a library utility with no application entry point or security boundary to cross
- **[FP]** `modules/compact.js:5` logic-flaw (spec-logic-bug-44) — intentional API design; the function's documented purpose is to remove falsy values including 0/false/"". No security boundary crossed, no exploit path.
- **[VERIFY-ERR]** `modules/contains.js:6` logic-flaw (spec-logic-bug-47) — verifier output unparseable
- **[FP]** `modules/debounce.js:23` logic-flaw (spec-logic-bug-50) — The code is a generic utility library with no embedded trust boundary or security semantics; there are zero production callers and no external entry point. The described "context leak" is a generic `this`-binding race with demonstrated behavioral incorrectness but zero security impact.
- **[FP]** `modules/defaults.js:1` logic-flaw (spec-logic-bug-51) — Underscore library source code with no application-level external input path; prototype pollution in library code is handled by SCA pipeline
- **[VERIFY-ERR]** `modules/defer.js:3` logic-flaw (spec-logic-bug-52) — verifier output unparseable
- **[VERIFY-ERR]** `modules/delay.js:6` logic-flaw (spec-logic-bug-53) — verifier output unparseable
- **[VERIFY-ERR]** `modules/difference.js:8` logic-flaw (spec-logic-bug-54) — verifier output unparseable
- **[FP]** `modules/each.js:9` logic-flaw (spec-logic-bug-55) — Scanner misidentified standard library forEach behavior as a vulnerability; context mutation is inherent to object passing in JS, not a logic flaw in a collection utility with no security gates.
- **[FP]** `modules/escape.js:1` logic-flaw (spec-logic-bug-56) — The scanner misread the data flow: escapeMap is an unexported internal object in a dependency-free module; the regex alphabet is baked at initialization time with no external influence path, and escapeMap never escapes its module scope to any attacker-controlled context.
- **[FP]** `modules/extend.js:1` injection (spec-logic-bug-58) — (no reason given)
- **[VERIFY-ERR]** `modules/extendOwn.js:7` injection (spec-logic-bug-59) — verifier output unparseable
- **[VERIFY-ERR]** `modules/findKey.js:5` logic-flaw (spec-logic-bug-63) — verifier output unparseable
- **[VERIFY-ERR]** `modules/first.js:5` logic-flaw (spec-logic-bug-66) — verifier output unparseable
- **[FP]** `modules/has.js:8` logic-flaw (spec-logic-bug-71) — The scanner's core technical claim is factually wrong: hasOwnProperty.call never returns true for inherited properties; the function works exactly as designed, and there is no external attacker-facing entry point.
- **[FP]** `modules/initial.js:6` logic-flaw (spec-logic-bug-78) — The arithmetic misbehavior exists but `initial` is a pure data-transformation utility in Underscore.js with no security boundary, no external attacker entry point, and no downstream security-sensitive usage.
- **[VERIFY-ERR]** `modules/intersection.js:6` logic-flaw (spec-logic-bug-79) — verifier output unparseable
- **[FP]** `modules/isArrayBuffer.js:1` logic-flaw (spec-logic-bug-84) — Scanner misread the code mechanism (capture-by-reference prevents `Object.prototype.toString` poisoning), and the code is a non-secure utility library with no security boundary.
- **[FP]** `modules/isEmpty.js:9` logic-flaw (spec-logic-bug-89) — Scanner misidentified documented library behavior as a bug; no attacker-facing entry points exist; the "conflation" is the intentional semantic contract of _.isEmpty()
- **[FP]** `modules/isFinite.js:5` logic-flaw (spec-logic-bug-92) — Predicate behavior is by-design per test suite; underscore uses loose coercion intentionally, not a vulnerability
- **[VERIFY-ERR]** `modules/isMatch.js:5` logic-flaw (spec-logic-bug-95) — verifier output unparseable
- **[VERIFY-ERR]** `modules/isTypedArray.js:8` logic-flaw (spec-logic-bug-104) — verifier output unparseable
- **[FP]** `modules/keys.js:9` logic-flaw (spec-logic-bug-109) — scanner misread `!!obj` guard in isObject; `isObject(null)` is `false`, so `null` returns `[]` early at line 9 and never reaches `nativeKeys(null)`. Test `test/objects.js:16` confirms this behavior.
- **[FP]** `modules/last.js:6` logic-flaw (spec-logic-bug-110) — V8 has explicit hard limits on array length that prevent the claimed unbounded allocation; the impact is a predictable RangeError, not heap exhaustion
- **[FP]** `modules/lastIndexOf.js:1` logic-flaw (spec-logic-bug-111) — (no reason given)
- **[FP]** `modules/min.js:10` logic-flaw (spec-logic-bug-117) — **
- **[VERIFY-ERR]** `modules/once.js:6` logic-flaw (spec-logic-bug-124) — verifier output unparseable
- **[FP]** `modules/propertyOf.js:7` logic-flaw (spec-logic-bug-131) — Prototype chain traversal via object[key] is standard JavaScript and the **intended, documented** behavior of Underscore.js's `_.propertyOf`. The test at line 1064 explicitly confirms this: `"should return properties from further up the prototype chain"`. Getting `constructor`, `prototype`, or other Object.prototype members is always publicly accessible in JS and provides no attack surface beyond what any code already possesses.
- **[FP]** `modules/reject.js:6` logic-flaw (spec-logic-bug-136) — Scanner fabricated a "sentinel dispatcher" in cb that doesn't exist; baseIteratee returns property() for string predicates, not identity, and no external entry point exists
- **[FP]** `modules/restArguments.js:6` logic-flaw (spec-logic-bug-138) — No production caller triggers this path; zero-length functions are never passed to `restArguments` within this codebase. The scenario requires external misuse of the public API.
- **[VERIFY-ERR]** `modules/result.js:14` logic-flaw (spec-logic-bug-139) — verifier output unparseable
- **[FP]** `modules/sample.js:12` logic-flaw (spec-logic-bug-140) — Underscore.js pure utility library; no external entry point or caller that could pass untrusted `n`; impact is only empty-array return
- **[VERIFY-ERR]** `modules/shuffle.js:5` logic-flaw (spec-logic-bug-141) — verifier output unparseable
- **[VERIFY-ERR]** `modules/size.js:5` logic-flaw (spec-logic-bug-142) — verifier output unparseable
- **[VERIFY-ERR]** `modules/some.js:8` logic-flaw (spec-logic-bug-143) — verifier output unparseable
- **[FP]** `modules/sortBy.js:15` logic-flaw (spec-logic-bug-144) — Correctly identified type-coercion behavior in a general-purpose sorting utility, but the "impact" is a logic/correctness issue with no security boundary, no auth bypass, and no data exposure; the claimed exploit scenario relies on downstream application misuse rather than a vulnerable component.
- **[VERIFY-ERR]** `modules/throttle.js:8` logic-flaw (spec-logic-bug-149) — verifier output unparseable
- **[VERIFY-ERR]** `modules/toArray.js:10` logic-flaw (spec-logic-bug-151) — 'utf-8' codec can't encode character '\ud800' in position 6663: surrogates not allowed
- **[FP]** `modules/underscore-array-methods.js:13` logic-flaw (spec-logic-bug-153) — scanner misread reachability: for frozen/TypedArray inputs, method.apply() on line 12 throws before the delete line; for normal arrays, delete on index 0 after length=0 is a no-op with no residual data; no security boundary in a pure client-side utility library.
- **[FP]** `modules/underscore.js:6` logic-flaw (spec-logic-bug-154) — The scanner confused the instance field name "_wrapped" with sensitive internal state. The data through this function is entirely caller-owned with no security boundary crossed; mutations of caller-provided data are not exploitable.
- **[VERIFY-ERR]** `modules/unescape.js:2` logic-flaw (spec-logic-bug-155) — verifier output unparseable
- **[VERIFY-ERR]** `modules/union.js:7` logic-flaw (spec-logic-bug-156) — verifier output unparseable
- **[FP]** `modules/uniq.js:12` logic-flaw (spec-logic-bug-157) — The scanner misread `baseIteratee`'s fallback logic; `cb()` always returns a truthy property accessor for numeric inputs, and the behavior is an intentional, test-verified API feature.
- **[FP]** `modules/unzip.js:8` logic-flaw (spec-logic-bug-159) — underscore.js utility library with no server-side or network-facing entry point; the library transposes data structures and has no inherent attack surface, and the prototype traversal claim is a semantic quirk with no security boundary crossed by numeric array indices
- **[VERIFY-ERR]** `modules/values.js:4` logic-flaw (spec-logic-bug-160) — verifier output unparseable
- **[FP]** `modules/without.js:5` logic-flaw (spec-logic-bug-162) — ** — The scanner misread the call chain: `difference` calls `flatten(rest, true, true)` which correctly unwraps the packed arrays, so the claimed "structural mismatch" does not occur for contained scalar values. The `NaN !== NaN` observation is a standard JS quirk, not a bypassable flaw in this function's logic.
- **[FP]** `modules/wrap.js:6` logic-flaw (spec-logic-bug-163) — Pure library function in Underscore.js with no external caller or input path; no exploitation boundary exists


---

## Appendix: Scan Scope

### Folders scanned (2)

- `./`
- `modules/`

### Excluded from scan (241 files)

**Folders** (matched `exclude_dirs`):

- `docs/` — 179 files
- `.git/` — 28 files
- `test/` — 14 files
- `.github/` — 3 files
- `test-treeshake/` — 3 files
- `checkpoints/` — 1 files
- `patches/` — 1 files

**File types** (matched `exclude_exts`):

- `*.map` — 8 files
- `*.ico` — 1 files

**Patterns** (matched `exclude_globs`):

- `**/LICENSE` — 1 files
- `**/.gitignore` — 1 files
- `**/.editorconfig` — 1 files
