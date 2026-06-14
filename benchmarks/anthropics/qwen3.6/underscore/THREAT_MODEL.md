# Threat Model: Underscore.js

## 1. System context

Underscore.js (v1.13.8) is a JavaScript functional programming utility library originally created by Jeremy Ashkenas at DocumentCloud. It provides ~100 functions for common data manipulation patterns — maps, filters, reductions, collections iteration, object introspection, array operations, function binding/delegation (bind, throttle, debounce), and string templating. It is distributed as an npm package (`underscore`) consumed by millions of downstream projects in both browser clients and Node.js servers.

The library has no direct infrastructure surface (no network listeners, no database connectors, no file I/O of its own). Its trust boundary is the JavaScript execution environment: attackers who can inject data consumed by Underscore functions can potentially achieve code execution (via template compilation), denial of service (via deeply nested data), or object-graph corruption (via prototype pollution through extend functions) within whatever process or browser context imports the library. It is one of the most widely-adopted npm dependencies ever, making a successful attack on Underscore multiply-impactful across the ecosystem.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Host process integrity (Node.js) | Integrity of the Node.js process that imports and executes Underscore functions | critical |
| Client-side execution sandbox (browser) | Integrity of the browser sandbox (DOM, cookies, session storage, origin isolation) when Underscore runs in a client context | critical |
| Template data confidentiality | Data values passed into `_.template()` that may contain sensitive information rendered or evaluated | high |
| Application object graph integrity | Integrity of JavaScript objects modified by `_.extend`, `_.defaults`, etc. that propagate to application state | high |
| Application availability | Availability of applications that depend on Underscore for core data processing | medium |
| Library supply chain | The npm package integrity and distribution pipeline for Underscore itself | critical |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|-|
| `_.template()` | Compiles arbitrary strings into executable JavaScript via `new Function()` | untrusted text → generated code → host process | Host process integrity, client-side execution sandbox, template data confidentiality |
| `_.isEqual()` | Deep equality comparison on two arbitrary objects | untrusted objects → memory/heap (DoS) or false-equality logic errors | Host process integrity, client-side execution sandbox, application object graph integrity |
| `_.flatten()` | Flattens arbitrary nested arrays | untrusted arrays → memory/heap (DoS) | Application availability, host process integrity |
| `_.extend()` / `_.extendOwn()` / `_.defaults()` | Copies enumerable properties from source objects into a target object | untrusted source objects → target object | Application object graph integrity |
| `_.result()` / `_.get()` | Traverses arbitrary object paths, invoking function-valued intermediates | untrusted object + path → arbitrary property/method access | Template data confidentiality, host process integrity, client-side execution sandbox |
| `_.invert()` | Inverts object key-value pairs; values become new keys | untrusted object values → object construction | Application object graph integrity |
| `_.mixin()` | Injects arbitrary function definitions into the Underscore global namespace and prototype | untrusted code definition → library namespace | Host process integrity, client-side execution sandbox |
| `_.propertyOf()` | Generates a function that looks up paths in an arbitrary object | untrusted object → arbitrary property access | Template data confidentiality |
| Build pipeline (`package.json` scripts) | Rollup bundling + Terser minification pipeline, `prepublishOnly` hook | build inputs → published artifact | Library supply chain |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Arbitrary code execution via untrusted data passed to `_.template()` | remote_unauth | `_.template()` code compilation (`new Function()`) | Host process integrity, client-side execution sandbox | critical | likely | partially_mitigated | bareIdentifier check on `variable` setting (CVE-2021-23358 fix) | CVE-2021-23358 |
| T2 | Denial of service via deeply nested data structures in `_.isEqual()` | remote_unauth | `_.isEqual()` object traversal / comparison | Host process integrity, application availability | critical | likely | partially_mitigated | iterative trampolining replaces recursion (CVE-2026-27601 fix); siblings may exist in derived paths | CVE-2026-27601 |
| T3 | Array prototype pollution via `_.extend()` / `_.defaults()` with untrusted source objects | remote_unauth | `_.extend()`/`_.defaults()` property copy (enumerates `for...in`, includes inherited properties like `__proto__`, `constructor`, `prototype`) | Application object graph integrity | critical | likely | unmitigated | none | |
| T4 | Denial of service via deeply nested arrays in `_.flatten()` | remote_unauth | `_.flatten()` array traversal | Application availability, host process integrity | medium | likely | partially_mitigated | iterative trampolining replaces recursion (CVE-2026-27601 fix) | CVE-2026-27601 |
| T5 | Sandbox escape via `_.template()` default `with(obj||{})` mode | remote_unauth | `_.template()` compilation with default (unspecified) variable setting; `with()` statement grants access to all scope properties as implicit variables | Host process integrity, client-side execution sandbox | critical | likely | partially_mitigated | bareIdentifier check (mitigates one path); `with()` remains the default | CVE-2021-23358 |
| T6 | Arbitrary function execution via `_.result()` with untrusted path traversing function-valued properties | remote_unauth | `_.result()` function invocation along path (`prop.call(obj)`) | Host process integrity, template data confidentiality | critical | possible | unmitigated | none | |
| T7 | Information loss or prototype pollution via `_.invert()` with untrusted values | remote_unauth | `_.invert()` creating new object keys from user-controlled values | Application object graph integrity | medium | possible | partially_mitigated | `Object.create(null)` would be needed for full mitigation; currently uses `{}` Literal | |
| T8 | Supply-chain compromise of the Underscore npm package affecting all downstream consumers | supply_chain | npm distribution pipeline | Library supply chain | critical | rare | partially_mitigated | npm registry protections; long reputation history | |
| T9 | Information exposure of sensitive data embedded in template evaluation context objects | remote_unauth | `_.template()` `with(obj||{})` — all properties of `obj` become accessible without explicit keys | Template data confidentiality | high | possible | partially_mitigated | `_.escape()` HTML-escapes interpolated values; but `with()` scope is still exposed | CVE-2021-23358 |
| T10 | Library namespace hijacking via `_.mixin()` with untrusted function definitions | remote_unauth | `_.mixin()` injecting arbitrary functions onto `_.prototype` | Host process integrity, client-side execution sandbox | high | possible | unmitigated | none | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Cross-site scripting via `_.template()` output | Mitigated by `_.escape()`; the remaining concern is in the consuming application's choice of `innerHTML` vs `textContent`, which is out of scope for Underscore itself |
| Repudiation | Not applicable; Underscore produces no network logs, audit trails, or multi-user action records |
| Data persistence integrity | Not applicable; Underscore operates on in-memory objects only and never persists data to disk or databases |
| Encryption/secret exposure | Not applicable; Underscore does not handle cryptographic keys, passwords, or secrets directly |
| Timing side-channel attacks on `_.isEqual()` | Lower priority; while the iterative comparison avoids recursion-based DoS, the linear search over keys still has data-dependent timing. However, exploiting this in practice requires a network-latency-observable deployment and is unlikely against a browser context |

## 6. Open questions

- The documentation says `_.template` must only be used for trusted input, but what deployment contexts in practice pass untrusted user data to `_.template()`? (This determines whether T1/T5/T9 have active exploitation in the wild.)
- How many consumers still rely on the `with(obj||{})` default mode of `_.template()` (setting `variable` explicitly is the safe path)? The current codebase has no way to measure usage.
- Is `_.extend()` / `_.defaults()` used with objects whose prototype chain the caller did not construct (e.g., deserialized JSON with `Object.create(null)` vs plain objects)? The `for...in` enumeration of `allKeys()` inherently traverses inherited properties — but does any real consumer call it on `__proto__`-tainted objects?
- Does `_.result()` get used to access properties through `__proto__` where function-valued prototype methods (e.g., `toString`, `valueOf`, `hasOwnProperty`) are invoked as callbacks?
- What is the actual download/install base of v1.13.x, and how rapidly is the stack-overflow fix (CVE-2026-27601) deploying? Many old applications still pin to vulnerable versions.
- The `_.escape()` function only handles six HTML entities (`&`, `<`, `>`, `"`, `'`, `` ` ``). Are there additional XSS vectors in rendering contexts (URL fragment injection, event handler attributes) that the escaping function does not address?
- `_.propertyOf()` generates closures over a passed-in object — can this be abused in memory-exhaustion scenarios if the object is attacker-controlled and contains millions of properties?

## 7. Provenance

- mode: bootstrap
- date: 2026-06-12
- target: /home/higgs/workspace/cyness/underscore @ d3ceb2a
- inputs: git-log + CHANGELOG mined; public source code only
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Remove `with(obj||{})` from `_.template()` default mode and require explicit `variable` setting | T1, T5, T9 | partial | L |
| Deprecate `_.extend()` in favor of `Object.assign()` or `lodash.cloneDeep` to prevent prototype pollution; or add `Object.create(null)` guard in `createAssigner` | T3 | partial | M |
| Remove `_.mixin()` or add strict allowlist gating for function names injected into the global namespace | T10 | partial | M |
| Add `_.result()` mode that skips property lookups on `__proto__` and only traverses `Object.create(null)`-safe paths | T6 | partial | M |
| Document `_.invert()` prototype pollution risk and add `Object.create(null)` in the implementation | T7 | partial | S |
| Pin npm integrity (`package-lock.json` / `shrinkwrap`) in downstream projects to specific package hashes to prevent lying-in-wait attacks | T8 | partial | S |
