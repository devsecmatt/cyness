# Threat Model: Underscore.js

## 1. System context

Underscore is a JavaScript functional-programming utility library (package
`underscore` v1.13.8, "JavaScript's functional programming helper library").
The source is authored as ~161 small ES modules under `modules/` and bundled
into UMD, ESM, and CommonJS distributables (`underscore-umd.js`,
`underscore-esm.js`, `underscore-node*.cjs/mjs`, and minified variants) that
ship on npm. It has no runtime of its own: it is a dependency embedded inside
other programs and executes wherever the host does — in a browser tab, in a
Node.js server, or in a build tool.

Because it is a library, the trust boundary is the **embedding application**.
Underscore exposes no network listeners, no file or process I/O, and reads no
configuration; it operates entirely on the JavaScript values its caller passes
in. Its security-relevant behavior therefore lives in (a) functions that
transform caller data and can be driven into pathological work, (b) the HTML
escaping helpers whose correctness downstream code relies on to prevent XSS,
and (c) `_.template`, which compiles a caller-supplied string into executable
code via the `Function` constructor — powerful by design, and dangerous if the
caller feeds it untrusted input.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Host application integrity | The JS execution context (browser realm or Node process) the library runs inside; `_.template` compiles strings to code in it. | critical |
| Host availability (event loop / call stack) | The single-threaded runtime that recursive/iterative helpers consume; stack and CPU are exhaustible. | medium |
| Output-encoding correctness | The HTML-escaping guarantee of `_.escape`; downstream templates rely on it to prevent stored/reflected XSS. | high |
| Object/prototype integrity | The shared `Object.prototype` of the host realm, mutable through key-copying helpers if `__proto__`/`constructor` keys are honored. | high |
| Downstream embedder data | Whatever application data flows through the library; as a dependency, a defect here is inherited by every embedder. | high |
| Distributed build artifacts | The prebuilt bundles committed to the repo and published to npm; the bytes embedders actually load. | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `_.template(text, settings)` (`modules/template.js`) | Compiles a template string into a render function via `new Function`; `settings.variable` becomes a parameter name. | caller-supplied template string / `variable` → arbitrary code in host realm | Host application integrity |
| Recursive data helpers (`_.flatten`/`modules/_flatten.js`, `_.isEqual`/`modules/isEqual.js`, `_.extend`, `_.defaults`, `_.values`, `_.pairs`) | Walk caller-supplied (possibly attacker-shaped) arrays/objects, recursing or iterating over structure. | untrusted data values → host call stack / CPU | Host availability |
| Key-copying helpers (`_.extend`, `_.extendOwn`, `_.defaults`, `_.invert`, `_.mapObject`) | Copy enumerable keys from a source object into a target. | untrusted object keys (`__proto__`, `constructor`) → object/prototype state | Object/prototype integrity, Host application integrity |
| `_.escape` / `_.unescape` (`modules/escape.js`, `_escapeMap.js`) | Map a fixed set of HTML metacharacters to/from entities. | library output → downstream HTML sink | Output-encoding correctness |
| Supply chain: npm package + committed prebuilt bundles + `package-lock.json` | The distributed `underscore-*.js` artifacts and lockfile that embedders load. | build/distribution pipeline → embedding application | Distributed build artifacts, Host application integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Arbitrary code execution in the host realm when an attacker-controlled template string is passed to `_.template` | remote_unauth | `_.template(text, settings)` | Host application integrity | critical | possible | risk_accepted | Documented contract: template body is `eval`-equivalent by design; caller must pass only trusted templates (SECURITY.md) | CVE-2021-23358 |
| T2 | Code injection via a malicious `settings.variable` option breaking out of the generated function signature | remote_unauth | `_.template(text, settings)` | Host application integrity | critical | rare | mitigated | `bareIdentifier` regex `^\s*(\w\|\$)+\s*$` rejects non-identifier `variable` values before `new Function` (template.js:71-74) | CVE-2021-23358 |
| T3 | Denial of service via stack exhaustion from deeply-nested input to recursive helpers (`_.flatten`, `_.isEqual`) | remote_unauth | Recursive data helpers | Host availability | medium | possible | mitigated | Trampolined / depth-bounded traversal replacing native recursion (`_flatten.js`, `isEqual.js`) | CVE-2026-27601 |
| T4 | Downstream XSS when output is interpolated unescaped (`<%= %>`) or routed around `_.escape` instead of the escaping delimiter (`<%- %>`) | remote_unauth | `_.escape` / `_.template` interpolation | Output-encoding correctness | high | possible | partially_mitigated | `_.escape` covers `& < > " ' \``; escaping is opt-in per interpolation, not default | |
| T5 | Prototype pollution / unintended object mutation when key-copying helpers process attacker-controlled keys (`__proto__`, `constructor`) | remote_auth | Key-copying helpers | Object/prototype integrity, Host application integrity | high | possible | partially_mitigated | Helpers copy own-enumerable keys only; no explicit `__proto__` denylist verified | |
| T6 | Supply-chain compromise: a tampered or drifted prebuilt bundle ships code different from the audited `modules/` source | supply_chain | Supply chain (bundles + lockfile) | Distributed build artifacts, Host application integrity | critical | rare | partially_mitigated | `package-lock.json` pins deps; bundles are reproducible from source but committed to the repo | |

## 5. Deprioritized

| threat | reason |
|---|---|
| ReDoS in internal regexes | Library-internal regexes (`escapeRegExp`, `bareIdentifier`, the template delimiter matcher) are simple, anchored, and not driven by attacker-controlled patterns; no catastrophic backtracking path. |
| Spoofing / authentication bypass | No identity, session, or authentication concept exists in a utility library. |
| Repudiation | No logging, auditing, or multi-user action surface. |
| Sensitive-data disclosure from the library itself | Underscore holds no secrets or persistent state; any data exposure is the embedder's, not the library's. |
| Volumetric DoS / rate limiting | Resource consumption is the host's concern; only algorithmic/stack-exhaustion (T3) is in scope. |

## 6. Open questions

- **Deployment context.** In which embedders is `_.template` fed strings that
  originate, even partially, from untrusted input? T1's likelihood is set for a
  worst-case web embedder; an owner can confirm or lower it.
- **Escaping discipline.** Do downstream consumers consistently use the
  escaping delimiter (`<%- %>` / `_.escape`) for untrusted interpolation, or is
  raw `<%= %>` used with user data (T4)?
- **Prototype-pollution exposure (T5).** Are `_.extend`/`_.defaults`/`_.invert`
  ever called with objects whose keys come from untrusted JSON? Does any
  supported runtime honor `__proto__` as an assignable own key here?
- **Distribution integrity.** Are the published npm bundles verified against a
  from-source rebuild (provenance / SLSA), or trusted as committed (T6)?

## 7. Provenance

- mode: bootstrap
- date: 2026-06-12
- target: underscore @ 5f37c37
- inputs: git-log + SECURITY.md + source mined (no --vulns file)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Treat `_.template` like `eval`: never pass untrusted template strings; precompile templates at build time from trusted source only | T1 | partial | S |
| Default untrusted interpolation to the escaping delimiter and document `<%= %>` as unsafe-by-default | T4 | partial | M |
| Add an explicit `__proto__`/`constructor` key guard to key-copying helpers (or document that callers must filter untrusted keys) | T5 | partial | M |
| Keep recursive helpers depth-bounded/trampolined and add regression tests for adversarially-nested inputs | T3 | yes | S |
| Publish with build provenance (npm provenance / SLSA) and verify bundles rebuild byte-identical from `modules/` in CI | T6 | partial | M |
