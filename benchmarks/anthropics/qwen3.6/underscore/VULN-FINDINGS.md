# Vulnerability Scan Findings: Underscore.js

**Target:** `/home/higgs/workspace/cyness/underscore`  
**Scanned at:** 2026-06-12  
**Source files scanned:** 60+ modules, 2077-line main bundle  
**THREAT_MODEL.md:** parsed from `benchmarks/anthropics/underscore/THREAT_MODEL.md`  

## Summary

| Category | Count |
|----------|-------|
| Total findings | 10 |
| HIGH | 6 |
| MEDIUM | 4 |
| LOW | 0 |
| Low confidence (<0.4) | 0 |

## Top Findings by Confidence

| # | ID | Severity | Category | File:Line | Title |
|---|------|----------|-------------------|-----------|-------|
| 1 | F-001 | HIGH | code-injection | template.js:77 | Arbitrary code execution via _.template() with() default mode escape |
| 2 | F-002 | HIGH | code-injection | template.js:87 | Unvalidated template interpolation produces arbitrary code via Function constructor |
| 3 | F-003 | HIGH | prototype-pollution | _createAssigner.js:12 | Prototype pollution via _.extend() through inherited property enumeration |
| 4 | F-004 | HIGH | prototype-pollution | _createAssigner.js:13 | Prototype pollution via _.defaults() constructor injection path |
| 5 | F-005 | HIGH | security-misconfiguration | mixin.js:11 | Unrestricted function injection via _.mixin() pollutes global namespace |
| 6 | F-006 | HIGH | injection | result.js:19 | Arbitrary method invocation via _.result() with attacker-controlled path |
| 7 | F-007 | MEDIUM | prototype-pollution | invert.js:8 | Prototype pollution via _.invert() with __proto__ valued keys |
| 8 | F-008 | MEDIUM | prototype-pollution | object.js:10 | Prototype pollution via _.object() with untrusted key-value pairs |
| 9 | F-009 | MEDIUM | denial-of-service | _flatten.js:23 | Stack overflow risk in _.flatten() via excessive implicit depth |
| 10 | F-010 | MEDIUM | performance-impact | isEqual.js:152 | Quadratic time complexity in _.isEqual() cycle detection via linear search |

---

### F-001 — Arbitrary code execution via _.template() with() default mode escape

- **Severity:** HIGH | **Confidence:** 0.95
- **File:** `modules/template.js`, line 77
- **Category:** code-injection

**Description:** When _.template() is called without an explicit `variable` setting, line 77 wraps generated source in `with(obj||{}){...}`. This creates a with-statement that grants the template body access to ALL properties of the global scope chain as implicit variables. An attacker controlling the template string can escape the with-block scope by referencing Object.prototype properties (e.g., `constructor`, `__proto__`, `prototype`) to access the global object and execute arbitrary code. CVE-2021-23358 partially mitigated this by adding a bareIdentifier check on the `variable` parameter, but the `with(obj||{})` wrapper itself remains the default when no variable is specified (line 75-78). The attack path: pass untrusted template string → template compiler generates `with(obj){ __t=(constructor) }` → access `constructor.constructor('return this')().process.exit()` → full RCE in Node.js or sandbox escape in browser.

**Exploit scenario:** In a Node.js app: `_.template(userControlledString)()` where userControlledString contains `constructor.constructor('require("child_process").execSync("id")')`. Without explicit `variable` option, the with(obj) scope grants access to Object.prototype.constructor which can reach the global object.

**Recommendation:** Remove the `with(obj||{})` default (line 77) entirely. Require callers to explicitly set the `variable` option to a validated identifier. Throw by default when `variable` is unspecified rather than falling back to with().

---

### F-002 — Unvalidated template interpolation produces arbitrary code via Function constructor

- **Severity:** HIGH | **Confidence:** 0.90
- **File:** `modules/template.js`, line 87
- **Category:** code-injection

**Description:** Line 87 uses `new Function(argument, '_', source)` to compile template output. The `source` variable is constructed from untrusted template input: interpolate expressions are embedded directly as JavaScript expressions (line 59: `'+'\\n((__t=(' + interpolate + '))==null?'':__t)+'\\n'`). If the template string is attacker-controlled, any valid JavaScript expression can be evaluated in the compiled function scope. The bareIdentifier check on line 72 only validates the `variable` name, not the template content itself. Attack path: attacker provides `_<%=evil%>` template → source becomes `'+'\\n((__t=(evil))==null?'':__t)+'\\n'` → new Function evaluates `evil` expression → arbitrary code execution.

**Exploit scenario:** User submits template string `_-_<%=require('fs').readFileSync('/etc/passwd')%>_` in a server-side Node.js app. The interpolated expression is directly embedded into the Function constructor body and executed.

**Recommendation:** Only allow safe interpolation syntax (e.g., variable names or property access chains, not arbitrary expressions). Alternatively, use a template engine that sanitizes expressions or compiles to a non-executable AST representation.

---

### F-003 — Prototype pollution via _.extend() through inherited property enumeration

- **Severity:** HIGH | **Confidence:** 0.85
- **File:** `modules/_createAssigner.js`, line 12
- **Category:** prototype-pollution

**Description:** _.extend() delegates to createAssigner(allKeys) where allKeys (modules/allKeys.js:6-12) uses `for...in` enumeration which traverses the prototype chain including inherited properties like `__proto__`, `constructor`, and `prototype`. When allKeys encounters a property from Object.prototype, it returns that key (e.g., '__proto__') which is then used as an assignment target in createAssigner.js:13: `obj[key] = source[key]`. In environments where `__proto__` assignment works (Node.js, most browsers), this directly pollutes Object.prototype. Additionally, collectNonEnumProps (modules/_collectNonEnumProps.js:36) can enumerate `constructor` and `prototype` properties on the source object, providing another path. The assigner has no guard against `__proto__`, `constructor`, and `prototype` keys.

**Exploit scenario:** Attacker controls input object: `{__proto__: {isAdmin: true}}`. Passing this to `_.extend({}, maliciousInput)` causes all subsequent object literals to inherit `isAdmin: true`. Or: `_.defaults(obj, {constructor: {prototype: {admin: true}}})` in environments supporting constructor-prototype pollution path.

**Recommendation:** Filter out prototype-inherited keys in allKeys() or createAssigner: explicitly skip '__proto__', 'constructor', 'prototype'. Or use `Object.defineProperty` with `enumerable: false` to prevent injection. Consider requiring objects created with `Object.create(null)` as sources.

---

### F-004 — Prototype pollution via _.defaults() constructor injection path

- **Severity:** HIGH | **Confidence:** 0.80
- **File:** `modules/_createAssigner.js`, line 13
- **Category:** prototype-pollution

**Description:** _.defaults() delegates to createAssigner(allKeys, true) — same allKeys enumeration as extend but with defaults=true (only sets if property is undefined). Since defaults only writes missing properties, attacker must first ensure target has no own `__proto__` property, then inject via `__proto__` key from the source. The allKeys() function traverses the prototype chain, so `source.constructor` yields the Object constructor function, and `source.constructor.prototype` is accessible via the chain.

**Exploit scenario:** Given a plain object `target = {}`, calling `_.defaults(target, {constructor: {prototype: {pwned: true}}})` will set Object.prototype.pwned to true because createAssigner iterates inherited properties via allKeys() and assigns them when the target lacks the own property.

**Recommendation:** Add explicit denial of 'constructor' and 'prototype' keys in createAssigner. Use Object.defineProperty or Object.create(null) guard. Deprecate _.defaults in favor of Object.assign with pre-filtered sources.

---

### F-005 — Unrestricted function injection via _.mixin() pollutes global namespace

- **Severity:** HIGH | **Confidence:** 0.75
- **File:** `modules/mixin.js`, line 11
- **Category:** security-misconfiguration

**Description:** _.mixin() (line 9) accepts any object and injects all function-valued properties onto both `_[name]` and `_.prototype[name]` without any allowlist or validation. An attacker controlling the argument can add arbitrary functions as methods on the Underscore prototype, making them available chainably on all wrapped values.

**Exploit scenario:** Attacker-supplied object to `_.mixin()`: `{eval: function(x){return require('child_process').execSync(x)}}`. This injects the function as `_.eval` and `_.prototype.eval`.

**Recommendation:** Add a strict allowlist of permitted function names. Reject or log-warning on unknown function injections. Do not inject onto _.prototype without explicit opt-in.

---

### F-006 — Arbitrary method invocation via _.result() with attacker-controlled path

- **Severity:** HIGH | **Confidence:** 0.70
- **File:** `modules/result.js`, line 19
- **Category:** injection

**Description:** _.result() (line 19) invokes `prop.call(obj)` whenever a traversed property is a function. With an attacker-controlled path traversing an object with attacker-tainted prototype, this can invoke hidden prototype methods. A path like `['constructor', 'constructor']` on any object resolves to `Object.constructor.constructor` (the Function constructor).

**Exploit scenario:** With an object that has an attacker-controlled prototype chain, `_.result(obj, ['constructor', 'constructor', 'return', 'process'])` followed by a subsequent lookup of the returned value as a function could lead to arbitrary evaluation.

**Recommendation:** Add a mode to _.result() that skips __proto__ lookups and only traverses Object.create(null)-safe paths. Validate that resolved paths don't traverse Object.prototype methods.

---

### F-007 — Prototype pollution via _.invert() with __proto__ valued keys

- **Severity:** MEDIUM | **Confidence:** 0.70
- **File:** `modules/invert.js`, line 8
- **Category:** prototype-pollution

**Description:** _.invert() creates a new result object using `{}` literal (line 5) and assigns `result[obj[_keys[i]]] = _keys[i]`. If any object value is the string '__proto__', 'constructor', or 'prototype', these become own properties in the result that pollute Object.prototype.

**Exploit scenario:** `_.invert(obj) {a: 'constructor'}` produces `{constructor: 'a'}`, polluting any object that uses result as a prototype.

**Recommendation:** Use `Object.create(null)` on line 5. Check that inverted values don't contain `__proto__`, `constructor`, `prototype`.

---

### F-008 — Prototype pollution via _.object() with untrusted key-value pairs

- **Severity:** MEDIUM | **Confidence:** 0.65
- **File:** `modules/object.js`, line 10
- **Category:** prototype-pollution

**Description:** _.object() (lines 7-15) constructs an object using `{}` literal and assigns keys directly. If the input pairs include an entry where the key is '__proto__', 'constructor', or 'prototype', Object.prototype gets polluted.

**Exploit scenario:** `_.object([['a', 1], ['__proto__', {'pwned': true}]])` directly sets the prototype of the result object.

**Recommendation:** Use `Object.create(null)` for the result object. Validate and reject keys that match `__proto__`, `constructor`, `prototype`.

---

### F-009 — Stack overflow risk in _.flatten() via excessive implicit depth

- **Severity:** MEDIUM | **Confidence:** 0.65
- **File:** `modules/_flatten.js`, line 23
- **Category:** denial-of-service

**Description:** While CVE-2026-27601 fixed the recursive stack overflow, the default depth of Infinity (line 8) means the explicit stack can grow unbounded in heap memory. An attacker can supply deeply nested arrays causing O(n) heap exhaustion.

**Exploit scenario:** Pass a deeply nested array (depth 100,000+) to `_.flatten()` from a user-upload endpoint. The explicit stack grows unbounded, causing out-of-memory.

**Recommendation:** Add a configurable maximum depth with a default reasonable limit. Return an error when depth limit is reached.

---

### F-010 — Quadratic time complexity in _.isEqual() cycle detection

- **Severity:** MEDIUM | **Confidence:** 0.60
- **File:** `modules/isEqual.js`, line 152
- **Category:** performance-impact

**Description:** Cycle detection uses linear search over aStack/bStack arrays (line 119-128). For objects with many unique nested structures, cycle detection is O(n²) rather than O(n). Keys comparison on line 152 also triggers full keys enumeration on the second object.

**Exploit scenario:** Send two large objects with millions of unique nested nodes to `_.isEqual()`. Quadratic time blowup saturates the CPU.

**Recommendation:** Replace linear search with a Set/Map-based lookup. Use WeakSet for automatic GC. Pre-compute key counts on line 152.

---

## Next step

Run `/triage` to verify and prioritize these findings:

```
/triage /home/higgs/workspace/cyness/benchmarks/anthropics/underscore/VULN-FINDINGS.json --repo /home/higgs/workspace/cyness/underscore
```

**Note:** These are static candidates for review, not verified exploits. For execution-verified crashes, use `vuln-pipeline run`.

## Coverage by THREAT_MODEL.md threats

| Threat ID | Covered by findings | Finding IDs |
|-----------|--------------------|---------------|
| T1 — _.template() arbitrary code execution | Fully | F-001, F-002 |
| T2 — _.isEqual() DoS | Partially (performance class) | F-010 |
| T3 — _.extend() prototype pollution | Fully | F-003, F-004 |
| T4 — _.flatten() DoS | Partially | F-009 |
| T5 — _.template() with() scope escape | Fully | F-001 |
| T6 — _.result() sandbox escape | Fully | F-006 |
| T7 — _.invert() prototype pollution | Fully | F-007 |
| T8 — Supply chain | No (out of scope) | — |
| T9 — Template data confidentiality | Reflected in F-001 | F-001 |
| T10 — _.mixin() namespace hijacking | Fully | F-005 |
