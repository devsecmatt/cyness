# Triage Report — underscore

6 in → 0 duplicates, 5 false positives, 1 confirmed (0 high / 1 med / 0 low), 1 needs manual test.

Context: auto; environment = Library/SDK (caller is the trust boundary); scoring = derived HIGH/MEDIUM/LOW; precision noise policy.

> **Run note:** Subagent verifier fan-out was unavailable (Claude Fable 5 not
> available for spawning). The adversarial verification was performed inline by
> the Fable orchestrator instead of by independent fresh-context subagents, so
> verifier independence is reduced and `votes_per_finding` = 1.

## Act on these

### [MEDIUM] Prototype injection via `_.extend` / `_.defaults` copying a `__proto__` own key  (f001)
`modules/_createAssigner.js:13` | prototype-pollution | claimed HIGH (alignment -2) | confidence 6.5/10
**Owner:** component: modules/; no CODEOWNERS; sole recent committer Julian Gonggrijp
**Verdict:** needs_manual_test, votes {tp:1, fp:0, cv:0}
**Preconditions (3):**
- App calls `_.extend`/`_.defaults` with an attacker-controlled object as a **source** (e.g. parsed untrusted JSON)
- That object carries a `__proto__` own-enumerable key (survives `JSON.parse` as an own data property)
- App later reads an inherited property off the destination object supplied by the injected prototype
**Threat-model match:** T5 (prototype pollution / unintended object mutation)
**Why:** `allKeys` uses `for (var key in obj)` (allKeys.js:9) so a `__proto__` own key IS enumerated, and `createAssigner` runs `obj['__proto__']=source['__proto__']` (_createAssigner.js:13). With no own `__proto__` on the destination, the bracket assignment hits the inherited `__proto__` setter and reassigns the **destination object's** prototype to the attacker object. The scanner's claim of global `Object.prototype` pollution is **overstated** — the copy is shallow, so this is localized prototype injection on the target object, not realm-wide pollution. Severity corrected HIGH→MEDIUM.
**Reachability evidence:** modules/_createAssigner.js:13, modules/allKeys.js:9, modules/defaults.js:5
> Recommend a human build a PoC against a representative `_.defaults(opts, untrustedJSON)` call site; static reasoning establishes the mechanism but exploitability hinges on embedder usage.

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f002 | `_.template` code execution via `new Function` | modules/template.js:87 | intentional_behavior; exclusion rule 3 — documented eval-like design contract (SECURITY.md); captured as threat T1 (risk_accepted). The fixable `variable` variant (CVE-2021-23358) is already mitigated. |
| f003 | `_.invert` prototype pollution via `__proto__` value | modules/invert.js:8 | implausible_trigger / misread_code — assigned value is always a string; `__proto__` setter ignores non-object values, so no prototype change occurs. |
| f004 | Unescaped `<%= %>` interpolation | modules/template.js:59 | intentional_behavior; exclusion rule 3 — raw vs escaped delimiter is author-selected and documented; trusted template authors. Embedder risk captured as T4. |
| f005 | `_.result` path traversal of reserved keys | modules/result.js:14 | not_actionable; exclusion rule 13 — read-only traverse primitive, no concrete write/exec exploit demonstrated. |
| f006 | `_.escape` omits `/` | modules/_escapeMap.js:1 | not_actionable; exclusion rule 13 — `<`/`>` are encoded; omitting `/` is standard and safe in normal HTML contexts; defense-in-depth only. |
