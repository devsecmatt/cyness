# Triage Report — nokogiri

4 in → 0 duplicates, 2 false positives, 2 confirmed (0 high / 2 med / 0 low), 2 need manual test.

Context: auto; environment = Library/SDK (caller is the trust boundary); scoring = derived HIGH/MEDIUM/LOW; precision noise policy.

> **Run note:** Subagent verifier fan-out was unavailable (Claude Fable 5 not
> available for spawning). Adversarial verification was performed inline by the
> Fable orchestrator; verifier independence is reduced and `votes_per_finding` = 1.
> Note also that the dominant nokogiri risk — native memory corruption in
> vendored libxml2/libxslt (threat T1) — is out of static scope; those sources
> are not in this checkout. Use `vuln-pipeline` for the native parsers.

## Act on these

### [MEDIUM] `DEFAULT_XSLT` enables `NOENT` + `DTDLOAD` (entity/DTD loading for XSLT)  (f001)
`lib/nokogiri/xml/parse_options.rb:342` | xxe | claimed HIGH (alignment -1) | confidence 6.0/10
**Owner:** no CODEOWNERS; top committer Mike Dalessio (17/30 recent commits)
**Verdict:** needs_manual_test, votes {tp:1, fp:0, cv:0}
**Preconditions (2):**
- App compiles/parses an attacker-influenced XSLT stylesheet (or transforms a doc pulling a malicious DTD) under default XSLT options
- A `SYSTEM` entity / external DTD references a readable local file (network is blocked by the `NONET` default)
**Threat-model match:** T5
**Why:** Confirmed at parse_options.rb:342 — `DEFAULT_XSLT` sets `NOENT|DTDLOAD` unlike `DEFAULT_XML` (line 334). Entity substitution + DTD loading are enabled, so local-file disclosure and entity-expansion DoS are reachable for untrusted XSLT/DTD. `NONET` blocks the network/SSRF half, so HIGH→MEDIUM. Documented with a warning and intrinsic to XSLT, but actionable: ship/recommend a hardened XSLT option set.
**Reachability evidence:** parse_options.rb:342, parse_options.rb:334

### [MEDIUM] XSLT/XPath parameter injection when `transform()` params are not quoted  (f002)
`ext/nokogiri/xslt_stylesheet.c:160` | injection | claimed MEDIUM (alignment 0) | confidence 5.5/10
**Owner:** no CODEOWNERS; top committer Mike Dalessio (25/30 recent commits)
**Verdict:** needs_manual_test, votes {tp:1, fp:0, cv:0}
**Preconditions (2):**
- App forwards untrusted input as a `transform()` parameter value
- The value is not wrapped in `Nokogiri::XSLT.quote_params`
**Threat-model match:** none (selector/param injection, adjacent to T5)
**Why:** `build_xslt_params` (xslt_stylesheet.c:155-163) passes raw param C strings (line 160) to `xsltApplyStylesheet`, and libxslt evaluates param values as XPath. Unquoted untrusted params are an XPath-injection sink. `quote_params` exists and is documented (caller misuse), but the raw-value-as-XPath default is a genuine footgun; kept at MEDIUM.
**Reachability evidence:** ext/nokogiri/xslt_stylesheet.c:160, :336
> Recommend a human PoC against a representative `transform(doc, {k => userInput})` call site.

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f003 | XPath injection via untrusted selectors | lib/nokogiri/css/xpath_visitor.rb:304 | not_actionable (rule 13) — the unsafe string-building happens in the caller; nokogiri already offers parameterized XPath, and `validate_xpath_function_name` guards the part it owns. |
| f004 | CDATA length truncated by `(int)` cast | ext/nokogiri/gumbo.c:231 | implausible_trigger — real latent cast bug, but needs a single >2 GiB CDATA node; defense-in-depth only, no realistic exploit. |
