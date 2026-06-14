# Vuln-Scan Findings: nokogiri

Static review (read-only), scoped by `THREAT_MODEL.md`. 4 in-tree candidates.

> **Scope.** Covers nokogiri's own code: the C bridge (`ext/nokogiri/*.c`) and
> the Ruby API (`lib/`). The vendored native libraries (libxml2, libxslt,
> gumbo-parser, zlib, libiconv) are fetched/compiled at build time and are **not
> in this checkout**, so their memory-corruption surface — the dominant
> historical CVE source (threat T1) — cannot be statically reviewed here. For
> execution-verified crashes in the native parsers, use `vuln-pipeline`. The
> in-tree C bridge is notably hardened: `nokogiri.c:89`'s `memcpy` is
> length-bounded, and `xml_document.c:655` checks the `xmlC14NExecute` return
> value (the GHSA-wx95 fix), raising on failure at line 665.

| id | severity | category | file:line | confidence | title |
|---|---|---|---|---|---|
| F-001 | HIGH | xxe | lib/nokogiri/xml/parse_options.rb:342 | 0.5 | `DEFAULT_XSLT` enables `NOENT`+`DTDLOAD` (entity/DTD load) |
| F-002 | MEDIUM | injection | ext/nokogiri/xslt_stylesheet.c:160 | 0.45 | XSLT/XPath param injection when params not quoted |
| F-003 | MEDIUM | injection | lib/nokogiri/css/xpath_visitor.rb:304 | 0.35 | XPath injection via untrusted selectors built by caller |
| F-004 | LOW | integer-overflow | ext/nokogiri/gumbo.c:231 | 0.3 | CDATA length truncated by `(int)` cast of `strlen` |

### F-001 — `DEFAULT_XSLT` enables `NOENT` + `DTDLOAD`
`lib/nokogiri/xml/parse_options.rb:342` · xxe · HIGH · confidence 0.5

`DEFAULT_XSLT = RECOVER | NONET | NOENT | DTDLOAD | DTDATTR | NOCDATA | BIG_LINES`.
Unlike `DEFAULT_XML` (line 334), the XSLT default substitutes entities and loads
DTDs. `NONET` blocks network fetches, but local-file disclosure via `SYSTEM`
entities/DTD load and entity-expansion DoS remain. Code carries an explicit "do
not parse untrusted XSLT" warning. **Fix:** never parse untrusted XSLT; offer a
hardened option set without `NOENT`/`DTDLOAD`.

### F-002 — XSLT/XPath parameter injection
`ext/nokogiri/xslt_stylesheet.c:160` · injection · MEDIUM · confidence 0.45

`build_xslt_params` passes raw param C strings to `xsltApplyStylesheet`; libxslt
treats param VALUES as XPath expressions. Untrusted params not wrapped in
`Nokogiri::XSLT.quote_params` allow attacker-controlled XPath. **Fix:** always
`quote_params` untrusted values.

### F-003 — XPath injection via untrusted selectors
`lib/nokogiri/css/xpath_visitor.rb:304` · injection · MEDIUM · confidence 0.35

Translation validates function *names* but not attacker-controlled selector
*values*; interpolating untrusted input into a selector/XPath string passed to
`#search`/`#xpath`/`#css` permits query injection. **Fix:** use parameterized
XPath variable bindings instead of string interpolation.

### F-004 — CDATA length truncated by `(int)` cast
`ext/nokogiri/gumbo.c:231` · integer-overflow · LOW · confidence 0.3

`xmlNewCDataBlock(..., (int) strlen(...))` truncates/negates for text >INT_MAX.
Requires a multi-gigabyte single CDATA node — defense-in-depth. **Fix:**
validate the length fits in `int` before the cast.

---
**Next:** `/triage benchmarks/anthropics/fable/nokogiri/VULN-FINDINGS.json --repo nokogiri`
Static candidates; native-parser crashes need `vuln-pipeline`.
