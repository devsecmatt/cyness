# Agentic SAST — nokogiri

## Summary
Two independent, scoped logic/injection flaws were found, neither reaching memory corruption or auth bypass. Finding 0 is a JRuby schema-parsing SSRF/file-read where the NONET guard only filters http/ftp, leaving https/file/jar exploitable when an app parses an untrusted XSD with network blocking expected. Finding 1 is a CSS-to-XPath query injection on CRuby via an unescaped id selector. There is no exploit chain between them (different runtimes, different assets), and neither delivers RCE or bulk data exposure; both are Medium per their CVSS bands.

## Scan Metrics

- Scan ID: 2026-06-17T01:14:02Z__nokogiri
- Module: nokogiri
- Start: 2026-06-17T01:14:02Z
- End: 2026-06-17T01:58:19Z
- Duration (sec): 2657
- Files in scope: 259
- Files analyzed (unique): 258
- Coverage: 99.6%
- Chunks: 87 (risk=15, catch-all=18, specialist=54)
- Tokens (prompt): 7415214
- Tokens (completion): 499921
- Tokens (total): 7915135

- Folders scanned: 26
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s4-deepdive | 87 | 7,202,647 | 440,172 | 7,642,819 | 96.6 | 0 |
| s6-verify | 6 | 126,252 | 39,691 | 165,943 | 2.1 | 919,663 |
| s3-decompose | 1 | 31,505 | 6,123 | 37,628 | 0.5 | 0 |
| s1-preprocess | 1 | 29,302 | 6,694 | 35,996 | 0.5 | 355,328 |
| s2-threatmodel | 1 | 12,710 | 5,478 | 18,188 | 0.2 | 0 |
| s1-autoexclude | 1 | 6,343 | 1,644 | 7,987 | 0.1 | 0 |
| unlabeled | 1 | 4,508 | 4 | 4,512 | 0.1 | 15,379 |
| s7-dedup | 1 | 1,947 | 115 | 2,062 | 0.0 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| c-cpp | 44231 | 44231 | 100.0 |
| java | 19714 | 19714 | 100.0 |
| other | 3674 | 3649 | 99.3 |
| ruby | 12252 | 12252 | 100.0 |

## Scan Health

- Recoverable errors logged by stage: s4=5
- Full error log: `nokogiri_20260617T011402Z_errors.jsonl`

## Threat Model

### System context

Nokogiri is a widely-deployed Ruby gem (library) that parses, queries, modifies, and serializes XML and HTML. On CRuby it is a C extension binding the vendored libxml2/libxslt libraries plus a vendored gumbo HTML5 parser; on JRuby it is backed by Xerces/Xalan with a vendored XML-C14N implementation. It is not a service — it runs in-process inside whatever application embeds it (web apps, scrapers, document pipelines, CLI tools, batch jobs). Its security posture is therefore inherited by every consuming application.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Host process memory integrity | critical | Memory safety of the Ruby/JRuby process embedding Nokogiri; corruption leads to crash or RCE in the consuming application |
| Service availability | high | CPU/memory of the consuming application; parsing must terminate in bounded resources |
| Local files and internal network resources | high | Filesystem and SSRF-reachable endpoints accessible to the process, exposable via XXE external entities or XSLT document()/extension functions |
| Parsed document integrity | high | Correctness/trustworthiness of the DOM returned to downstream consumers (e.g. sanitizers, security decisions built atop query results) |
| Vendored native dependency chain | high | libxml2, libxslt, libgumbo, libiconv, Xerces/Xalan, Saxon-HE shipped inside the gem |

### Trust boundaries

- **ext/nokogiri/gumbo.c::noko_gumbo_s_parse / noko_gumbo_s_fragment** — untrusted HTML5 bytes → vendored gumbo C parser → Host process memory integrity, Service availability, Parsed document integrity
- **ext/nokogiri/html4_document.c::rb_html_document_s_read_memory** — untrusted HTML4 bytes → libxml2 HTML parser (C) → Host process memory integrity, Service availability, Parsed document integrity
- **ext/nokogiri/xml_document.c::noko_xml_document_s_read_memory / read_io** — untrusted XML bytes → libxml2 XML parser (C) → Host process memory integrity, Service availability, Local files and internal network resources, Parsed document integrity
- **ext/nokogiri/xml_node.c::noko_xml_node__in_context (xmlParseInNodeContext)** — untrusted fragment bytes parsed in node context → libxml2 (C) → Host process memory integrity, Parsed document integrity
- **ext/nokogiri/xml_reader.c::from_memory / from_io** — untrusted XML stream → libxml2 streaming reader (C) → Host process memory integrity, Service availability, Local files and internal network resources
- **ext/nokogiri/xml_sax_parser_context.c::noko_xml_sax_parser_context__parse_with** — untrusted SAX/push input → libxml2 SAX parser (C) → Host process memory integrity, Service availability
- **ext/nokogiri/xml_xpath_context.c::noko_xml_xpath_context_evaluate** — caller-supplied / interpolated query string → XPath engine → Parsed document integrity, Service availability
- **ext/nokogiri/xslt_stylesheet.c::transform/parse** — untrusted XSLT stylesheet → libxslt execution (file/network/extension functions) → Local files and internal network resources, Host process memory integrity, Service availability
- **Vendored dependency supply chain (dependencies.yml / native.yml)** — upstream libxml2/libxslt/gumbo/Saxon → shipped gem binary → Vendored native dependency chain, Host process memory integrity, Local files and internal network resources

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | Crafted HTML5 input triggers a heap/stack buffer overflow in the vendored gumbo parser, leading to memory corruption and potential remote code execution in the host process. | remote_unauth | ext/nokogiri/gumbo.c::noko_gumbo_s_parse / noko_gumbo_s_fragment | Host process memory integrity | critical | possible | Length-clamped memcpy (safe_len) at nokogiri.c:89; in-place known-table strcpy in adjust_svg_tag; C extension treats all input as untrusted |
| T2 | Malicious XML/HTML triggers a memory-corruption bug (UAF/OOB write/integer overflow) inside vendored libxml2, escalating to code execution in the consuming application. | remote_unauth | ext/nokogiri/xml_document.c::noko_xml_document_s_read_memory / read_io | Host process memory integrity | critical | possible | Vendored libxml2 kept current (v2.14.6); rapid security patch cadence |
| T3 | Untrusted XSLT stylesheet executes document()/external entity/extension-function access to read local files or reach internal network endpoints (SSRF) and exhaust memory. | remote_unauth | ext/nokogiri/xslt_stylesheet.c::transform/parse | Local files and internal network resources | critical | possible | Documented as unsafe with untrusted stylesheets in lib/nokogiri/xslt.rb; libxslt security prefs available |
| T4 | XML with external entity references or DTD external subsets exfiltrates local files or performs SSRF when NOENT/DTDLOAD parse options are enabled by the consuming app (XXE). | remote_unauth | ext/nokogiri/xml_document.c::noko_xml_document_s_read_memory / read_io | Local files and internal network resources | high | possible | Secure-by-default: NOENT and DTDLOAD OFF by default; entity substitution disabled unless explicitly enabled |
| T5 | Use-after-free or double-free reachable through fragment-in-context parsing or SAX context input corrupts the host process. | remote_unauth | ext/nokogiri/xml_node.c::noko_xml_node__in_context (xmlParseInNodeContext) | Host process memory integrity | critical | rare | SAX ParserContext now retains input reference to avoid UAF (#3395); upstream libxml2 patched |
| T6 | Maliciously nested entities or deeply-nested/oversized markup cause unbounded CPU/memory consumption (billion-laughs / quadratic blowup), denying service to the consuming application. | remote_unauth | ext/nokogiri/xml_reader.c::from_memory / from_io | Service availability | high | possible | libxml2 entity-expansion limits; HTML5 attribute parsing made linear (#3393) |
| T7 | A crafted CSS selector triggers exponential regex backtracking in the selector tokenizer, hanging the consuming application (ReDoS). | remote_unauth | ext/nokogiri/xml_xpath_context.c::noko_xml_xpath_context_evaluate | Service availability | high | possible | Fixed in v1.19.3 by removing exponential backtracking in CSS tokenizer |
| T8 | Untrusted SAX/push parser input drives a memory-safety fault or unbounded resource use in the streaming libxml2 callbacks. | remote_unauth | ext/nokogiri/xml_sax_parser_context.c::noko_xml_sax_parser_context__parse_with | Host process memory integrity | high | rare | Input reference retained to avoid UAF; libxml2 patched |
| T9 | User-controlled values interpolated into XPath/CSS expressions allow query injection that returns unintended nodes, subverting downstream security/filtering decisions. | remote_unauth | ext/nokogiri/xml_xpath_context.c::noko_xml_xpath_context_evaluate | Parsed document integrity | medium | possible | Parameterized variable binding API available; StringValueCStr used on full expression (no auto-sanitization) |
| T10 | HTML4 parsing of attacker markup hits a memory-corruption or crash bug in the libxml2 HTML parser path. | remote_unauth | ext/nokogiri/html4_document.c::rb_html_document_s_read_memory | Host process memory integrity | high | rare | Vendored libxml2 current; HTML5 parser raw-text spec alignment in v2.14 |
| T11 | A compromised or vulnerable upstream vendored dependency (libxml2/libxslt/gumbo/Saxon-HE) ships memory-safety or logic flaws to every gem consumer. | supply_chain | Vendored dependency supply chain (dependencies.yml / native.yml) | Vendored native dependency chain | high | likely | Active dependency tracking, frequent security patch releases, pinned versions in dependencies.yml, precompiled native gems with reproducible builds |
| T12 | Unchecked native return value (e.g. C14N canonicalization) silently produces malformed output, contributing to signature-bypass in downstream consumers like ruby-saml. | remote_unauth | Vendored dependency supply chain (dependencies.yml / native.yml) | Parsed document integrity | high | rare | Fixed: xmlC14NExecute return value now checked (v1.19.1) |

### Open questions

- Does the embedding application expose any parse entry point to remote unauthenticated input (web request bodies, uploaded files), or only to trusted internal data?
- Do consumers enable non-default parse options (NOENT, DTDLOAD, NONET off) that re-introduce XXE/SSRF exposure?
- Are XSLT stylesheets ever sourced from untrusted parties, and is libxslt's security-preferences API engaged by the host app?
- Is parsing run with resource limits / sandboxing, or directly in a request-serving process where a crash or hang is a full DoS?
- Which platform path (CRuby+libxml2 vs JRuby+Xerces/Xalan) is in production, since their native attack surfaces differ?
- Are query strings (XPath/CSS) ever built from user input rather than developer-controlled literals?

## Verification
- Raw findings (pre-verification): 47
- True positives (verified): 2
- False positives (dropped): 4
- Verifier errors (excluded — undetermined, not confirmed clean): 0
- Duplicates collapsed (all passes): 0
- Verification precision: 4.3%

## Findings (2)

### 1. [MEDIUM] NONET schema guard only blocks http/ftp, not https/file/jar
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `ext/java/nokogiri/XmlSchema.java:292-305`
**CVSS 3.1:** **5.8** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
createSchemaInstance() builds a SchemaResourceResolver using `noNet` derived from the caller-supplied parse options (XmlSchema.java:77,80-81). During schema parsing, the XML library calls resolveResource() with `systemId`/`baseURI` taken directly from the attacker-controlled schema document (e.g. an <xs:import schemaLocation=...> or external entity). The network-blocking branch at line 292 fires only when `systemId.startsWith("http://") || systemId.startsWith("ftp://")`. Any other scheme — https://, file://, jar:, ftps:// — falls into the else branch (line 300-305) where adjustSystemIdIfNecessary() is called and the systemId is set on `lsInput`, causing the resource to be loaded. Thus the NONET protection is incomplete and bypassable simply by using an https:// (or file://) URL inside the schema.

#### Impact
When an application parses an attacker-supplied XML Schema (or RelaxNG) with the NONET option set to forbid network access, the resolver still resolves systemIds that use https://, file://, jar:, etc. An attacker can therefore make the validator fetch a remote schema over HTTPS (SSRF) or read a local file (XXE-style disclosure) despite NONET being requested.

#### Exploit scenario
An application validates user data against a user-provided XSD with NONET set, calling Schema.from_document on the attacker's schema. The schema contains `<xs:import namespace="x" schemaLocation="https://attacker.example/track.xsd"/>` or `schemaLocation="file:///etc/passwd"`. resolveResource() skips the http/ftp guard, sets the systemId on the LSInput, and the parser fetches the URL — yielding SSRF (HTTPS callback / internal endpoint probe) or local-file inclusion even though network access was supposed to be disabled.

#### Preconditions
- Application validates against an attacker-influenced XML Schema / RelaxNG document
- NONET parse option is relied upon to prevent network/external access

```
if (noNet && systemId != null && (systemId.startsWith("http://") || systemId.startsWith("ftp://"))) {
  if (systemId.startsWith(XMLConstants.W3C_XML_SCHEMA_NS_URI)) {
    return null; // use default resolver
  }
  try {
    this.errorHandler.warning(new SAXParseException(String.format("Attempt to load network entity '%s'", systemId), null));
  } catch (SAXException ignored) {
  }
} else {
  String adjusted = adjustSystemIdIfNecessary(currentDir, scriptFileName, baseURI, systemId);
  lsInput.setPublicId(publicId);
  lsInput.setSystemId(adjusted != null ? adjusted : systemId);
  lsInput.setBaseURI(baseURI);
}
```

#### How to fix
The network/external-resource guard must cover all non-local and remote schemes, not just http/ftp. In resolveResource() (XmlSchema.java:292) replace the literal `http://`/`ftp://` prefix test with a scheme allow-list (or block-list including https, file, jar, ftps, etc.), and when noNet is set refuse to resolve any absolute external systemId rather than falling through to set it on lsInput.

**Exploitability:** CVSS 6.8 (Medium band, S:C/C:L). Pre-auth reachable but requires multiple realistic preconditions: app runs on JRuby, parses an attacker-controlled XML Schema, and relies on the noNet/NONET option for protection (the bug only matters if NONET is expected to block loads). Primitive is a confidentiality leak (file:// local read, https/jar SSRF) with no write or code execution — incomplete deny-list scheme filter. Blast radius is files/internal endpoints reachable by the process, scope-changed but C:L only. Settling at Medium per the CVSS band and the stacked preconditions.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — NONET guard checks only http/ftp prefixes; https/file/jar schemes in an attacker-supplied schema's xs:import bypass it, yielding SSRF/forced local-file load despite NONET being set.

**Analysis**

**A. The sink (XmlSchema.java:292-305)** — verified verbatim against the file. The scanner read it correctly. The network guard fires *only* for `systemId.startsWith("http://") || systemId.startsWith("ftp://")`. Every other scheme (`https://`, `file://`, `jar:`, `ftps://`) falls into the `else` branch, which calls `adjustSystemIdIfNecessary()` and then `lsInput.setSystemId(...)` / `setBaseURI(...)` and returns the populated `lsInput`. A `SchemaLSInput` carrying only a `systemId` (no byteStream/charStream/stringData) causes Xerces to dereference and fetch that systemId — the resource is loaded.

Note the asymmetry that confirms the bug: in the http/ftp branch the code emits a warning and returns an **empty** `lsInput` (no systemId set) → effectively blocked. For all other schemes it returns a fully-populated `lsInput` → loaded.

**B. Call chain to external entry** — `resolveResource` is wired via `schemaFactory.setResourceResolver()` in `getSchema()` (line 83), invoked from `createSchemaInstance()` ← `getSchema()` ← `from_document` (`@JRubyMethod meta=true`, public `Schema.from_document`). This is reachable from Ruby with an attacker-influenced XSD. The `systemId`/`baseURI` originate from the schema document's `<xs:import schemaLocation=...>` — attacker-controlled, full URL (host + scheme).

**C. Defenses checked:**
- `noNet` derived from `ParserContext.Options(parseOptions).noNet`, `NONET = 1<<11` (ParserContext.java:209/254). `DEFAULT_SCHEMA = NONET | BIG_LINES` (parse_options.rb:350) — so NONET is **on by default**, exactly the configuration the finding targets.
- `adjustSystemIdIfNecessary()` (NokogiriHelpers.java:689) does *not* block schemes — for absolute URIs/paths it returns the systemId unchanged or resolves a local file; it is a path-resolution helper, not a security gate.
- No allow-list, no scheme filtering beyond the two literal prefixes.

**D. Defense coverage** — the guard is a literal two-prefix check; it manifestly does not cover `https://`/`file://`/`jar:`. Trivially bypassed.

**Scope check:** This is not the "path-only SSRF" exclusion — the attacker controls the full URL (host *and* scheme), so it qualifies. `file://` yields forced local-file load (LFI/blind SSRF). Impact is primarily forced resource load / blind SSRF (internal endpoint probing, HTTPS callback) with limited confidentiality leak via parse errors — `I`/`A` unaffected.

The NONET protection is genuinely incomplete and the path reaches an unauthenticated external entry point with no compensating control.

### 2. [MEDIUM] Unescaped CSS id interpolated into XPath string literal
**Class:** CWE-643: Improper Neutralization of Data within XPath Expressions (XPath Injection)
**CWE:** CWE-643: Improper Neutralization of Data within XPath Expressions (XPath Injection) - https://cwe.mitre.org/data/definitions/643.html
**File:** `lib/nokogiri/css/xpath_visitor.rb:170-173`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
visit_id matches the id fragment with /^#(.*)$/ and interpolates the captured group directly into "@id='...'" with no escaping. The id value reaching this visitor has already passed through unescape_css_identifier (parser.rb _reduce_64, line 694), which turns CSS escape sequences such as \27 or \' into a literal single quote. A single quote in the id therefore terminates the XPath string literal and lets attacker text be parsed as XPath. Unlike visit_attribute_condition (lines 179-188) which deliberately neutralizes embedded quotes with a concat() construction, visit_id performs no quoting at all. The resulting XPath string is handed verbatim to xmlXPathEvalExpression via noko_xml_xpath_context_evaluate (xml_xpath_context.c:379-395).

#### Impact
An application that builds a CSS selector from untrusted input (e.g. doc.css("#" + user_id)) gets XPath injection: the id value is dropped raw into a single-quoted XPath literal. An attacker can break out of the literal and change which nodes the query returns, bypassing an intended element filter or forcing a query error.

#### Exploit scenario
An app does doc.css("#" + params[:anchor]). Attacker sends anchor = "x\27]|//user[secret/text()=\27" which unescapes to id text x']|//user[secret/text()='. visit_id emits @id='x']|//user[secret/text()='', producing a valid injected XPath union that selects nodes outside the intended scope. The attacker thereby reads or matches document nodes the query was never meant to expose.

#### Preconditions
- Application concatenates untrusted data into a CSS id selector passed to css()/search()
- Attacker can include CSS escape sequences (e.g. \27) in that data

```
def visit_id(node)
  node.value.first =~ /^#(.*)$/
  "@id='#{Regexp.last_match(1)}'"
end
```

#### How to fix
visit_id must emit the id value as a properly quoted XPath literal. Apply the same quote-neutralizing logic used in visit_attribute_condition (or a shared helper that wraps values in concat() when they contain quote characters) at xpath_visitor.rb:172 instead of bare single-quote interpolation.

**Exploitability:** CVSS 5.3 (Medium band, S:U/C:L). Query-injection: an unescaped CSS id is interpolated into an XPath string literal, letting a single quote (decoded by unescape_css_identifier) break out and inject XPath. Precondition: the application must pass an attacker-controlled CSS selector string into a .css()/at_css() query — uncommon but plausible. Primitive is parsed-document-integrity subversion (returns unintended nodes), not memory corruption or auth bypass; impact is bounded to fooling downstream filtering/sanitization logic. No info leak beyond document contents already in scope. Medium per CVSS band; would be Low on impact alone but anchored to the band.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — unescaped id with literal-quote injected verbatim into the `@id='...'` XPath literal; full path from `css()` to sink confirmed, no escaping anywhere unlike `visit_attribute_condition`. Impact confined to the queried document (read-only), hence limited confidentiality.

I have confirmed the full chain in the actual source. Let me verify my findings:

**A. The sink (xpath_visitor.rb:170-173)** — Confirmed verbatim:
```ruby
def visit_id(node)
  node.value.first =~ /^#(.*)$/
  "@id='#{Regexp.last_match(1)}'"
end
```
No escaping, no quote neutralization. Contrast with `visit_attribute_condition` (lines 182-188) which builds a `concat()` when the value contains its own quote char — `visit_id` does nothing equivalent.

**B. The unescaping claim** — Confirmed. `parser.rb` `_reduce_64` (line 694) builds the `:ID` node via `unescape_css_identifier(val[0])`. That function (line 26-28):
```ruby
identifier.gsub(/\\(?:([^0-9a-fA-F])|([0-9a-fA-F]{1,6})\s?)/){ |m| $1 || [$2.hex].pack('U') }
```
So `\27` → `[0x27].pack('U')` → literal `'`. Special chars like `]`, `|`, `/`, `[`, `(` can all be smuggled as hex escapes (`\5d`, `\7c`, `\2f`, …), and the tokenizer's HASH rule (tokenizer.rb:72) explicitly accepts `\[0-9A-Fa-f]{1,6}` and `\[^...]` escape forms inside the `#…` token. After unescaping, those become literal XPath metacharacters.

**C/D. Searching for a defense** — None exists:
- `Searchable#css` → `css_internal` → `css_rules_to_xpath` → `xpath_for` → `ast.to_xpath(visitor)`. No sanitization between the public entry point and the visitor.
- The unescape happens at parse time and the result flows directly into the string-interpolated literal. No allow-list, length, or quote-stripping guard on the id path.
- The asymmetry with `visit_attribute_condition` confirms this is an oversight, not intentional handling.

**External entry point** — `doc.css("#" + params[:anchor])` is a realistic, common app pattern; the CSS selector string is the untrusted boundary. A crafted `#x\5d|...` selector unescapes into `@id='x']|//...'`, terminating the XPath string literal and injecting a XPath union — reading document nodes outside the intended query scope.

**Impact bounds** — XPath injection via `xmlXPathEvalExpression` is read-only evaluation against the already-loaded document. Confidentiality impact is limited to nodes within that one document (no integrity write, no inherent file/network access under default libxml2 options). So C:L / I:N / A:N.

The scanner correctly read the sink, the class, and the data flow. The exploit is real and no upstream control closes it.

## Exploit Chains

No exploit chains were identified — the findings above are independent and do not combine into a multi-step path.


## Dropped Findings

- **[UNCONFIRMED]** `gumbo-parser/src/parser.c:1993` heap-overflow (chunk-02) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/error.c:387` info-leak (chunk-03-c) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/xml_document.c:427` integer-overflow (chunk-04) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/xml_reader.c:652` use-after-free (chunk-05) — s4 confidence 0.35 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/xml_node.c:1967` injection (chunk-06) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/html4_document.c:106` integer-overflow (chunk-07) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/xslt_stylesheet.c:323` other (chunk-08) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `lib/nokogiri/css/xpath_visitor.rb:365` injection (chunk-09) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/c14n/Canonicalizer11.java:510` logic-flaw (chunk-11) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XsltStylesheet.java:153` other (catchall-02) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlNamespace.java:180` injection (catchall-03) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlSchema.java:79` other (catchall-03) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/tag.c:188` integer-overflow (catchall-06) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlDocument.java:176` other (catchall-09) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlAttributeDecl.java:103` logic-flaw (catchall-09) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/HtmlDomParserContext.java:203` logic-flaw (spec-crypto-14) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/ReaderNode.java:391` logic-flaw (spec-logic-bug-14) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/SaveContextVisitor.java:405` injection (catchall-11) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/SaveContextVisitor.java:870` injection (catchall-11) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/dom2dtm/DOM2DTM.java:883` other (catchall-12) — s4 confidence 0.35 < gate 0.60
- **[UNCONFIRMED]** `lib/nokogiri/css/selector_cache.rb:16` other (catchall-17) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `lib/nokogiri/xml/document_fragment.rb:96` injection (catchall-18) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/xml_node.c:1951` injection (spec-crypto-01) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/hashmap.c:288` logic-flaw (spec-crypto-04) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/gumbo.c:167` other (spec-crypto-05) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/c14n/ElementProxy.java:238` logic-flaw (spec-crypto-15) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/string_set.c:6` logic-flaw (spec-crypto-17) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `lib/nokogiri/xml/document_fragment.rb:268` injection (spec-crypto-18) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/xml_document.c:424` logic-flaw (spec-logic-bug-01) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/hashmap.c:270` integer-overflow (spec-logic-bug-04) — s4 confidence 0.32 < gate 0.60
- **[UNCONFIRMED]** `ext/nokogiri/gumbo.c:230` integer-overflow (spec-logic-bug-05) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `lib/nokogiri/css/xpath_visitor.rb:341` logic-flaw (spec-logic-bug-06) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlXpathContext.java:133` logic-flaw (spec-logic-bug-07) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XsltStylesheet.java:117` logic-flaw (spec-logic-bug-07) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/error.c:154` integer-overflow (spec-logic-bug-10) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/internals/c14n/Canonicalizer11.java:504` logic-flaw (spec-logic-bug-15) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/token_buffer.c:42` integer-overflow (spec-logic-bug-17) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `gumbo-parser/src/utf8.h:79` logic-flaw (spec-logic-bug-17) — s4 confidence 0.20 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XsltStylesheet.java:260` injection (spec-access-control-07) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlSchema.java:292` info-leak (spec-access-control-08) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `ext/java/nokogiri/XmlRelaxng.java:76` other (spec-access-control-14) — s4 confidence 0.40 < gate 0.60
- **[FP]** `ext/java/nokogiri/XsltStylesheet.java:153` logic-flaw (spec-crypto-07) — XSLT stylesheets are trusted executable code by Nokogiri's explicit, documented design (mirrored on the CRuby/libxslt path); absence of secure-processing is intentional, and no untrusted-stylesheet flow exists within the scanned library — exploitability requires the consuming app to violate the documented "do not pass untrusted stylesheets" contract.
- **[FP]** `gumbo-parser/src/tokenizer.c:849` info-leak (spec-logic-bug-02) — real uninitialized-write bug, but Nokogiri's only GumboAttribute consumer (gumbo.c) reads just name/value; value_start/value_end are never read or serialized, so no data ever leaks.
- **[FP]** `ext/java/nokogiri/XsltStylesheet.java:153` injection (spec-access-control-07) — Stylesheet is developer-supplied code, not parsed untrusted data; the library explicitly documents that stylesheets must be trusted and intentionally supports extension functions, so the missing secure-processing flag is working-as-designed, exploitable only by app contract violation.
- **[FP]** `ext/nokogiri/html4_element_description.c:27` info-leak (spec-logic-bug-16) — claimed OOB info-leak cannot trigger (no element has attrs_depr longer than attrs_req); real behavior is a no-data NULL-deref crash, out of scope per rule B, and reachable only via an uncommon app-exposed introspection API.


---

## Appendix: Scan Scope

### Folders scanned (26)

- `./`
- `bin/`
- `ext/java/nokogiri/`
- `ext/java/nokogiri/internals/`
- `ext/java/nokogiri/internals/c14n/`
- `ext/java/nokogiri/internals/dom2dtm/`
- `ext/nokogiri/`
- `gumbo-parser/`
- `gumbo-parser/src/`
- `lib/`
- `lib/nokogiri/`
- `lib/nokogiri/css/`
- `lib/nokogiri/decorators/`
- `lib/nokogiri/html4/`
- `lib/nokogiri/html4/sax/`
- `lib/nokogiri/html5/`
- `lib/nokogiri/jruby/`
- `lib/nokogiri/version/`
- `lib/nokogiri/xml/`
- `lib/nokogiri/xml/node/`
- `lib/nokogiri/xml/pp/`
- `lib/nokogiri/xml/sax/`
- `lib/nokogiri/xml/xpath/`
- `lib/nokogiri/xslt/`
- `lib/xsd/xmlparser/`
- `misc/`

### Excluded from scan (287 files)

**Folders** (matched `exclude_dirs`):

- `test/` — 144 files
- `.git/` — 28 files
- `oci-images/` — 19 files
- `rakelib/` — 14 files
- `.github/` — 11 files
- `scripts/` — 10 files
- `gumbo-parser/test/` — 10 files
- `gumbo-parser/fuzzer/` — 5 files
- `doc/` — 3 files
- `adr/` — 2 files
- `suppressions/` — 2 files
- `checkpoints/` — 1 files

**File types** (matched `exclude_exts`):

- `*.md` — 11 files
- `*.jar` — 11 files
- `*.patch` — 5 files
- `*.gperf` — 4 files
- `*.sed` — 1 files

**Patterns** (matched `exclude_globs`):

- `**/.gitignore` — 2 files
- `**/.gitkeep` — 2 files
- `**/.gitmodules` — 1 files
- `**/.editorconfig` — 1 files
