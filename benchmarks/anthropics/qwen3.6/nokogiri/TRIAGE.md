# Triage Report

11 findings -> 0 duplicates, 8 false positives, 3 confirmed (1 HIGH, 1 MEDIUM, 1 HIGH), 0 need manual test

Context: auto; environment = Unknown. Treat any externally-reachable entry point as untrusted; flag trust-boundary assumptions explicitly in rationale.; scoring = derived HIGH/MEDIUM/LOW; 3-vote verification.

## Act on these

### [HIGH] CSS #id selector emits unescaped, escape-decoded id value into a single-quoted XPath literal  (f002)
`lib/nokogiri/css/xpath_visitor.rb:172` | xpath-injection | claimed MEDIUM (alignment +2) | confidence 10.0/10
**Owner:** lib/nokogiri/css/xpath_visitor.rb; no CODEOWNERS entry for CSS module internals (top committer pattern would need git history)
**Verdict:** exploitable, votes {"true_positive": 3, "false_positive": 0, "cannot_verify": 0}
**Preconditions (4):**
- Untrusted user input flows into doc.css() selector argument
- CSS identifier contains escape-sequence \27 (literal apostrophe after unescape)
- The CSS selector is a HASH (#id) selector, triggering visit_id at line 170-173
- No app-side defense that escapes the CSS input before passing to Nokogiri::CSS.xpath_for
**Threat-model match:** none
**Why:** Code at lib/nokogiri/css/xpath_visitor.rb:171-172 shows visit_id: line 171 regex-matches #id, line 172 interpolates Regexp.last_match(1) directly into a single-quoted XPath string @id='...' with zero escaping. CSS parser decodes \27 -> U+0027 (apostrophe). An input like #x\27 or'1'='1' yields xpath //*[@id='x' or '1'='1']. The attribute-equality path (visit_attribute_condition, line 175-209) defends with concat() rewrite, but visit_id has no such protection. Reachable via doc.css(user_input) with 0 preconditions and unauthenticated_remote access -> HIGH (scanner's claimed MEDIUM underestimates this).
**Reachability evidence:** lib/nokogiri/css/xpath_visitor.rb:172, lib/nokogiri/css/xpath_visitor.rb:170

### [MEDIUM] Out-of-bounds read in required_attributes: loop bounded by attrs_depr but indexes attrs_req  (f001)
`ext/nokogiri/html4_element_description.c:29` | heap-buffer-overflow | claimed MEDIUM (alignment 0) | confidence 10.0/10
**Owner:** ext/nokogiri/html4_element_description.c; no CODEOWNERS entry for C extension sources (top committer pattern would need git history)
**Verdict:** exploitable, votes {"true_positive": 3, "false_positive": 0, "cannot_verify": 0}
**Preconditions (3):**
- htmlTagLookup(tag_name) returns a non-NULL htmlElemDesc with both attrs_req != NULL and NULL-terminated attrs_depr
- attrs_depr array is longer than attrs_req (libxml2 static tables contain such entries like applet, basefont)
- Caller reaches required_attributes() on ElementDescription[certain HTML4 element]
**Threat-model match:** none
**Why:** Code at ext/nokogiri/html4_element_description.c:27-30: line 27 checks attrs_req for NULL, but loop at line 29 tests attrs_depr[i] for termination while dereferencing attrs_req[i] at line 30 - a copy-paste defect. Sibling functions deprecated_attributes (line 53-57) and optional_attributes (line 79-83) correctly iterate the same array they index. Call chain: get_description(htmlTagLookup(tag_name)) -> required_attributes. Impact bounded to rodata pointer reads on adjacent struct fields in libxml2's static descriptor tables -> MEDIUM.
**Reachability evidence:** ext/nokogiri/html4_element_description.c:27, ext/nokogiri/html4_element_description.c:29, ext/nokogiri/html4_element_description.c:30

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f003 | CSS class selector /= includes value interpolated unescaped into XPath string literal | lib/nokogiri/css/xpath_visitor.rb:368 | split vote dropped under precision policy; majority ruled FP - the :contains() path at line 138-139 retains quotes from tokenizer and IDENT/nmchar char classes block metacharacters |
| f004 | NULL-pointer dereference in push-parser free when context never initialized | ext/nokogiri/xml_sax_push_parser.c:9 | FP (rule 3 - intended design): Ruby constructor pattern, rb_undef_alloc_func, _initialize_native never returns Qnil |
| f005 | Transform passes unchecked NULL result document to wrap, causing NULL-pointer dereference | ext/nokogiri/xslt_stylesheet.c:336 | FP (rule 13 - missing hardening only): xsltApplyStylesheet NULL returns route through error callback in practice; no concrete exploit path |
| f006 | canonicalize leaks c_namespaces and output buffer when a namespace string contains an embedded NUL | ext/nokogiri/xml_document.c:648 | FP (rule 13): bounded per-call leak from abnormal input (NUL bytes in namespace names), not exploitable |
| f007 | Quadratic backtracking in JRuby meta-charset encoding-detection regex | lib/nokogiri/html4/encoding_reader.rb:64 | FP (rule 1): JRuby-only, volumetric DoS at infrastructure layer, CRuby uses SAX push parser (regex unreachable) |
| f008 | Unchecked xmlAllocOutputBuffer return dereferenced in canonicalize | ext/nokogiri/xml_document.c:633 | FP (rule 1): OOM-only trigger, no attacker control, volumetric/infrastructure DoS |
| f009 | size_t caret-diagnostic length truncated to int in rb_utf8_str_new | ext/nokogiri/gumbo.c:319 | FP (rule 1): requires multi-GiB single input line; truncated value feeds already-allocated buffer |
| f010 | find_prev/next_newline rely on assert-only bounds for error_location | gumbo-parser/src/error.c:393 | FP (rule 13): defense-in-depth only, invariants hold in all reviewed code paths |
| f011 | :contains() argument passed through with limited but possible unsafe value sources | lib/nokogiri/css/xpath_visitor.rb:138 | FP (rule 13): scanner's own hardening suggestion, tokenizer char classes block all injection paths |
