# Vuln-scan findings: nokogiri

Target: `/home/higgs/workspace/cyness/nokogiri` (commit 7ab68ffc)
Scanned: 2026-06-12 — static, read-only. **Candidates for /triage, not verified.**
11 findings: 0 HIGH / 5 MEDIUM / 6 LOW (4 low-confidence < 0.4), across 6 focus areas.

| id | sev | conf | category | file:line | title |
|---|---|---|---|---|---|
| F-001 | MEDIUM | 0.8 | heap-buffer-overflow | ext/nokogiri/html4_element_description.c:29 | OOB read in required_attributes (loop bounds attrs_depr, indexes attrs_req) |
| F-002 | MEDIUM | 0.8 | xpath-injection | lib/nokogiri/css/xpath_visitor.rb:172 | CSS #id selector emits escape-decoded value unescaped into XPath literal |
| F-003 | MEDIUM | 0.8 | xpath-injection | lib/nokogiri/css/xpath_visitor.rb:368 | CSS class / ~= value interpolated unescaped into XPath literal (css_class) |
| F-004 | LOW | 0.8 | null-deref | ext/nokogiri/xml_sax_push_parser.c:9 | NULL-deref in push-parser free when context never initialized |
| F-005 | MEDIUM | 0.7 | null-deref | ext/nokogiri/xslt_stylesheet.c:336 | Transform wraps unchecked NULL result document -> NULL write |
| F-006 | LOW | 0.7 | memory-leak | ext/nokogiri/xml_document.c:648 | canonicalize leaks c_namespaces + output buffer on embedded-NUL namespace |
| F-007 | MEDIUM | 0.6 | redos | lib/nokogiri/html4/encoding_reader.rb:64 | Quadratic backtracking in JRuby meta-charset regex on full untrusted doc |
| F-008 | LOW | 0.3 | null-deref | ext/nokogiri/xml_document.c:633 | Unchecked xmlAllocOutputBuffer return dereferenced (OOM only) |
| F-009 | LOW | 0.2 | integer-overflow | ext/nokogiri/gumbo.c:319 | size_t caret-diagnostic length truncated to int (>2GiB line) |
| F-010 | LOW | 0.2 | out-of-bounds-read | gumbo-parser/src/error.c:393 | find_prev/next_newline rely on assert-only bounds (no reachable path) |
| F-011 | LOW | 0.2 | xpath-injection | lib/nokogiri/css/xpath_visitor.rb:138 | :contains() argument passed through unquoted (no reachable breakout) |

---

### F-001 — Out-of-bounds read in required_attributes (loop bounded by attrs_depr but indexes attrs_req)
`ext/nokogiri/html4_element_description.c:29` | heap-buffer-overflow | MEDIUM | confidence 0.8

In `required_attributes()` the NULL check is on `description->attrs_req` (line 27), but the loop termination reads `description->attrs_depr[i]` (line 29) while the body dereferences `description->attrs_req[i]` (line 30). `attrs_req` and `attrs_depr` are independent NULL-terminated arrays in libxml2's static `htmlElemDesc` tables with frequently different lengths. If `attrs_depr` is longer, the loop runs past `attrs_req`'s terminator, reading `attrs_req[i]` OOB and passing it to `NOKOGIRI_STR_NEW2` -> `strlen()` on a garbage pointer. The sibling functions (deprecated/optional/sub) correctly index the array they iterate, confirming a copy-paste defect. Deprecated elements (applet/basefont/isindex) carry a longer `attrs_depr` than a short non-NULL `attrs_req`.

- **Exploit:** `Nokogiri::HTML4::ElementDescription[tag].required_attributes` on such an element performs an OOB read of adjacent rodata, possibly crashing or leaking adjacent static memory into the returned String.
- **Fix:** iterate the array being indexed: `for (i = 0; description->attrs_req[i]; i++)`.
- **Score reason:** Confirmed defect; reachable, though impact bounded to static-memory adjacency.

### F-002 — CSS #id selector emits unescaped, escape-decoded id value into a single-quoted XPath literal
`lib/nokogiri/css/xpath_visitor.rb:172` | xpath-injection | MEDIUM | confidence 0.8

`visit_id` builds `"@id='#{Regexp.last_match(1)}'"` with no quoting. The id value comes from `unescape_css_identifier`, which decodes `\27` to an apostrophe; the HASH token admits `{escape}` sequences, so `#x\27 ...` yields an id with a literal apostrophe that closes the XPath literal early. The attribute-equality path uses a `concat()` rewrite for defense; `visit_id` has none. Verified end-to-end (unescape precedes `visit_id`, not re-escaped downstream).

- **Exploit:** `doc.css("##{params[:id]}")` with an id like `x\27 or\20 \271\27 =\271` -> `//*[@id='x' or '1'='1']`, selecting nodes the app intended to exclude. The escape vector bypasses naive app-side quote filters.
- **Fix:** route id through a shared XPath string-literal quoting helper (handle `'` and `"`) in `visit_id`/`visit_class_condition`/`css_class`.
- **Score reason:** Verified breakout; deduction since exploitation needs app-side interpolation into doc.css.

### F-003 — CSS class selector / ~= includes value interpolated unescaped into XPath literal (css_class)
`lib/nokogiri/css/xpath_visitor.rb:368` | xpath-injection | MEDIUM | confidence 0.8

`css_class(hay, needle)` interpolates `needle` into XPath literals with no escaping in both the builtin branch (line 368, `nokogiri-builtin:css-class(...,'#{needle}')`) and the default branch (line 371, `... ' #{needle} '`). `needle` comes from `visit_class_condition` (unescape_css_identifier) and the `~=` `:includes` branch; `\27` decodes to apostrophe so `.foo\27 bar` -> needle `foo'bar` breaks out of the literal. No `concat()` protection unlike attribute-equality. `doc.css` uses OPTIMAL, hitting the builtin branch on libxml.

- **Exploit:** `doc.css(".tag-#{user_tag}")` / `doc.css("[class~='#{user_tag}']")` with a `\27`-bearing value alters the `contains(...)` match set, selecting nodes outside the intended class filter.
- **Fix:** escape `needle` via a shared quoting helper; fix the `:includes` branch to strip quotes on the raw value before re-quoting.
- **Score reason:** Verified end-to-end; gated only by an app interpolating untrusted input into a class selector.

### F-004 — NULL-pointer dereference in push-parser free when context never initialized
`ext/nokogiri/xml_sax_push_parser.c:9` | null-deref | LOW | confidence 0.8

`xml_sax_push_parser_free` dereferences `ctx->myDoc` (line 9) before the `if(ctx)` check (line 12). `allocate` wraps a NULL data ptr; `DATA_PTR` is set only after `xmlCreatePushParserCtxt` succeeds (line 99). If a PushParser is allocated but GC'd without successful init (`.allocate` directly, or init raising between allocate and line 99), `ctx` is NULL and `ctx->myDoc` derefs NULL during GC. Shared by the HTML4 push parser. Reachable via Ruby-API misuse / init-failure, not untrusted document bytes.

- **Exploit:** `Nokogiri::XML::SAX::PushParser.allocate` then GC -> `free(NULL)` executes `NULL->myDoc`, crashing.
- **Fix:** `if (ctx == NULL) { return; }` at the top of the free function.
- **Score reason:** Real NULL-deref but only via API misuse/init-failure, not untrusted documents.

### F-005 — Transform passes unchecked NULL result document to wrap, causing NULL-pointer dereference
`ext/nokogiri/xslt_stylesheet.c:336` | null-deref | MEDIUM | confidence 0.7

`c_result_document = xsltApplyStylesheet(...)` (line 336) is never NULL-checked; the only guard is the generic-error-string check (line 347). `xsltApplyStylesheet` can return NULL on failures that bypass the generic error func (alloc failures, transform-context init failures, silent early-returns), leaving `rb_error_str` empty. Execution then calls `noko_xml_document_wrap(0, NULL)` -> `_xml_document_data_ptr_set`, where `assert(c_document->_private == NULL)` is compiled out under NDEBUG (release gems) and `c_document->_private = tuple` writes through NULL.

- **Exploit:** a stylesheet/input combination that returns NULL with empty error string crashes the Ruby process (DoS). The cited `terminate="yes"` case is likely caught by the hooked generic-error handler.
- **Fix:** check `c_result_document == NULL` before wrapping and raise a RuntimeError when no result and no parse error.
- **Score reason:** Real unguarded NULL write; NULL-with-empty-error realistic via OOM/silent returns.

### F-006 — canonicalize leaks c_namespaces and output buffer when a namespace string contains an embedded NUL
`ext/nokogiri/xml_document.c:648` | memory-leak | LOW | confidence 0.7

In `rb_xml_document_canonicalize`, `inclusive_namespaces` is marshalled at lines 648-652: `ruby_xcalloc` then a loop of `StringValueCStr(entry)`. `StringValueCStr` raises on embedded NUL, propagating before `ruby_xfree(c_namespaces)` (661) and `xmlOutputBufferClose(c_obuf)` (662), leaking both. Same leak class as the fixed XSLT path (GHSA-v2fc-qm4h-8hqv via rb_protect), not applied here. Caller-supplied; each NUL-containing call leaks.

- **Exploit:** `doc.canonicalize(mode, ["ns\x00evil"])` from attacker-influenced input; if the caller rescues and retries, repeated calls exhaust memory.
- **Fix:** marshal under `rb_protect`, or use `rb_ensure`/validate for NUL-free strings before allocating.
- **Score reason:** Confirmed no cleanup on the raise path; real but low-impact per-call leak.

### F-007 — Quadratic backtracking in JRuby meta-charset encoding-detection regex on full untrusted document
`lib/nokogiri/html4/encoding_reader.rb:64` | redos | MEDIUM | confidence 0.6

On the JRuby branch (`Nokogiri.jruby?`), `detect_encoding` runs `/(<meta\s)(.*)(charset\s*=\s*([\w-]+))(.*)/i` against `chunk` (line 64). Two greedy `.*` groups around a required literal produce O(n^2) backtracking per line when `<meta` is present but `charset=` is absent. The string parse path passes the ENTIRE document unbounded (`HTML4::Document.parse` -> `detect_encoding(input)`), reached via `Nokogiri.HTML(str)`/`HTML4.parse(str)`. The IO path is bounded (~1KB). CRuby uses a SAX push parser and does not hit this regex; JRuby-only, quadratic (not exponential).

- **Exploit:** on JRuby, `Nokogiri.HTML(body)` with a single newline-free line `"<meta " + "a"*2_000_000` (no `charset=`) pins a CPU core; repeated requests amplify to DoS.
- **Fix:** detect on a bounded prefix (`chunk[0,1024]`) and rewrite to avoid two unbounded `.*` around a literal, e.g. `/<meta\b[^>]*?charset\s*=\s*([\w-]+)/i`.
- **Score reason:** Verified; real but moderate (needs literal `<meta`, long newline-free run, JRuby-only, quadratic).

### F-008 — Unchecked xmlAllocOutputBuffer return dereferenced in canonicalize
`ext/nokogiri/xml_document.c:633` | null-deref | LOW | confidence 0.3 (low-confidence)

`c_obuf = xmlAllocOutputBuffer(NULL)` (line 633) is unchecked; lines 635-637 dereference it. Returns NULL on allocation failure -> NULL write. OOM-only, no attacker control.

- **Fix:** `if (c_obuf == NULL) rb_raise(rb_eNoMemError, ...)` after line 633.
- **Score reason:** Real latent NULL-deref but OOM-triggered with no attacker control; defense-in-depth.

### F-009 — size_t caret-diagnostic length truncated to int in rb_utf8_str_new
`ext/nokogiri/gumbo.c:319` | integer-overflow | LOW | confidence 0.2 (low-confidence)

`add_errors()` passes a size_t diagnostic length (driven by `error->position.column`) to `rb_utf8_str_new(msg, (int)size)`. A single input line >~2 GiB makes `(int)size` negative/truncated. Volumetric/oversized-input precondition; value feeds a copy of an already-allocated buffer.

- **Fix:** clamp `size` to INT_MAX (or a sane line limit) before the cast.
- **Score reason:** Genuine sign-truncation but >2GiB single line is a volumetric FP precondition; no realistic OOB.

### F-010 — find_prev/next_newline rely on assert-only bounds for error_location
`gumbo-parser/src/error.c:393` | out-of-bounds-read | LOW | confidence 0.2 (low-confidence)

`find_prev_newline`/`find_next_newline` scan from `error_location` guarded only by `assert(...)`, which compiles out under NDEBUG. No reachable path produces an out-of-buffer `error_location` (all error sites set `original_text.data` from in-buffer iterator pointers).

- **Fix:** replace asserts with runtime clamps to `[source_text, source_end]`.
- **Score reason:** No reachable trigger; pure defense-in-depth (exclusion rule 13).

### F-011 — :contains() argument passed through with limited but possible unsafe value sources
`lib/nokogiri/css/xpath_visitor.rb:138` | xpath-injection | LOW | confidence 0.2 (low-confidence)

`visit_function` emits `"contains(.,#{node.value[1]})"`. STRING args keep their quotes and forbid unescaped matching quotes; IDENT/xpath_attribute args are unquoted but the tokenizer `nmchar` class excludes parens/quotes/spaces, so no injection metacharacter reaches the interpolation. No reachable breakout found.

- **Fix:** route the argument through the shared quoting helper anyway (defense-in-depth).
- **Score reason:** Tokenizer char classes block every interpolation path; no constructible breakout.
