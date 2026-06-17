# Agentic SAST — nokogiri

## Summary
The dataset contains a single verified SSRF vulnerability in Nokogiri's RelaxNG schema parser. Preconditions: an attacker supplies untrusted XML/schema to an internet-facing validation entry point. Access level: anonymous/any (zero authentication or UI interaction required). Blast radius: scoped to a single request but yields reliable internal network access or local file disclosure via unrestricted external entity resolution. No design controls mitigate the fetch, and with only one finding present, no cross-vulnerability chains are exploitable. The finding's CVSS 6.5 base score anchors to the Medium band per the explicit mapping rules, though its pre-auth reachability pushes it near the High tier boundary.

## Scan Metrics

- Scan ID: 2026-06-15T10:04:22Z__nokogiri
- Module: nokogiri
- Start: 2026-06-15T10:04:22Z
- End: 2026-06-16T08:55:49Z
- Duration (sec): 82287
- Files in scope: 262
- Files analyzed (unique): 253
- Coverage: 96.6%
- Chunks: 132 (risk=9, catch-all=23, specialist=100)
- Tokens (prompt): 15460760
- Tokens (completion): 1245811
- Tokens (total): 16706571

- Folders scanned: 24
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s6-verify | 668 | 10,412,959 | 1,136,906 | 11,549,865 | 69.1 | 0 |
| s4-deepdive | 132 | 4,563,684 | 72,444 | 4,636,128 | 27.8 | 0 |
| s1-preprocess | 11 | 441,665 | 7,815 | 449,480 | 2.7 | 0 |
| s5-prefilter | 1 | 15,715 | 11,297 | 27,012 | 0.2 | 0 |
| s3-decompose | 1 | 13,630 | 5,751 | 19,381 | 0.1 | 0 |
| s2-threatmodel | 1 | 8,563 | 6,083 | 14,646 | 0.1 | 0 |
| s1-autoexclude | 1 | 3,983 | 5,101 | 9,084 | 0.1 | 0 |
| unlabeled | 2 | 561 | 414 | 975 | 0.0 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| c-cpp | 44231 | 44231 | 100.0 |
| java | 19714 | 19714 | 100.0 |
| other | 3792 | 782 | 20.6 |
| ruby | 12252 | 12252 | 100.0 |

## Scan Health

- ⚠️ Degraded coverage: 4/132 deep-dive chunk(s) failed or timed out — their findings are absent from this report.
- Recoverable errors logged by stage: s2=1, s4=11, s6-verify=16
- Full error log: `nokogiri_20260615T100422Z_errors.jsonl`

## Verification
- Raw findings (pre-verification): 71
- True positives (verified): 1
- False positives (dropped): 32
- Verifier errors (excluded — undetermined, not confirmed clean): 16
- Duplicates collapsed (all passes): 12
- Verification precision: 1.4%

## Findings (1)

### 1. [MEDIUM] Unmitigated SSRF via external schema resolution in RelaxNG.new
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `lib/nokogiri/xml/relax_ng.rb:60-62`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The RelaxNG.new method at line 61 passes the unvalidated 'input' directly to Nokogiri::XML::Document.parse, which then routes it to the underlying C-level RelaxNG parser. As explicitly documented in the class header (lines 18-21), RELAX NG input is fundamentally treated as trusted by the underlying libraries, causing them to automatically dereference external schema references (e.g., <externalRef> or XInclude directives) without restriction. The Ruby wrapper performs zero sanitization, allow-listing, or network sandboxing, meaning any untrusted schema content triggers unrestricted resource resolution before validation even begins.

#### Impact
An attacker supplying a crafted RELAX NG schema can force the server to make arbitrary outbound HTTP requests or read local files via libxml2's schema resolution, leaking internal network topology or sensitive data.

#### Exploit scenario
An attacker submits an HTTP payload containing a RELAX NG schema with an <externalRef href="http://169.254.169.254/latest/meta-data/iam/security-credentials/"/> pointer to a cloud-metadata endpoint. The application instantiates Nokogiri::XML::RelaxNG.new(attached_schema), causing libxml2 to automatically fetch the pointer, initiate an SSRF request to the internal metadata service, and return the exposed IAM credentials in the response.

#### Preconditions
- Application must instantiate Nokogiri::XML::RelaxNG.new (or read_memory) with attacker-controlled input
- Underlying system's libxml2 is compiled with default external entity resolution enabled

```
      def self.new(input, parse_options_ = ParseOptions::DEFAULT_SCHEMA, options: parse_options_)
        from_document(Nokogiri::XML::Document.parse(input), options)
      end
```

#### How to fix
Never instantiate Nokogiri::XML::RelaxNG with untrusted content. Enforce a strict allow-list of trusted, local schema paths before parsing, or process schema validation in a network-isolated environment with no outbound connectivity.

**Exploitability:** CVSS 6.5 falls within the Medium band (4.0-6.9) per the authoritative mapping rule. Pre-auth reachability (AV:N/PR:N/UI:N/AC:L) and zero preconditions would normally qualify for the HIGH tier, but the explicit CVSS band takes precedence. The Ruby wrapper delegates unvalidated input directly to the C-level RelaxNG parser, which treats schemas as trusted and automatically dereferences external URIs (XInclude/externalRef) without network sandboxing or allow-listing. Impact is limited to C:L/I:L for a single request process, bounded by the host's actual network exposure. No downgrade triggers apply (not debug/test, does not require a second vuln).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Scanner confirmed: RelaxNG.new passes input to C-layer which treats schemas as fully trusted with no NONET enforcement; documented explicitly in code header as an intentional exception to Nokogiri's trust model

Now I have the full picture. The scanner's claim is that `RelaxNG.new(input)` allows unrestricted external network access when parsing RELAX NG schemas containing `<externalRef>` or XInclude directives. Let me verify:

**Line 61 of `relax_ng.rb`:** `from_document(Nokogiri::XML::Document.parse(input), options)`
- `input` goes through `Document.parse` (uses `DEFAULT_XML` which includes NONET)
- But the resulting document is then passed to the C-level RelaxNG constructor via `from_document`

**The critical evidence is in the class header (lines 16-21 of `relax_ng.rb`):**
```
🛡 <b>Do not use this class for untrusted schema documents.</b> RELAX NG input is always
treated as *trusted*, meaning that the underlying parsing libraries <b>will access network
resources</b>. This is counter to Nokogiri's "untrusted by default" security policy, but is an
unfortunate limitation of the underlying libraries.
```

And lines 52, 56-57 confirm `parse_options` is **unused**:
```
- +options:+ (Nokogiri::XML::ParseOptions)
  Defaults to ParseOptions::DEFAULT_SCHEMA ⚠ Unused
⚠ +parse_options+ is currently unused by this method and is present only as a placeholder for
future functionality.
```

**`ParseOptions::DEFAULT_SCHEMA = NONET | BIG_LINES`** (line 350 of `parse_options.rb`) — but this is explicitly documented as unused for `RelaxNG.new`. The NONET flag on the intermediate `Document.parse` call blocks network access _for that parse_, but the subsequent `from_document` path routes to the C-level RelaxNG processing which has its own trust model — as the header warns, it treats Relax NG input as fully trusted and will access network resources.

**Call chain verification:**
- `RelaxNG.new(input)` → `from_document(Document.parse(input), options)` → C-level RelaxNG constructor
- There is **no** code-level defense — the only "defense" is the explicit documentation warning in lines 18-21

**Impact:** If an application passes attacker-controlled content to `RelaxNG.new()`, the C-layer will fetch any `<externalRef href="...">` URLs including local metadata endpoints (e.g., `http://169.254.169.254/...`). This is documented and intentional, but **the scanner's technical claim is correct** — there is zero input validation or network restriction in the call path.

This is **not** a false positive — the scanner correctly identified that:
1. The code path reaches the sink (no blocking code)
2. The documentation explicitly confirms relaxed trust
3. `parse_options` is unused (nonet doesn't apply)

However, it's a known, documented limitation of the library, not a bug. Still a TRUE finding.

## Exploit Chains

No exploit chains were identified — the findings above are independent and do not combine into a multi-step path.


## Dropped Findings

- **[UNCONFIRMED]** `ext/nokogiri/xml_node.c:1951` injection (catchall-10) — s4 confidence 0.50 < gate 0.60
- **[EXCLUDED]** `crypto/src/kdf.rs:112` injection (catchall-15) — file not in repo inventory
- **[EXCLUDED]** `src/config/settings.env:3` other (spec-crypto-23) — file not in repo inventory
- **[EXCLUDED]** `src/main.py:45` injection (spec-crypto-23) — file not in repo inventory
- **[EXCLUDED]** `src/main.py:12` injection (spec-crypto-23) — file not in repo inventory
- **[EXCLUDED]** `src/api/client.py:25` logic-flaw (spec-crypto-23) — file not in repo inventory
- **[EXCLUDED]** `src/api/client.py:30` logic-flaw (spec-crypto-23) — file not in repo inventory
- **[EXCLUDED]** `src/server.py:45` injection (spec-access-control-18) — file not in repo inventory
- **[EXCLUDED]** `src/utils.py:90` injection (spec-access-control-18) — file not in repo inventory
- **[EXCLUDED]** `src/app.js:37` other (spec-batch-etl-23) — file not in repo inventory
- **[DUP (pre-verify)]** `lib/nokogiri/html4/document_fragment.rb:53` logic-flaw (spec-logic-bug-03) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `lib/nokogiri/decorators/slop.rb:21` injection (spec-logic-bug-09) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `ext/java/nokogiri/internals/dom2dtm/DOM2DTM.java:883` logic-flaw (spec-batch-etl-19) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `lib/nokogiri/xml/parse_options.rb:342` logic-flaw (spec-crypto-02) — pre-verify semantic: Traces to the same DEFAULT_XSLT constant enabling unsafe parse flags; fixing the constant closes both.
- **[DUP (pre-verify)]** `lib/nokogiri/xml/relax_ng.rb:16` logic-flaw (spec-crypto-07) — pre-verify semantic: Identical RelaxNG.new SSRF defect described from different lines; one wrapper patch suffices.
- **[DUP (pre-verify)]** `ext/nokogiri/xml_document.c:430` other (spec-batch-etl-15) — pre-verify semantic: Identical RSTRING_LEN truncation in xml_document.c; a single cast validation resolves both.
- **[DUP (pre-verify)]** `gumbo-parser/src/vector.c:81` logic-flaw (spec-logic-bug-24) — pre-verify semantic: Identical unsigned underflow in gumbo_vector_insert_at; one boundary check fixes both.
- **[DUP (pre-verify)]** `ext/nokogiri/html4_document.c:106` integer-overflow (spec-access-control-14) — pre-verify semantic: Exact duplicate in html4_document.c; unified length validation fix resolves both.
- **[DUP (pre-verify)]** `lib/nokogiri/xml/parse_options.rb:342` injection (spec-batch-etl-02) — pre-verify semantic: Traces to the same DEFAULT_XSLT constant enabling unsafe parse flags; fixing the constant closes both.
- **[DUP (pre-verify)]** `lib/nokogiri/xml/relax_ng.rb:60` injection (spec-batch-etl-07) — pre-verify semantic: Same RelaxNG.new SSRF defect described from different lines; one patch to the wrapper suffices.
- **[DUP (pre-verify)]** `ext/nokogiri/html4_element_description.c:29` other (spec-batch-etl-20) — pre-verify semantic: Identical array length mismatch in required_attributes; one loop bound fix resolves both.
- **[DUP (pre-verify)]** `gumbo-parser/src/attribute.c:38` logic-flaw (spec-batch-etl-21) — pre-verify semantic: Same NULL dereference in gumbo_get_attribute; a single guard resolves both.
- **[FP]** `lib/nokogiri/xslt.rb:79` injection (chunk-01) — Scanner's core factual claim that DEFAULT_XSLT lacks NONET is directly contradicted by source (line 342 of parse_options.rb); NONET does block network access, neutralizing the SSRF vector. The remaining local file access is a documented, intentional design, not an undisclosed vulnerability.
- **[VERIFY-ERR]** `lib/nokogiri/html5/document.rb:149` integer-overflow (chunk-02-a) — verifier output unparseable
- **[FP]** `ext/nokogiri/gumbo.c:384` logic-flaw (chunk-02-b) — Scanner misread: (1) `rb_get_kwargs` always populates all array slots with `Qundef` for missing keys; (2) `rb_raise` before `rb_ensure` propagates the exception to the caller, NOT to a cleanup handler that was never registered; (3) `args` is a fully-initialized local struct, never garbage memory.
- **[FP]** `gumbo-parser/src/string_buffer.c:25` integer-overflow (chunk-02-c) — Scanner misread code: GumboStringPiece::length is derived from pointer arithmetic within the bounded input buffer, not independently user-controllable; overflow of SIZE_MAX is physically impossible
- **[FP]** `gumbo-parser/src/parser.c:1988` heap-overflow (chunk-02-c) — The gperf replacement table maps every known-input key to a target string that is the same length or shorter; no heap overflow is possible regardless of input.
- **[VERIFY-ERR]** `gumbo-parser/src/vector.c:77` integer-overflow (chunk-02-d) — verifier output unparseable
- **[FP]** `lib/nokogiri/xml/parse_options.rb:401` logic-flaw (chunk-03) — **
- **[FP]** `ext/nokogiri/xml_sax_parser_context.c:227` injection (spec-crypto-12) — the scanner conflates XML_PARSE_NOENT with XML_PARSE_DTDLOAD; `replace_entities=` only enables entity replacement, not external DTD loading, so file-reading XXE is impossible without a DTDLOAD option which is not exposed on the SAX parser context
- **[VERIFY-ERR]** `lib/nokogiri/css/xpath_visitor.rb:175` injection (chunk-05) — verifier output unparseable
- **[FP]** `lib/nokogiri/xml/document_fragment.rb:104` injection (catchall-02) — Default parse options (DEFAULT_XML) explicitly exclude NOENT and DTDLOAD, making the XXE attack impossible as described; the scanner conflated unescaped string interpolation with actionable injection, ignoring the parse-option defaults that neutralize the impact.
- **[FP]** `lib/nokogiri/html4/document_fragment.rb:152` logic-flaw (catchall-03) — scanner misidentifies expected HTML parsing semantics (closing body tag corrects structure) as a security flaw; Nokogiri is a parser with no sanitization responsibility or security boundary in this path
- **[VERIFY-ERR]** `lib/nokogiri/html5/document_fragment.rb:169` logic-flaw (catchall-04) — verifier output unparseable
- **[VERIFY-ERR]** `lib/nokogiri/html4/sax/push_parser.rb:23` logic-flaw (catchall-06) — verifier output unparseable
- **[FP]** `lib/nokogiri/decorators/slop.rb:14` injection (spec-crypto-09) — Scanner incorrectly models Ruby method names as arbitrary XPath payloads; the . prefix prevents document-root scope, and if the attacker controls the document they can already use any XPath via standard APIs.
- **[FP]** `ext/nokogiri/xml_node.c:2055` other (catchall-10) — No security impact; the finding describes a metadata correctness bug in line-number reporting with no path to data exposure, auth bypass, or code execution. The scanner explicitly notes it "lacks direct security impact" and only affects debug/error tooling output.
- **[VERIFY-ERR]** `ext/nokogiri/xml_node.c:810` info-leak (catchall-10) — verifier output unparseable
- **[FP]** `ext/java/nokogiri/internals/c14n/NameSpaceSymbTable.java:360` logic-flaw (catchall-11) — Scanner misread the code by missing line 367 (`free = entries.length`); the `free` counter is correctly reset before each rehash and the claimed "silent overwrite" mechanism is impossible
- **[FP]** `ext/java/nokogiri/internals/dom2dtm/DOM2DTM.java:1629` logic-flaw (catchall-16) — Logic flaw causing incorrect SAX event emission for root-level PIs/comments; no security impact, no code execution, data exposure, or DoS path confirmed. It is a parser correctness bug.
- **[FP]** `ext/nokogiri/xml_sax_push_parser.c:10` use-after-free (catchall-17) — (no reason given)
- **[FP]** `gumbo-parser/src/attribute.c:29` other (catchall-20) — Scanner misidentified both the C type promotion rules and the type of GumboVector::length; length and capacity are the same unsigned int type so it can never exceed 2^32-1, and a max_attributes hard cap of 400 bounds the practical upper limit.
- **[VERIFY-ERR]** `gumbo-parser/src/error.c:638` type-confusion (catchall-22) — verifier output unparseable
- **[FP]** `lib/nokogiri/html4/element_description_defaults.rb:1112` logic-flaw (catchall-23) — data typo confirmed in source (htrue instead of h1/h2/h3), but DefaultDescriptions is metadata-only, not used in any parsing, filtering, or security-critical path; impact is zero
- **[FP]** `ext/nokogiri/xml_document.c:430` integer-overflow (spec-crypto-15) — Scanner correctly identified the int-cast but misread the data flow: the buffer comes from an already-allocated Ruby string heap, so truncation only controls how many bytes are processed, not the allocation size — no OOB access possible
- **[FP]** `lib/nokogiri.rb:68` logic-flaw (spec-logic-bug-01) — `opts` is indeed ignored, but the fallback defaults (DEFAULT_HTML) include NONET (disable external network) and exclude NOENT (no entity expansion), so the parser stays in SECURE mode; the exploit scenario is inverted (NOENT enables, not disables, entity expansion). No production callers found in lib/.
- **[VERIFY-ERR]** `lib/nokogiri/xml/parse_options.rb:415` other (spec-logic-bug-02) — verifier output unparseable
- **[FP]** `lib/nokogiri/html5.rb:344` logic-flaw (spec-logic-bug-04) — Scanner misidentified which exceptions are caught (Encoding::InvalidByteSequenceError inherits ArgumentError), and even where it's right, the crash is a per-request exception with no exploitable security impact.
- **[FP]** `lib/nokogiri/xslt.rb:79` logic-flaw (spec-access-control-05) — (no reason given)
- **[VERIFY-ERR]** `lib/nokogiri/xml/sax/push_parser.rb:35` logic-flaw (spec-logic-bug-06) — verifier output unparseable
- **[FP]** `lib/nokogiri/xml/schema.rb:69` logic-flaw (spec-logic-bug-07) — Scanner correctly identified that user-provided parse_options are silently ignored in Schema.new, but is wrong about the impact: the actual Document.parse call defaults to DEFAULT_XML which includes NONET (network-disabled), so the default parsing is secure regardless. The "bug" only prevents users from enabling dangerous options (NOENT/DTDLOAD) which is arguably more secure. The XSD parsing always has network access blocked by default, nullifying the claimed SSRF/XXE attack vector.
- **[FP]** `lib/nokogiri/encoding_handler.rb:10` logic-flaw (spec-logic-bug-10) — No production code queries NOKOGIRI-SENTINEL; only a test asserts it is non-nil. The scanner invented a broken-invariant scenario with zero downstream consumers.
- **[FP]** `ext/nokogiri/xml_sax_parser_context.c:89` use-after-free (spec-logic-bug-12) — Scanner misread CRuby control flow: rb_exc_raise/rb_raise never return, so the wrap-after-free line is unreachable
- **[VERIFY-ERR]** `ext/java/nokogiri/internals/c14n/NameSpaceSymbTable.java:125` logic-flaw (spec-logic-bug-13) — verifier output unparseable
- **[VERIFY-ERR]** `ext/nokogiri/html4_document.c:106` logic-flaw (spec-logic-bug-14) — verifier output unparseable
- **[VERIFY-ERR]** `ext/nokogiri/xml_document.c:571` other (spec-logic-bug-15) — verifier output unparseable
- **[FP]** `ext/java/nokogiri/internals/dom2dtm/DOM2DTM.java:1665` logic-flaw (spec-logic-bug-19) — scanner misread the code; the finally block exists at lines 1680-1682 and there is also a guard that allocates a new TreeWalker if m_walker has a stale handler
- **[FP]** `ext/java/nokogiri/internals/dom2dtm/DOM2DTM.java:1144` logic-flaw (spec-logic-bug-19) — No vector to construct cyclic EntityReferences; the Xerces DOM invariants are acyclic by design and enforced by both the parser and the DOM API
- **[VERIFY-ERR]** `ext/nokogiri/xml_sax_push_parser.c:56` logic-flaw (spec-logic-bug-20) — verifier output unparseable
- **[FP]** `ext/nokogiri/html4_element_description.c:28` logic-flaw (spec-logic-bug-20) — The loop mismatch (bug) is real, but `required_attributes` is a pure metadata/introspection method with zero calls in any production parsing path; it requires explicit user-level introspection code, not triggered by HTML parsing.
- **[FP]** `gumbo-parser/src/attribute.c:25` logic-flaw (spec-logic-bug-21) — Scanner misread vector implementation: removal compacts via memmove, no NULL gaps are ever created, and all gumbo_vector_add callers pass non-NULL pointers.
- **[VERIFY-ERR]** `lib/nokogiri/xml/node/save_options.rb:51` logic-flaw (spec-logic-bug-25) — verifier output unparseable
- **[FP]** `ext/nokogiri/html4_sax_parser_context.c:36` other (spec-access-control-20) — The C function implements the documented core API for a file-parsing library. Expecting application-level authorization or path-traversal sanitization on a general-purpose I/O contract is a category error; Ruby's standard File/IO APIs similarly lack these checks. The lack of mitigation is by design for a data ingestion primitive, and the claimed impact relies on application-layer path construction flaws, not a defect in this codebase.
- **[FP]** `lib/nokogiri.rb:42` injection (spec-batch-etl-01) — NONET is unconditionally set in both DEFAULT_HTML and DEFAULT_XML parse options, which blocks all network access during parsing; the scanner misread the code by ignoring this default defense
- **[FP]** `lib/nokogiri/html4/document.rb:197` other (spec-batch-etl-03) — **
- **[VERIFY-ERR]** `lib/nokogiri/xml/sax/parser.rb:187` other (spec-batch-etl-06) — verifier output unparseable
- **[FP]** `lib/nokogiri/xml/schema.rb:104` other (spec-batch-etl-07) — scanner misreads a validation sink as a file read sink; file is read for XML validation but contents are never returned to the caller
- **[FP]** `lib/nokogiri/html4/sax/push_parser.rb:11` logic-flaw (spec-batch-etl-08) — The default parameter instantiates `Nokogiri::XML::SAX::Document` (or its HTML4 alias), which the source confirms contains zero instance variables and only defines empty callback stubs. Concurrent `PushParser` instances therefore share a completely stateless event sink, making cross-tenant data leakage or state corruption impossible. (Additionally, if `HTML4::SAX::Document` is not explicitly defined/aliased in the runtime, the default evaluates to a `NameError` at call time, fully killing the path.)
- **[VERIFY-ERR]** `ext/nokogiri/xslt_stylesheet.c:279` injection (spec-batch-etl-12) — verifier output unparseable
- **[FP]** `gumbo-parser/src/vector.c:40` integer-overflow (spec-batch-etl-24) — Scanner ignored the `if (vector->capacity)` guard on line 42; wrapping `capacity` to 0 triggers an explicit reset to capacity 2 rather than a persistent undersized buffer. Furthermore, reaching `1 << 31` elements requires hundreds of GB of contiguous memory, triggering OS-level OOM kill long before integer overflow logic is reached.


---

## Appendix: Scan Scope

### Folders scanned (24)

- `./`
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

### Excluded from scan (284 files)

**Folders** (matched `exclude_dirs`):

- `test/` — 144 files
- `.git/` — 28 files
- `oci-images/` — 19 files
- `rakelib/` — 14 files
- `.github/` — 11 files
- `scripts/` — 10 files
- `gumbo-parser/test/` — 10 files
- `patches/` — 7 files
- `misc/` — 3 files
- `doc/` — 3 files
- `adr/` — 2 files
- `suppressions/` — 2 files
- `bin/` — 1 files
- `checkpoints/` — 1 files

**File types** (matched `exclude_exts`):

- `*.jar` — 11 files
- `*.gperf` — 4 files
- `*.gemspec` — 1 files
- `*.sed` — 1 files
- `*.y` — 1 files
- `*.zip` — 1 files
- `*.rl` — 1 files

**Patterns** (matched `exclude_globs`):

- `gumbo-parser/fuzzer/**` — 4 files
- `**/.gitignore` — 2 files
- `**/.gitmodules` — 1 files
- `**/LICENSE.*` — 1 files
- `**/.editorconfig` — 1 files
