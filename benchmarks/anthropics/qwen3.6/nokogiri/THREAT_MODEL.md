# Threat Model: Nokogiri

## 1. System context

Nokogiri is a widely deployed Ruby gem that provides high-level APIs for parsing, manipulating, querying, and serializing XML and HTML documents. It wraps three underlying C parser libraries: libxml2 (XML, HTML4, XSD, RelaxNG), libxslt (XSLT transformations), and libgumbo (HTML5 parsing). The gem uses both Ruby code and a large C extension (~50 .c files in ext/nokogiri/) to bridge between Ruby and these native libraries.

The CRuby implementation uses Ruby's memory management layer (ruby_xmalloc/ruby_xfree) to integrate libxml2 allocation with Ruby GC, a design decision documented in an ADR due to its memory and correctness trade-offs. The JRuby implementation uses Java equivalents (Xerces, NekoHTML, Saxon, Xalan) with a similar thin-layer architecture. Both implementations ship pre-packaged versions of libxml2 and libxslt by default, downloading them from upstream during build-time with SHA-256 integrity verification.

Nokogiri is one of the most popular Ruby gems (over 500M downloads), embedded in virtually every Ruby web framework (Rails, Sinatra, Hanami) and countless document-processing applications. Typical usage involves parsing untrusted HTML/XML from user-supplied URLs, uploaded files, or scraped web pages. The guiding principle is "be secure-by-default by treating all documents as untrusted," but this applies at the parsing level only — downstream XSLT, schema validation, and entity resolution still carry their own trust assumptions.

The gem targets Ruby >= 3.2 and CRuby 3.2–4.0; JRuby >= 10.0 has a separate implementation path. The project has an explicit security policy with 24-hour response SLA and coordinates vulnerability disclosure via GitHub Security Advisories.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Host process integrity | The Ruby process running Nokogiri; memory corruption can trigger segfaults, RCE via C extension bugs, or GC corruption | critical |
| Document content (input) | XML/HTML documents provided to the parser, potentially from untrusted sources (user uploads, scraped pages, URLs) | high |
| Document content (output) | Parsed document trees, serialized strings, transformation results; may contain processed user data or secrets | high |
| Network resources | External DTDs, entities, XSLT imports, schema references; parsed documents may trigger network access | high |
| XSLT stylesheet | Stylesheet documents applied via Nokogiri::XSLT::Stylesheet; untrusted stylesheets can invoke extension functions | critical |
| Host filesystem | Entity/URI resolution can read arbitrary local files via file:// URIs in DTDs and entities | high |
| Service availability | CPU/memory exhaustion via entity expansion, deeply nested documents, or pathological parsing input | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Nokogiri::XML.parse / Nokogiri.parse (XML) | Parses XML strings or IO streams via libxml2 | untrusted string/IO → host process memory + libxml2 native heap | host process integrity, document content (input+output), network resources, host filesystem |
| Nokogiri::HTML4.parse / Nokogiri::HTML4::DocumentFragment.parse (HTML4) | Parses HTML4 or HTML fragments via libxml2 HTML parser | untrusted string/IO → host process memory + libxml2 native heap | host process integrity, document content (input+output), network resources, host filesystem |
| Nokogiri::HTML5.parse / Nokogiri::HTML5::DocumentFragment.parse (HTML5) | Parses HTML5 via bundled libgumbo parser (forked from Google's Gumbo) | untrusted string → host process memory + gumbo native heap | host process integrity, document content (input+output), network resources |
| Nokogiri::XSLT::Stylesheet.new / parse_stylesheet_doc | Compiles + applies XSLT stylesheets via libxslt | untrusted stylesheet/XSLT → host process + extension function execution | host process integrity, document content (input+output), network resources, host filesystem, XSLT stylesheet |
| Nokogiri::XML::Reader (streaming) | Expats-style SAX read-ahead via libxml2 xmlTextReader | untrusted string/IO → host process memory | host process integrity, document content (input+output), network resources |
| SAX parsers (XML/HTML4) | Event-driven parsing callbacks | untrusted IO + callback Ruby code → host process | host process integrity, document content (input+output) |
| Push parsers | Incremental parsing via xmlParserCtxt | untrusted chunked data → host process | host process integrity, document content (input+output), network resources |
| Schema validation (XSD, RelaxNG) | Validates documents against schemas via libxml2 | untrusted schema + document → host process | host process integrity, document content (input+output), network resources, host filesystem |
| Entity / URI resolution (DTD resolution) | libxml2 entity loading triggered by parsed documents | untrusted document → file:// / http:// access | host process integrity, host filesystem, network resources |
| Nokogiri::XML::Builder DSL | Ruby DSL that builds documents (historically used eval); currently safe | trusted Ruby code → document construction | document content (output) |
| Slop decorator (method_missing) | Dynamic attribute access on parsed nodes via Ruby method_missing | untrusted document → dynamic dispatch on arbitrary method names | document content (input+output) |
| Builder#initialize Ruby interpolation | Ruby string interpolation in Builder methods used to construct HTML/XML | untrusted output → potential injection if unescaped values flow into markup | document content (output), host process integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Remote code execution via memory corruption in native parsers triggered by untrusted XML/HTML/XHTML input | remote_unauth | Nokogiri::XML.parse, Nokogiri::HTML4.parse, Nokogiri::HTML5.parse, SAX/push parsers | host process integrity | critical | likely | unmitigated | no | CVE-2024-40896, CVE-2024-25062, CVE-2022-29824, CVE-2020-7595, CVE-2018-14404, CVE-2018-14567, CVE-2017-15412, CVE-2016-4658, CVE-2016-5131 |
| T2 | Server-side request forgery and local file read via entity/URI resolution of external DTDs and entities in untrusted XML | remote_unauth | Entity/URI resolution, Nokogiri::XML.parse, Nokogiri::XML::Reader, SAX parsers | host filesystem, network resources | critical | likely | partially_mitigated | none | CVE-2015-7499, CVE-2015-7500, CVE-2014-0191, CVE-2020-26247 |
| T3 | Arbitrary code execution via extension functions in untrusted XSLT stylesheets | remote_unauth | Nokogiri::XSLT::Stylesheet.parse + apply | XSLT stylesheet, host process integrity | critical | likely | partially_mitigated | none | CVE-2025-24855, CVE-2024-55549, CVE-2019-11068, CVE-2021-30560 |
| T4 | Remote code execution via memory corruption in bundled libgumbo HTML5 parser triggered by malicious HTML5 | remote_unauth | Nokogiri::HTML5.parse, Nokogiri::HTML5::DocumentFragment.parse | host process integrity | critical | likely | partially_mitigated | none | fuzzing corpus (gumbo_corpus.zip), oss-fuzz integration |
| T5 | Denial of service via entity expansion / billion laughs or pathologically nested input exhausting CPU or memory | remote_unauth | Nokogiri::XML.parse, Nokogiri::HTML4.parse, SAX parsers, push parsers | service availability, host process integrity | high | likely | partially_mitigated | ParseOptions::NOENT, ParseOptions::HUGE docs; Nokogiri::XML::ParseOptions::NONET | CVE-2022-2309, CVE-2022-24836, CVE-2022-40303, CVE-2022-40304 |
| T6 | XSS via attribute/HTML escaping bypass through libxml2 or gumbo-parser escaping edge cases | remote_unauth | Nokogiri::HTML5.parse, Serialization (to_html, to_xml), Nokogiri::HTML4.parse | document content (output) | high | possible | partially_mitigated | none | CVE-2016-9318 (libxml2), test demonstrating libxml2 XSS vulnerability |
| T7 | XXE-to-SSRF chain where untrusted XML contains entity definitions that resolve to internal network endpoints | remote_unauth | Entity/URI resolution, Nokogiri::XML.parse, XML::Reader | host filesystem, network resources | high | likely | partially_mitigated | none | CVE-2015-7499, CVE-2015-8241, CVE-2015-8242, CVE-2015-8317, CVE-2020-26247 |
| T8 | Supply-chain compromise via compromised libxml2/libxslt/libgumbo upstream distribution during build-time download | supply_chain | extconf.rb build process, dependencies.yml | host process integrity | critical | possible | mitigated | SHA-256 checksums on all downloads, dependencies.yml with pinned versions | CVE-2022-37434 (zlib), CVE-2022-23437 (xerces), CVE-2022-24839 (nekohtml) |
| T9 | DoS or information disclosure via memory management edge cases where ruby_xmalloc/ruby_xfree interacts incorrectly with libxml2 during GC or process-teardown | local_user | Any parsing operation (memory management path) | host process integrity | medium | possible | partially_mitigated | NOKOGIRI_LIBXML_MEMORY_MANAGEMENT environment variable | ADR 2023-04, issues #2059, #2241, #2785, #2822 |
| T10 | Data exposure via prototype pollution in SAX error callback Ruby objects or entity reference resolution creating unexpected JavaScript-like properties on parsed node objects | remote_unauth | SAX parsers, Entity/URI resolution, entity references | document content (output) | medium | possible | mitigated | none | CVE-2015-1819, CVE-2015-7941_1, CVE-2015-7941_2 |
| T11 | SSRF or XXE via untrusted XSLT import URLs resolving to internal resources during stylesheet compilation or application | remote_unauth | XSLT import/include resolution | network resources, host filesystem | high | possible | partially_mitigated | none | CVE-2019-13117, CVE-2019-13118, CVE-2019-18197, CVE-2019-19956 |
| T12 | Schema injection where untrusted RelaxNG or XSD schema is used from an untrusted source, causing schema validation bypass or DoS | remote_unauth | Schema validation (XSD, RelaxNG) | host process integrity, document content (input) | medium | possible | mitigated | XML::Schema NONET behavior (since 9e0da213) | doc: Note security assumptions of XML::{Schema,RelaxNG} |

## 5. Deprioritized

| threat | reason |
|---|---|
| SQL injection via Nokogiri | Nokogiri is an XML/HTML parser, not a database layer. Data flows through XML/HTML, not SQL. |
| Cross-site scripting via CSS selector engine | CSS selectors query nodes; they do not output HTML. CSS input is trusted Ruby code strings, not user input. |
| Path traversal via Builder DSL | Builder DSL constructs documents from trusted Ruby code, not untrusted strings. Eval was removed in commit abb547f6. |
| Repudiation | Nokogiri has no logging or audit trail; not applicable as a threat model concern. |
| Elevation of privilege via the gem itself | Nokogiri C extension runs within the Ruby process with the Ruby process's privileges; it does not manage OS-level permissions. |
| Repudiation via SAX error handler | SAX parsers emit events to Ruby callbacks; attributability depends on the application's error handling, not Nokogiri itself. |
| Information disclosure via JRuby platform jar files | JRuby jar dependencies (Xerces, NekoHTML, Saxon) receive independent supply-chain updates and are tracked with SHA-256 checksums. |

## 6. Open questions

- Are downstream applications typically using `ParseOptions::NONET` for XML parsing when processing untrusted input, or relying on the default (which allows network access for DTD/entity resolution)?
- For XSLT stylesheets: are user-supplied stylesheets a realistic input vector in typical Nokogiri deployments, or are stylesheets always application-owned?
- What network access (firewall / egress controls) exist between the application running Nokogiri and the broader internet or internal network?
- Does the application using Nokogiri set memory limits (e.g., `ParseOptions::HUGE` guard) before passing input to the parser?
- In the C extension's SAX callbacks, does the application validate the structure and types of data returned from the C side before trusting them?
- Is the gem typically used with `NOKOGIRI_USE_SYSTEM_LIBRARIES` in some deployments, which would bypass the packaged library integrity checks?
- What is the typical trust boundary around the Builder DSL — is it always application-controlled, or can user data flow into template strings?
- Is the HTML5 (gumbo) parser used in contexts where the HTML5 parse tree could produce different output than expected by downstream code (browser behavior variations)?
- How often are downstream applications using the Slop decorator with untrusted document content?

## 7. Provenance

- mode: bootstrap
- date: 2026-06-12
- target: /home/higgs/workspace/cyness/nokogiri @ not a git repo
- inputs: CHANGELOG.md, misc/CHANGELOG-archive.md, git log (CVE/security/vuln entries), ADRs, SECURITY.md, patches, ext/, gumbo-parser/, lib/
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Default ParseOptions::NONET for XML parsing with untrusted input | T2, T5, T7, T11, T12 | partial | S |
| Default ParseOptions::NOENT for XML parsing with untrusted input | T5 | partial | S |
| Validate XSLT stylesheet source — only trust application-owned stylesheets; never compile user-supplied XSLT | T3, T11 | partial | S |
| Enforce input size limits (ParseOptions::HUGE) before parsing untrusted documents | T5 | partial | S |
| Pin library versions with SHA-256 verification and monitor upstream advisories | T8 | yes | S |
| Disable external entity resolution at the library level via xmlCreateIOOverrides or similar | T2, T5, T7 | yes | M |
| Audit downstream apps for NONET/NOENT usage and add gem-level default warnings | T2, T5, T7 | partial | L |
| Use Nokogiri::HTML5 parsing only when HTML5 behavior is required (otherwise HTML4 parser has longer security track record) | T4 | partial | S |
