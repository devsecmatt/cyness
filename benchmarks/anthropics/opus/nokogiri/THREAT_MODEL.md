# Threat Model: Nokogiri

## 1. System context

Nokogiri is a Ruby gem for parsing and manipulating XML and HTML
("makes it easy and painless to work with XML and HTML from Ruby"). On CRuby it
is a C extension (`ext/nokogiri/*.c`) that bridges Ruby objects to vendored
native libraries — **libxml2 2.14.6**, **libxslt 1.1.43**, the **gumbo** HTML5
parser, plus zlib 1.3.1 and libiconv 1.18 (versions and SHA-256 hashes pinned in
`dependencies.yml`). On JRuby it bridges to Xerces/NekoHTML/Saxon instead. The
native libraries are fetched and compiled at build time (precompiled platform
gems ship them prebuilt); this repository contains nokogiri's own bridge code,
its Ruby API (`lib/nokogiri/**`), and the patch set applied to the vendored
sources (`patches/`).

Nokogiri is one of the most widely deployed Ruby dependencies: it underpins
HTML/XML handling in Rails apps, scrapers, SAML/SOAP stacks, and document
pipelines. Its dominant trust boundary is **untrusted markup → native parser
memory**: callers routinely feed it documents from the network or end users.
Because the heavy lifting happens in C, the security-relevant surface is (a) the
vendored C libraries and their long CVE history, (b) nokogiri's own C bridge
(memory management, return-value checking, refcounting across the Ruby/C
boundary), and (c) Ruby-level surfaces such as the CSS-selector tokenizer and
parse-option handling that governs XXE/SSRF exposure.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Host process integrity | Native heap/stack of the Ruby process; corruptible by parser bugs in C. | critical |
| Service availability | CPU/memory of the host; exhaustible via entity expansion, algorithmic blowup, or ReDoS during parse. | high |
| Local file / internal-network confidentiality | Files and intranet endpoints reachable via external entities, DTD/XInclude fetches, or XSLT `document()` when enabled. | high |
| Parse-result integrity | Correctness of the DOM/canonical form downstream code trusts — e.g. C14N output feeding SAML/XML-DSig signature checks. | high |
| Downstream embedder applications | As a near-ubiquitous dependency, any defect is inherited by a vast number of apps. | critical |
| Supply-chain integrity of vendored native libs | The libxml2/libxslt/zlib/libiconv tarballs + `patches/` that become the shipped binary. | critical |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| XML document parsing (`Nokogiri::XML`, DOM/SAX/push/Reader) — `ext/nokogiri/xml_document.c`, `xml_sax_parser_context.c`, `xml_sax_push_parser.c`, `xml_reader.c` | Parse untrusted XML bytes via vendored libxml2. | untrusted XML → native parser memory | Host process integrity, Service availability, Local file/network confidentiality |
| HTML parsing — HTML4 via libxml2 (`html4_*.c`), HTML5 via gumbo (`gumbo.c`, `gumbo-parser/`) | Parse untrusted HTML into a document tree. | untrusted HTML → native parser memory | Host process integrity, Service availability |
| XSLT transform — `ext/nokogiri/xslt_stylesheet.c` | Compile and apply XSLT stylesheets via libxslt. Default options enable `NOENT \| DTDLOAD`. | untrusted stylesheet/document → libxslt memory & entity/DTD loading | Host process integrity, Local file/network confidentiality, Service availability |
| XPath / CSS selector evaluation — `xml_xpath_context.c`, `lib/nokogiri/css/tokenizer.rb`, `css/parser.rb` | Compile selector/XPath strings, some built from application or user input. | selector string → XPath engine / regex tokenizer | Service availability (ReDoS), Parse-result integrity (selector injection) |
| Schema & RelaxNG validation — `xml_schema.c`, `xml_relax_ng.c` | Validate documents against untrusted schemas. | untrusted schema/doc → libxml2 validator | Host process integrity, Local file/network confidentiality |
| Canonicalization (C14N) — `xml_node.c` (`canonicalize`) → `xmlC14NExecute` | Produce canonical XML, often consumed by signature verification. | document → canonical bytes trusted downstream | Parse-result integrity |
| Parse-option configuration — `lib/nokogiri/xml/parse_options.rb` | `NOENT`/`DTDLOAD`/`NONET`/`HUGE`/`XINCLUDE` flags chosen by the caller govern XXE/SSRF/DoS exposure. | caller config → parser security posture | Local file/network confidentiality, Service availability |
| Supply chain — `dependencies.yml`, `patches/`, build scripts (`ext/nokogiri/extconf.rb`) | Vendored native source tarballs (hash-pinned) + applied patches compiled into the gem. | upstream tarball/patch → shipped native binary | Supply-chain integrity, Host process integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Memory corruption (RCE or crash) via vendored libxml2/libxslt while parsing untrusted XML/HTML | remote_unauth | XML document parsing; HTML parsing; XSLT transform | Host process integrity | critical | almost_certain | partially_mitigated | Vendored libs kept current; upstream patches applied promptly; `dependencies.yml` SHA-256 pins | GHSA-353f-x4gh-cqq8 (CVE-2025-6021/6170/49794/49795/49796), GHSA-5w6v-399v-w3cc (CVE-2025-32414/32415), GHSA-vvfq-8hwr-qm4m (CVE-2025-24928/CVE-2024-56171), GHSA-mrxw-mxhj-p664 (CVE-2025-24855/CVE-2024-55549), GHSA-xc9x-jj77-9p9j (CVE-2024-25062) |
| T2 | Memory corruption / leak / unchecked-error in nokogiri's own C bridge (refcounting, return-value checks, free paths) | remote_unauth | XSLT transform; canonicalization; XML/HTML parsing | Host process integrity, Service availability | high | likely | partially_mitigated | Code review; Valgrind/ASAN in CI; defensive checks | GHSA-v2fc-qm4h-8hqv (XSLT::Stylesheet#transform memory leak), GHSA-wx95-c6cv-8532 (unchecked `xmlC14NExecute` return) |
| T3 | Incorrect canonicalization weakens downstream XML-DSig/SAML signature verification | remote_unauth | Canonicalization (C14N) | Parse-result integrity | high | possible | mitigated | Return value of `xmlC14NExecute` now checked | GHSA-wx95-c6cv-8532 (contributing cause to ruby-saml GHSA-x4h9-gwv3-r4m4) |
| T4 | Denial of service via ReDoS in the CSS selector tokenizer on attacker-influenced selectors | remote_unauth | CSS selector tokenizer | Service availability | medium | possible | mitigated | Exponential-backtracking patterns replaced | GHSA-c4rq-3m3g-8wgx |
| T5 | XXE / SSRF / local file disclosure when the caller enables `NOENT`/`DTDLOAD` or clears `NONET` | remote_unauth | Parse-option configuration; XML parsing; XSLT transform | Local file/network confidentiality | high | possible | partially_mitigated | Safe XML defaults: `DEFAULT_XML = RECOVER\|NONET\|BIG_LINES` (NOENT off, network off). **XSLT default enables `NOENT\|DTDLOAD`** | |
| T6 | Denial of service via entity-expansion ("billion laughs") or algorithmic blowup during parse | remote_unauth | XML parsing; XSLT transform | Service availability | high | possible | partially_mitigated | libxml2 default expansion limits; `HUGE` not set by default; XSLT default `NOENT` raises exposure for stylesheet inputs | |
| T7 | Supply-chain compromise of a vendored native tarball or applied patch shipped in the precompiled gem | supply_chain | Supply chain | Supply-chain integrity, Host process integrity | critical | rare | partially_mitigated | SHA-256 hashes pinned in `dependencies.yml`; signature/keyring notes for libiconv | |
| T8 | Resource exhaustion / unexpected network or decompression via implicit libxml2 features (HTTP fetch, zlib/lzma auto-decompression) | remote_unauth | XML parsing | Service availability, Local file/network confidentiality | medium | possible | partially_mitigated | `NONET` default blocks HTTP; opt-in `--disable-xml2-legacy` removes zlib/lzma + implicit HTTP | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Authentication / session bypass | Nokogiri has no authentication or session concept; it is a parsing library. |
| Repudiation / audit-log tampering | No logging or multi-user action surface in the library itself. |
| Volumetric DoS / rate limiting | An infrastructure concern; only algorithmic/entity-expansion/ReDoS (T4, T6) are in scope here. |
| XSS in nokogiri output | Output encoding for HTML sinks is the embedding application's responsibility; nokogiri provides escaping helpers but does not own the sink. |
| JRuby Xerces/Saxon CVEs | Real for the JRuby backend (see #3611) but a different native stack; tracked separately and out of scope for the CRuby-focused model unless JRuby is the deployment target. |

## 6. Open questions

- **Deployment posture.** Do consumers parse attacker-supplied documents
  (almost always yes for web apps)? This sets T1/T6 likelihood.
- **Parse options in practice.** Does any embedder enable `NOENT`,
  `DTDLOAD`, `HUGE`, or `XINCLUDE`, or clear `NONET`? Each materially raises
  T5/T6.
- **XSLT input trust.** Are stylesheets ever attacker-influenced? The XSLT
  default (`NOENT|DTDLOAD`) makes that path notably riskier than XML parsing.
- **Signature-verification consumers.** Which downstream stacks rely on
  nokogiri's C14N output for XML-DSig/SAML (T3)?
- **Build provenance.** Are the vendored tarballs verified against their pinned
  hashes in every build, and are the `patches/` reviewed (T7)?

## 7. Provenance

- mode: bootstrap
- date: 2026-06-12
- target: nokogiri @ 7ab68ffc
- inputs: git-log + CHANGELOG.md + SECURITY.md + dependencies.yml mined (no --vulns file)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Keep vendored libxml2/libxslt pinned to the latest patched release and automate upstream-CVE tracking + hash verification in CI | T1,T7 | partial | M |
| Build and fuzz the C bridge under ASAN/Valgrind continuously; assert on every libxml2/libxslt return value and free path | T2,T3 | partial | L |
| Keep XML defaults locked to `NONET` + no `NOENT`/`DTDLOAD`; document the XSLT default's entity/DTD exposure and offer a hardened XSLT option set | T5,T6 | partial | S |
| Enforce libxml2 entity-expansion limits and never set `HUGE` for untrusted input; add billion-laughs regression tests | T6 | partial | S |
| Treat all selector/XPath tokenizers as untrusted-input regex surfaces; keep linear-time patterns and add ReDoS fuzzing | T4 | yes | M |
| Offer/recommend `--disable-xml2-legacy` builds to drop implicit HTTP + zlib/lzma for security-sensitive deployments | T8 | partial | S |
