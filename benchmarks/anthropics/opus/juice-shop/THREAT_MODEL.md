# Threat Model: OWASP Juice Shop

## 1. System context

Juice Shop (package `juice-shop` v19.2.1, self-described as "probably the most
modern and sophisticated insecure web application") is OWASP's deliberately
vulnerable training application. It is a TypeScript application with an
Express/Node.js REST backend (~61 route modules under `routes/`, Sequelize
models under `models/`, shared logic in `lib/`) and an Angular single-page
frontend (`frontend/src/`). It ships a SQLite database, file upload/serving, a
JWT-based auth scheme, a B2B order interface, a chatbot, and a large set of
"challenges" that gate the intended vulnerabilities.

The code is real, exploitable Express/Angular code — the vulnerabilities are
the product's training content, not annotated stubs — so for the purpose of
this model they are treated as genuine, reachable defects rather than dismissed
as demo. The dominant trust boundary is **unauthenticated/authenticated HTTP →
application logic, database, filesystem, and host process**. The repository was
flattened to a single commit ("Raw source - no comments, no history"), so this
bootstrap derives threats from the code plus the well-known OWASP-Top-10 mapping
of Juice Shop's challenges rather than from git history.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| User accounts & PII | Credentials, email, addresses, security answers, order history in the SQLite DB. | high |
| Payment / card data | Stored card details and wallet balances. | critical |
| Authentication & session integrity | The JWT scheme and the RSA key that signs tokens; forging tokens grants any role. | critical |
| Administrative functions | Admin-only endpoints, user management, challenge state. | high |
| Host process & filesystem | The Node process and server filesystem (`ftp/`, `logs/`, `/etc/passwd`) reachable via traversal, XXE, SSRF, or eval. | critical |
| Database integrity & confidentiality | The full SQLite store, exfiltrable/modifiable via SQL injection. | critical |
| Internal network reachability | Intranet endpoints reachable via server-side request forgery. | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Authentication endpoint — `routes/login.ts` | Raw SQL login query built from request body. | unauth HTTP → DB / session | Authentication & session integrity, User accounts & PII, Database |
| Product search — `routes/search.ts` | Raw SQL query built from the `q` parameter. | unauth HTTP → DB | Database, User accounts & PII |
| JWT auth library — `lib/insecurity.ts` | Token sign/verify/decode, role checks, redirect allowlist, hashing. | token / config → authorization decisions | Authentication & session integrity, Administrative functions |
| File serving — `routes/fileServer.ts`, `logfileServer.ts`, `quarantineServer.ts` | `res.sendFile(path.resolve(<dir>, file))` from a path parameter. | unauth/auth HTTP → server filesystem | Host process & filesystem |
| File upload — `routes/fileUpload.ts` | Parses uploaded XML (`noent:true`) and YAML inside a `vm` sandbox. | unauth/auth upload → parser / filesystem | Host process & filesystem, Service availability |
| Profile image by URL — `routes/profileImageUrlUpload.ts` | Server `fetch()` of a user-supplied URL. | auth HTTP → outbound network | Internal network reachability |
| B2B order — `routes/b2bOrder.ts` | Evaluates `orderLinesData` via `notevil` `safeEval` inside a `vm`. | auth HTTP → expression evaluation | Host process & filesystem, Service availability |
| Open redirect — `routes/redirect.ts` + `isRedirectAllowed` | Redirect target validated against a substring allowlist. | unauth HTTP → client navigation | User accounts (phishing/token theft) |
| Product reviews / B2B / chatbot / order — other `routes/*.ts` | CRUD and messaging endpoints with per-route authorization. | unauth/auth HTTP → app logic & DB | Administrative functions, Database, User accounts & PII |
| Angular SPA — `frontend/src/**` | Client-side rendering of server/user data; DOM sinks. | server/user data → browser DOM | User accounts & session (XSS) |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Authentication bypass and full DB exfiltration via SQL injection | remote_unauth | `routes/login.ts`, `routes/search.ts` | Authentication & session integrity, Database, Payment data | critical | almost_certain | unmitigated | none (raw string-interpolated SQL) | login.ts:31, search.ts:19 |
| T2 | Full account/role takeover by forging JWTs with the hardcoded RSA private key | remote_unauth | `lib/insecurity.ts` | Authentication & session integrity, Administrative functions | critical | almost_certain | unmitigated | none (private key committed in source) | insecurity.ts:17, :50-52 |
| T3 | Arbitrary server file disclosure via path traversal in file-serving routes | remote_unauth | `routes/fileServer.ts`, `logfileServer.ts`, `quarantineServer.ts` | Host process & filesystem | high | likely | unmitigated | none on the path parameter | fileServer.ts:30 |
| T4 | Local file disclosure via XXE in uploaded XML parsed with entity substitution on | remote_unauth | `routes/fileUpload.ts` | Host process & filesystem | high | likely | partially_mitigated | `vm` sandbox + 2s timeout, but `noent:true` enables external entities | fileUpload.ts:78-82 |
| T5 | Server-side request forgery via profile-image-by-URL fetch | remote_auth | `routes/profileImageUrlUpload.ts` | Internal network reachability | high | likely | unmitigated | none (no host/scheme allowlist before `fetch`) | profileImageUrlUpload.ts:16-21 |
| T6 | Code evaluation / denial of service via `safeEval` of B2B order data inside `vm` | remote_auth | `routes/b2bOrder.ts` | Host process & filesystem, Service availability | high | possible | partially_mitigated | `notevil` sandbox + 2s `vm` timeout (historically bypassable) | b2bOrder.ts:19-20 |
| T7 | Privilege escalation via JWT verification/decoding weaknesses (decode-without-verify used in role checks) | remote_unauth | `lib/insecurity.ts` | Authentication & session integrity, Administrative functions | high | likely | unmitigated | none | insecurity.ts:51-52, :150-166 |
| T8 | Offline credential cracking due to unsalted MD5 password hashing and a hardcoded HMAC secret | remote_unauth | `lib/insecurity.ts` | User accounts & PII | high | likely | unmitigated | none (MD5, static HMAC key) | insecurity.ts:37-38 |
| T9 | Denial of service via YAML bomb / entity-expansion on file upload | remote_unauth | `routes/fileUpload.ts` | Service availability | medium | possible | partially_mitigated | 2s `vm` timeout, "Invalid string length" guard | fileUpload.ts (handleYamlUpload) |
| T10 | Phishing / token theft via open redirect (substring allowlist bypass) | remote_unauth | `routes/redirect.ts`, `isRedirectAllowed` | User accounts & session | medium | likely | partially_mitigated | substring `includes()` allowlist (bypassable) | insecurity.ts:128-133 |
| T11 | Stored/reflected/DOM XSS leading to session theft in the Angular client | remote_unauth | Angular SPA, review/search/feedback endpoints | User accounts & session | high | possible | partially_mitigated | Angular auto-escaping by default; bypassed where raw HTML / `bypassSecurityTrust*` is used | |
| T12 | Broken access control / IDOR across basket, order, and user endpoints | remote_auth | `routes/basket.ts`, `order.ts`, `userProfile.ts`, others | User accounts & PII, Payment data | high | likely | partially_mitigated | per-route auth middleware applied inconsistently | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Volumetric / network-flood DoS | Infrastructure concern; only algorithmic/expansion DoS (T6, T9) are in scope. |
| Outdated transitive dependencies | Managed by a separate dependency process; not the focus of this code-level model. |
| Memory-safety corruption | Node/TypeScript is memory-safe; no `unsafe`/FFI surface in app code (native risk lives in deps like libxmljs2, tracked under T4). |
| Self-XSS / CSRF-on-logout | Low-impact nuisance class; the impactful client threat is reflected/stored/DOM XSS (T11). |

## 6. Open questions

- **Deployment exposure.** Is this instance internet-facing (CTF/training) or
  isolated? All likelihoods assume a reachable HTTP surface.
- **Which JWT verification path is authoritative?** `verify` uses `jws.verify`
  with the public key, but `decode` (no verification) is also consumed in role
  checks (insecurity.ts:150-166) — needs runtime confirmation of which gates
  each privileged action (T7).
- **Is `notevil`/`vm` actually escapable on this Node version (T6)?** Static
  review shows the pattern; a runtime PoC is the right confirmation.
- **Frontend XSS sinks (T11).** Which Angular components use
  `bypassSecurityTrustHtml`/`innerHTML` with server/user data?
- **Authorization coverage (T12).** Which endpoints lack ownership checks on
  object IDs?

## 7. Provenance

- mode: bootstrap
- date: 2026-06-12
- target: juice-shop @ 6ed9ce4 (flattened single commit, no history)
- inputs: source + OWASP-Top-10 challenge mapping mined (no git history, no --vulns file)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Use parameterized queries / the ORM for every DB access; ban string-interpolated SQL | T1 | yes | M |
| Remove the committed private key; load signing keys from secrets, and verify (never `decode`) tokens with a fixed algorithm before any role check | T2,T7 | yes | M |
| Canonicalize and confine file paths to an allowlisted base dir; reject `..`/absolute paths before `sendFile` | T3 | yes | S |
| Disable external entities (`noent:false`, no DTD) for all untrusted XML; replace `vm`+`eval` with a real parser/expression allowlist | T4,T6 | partial | M |
| Validate SSRF targets against an egress allowlist (scheme + host) before any server-side fetch | T5 | yes | S |
| Hash passwords with a salted memory-hard KDF (bcrypt/argon2); rotate the static HMAC secret to per-deployment config | T8 | yes | M |
| Replace the substring redirect allowlist with exact-origin matching | T10 | yes | S |
| Enforce Angular auto-escaping; forbid `bypassSecurityTrust*`/`innerHTML` on untrusted data and add a CSP | T11 | partial | M |
| Add centralized object-ownership authorization checks to all per-resource endpoints | T12 | partial | L |
| Add billion-laughs/YAML-bomb size+depth limits before parsing | T9 | partial | S |
