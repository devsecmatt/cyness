# Vulnerability Findings — OWASP Juice Shop

**Target:** `/home/higgs/workspace/cyness/juice-shop`  
**Scanned:** 2026-06-12  
**Focus areas:** 8 (Auth & JWT, SQL/NoSQL Injection, File Upload & Path Traversal, Deserialization, SSTI & Code Exec, Hardcoded Secrets, Broken Access Control & Info Disclosure, CSRF & Business Logic)  
**Source files scanned:** ~609

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 10    |
| MEDIUM   | 18    |
| LOW      | 2     |
| **Total**| **30**|

## Findings Table

| ID | Severity | Category | File:Line | Title |
|----|----------|----------|-----------|-------|
| F-001 | HIGH | sql-injection | routes/login.ts:31 | SQL injection via raw string interpolation in login query |
| F-002 | HIGH | sql-injection | routes/search.ts:19 | SQL injection via raw string interpolation in product search |
| F-003 | HIGH | hardcoded-secret | routes/checkKeys.ts:10 | Ethereum wallet mnemonic phrase hardcoded in source code |
| F-004 | HIGH | hardcoded-secret | lib/insecurity.ts:17 | RSA private key hardcoded enabling JWT forgery |
| F-005 | HIGH | auth-bypass | lib/insecurity.ts:48 | JWT algorithm confusion: RS256 public key accepted as HS256 secret |
| F-006 | HIGH | weak-cryptography | lib/insecurity.ts:37 | MD5 password hashing with no salt |
| F-007 | HIGH | code-injection | routes/userProfile.ts:59 | Arbitrary JavaScript execution via eval() on username |
| F-008 | HIGH | xx-injection | routes/fileUpload.ts:80 | XXE injection via libxmljs with noent option |
| F-009 | HIGH | broken-access-control | server.ts:445 | finale-rest auto-scaffolding exposes full CRUD on all models |
| F-010 | HIGH | credential-exposure | routes/2fa.ts:66 | 2FA TOTP secret returned in cleartext in API response |
| F-011 | MEDIUM | nosql-injection | routes/dataExport.ts:30 | NoSQL injection in data export MongoDB query |
| F-012 | HIGH | hardcoded-secret | routes/checkKeys.ts:10 | Ethereum address comparison allows public key confusion |
| F-013 | MEDIUM | path-traversal | routes/fileUpload.ts:39 | ZIP upload path traversal via unzipper entry validation |
| F-014 | MEDIUM | xss | routes/userProfile.ts:85 | CSP bypass via user-controllable image URL in CSP header |
| F-015 | MEDIUM | open-redirect | lib/insecurity.ts:131 | Open redirect via String.includes() allowlist check |
| F-016 | MEDIUM | business-logic | lib/insecurity.ts:93 | Coupon forging via Z85 encoding (not encryption) |
| F-017 | MEDIUM | hardcoded-secret | routes/web3Wallet.ts:18 | Alchemy WebSocket API key hardcoded in source |
| F-018 | MEDIUM | nosql-injection | routes/orderHistory.ts:14 | NoSQL injection in order history MongoDB query |
| F-019 | MEDIUM | information-disclosure | routes/metrics.ts:66 | Prometheus metrics exposed without authentication |
| F-020 | MEDIUM | broken-access-control | lib/insecurity.ts:143 | Deluxe token HMAC with hardcoded private key |
| F-021 | MEDIUM | path-traversal | routes/fileServer.ts:25 | Null byte bypass in file path allowlist |
| F-022 | MEDIUM | xss | lib/insecurity.ts:55 | Stored XSS via bypassable sanitizeLegacy regex |
| F-023 | LOW | hardcoded-secret | routes/login.ts:56 | Service account default passwords hardcoded |
| F-024 | HIGH | path-traversal | routes/keyServer.ts:11 | Encryption key server lacks null byte processing |
| F-025 | MEDIUM | csrf | server.ts:549 | Missing CSRF protection on state-changing endpoints |
| F-026 | MEDIUM | denial-of-service | routes/fileUpload.ts:114 | YAML Bomb via unbounded YAML deserialization in B2B upload |
| F-027 | MEDIUM | ssrf | routes/profileImageUrlUpload.ts:21 | Server-Side Request Forgery via profile image URL upload |
| F-028 | MEDIUM | command-injection | routes/b2bOrder.ts:20 | Potential code execution in B2B order via noEval sandbox |
| F-029 | LOW | hardcoded-secret | lib/utils.ts:79 | CTF key loaded from plaintext file on disk |
| F-030 | MEDIUM | information-disclosure | server.ts:249 | Directory listing exposes sensitive files in FTP, encryptionkeys, and logs |

---

### F-001 — SQL injection via raw string interpolation in login query

**Severity:** HIGH | **Confidence:** 1.0  
**File:** routes/login.ts:31

**Description:** Login route POST /rest/user/login constructs a raw SQL query using untrusted `req.body.email` and `req.body.password` with string concatenation:
```sql
SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL
```
An attacker can terminate the email string and inject arbitrary SQL.

**Exploit scenario:** Send POST /rest/user/login with `{"email": "' OR 1=1 --", "password": "x"}` to bypass authentication, or use UNION SELECT to exfiltrate all user credentials and PII.

**Recommendation:** Replace with parameterized query using `sequelize.query('SELECT ... WHERE email = :email AND password = :passw', { replacements: ... })`.

---

### F-002 — SQL injection via raw string interpolation in product search

**Severity:** HIGH | **Confidence:** 1.0  
**File:** routes/search.ts:19

**Description:** GET /rest/products/search at line 19 constructs:
```sql
SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name
```
Input `req.query.q` is truncated at 200 chars but otherwise unsanitized and concatenated into raw SQL.

**Exploit scenario:** `GET /rest/products/search?q=' UNION SELECT * FROM Users--` exfiltrates the entire Users table. The code at lines 22-36 confirms UNION-based exfiltration is the intended challenge exploit path.

**Recommendation:** Use Sequelize parameterized query: `ProductModel.findAll({ where: { name: { [Op.like]: \`%${criteria}%\` } }, paranoid: true })`.

---

### F-003 — Ethereum wallet mnemonic phrase hardcoded in source code

**Severity:** HIGH | **Confidence:** 1.0  
**File:** routes/checkKeys.ts:10

**Description:** Plaintext BIP39 mnemonic `purpose betray marriage blame crunch monitor spin slide donate sport lift clutch` at line 10. Used to derive HDNodeWallet and full private key.

**Exploit scenario:** Any attacker reads this line, derives the wallet private key, and sweeps all funds from the corresponding Ethereum wallet. Also usable to sign arbitrary Ethereum transactions.

**Recommendation:** Store mnemonic in environment variable or secrets manager. Never commit to source.

---

### F-004 — RSA private key hardcoded in source enabling JWT forgery

**Severity:** HIGH | **Confidence:** 0.95  
**File:** lib/insecurity.ts:17

**Description:** RSA private key is a literal PEM string at line 17, used in `authorize()` (line 50) for signing all JWT tokens with RS256. Any attacker who reads the source can forge tokens for any user identity.

**Exploit scenario:** Extract key from source, sign a JWT with role: 'admin' via `jwt.sign()`, present to any `isAuthorized()`-protected route. Server verifies signature against the public key and accepts it.

**Recommendation:** Store RSA private key in KMS, environment variable, or restricted file. Never embed in source.

---

### F-005 — JWT algorithm confusion: RS256 public key as HS256 shared secret

**Severity:** HIGH | **Confidence:** 0.95  
**File:** lib/insecurity.ts:48

**Description:** `isAuthorized()` uses express-jwt with the public key as secret. `jws.verify()` accepts the token without restricting algorithm. An attacker creates an HS256 token signed with the public key bytes as the HMAC secret. The server verifies it because the same key works as both asymmetric public key and symmetric HMAC secret.

**Exploit scenario:** 1. Extract public key (line 16). 2. Create JWT with `alg=HS256`, signing with the public key bytes. 3. Set role to 'admin'. Server accepts it.

**Recommendation:** Use `express-jwt({ algorithms: ['RS256'] })` to explicitly restrict acceptable algorithms.

---

### F-006 — MD5 password hashing with no salt

**Severity:** HIGH | **Confidence:** 0.9  
**File:** lib/insecurity.ts:37

**Description:** `crypto.createHash('md5')` with no salt, used for password storage (models/user.ts:73) and login comparison. MD5 is fast and unsalted — trivial to brute-force or use rainbow tables against.

**Exploit scenario:** Extract hashed passwords from SQLite Users table. Use GPU-accelerated brute force or precomputed rainbow tables to recover plaintext passwords.

**Recommendation:** Replace with bcrypt/scrypt/argon2id with unique random salt per user and appropriate work factor.

---

### F-007 — Arbitrary JavaScript execution via eval() on username

**Severity:** HIGH | **Confidence:** 0.9  
**File:** routes/userProfile.ts:59

**Description:** When username matches `#{...}`, the substring is passed to `eval()` at line 59. The username is set via POST /profile (routes/updateUserProfile.ts:33), which accepts arbitrary input.

**Exploit scenario:** Set username to `#{}require('child_process').execSync('whoami')#` via POST /profile. Visit GET /profile. eval() executes the injected code, returning command output in the HTML response (RCE).

**Recommendation:** Remove the eval() call entirely. Use safe template engines or Pug's built-in escaping.

---

### F-008 — XXE injection via libxmljs with noent option

**Severity:** HIGH | **Confidence:** 0.9  
**File:** routes/fileUpload.ts:80

**Description:** B2B XML endpoint POST /b2b/v2/orders parses XML with `noent: true`, expanding external entities. Malicious XML reads server files via `SYSTEM` entity URIs.

**Exploit scenario:** POST with XML `<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>`. The noent option expands, and the parsed content leaks in the error response (line 84).

**Recommendation:** Set `noent: false`. Use a whitelist-based XML parser that does not process entities.

---

### F-009 — finale-rest auto-scaffolding exposes full CRUD on all models

**Severity:** HIGH | **Confidence:** 0.9  
**File:** server.ts:445

**Description:** 14 Sequelize models auto-scaffolded with `/api/{Name}s` endpoints. Some have partial authorization but bulk read endpoints remain accessible.

**Exploit scenario:** Authenticated user can read ALL users' card data, challenge definitions, and other sensitive records via the auto-generated endpoints.

**Recommendation:** Replace finale-rest auto-scaffolding with explicit route definitions and fine-grained authorization per resource.

---

### F-010 — 2FA TOTP secret returned in cleartext in API response

**Severity:** HIGH | **Confidence:** 0.85  
**File:** routes/2fa.ts:66

**Description:** GET /rest/2fa/status returns the raw TOTP secret in the response JSON (`res.json({ secret, ... })`). Anyone who intercepts the response can capture the secret and bypass 2FA.

**Exploit scenario:** Intercept GET /rest/2fa/status response, extract the secret field, use it in an authenticator app to generate valid TOTP codes.

**Recommendation:** Encode the secret as a QR code image instead of returning raw bytes. Do not include the secret in API responses.

---

### F-011 — NoSQL injection in data export MongoDB query

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** routes/dataExport.ts:30

**Description:** `db.ordersCollection.find({ email: updatedEmail })` uses email derived from JWT claims. If JWT is forged (F-004/F-005), attacker injects MongoDB operators in the email field.

**Exploit scenario:** Forge JWT with email set to `{ "$where": "this" }` to access all orders. Combined with F-004/F-005 this is exploitable.

**Recommendation:** Validate email with strict regex before using in queries. Use parameterized query helpers.

---

### F-012 — Ethereum address comparison in checkKeys allows public key confusion

**Severity:** HIGH | **Confidence:** 0.85  
**File:** routes/checkKeys.ts:10

**Description:** Lines 18-27 return different error messages for private key vs public key vs address mismatches, leaking which format the attacker provided. The hardcoded mnemonic at line 10 makes this trivial.

**Exploit scenario:** Read the mnemonic (line 10), derive the private key, sweep all wallet funds. The different error messages (lines 22-26) also serve as a side channel.

**Recommendation:** Use a single error message for all cases. Never commit mnemonics to source.

---

### F-013 — ZIP upload path traversal via unzipper entry validation

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** routes/fileUpload.ts:39

**Description:** ZIP entry paths from `unzipper.Parse()` are used at line 39 with only a substring guard (line 41) against `path.resolve('.')`. ZIP entries can contain `..` that reach outside `uploads/complaints/`.

**Exploit scenario:** Create ZIP with entry `../../etc/cron.d/malicious` — the file is written to a system directory.

**Recommendation:** Clean every path component (replace `..` with `/`) and compare the resolved path against the expected base directory.

---

### F-014 — CSP bypass via user-controllable image URL in Content-Security-Policy header

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** routes/userProfile.ts:85

**Description:** CSP header includes `${user?.profileImage}` — the user's profile image URL becomes part of the script-src directive, allowing the user to inject script sources.

**Exploit scenario:** Set profileImage to `'; script-src 'self' https://evil.com'`. The permissive CSP allows scripts from evil.com to execute.

**Recommendation:** Never include user input in CSP headers. Use hardcoded script-src directives.

---

### F-015 — Open redirect via String.includes() allowlist check

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** lib/insecurity.ts:131

**Description:** `isRedirectAllowed()` checks `url.includes(allowedUrl)` — an attacker embeds an allowed domain in a malicious URL, e.g., `https://evil.com?redirect=https://allowed.phish`.

**Exploit scenario:** `GET /redirect?to=https://evil.com%3Fredirect%3Dhttps://explorer.dash.org/...` — the include check finds 'explorer.dash.org' in the string and allows the redirect to evil.com.

**Recommendation:** Parse the URL and check if the hostname exactly matches an allowlisted domain. Use URL origin/hostname comparison, not string containment.

---

### F-016 — Coupon system uses Z85 encoding (not encryption) — any discount forgeable

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** lib/insecurity.ts:93

**Description:** `generateCoupon()` encodes coupons with Z85 (base85 encoding, not encryption). `discountFromCoupon()` validates only expiry format, not authenticity. Any attacker can encode any desired discount.

**Exploit scenario:** Encode `JAN26-99` in Z85 → apply it to any basket → receive 99% discount. The system only checks the month format, never verifies the issuer.

**Recommendation:** Sign coupons with HMAC-SHA256 using a server-side secret. Store coupon IDs server-side for one-time use.

---

### F-017 — Alchemy WebSocket API key hardcoded in source code

**Severity:** MEDIUM | **Confidence:** 0.9  
**File:** routes/web3Wallet.ts:18

**Description:** Alchemy WebSocket API key `FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ` in web3Wallet.ts:18 and nftMint.ts:16. Anyone can use it for unauthorized blockchain RPC access.

**Exploit scenario:** Extract the key from source code, use for authenticated requests to Alchemy JSON-RPC API.

**Recommendation:** Store in environment variable. Never hardcode credentials.

---

### F-018 — NoSQL injection in order history MongoDB query

**Severity:** MEDIUM | **Confidence:** 0.8  
**File:** routes/orderHistory.ts:14

**Description:** `ordersCollection.find({ email: updatedEmail })` — email massaged by vowel-star replacement does not sanitize MongoDB operators like `$gt`, `$regex`.

**Exploit scenario:** If JWT is forged with email containing `$gt` operator, access orders belonging to other users.

**Recommendation:** Validate email characters before use in queries. Use strict equality only.

---

### F-019 — Prometheus metrics endpoint exposed without authentication

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** routes/metrics.ts:63

**Description:** GET /metrics at server.ts:662 serves Prometheus metrics via `register.metrics()` with only a User-Agent filter (not auth). Metrics include wallet balances, user counts, order counts, challenge progress.

**Exploit scenario:** GET /metrics reveals total wallet balance, registered user counts by type, challenge solved counts.

**Recommendation:** Add authentication middleware. Restrict to admin/internal networks.

---

### F-020 — Deluxe token uses HMAC with hardcoded private key

**Severity:** MEDIUM | **Confidence:** 0.8  
**File:** lib/insecurity.ts:143

**Description:** `deluxeToken()` computes HMAC-SHA256(rsaPrivateKey, email + 'deluxe'). The key is hardcoded (F-004), so anyone can forge deluxe tokens.

**Exploit scenario:** `HMAC(privateKey, 'attacker@evil.comdeluxe')` → valid deluxe token.

**Recommendation:** Use a separate, random secret for deluxe token HMAC. Never use the RSA key as an HMAC key.

---

### F-021 — Null byte bypass in file path allowlist

**Severity:** MEDIUM | **Confidence:** 0.8  
**File:** routes/fileServer.ts:25

**Description:** Allowlist check (line 24) happens before null byte truncation (line 25). Serving `.pdf` allows access when null byte truncates the actual file extension.

**Exploit scenario:** `GET /ftp/incident-support.kdbx%00.pdf` — passes .pdf allowlist, null byte causes the system to serve the raw .kdbx file.

**Recommendation:** Strip null bytes first, then check allowlist. Use `path.resolve()` verification.

---

### F-022 — Stored XSS via bypassable sanitizeLegacy regex

**Severity:** MEDIUM | **Confidence:** 0.8  
**File:** lib/insecurity.ts:55

**Description:** `sanitizeLegacy()` regex `<\w+\W+?\w` allows tags without attributes (e.g., `<img>`, `<div onmouseover=...>`). Used in challenge mode for username/email sanitization (user.ts:46).

**Exploit scenario:** Set username to `<img src=x onerror=alert(1)>` — passes the legacy sanitization and renders as XSS.

**Recommendation:** Remove `sanitizeLegacy` entirely. Use `sanitizeSecure()` (sanitize-html library) everywhere.

---

### F-023 — Service account default passwords hardcoded

**Severity:** LOW | **Confidence:** 0.8  
**File:** routes/login.ts:56

**Description:** Hardcoded credentials for admin, support, and other service accounts (lines 56-62). Plaintext passwords embedded in challenge validators.

**Exploit scenario:** Login with `admin@localhost` / `admin123` if service accounts are active.

**Recommendation:** Never embed passwords in source. Use unique strong random passwords at deployment time.

---

### F-024 — Encryption key server lacks null byte processing

**Severity:** HIGH | **Confidence:** 0.75  
**File:** routes/keyServer.ts:11

**Description:** GET /encryptionkeys/:file serves files without null byte handling. Combined with serveIndex directory listing (server.ts:256), all key files are exposed.

**Exploit scenario:** GET /encryptionkeys/jwt.pub reveals the JWT public key, enabling the algo confusion attack (F-005).

**Recommendation:** Sanitize filenames. Use `path.resolve()` verification. Restrict which files are served.

---

### F-025 — Missing CSRF protection on state-changing endpoints

**Severity:** MEDIUM | **Confidence:** 0.85  
**File:** server.ts:549

**Description:** Post/put/delete routes at lines 549-618 lack CSRF tokens. Cookie at line 266 provides session persistence but no anti-CSRF mechanism.

**Exploit scenario:** Malicious page auto-submits POST to /rest/basket/:id/checkout — victim performs unwanted checkout.

**Recommendation:** Add csurf middleware or SameSite cookie attributes to all state-changing endpoints.

---

### F-026 — YAML Bomb via unbounded YAML deserialization in B2B upload

**Severity:** MEDIUM | **Confidence:** 0.75  
**File:** routes/fileUpload.ts:114

**Description:** `yaml.load(data)` processes unbounded YAML. A YAML bomb (billion laughs) causes exponential memory growth before the 2s timeout triggers.

**Exploit scenario:** POST .yaml with a deeply nested YAML structure — server memory exhausted before timeout cancels.

**Recommendation:** Use `YAML.safeLoad()` to disable arbitrary object instantiation. Limit document size.

---

### F-027 — SSRF via profile image URL upload

**Severity:** MEDIUM | **Confidence:** 0.8  
**File:** routes/profileImageUrlUpload.ts:21

**Description:** `fetch(url)` at line 21 accepts user-supplied imageUrl with no protocol/host validation. The catch block at line 31 stores the URL directly.

**Exploit scenario:** `POST /profile/image/url { "imageUrl": "http://localhost:3000/.well-known/security.txt" }` — server fetches internal resources.

**Recommendation:** Reject private IP ranges. Use DNS resolution to verify hostname resolves to non-private IP.

---

### F-028 — Potential code execution via noEval sandbox in B2B order

**Severity:** MEDIUM | **Confidence:** 0.7  
**File:** routes/b2bOrder.ts:20

**Description:** `vm.runInContext('safeEval(orderLinesData)', ...)` with user-controlled orderLinesData. noEval (notevil) strips dangerous globals but may have bypass vectors.

**Exploit scenario:** If noEval is bypassed, `process.mainModule.require('child_process')` executes arbitrary code.

**Recommendation:** Parse orderLinesData as strict JSON only. Remove the VM sandbox if possible.

---

### F-029 — CTF key loaded from plaintext file on disk

**Severity:** LOW | **Confidence:** 0.7  
**File:** lib/utils.ts:79

**Description:** `fs.readFileSync('ctf.key', 'utf8')` loads the CTF HMAC key from a plaintext file. Used for HMAC-SHA256 of challenge flags.

**Exploit scenario:** Read ctf.key from source directory, generate valid challenge flags.

**Recommendation:** Always use environment variable. Never include key file in repository.

---

### F-030 — Directory listing exposes sensitive files

**Severity:** MEDIUM | **Confidence:** 0.8  
**File:** server.ts:249

**Description:** serveIndex middleware enables directory listing for /ftp, /encryptionkeys, /support/logs at lines 249, 256, 259. All files listed and individually accessible.

**Exploit scenario:** Browse /encryptionkeys/ to enumerate all keys. Browse /support/logs/ to access server logs.

**Recommendation:** Remove serveIndex from sensitive directories. Require authentication for directory access.
