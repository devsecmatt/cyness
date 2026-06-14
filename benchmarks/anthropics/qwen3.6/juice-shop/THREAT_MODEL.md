# Threat Model: OWASP Juice Shop

## 1. System context

OWASP Juice Shop is a deliberately insecure modern web application designed for security training, awareness, and CTF competitions. It is a full-stack application built on Node.js/Express (TypeScript server, Angular frontend) with a SQLite relational database and a MongoDB instance for orders and reviews. The application emulates a commercial e-commerce platform selling "juice" products, complete with user authentication, shopping baskets, payment processing, product reviews, and a chatbot. It is deployed via Docker, Heroku, or plain `npm start`.

The app is intentionally riddled with security vulnerabilities — over 80 distinct challenge categories are hardcoded throughout the codebase (login flaws, SQL injection, NoSQL injection, XSS, file upload vulnerabilities, JWT issues, web3/crypto flaws, SSRF, SSTI, XXE, directory traversal, broken access control, and more). The `lib/insecurity.ts` library intentionally contains unsafe implementations (MD5 hashing, hardcoded cryptographic keys, z85 encoding as "encryption," legacy sanitization bypasses). The application documents itself as "an awareness, training, demonstration and exercise tool for security risks in modern web applications" (per `config/default.yml` and `package.json`). It is widely deployed via Docker, Heroku, and other hosting platforms.

The target directory is version 19.2.1 of Juice Shop. The git repository provides the primary provenance (one commit visible in the working copy). There is no remote configured in the local checkout, but the upstream repository is `https://github.com/juice-shop/juice-shop`.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| User credentials (passwords, emails) | Stored in SQLite Users table; passwords hashed with MD5 via `security.hash()` | critical |
| User authentication tokens (JWTs) | RS256 JWTs signed with a hardcoded RSA private key in `lib/insecurity.ts` | critical |
| Payment card data (credit card numbers) | Stored in Card model; partially masked in API responses (last 4 digits visible) | critical |
| User personal data (names, addresses, phone numbers, profile info) | Stored across User, Address, Wallet models; exposed via data export endpoint | high |
| Order history and purchase records | Stored in MongoDB orders collection; email partially anonymized (vowels replaced with `*`) | high |
| User reviews and product feedback | Stored in MongoDB posts/reviews collection; author email exposed | high |
| 2FA TOTP secrets | Stored in User.totpSecret column; stored in cleartext in database | high |
| Hardcoded RSA private key | Embedded in `lib/insecurity.ts` source code; used to sign and forge JWT tokens | critical |
| Hardcoded HMAC secret | Embedded in `lib/insecurity.ts` (constant string `pa4qacea4VK9t9nGv7yZtwmj`) | high |
| CTF key | Stored in `ctf.key` file; used for HMAC-signed challenge flags | medium |
| Ethereum wallet mnemonic phrase | Hardcoded in `routes/checkKeys.ts` (`purpose betray marriage blame crunch monitor spin slide donate sport lift clutch`) | critical |
| Alchemy API WebSocket key | Hardcoded in `routes/web3Wallet.ts` and `routes/nftMint.ts` (`FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ`) | medium |
| Premium encryption key | Stored in `encryptionkeys/premium.key` | medium |
| Product catalog and pricing | Public-facing but integrity-sensitive; modifiable via admin interfaces | medium |
| File system access (ftp/, logs/, uploads/) | Served via Express static directories and route handlers; accessible to authenticated and some unauthenticated users | high |
| Prometheus metrics | Exposed at `/metrics` endpoint; includes cheat scores, challenge progress, user counts, wallet balances | medium |
| Chatbot training data | Loaded from JSON files; chatbot processes user input via JS evaluation | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP API — User registration (`POST /api/Users`) | Public user registration endpoint with JWT token issuance | unauth network → authenticated session | user credentials, payment card data |
| HTTP API — Login (`POST /rest/user/login`) | Credentials-based login with raw SQL query; returns JWT | unauth network → authenticated session | user credentials, authentication tokens |
| HTTP API — Password reset (`POST /rest/user/reset-password`) | Security question-based password reset | unauth network → credential reset | user credentials |
| HTTP API — Basket/order operations (`POST /rest/basket/*/checkout`, `POST /api/BasketItems`) | Order placement and basket manipulation | unauth/low-priv network → financial transactions | payment card data, order history, product catalog |
| HTTP API — File upload (`POST /file-upload`, `POST /profile/image/*`) | Accepts zip, xml, yaml, pdf, image uploads | unauth network → file system | file system access, user personal data |
| HTTP API — Product search (`GET /rest/products/search`) | SQL query on Products table via raw query string interpolation | unauth network → database | user credentials, product catalog, database schema |
| HTTP API — B2B order (`POST /b2b/v2/orders`) | Deprecated B2B file upload (XML/YAML) with libxmljs/JS-yaml parsing in vm sandbox | unauth network → file system + server-side code execution | file system access, host process integrity |
| Public file serving (`GET /ftp/*`, `/encryptionkeys/*`, `/support/logs/*`) | Static file serving with directory listing, null byte bypass, backup files | unauth network → file system | customer data, credentials, order history |
| Redirect endpoint (`GET /redirect`) | URL redirect with allowlist checked via `String.includes()` | unauth network → arbitrary external destination | authentication tokens (open redirect phishing) |
| Web3 wallet endpoint (`POST /rest/web3/walletExploitAddress`) | Accepts wallet addresses and connects to Sepolia testnet | unauth network → external blockchain | ethereum wallet mnemonic, Alchemy API key |
| Chatbot (`POST /rest/chatbot/respond`) | NLP chatbot processes user text; supports JS eval via username field | auth network → server-side code | user personal data, host process integrity |
| Profile with SSTI (`GET /profile`) | Pug template rendering with user-controlled username; `eval()` on input | auth network → server-side code host | user credentials, host process integrity |
| NoSQL data export (`POST /rest/user/data-export`, `GET /rest/order-history`) | Exports user orders/reviews from MongoDB | auth network → data export | user personal data, order history, reviews |
| Metrics endpoint (`GET /metrics`) | Prometheus metrics with user-agent based bypass of ignore list | public network → telemetry | customer data, challenge progress, cheat scores |
| NFT mint verify (`POST /rest/web3/walletNFTVerify`) | Verifies Ethereum NFT ownership on Sepolia testnet | unauth network → external blockchain | ethereum wallet mnemonic, Alchemy API key |
| Express RESTful API auto-scaffolding (`/api/*`) | finale-rest auto-generates CRUD endpoints for all Sequelize models | auth network → full database | user credentials, payment card data, product catalog, order history, all assets |
| 2FA setup/verify (`POST /rest/2fa/*`) | TOTP two-factor authentication with secrets exposed in API responses | auth network → authentication bypass | 2FA TOTP secrets, authentication tokens |
| Coupon application (`PUT /rest/basket/*/coupon/*`) | Z85-encoded coupon decoding with public key/algorithm | auth/low-priv network → financial manipulation | order history, payment card data |
| Vue Code snippet serve (`GET /snippets/:challenge`, `POST /snippets/verdict`) | Serves vulnerable code snippets for training; checks line selections | auth network → training data exposure | product catalog (vulnerable code) |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Authentication bypass via hardcoded RSA private key enabling JWT forgery | remote_unauth | User login, JWT auth middleware | user credentials, authentication tokens | critical | likely | unmitigated | none | lib/insecurity.ts:17 (private key embedded), lib/insecurity.ts:50-52 (sign/verify), routes/verify.ts:114 |
| T2 | SQL injection in product search via raw Sequelize query string concatenation enabling full database exfiltration | remote_unauth | Product search, User login | user credentials, database schema, product catalog | critical | likely | unmitigated | none | routes/search.ts:19 (string-concatenated query), routes/login.ts:31 (string-concatenated query) |
| T3 | Hardcoded Ethereum mnemonic phrase exposed in source code enabling theft of NFT assets | remote_unauth | checkKeys route, web3 wallet | ethereum wallet mnemonic, NFT assets | critical | likely | unmitigated | none | routes/checkKeys.ts:10 |
| Alchemy WebSocket API key hardcoded in source code enabling unauthorized blockchain RPC access | remote_unauth | web3Wallet, nftMint | authentication tokens, external blockchain | critical | possible | unmitigated | none | routes/web3Wallet.ts:18, routes/nftMint.ts:16, route/web3Wallet.ts:18 (API key embedded) |
| T5 | Arbitrary file write via ZIP upload with path traversal enabling server-side code execution | remote_unauth | File upload | file system access, host process integrity | critical | likely | partially_mitigated | upload size/type checks, path traversal guard | routes/fileUpload.ts:39-45; siblings: profile image upload, memory upload with insufficient validation |
| T6 | Open redirect via URL allowlist using String.includes() enabling phishing of credentials | remote_unauth | Redirect endpoint | authentication tokens, user personal data | high | likely | unmitigated | none | lib/insecurity.ts:131 (includes check), routes/redirect.ts:13 |
| T7 | User credential exposure via MD5 password hashing with no salt enabling offline password cracking | remote_unauth | User registration, login | user credentials | critical | likely | unmitigated | none | lib/insecurity.ts:37 (MD5 hash, no salt), models/user.ts:73 |
| T8 | Reflected and stored XSS via insufficient HTML sanitization in user profile, username, and email fields | remote_unauth | User profile, registration, feedback, reviews | user personal data, session tokens | high | likely | partially_mitigated | sanitize-html used in some paths; escape in legacy path is bypassable | models/user.ts:47-49 (sanitizeLegacy bypass), routes/userProfile.ts:59 (unsafe eval), lib/insecurity.ts:55 (sanitizeLegacy bypass) |
| T9 | Server-Side Template Injection and arbitrary code execution via Pug template with eval() on user-controlled username | remote_unauth | User profile, registration, chatbot username | host process integrity, user personal data | critical | possible | unmitigated | none | routes/userProfile.ts:52-64 (eval of username), lib/botUtils.ts:22 (unrestricted chatbot response) |
| T10 | NoSQL injection in order history and review queries enabling unauthorized access to other users' data | remote_unauth | Data export, order history, reviews | user personal data, order history, reviews | high | likely | partially_mitigated | partial input length cap | routes/dataExport.ts:30-37 (MongoDB find with raw email/review author fields) |
| T11 | Server-Side Request Forgery via insecure file download allowing internal network enumeration and sensitive file access | remote_unauth | File upload processing, chatbot training data fetch | file system access, host process integrity | high | possible | partially_mitigated | timeout on vm sandbox | lib/utils.ts:117-124 (download function with no URL validation), routes/fileUpload.ts:33 |
| T12 | Broken access control on auto-generated CRUD API endpoints enabling full database read/write/delete for all Sequelize models | remote_unauth/adjacent_network | finale-rest auto-scaffolding | user credentials, payment card data, order history, all assets | critical | likely | partially_mitigated | Some endpoints have denyAll() but not all models are covered | server.ts:445-460 (auto-model generation for 14 models), particularly: Product PUT, Challenge CRUD, Card CRUD bypass |
| T13 | Information disclosure via Prometheus metrics endpoint leaking cheat scores, challenge progress, user counts, and wallet balances | remote_unauth | Metrics endpoint | customer data, challenge progress | medium | possible | partially_mitigated | User-agent based filtering of monitored agents | routes/metrics.ts:63-72, server.ts:662 |
| T14 | Authentication bypass via timing attack on 2FA secret retrieval — secret returned in cleartext in API response | remote_unauth | 2FA status endpoint | 2FA TOTP secrets, authentication tokens | high | likely | unmitigated | none | routes/2fa.ts:66 (secret returned in setup response) |
| T15 | Password reset vulnerability via predictable security answers (HMAC with hardcoded key) enabling account takeover | remote_unauth | Password reset | user credentials | critical | likely | unmitigated | none | lib/insecurity.ts:38 (hardcoded HMAC key), routes/resetPassword.ts:38 (comparing HMAC(answer) against stored answer) |
| T16 | YamlBomb denial of service via YAML deserialization explosion via file upload | remote_unauth | B2B file upload (YAML) | service availability | medium | likely | partially_mitigated | v8 timeout (2s) on vm sandbox | routes/fileUpload.ts:114 |
| T17 | XML external entity (XXE) injection via libxmljs parsing with noent option enabled in B2B upload | remote_unauth | B2B file upload (XML) | file system access, server-side code host | high | likely | partially_mitigated | v8 timeout (2s) on vm sandbox | routes/fileUpload.ts:80 (noblanks: true, noent: true) |
| T18 | Coupon forging via Z85 encoding (base85) which is encoding not encryption — any attacker can generate arbitrary discount coupons | remote_unauth | Coupon application | financial integrity, product catalog | medium | likely | partially_mitigated | expiry date check | routes/coupon.ts:12, lib/insecurity.ts:93-115 (z85 encode/decode) |
| T19 | Account takeover via weak/default passwords for service accounts visible in login route challenge validators | remote_unauth | User login | user credentials, authentication tokens, order history | critical | likely | partially_mitigated | Safety mode disables some challenges in Docker/production | routes/login.ts:56-62 (hardcoded weak credentials: admin123, support password, rap password, etc.) |
| T20 | Cross-Site Request Forgery on checkout and basket operations due to missing CSRF tokens on state-changing POST endpoints | remote_unauth | All POST API endpoints without CSRF check | financial integrity, user data | high | likely | unmitigated | none | server.ts:549-618 (numerous POST routes without CSRF middleware) |
| T21 | Directory listing exposing backup files, encryption keys, and sensitive configuration via served directories | remote_unauth | FTP directory, encryptionkeys directory, logs directory | customer data, credentials, order history, file system access | high | likely | partially_mitigated | robots.txt disallows /ftp (easily bypassed) | server.ts:249-259 (serveIndex for ftp, encryptionkeys, logs) |
| T22 | Private key for premium content encryption stored in plaintext file enabling unauthorized access to premium content | remote_unauth | File server, premium content route | premium content access, host process integrity | medium | likely | unmitigated | none | encryptionkeys/premium.key |
| T23 | Null byte (poison byte) file path traversal bypassing extension allowlists enabling access to restricted file types | remote_unauth | File server | file system access, customer data | high | likely | partially_mitigated | cutOffPoisonNullByte in fileServer; siblings in other file-reading paths may lack this | routes/fileServer.ts:25, lib/insecurity.ts:40-46 |
| T24 | Hardcoded HMAC secret for coupon generation enabling forging of valid discount coupons exceeding authorized limits | remote_unauth | Coupon application | financial integrity | medium | likely | unmitigated | none | lib/insecurity.ts:38 (constant hard-coded HMAC key) |
| T25 | JWT algorithm confusion attack: application verifies tokens with RS256 public key but accepts tokens signed with HS256 using the public key as HMAC secret | remote_unauth | JWT auth middleware | user credentials, authentication tokens, all protected data | critical | likely | partially_mitigated | jws.verify check, but express-jwt may accept HS256 with public key as shared secret | lib/insecurity.ts:48-52, routes/verify.ts:78-86 |
| T26 | Unauthenticated data erosion — Sequelize paranoid soft-delete hook can be bypassed via direct API access on Models without proper authorization | remote_unauth/adjacent_network | finale-rest auto-generated endpoints | user credentials, product catalog, all user data | high | possible | unmitigated | Some resources have denyAll() | server.ts:445-460 (auto-models), routes/fileUpload.ts:42 (uploads directory) |

Note: IDs T4 was assigned as a separate row below. Re-numbering for clarity:

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T4 | Exposed blockchain API key and wallet mnemonic enabling unauthorized use of Sepolia testnet resources and theft of wallet contents | remote_unauth | web3 endpoints, NFT verification | ethereum wallet mnemonic, Alchemy API key | critical | likely | unmitigated | none | routes/checkKeys.ts:10, routes/web3Wallet.ts:18, routes/nftMint.ts:16 |

Sorted table for file:

T1: critical/likely — JWT forgery via hardcoded RSA private key
T3: critical/likely — Hardcoded Ethereum mnemonic
T7: critical/likely — MD5 password hashing
T12: critical/likely — Broken access control on auto-REST API
T15: critical/likely — Predictable security question password reset
T21+T25: critical/likely — XXE + null byte path traversal + JWT algo confusion

## 5. Deprioritized

| threat | reason |
|---|---|
| Repudiation: User actions unattributed in logs | Juice Shop logs HTTP access via Morgan with combined format; sufficient for attribution. Multi-user actions are minimal (single-user e-commerce). |
| Elevation via privilege escalation from customer to admin | `denyAll()` protects most admin routes; role checking exists via JWT claims. This is covered under T1 (JWT forgery) and T12 (access control). |
| DoS via resource exhaustion on file upload | Upload size limited to 200KB (memory) / disk storage limits exist. Covered under T5 (file upload) and T16 (YamlBomb DoS). |
| Information disclosure via error messages | Express errorhandler is configured; error messages are partially mitigated via `getErrorMessage`. Covered under T8/XSS. |
| Supply-chain compromise of node_modules dependencies | Dependency lockfiles not present in the working copy; typosquatting challenges exist in the codebase. Covered under T12. |
| TLS/transport-layer interception | Not applicable to a local threat model; assumed to be handled by deployment infrastructure (reverse proxy, load balancer). |

## 6. Open questions

- Is Juice Shop exposed on a public network or accessible directly from the internet in the target deployment? What is the network perimeter?
- Is there a WAF, CDN, or cloud security group upstream that filters or inspects traffic before it reaches this application?
- Does the MongoDB instance run on the same host or a separate server? Is it exposed on any network interface?
- Are the hardcoded credentials (admin password, support password, Ethereum mnemonic) intended to be unique per deployment or shared across all instances?
- Is the `/metrics` endpoint accessible without authentication in the target deployment? What is the risk appetite for telemetry data exposure?
- Are B2B file upload endpoints (`/b2b/v2/orders`) actively used in production or disabled? What is the trusted source of B2B file uploads?
- Which environment (config profile: `default`, `ctf`, `unsafe`, `test`, `7ms`, etc.) is being targeted? Different configs expose different challenge sets and security postures.
- Is the application deployed via the Dockerfile (with USER 65532, distroless base) or via `npm start`/`ts-node`? What is the runtime environment privilege level?
- Are there any upstream rate limiting or bot protection mechanisms? What is the targeted threat actor sophistication (script kiddie, automated scanner, targeted attacker)?
- Is the `safetyMode` challenge enablement setting the same as the default (`auto`) or overridden? This affects which vulnerabilities are exploitable.
- Are there any custom integrations or middleware not visible in the source tree (e.g., custom auth providers, third-party payment gateways)?

## 7. Provenance

- mode: bootstrap
- date: 2026-06-12
- target: /home/higgs/workspace/cyness/juice-shop @ 6ed9ce4
- inputs: git-log + source code analysis
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Remove all hardcoded secrets (RSA private key, HMAC secret, Ethereum mnemonic, Alchemy API key) and use environment variables or a secrets manager | T1, T3, T4, T7, T15, T24 | yes | M |
| Replace MD5 password hashing with bcrypt/scrypt/argon2 and enforce minimum password policies | T7, T19 | yes | M |
| Parameterize all database queries — eliminate raw SQL string concatenation in login and search | T2 | yes | S |
| Replace finale-rest auto-scaffolding with explicit route definitions and fine-grained authorization per resource | T12, T26 | yes | L |
| Implement CSRF tokens on all state-changing endpoints | T20 | partial | M |
| Replace z85 encoding for coupons with a proper HMAC or HMAC-based signature scheme with server-side validity store | T18, T24 | partial | S |
| Remove `eval()` from username processing and sanitize Pug template rendering to prevent SSTI/RCE | T9 | yes | S |
| Remove null byte bypass capability and validate path components at every level of file reading | T23 | partial | S |
| Add authentication to the `/metrics` Prometheus endpoint | T13 | partial | S |
| Enforce content-type validation and URL allowlists with exact prefix matching for all redirects and file downloads | T6, T11 | partial | S |
| Remove plaintext encryption keys from the repository and use a KMS or secure storage backend | T22 | yes | S |
| Use the `none` algorithm explicitly in JWT header validation and reject algorithm switching in auth middleware | T25 | partial | M |
