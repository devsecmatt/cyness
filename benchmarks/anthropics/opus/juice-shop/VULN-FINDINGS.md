# Vuln-Scan Findings: juice-shop

Static review (read-only), scoped by `THREAT_MODEL.md`. 14 findings across 7
focus areas. Juice Shop's vulnerabilities are real, reachable Express/Angular
code (the product's training content), reported as genuine candidates. These
are static candidates; for execution-verified PoCs use `vuln-pipeline`.

| id | severity | category | file:line | conf | title |
|---|---|---|---|---|---|
| F-001 | HIGH | sql-injection | routes/login.ts:31 | 0.95 | SQLi in login → auth bypass |
| F-002 | HIGH | sql-injection | routes/search.ts:19 | 0.95 | SQLi in product search → DB exfiltration |
| F-003 | HIGH | hardcoded-secret | lib/insecurity.ts:17 | 0.92 | Hardcoded RSA private key → JWT forgery |
| F-004 | HIGH | path-traversal | routes/fileServer.ts:30 | 0.85 | Path traversal serves arbitrary files |
| F-005 | HIGH | xxe | routes/fileUpload.ts:80 | 0.85 | XXE file disclosure (`noent:true`) |
| F-006 | MEDIUM | weak-crypto | lib/insecurity.ts:37 | 0.85 | Unsalted MD5 password hashing |
| F-007 | HIGH | ssrf | routes/profileImageUrlUpload.ts:21 | 0.8 | SSRF via profile-image URL fetch |
| F-008 | MEDIUM | hardcoded-secret | lib/insecurity.ts:38 | 0.8 | Hardcoded HMAC secret |
| F-009 | MEDIUM | open-redirect | lib/insecurity.ts:131 | 0.78 | Open redirect (substring allowlist) |
| F-010 | HIGH | auth-bypass | lib/insecurity.ts:52 | 0.7 | JWT decoded without verification in role checks |
| F-011 | MEDIUM | dos | routes/fileUpload.ts:114 | 0.7 | YAML bomb DoS on upload |
| F-012 | HIGH | code-injection | routes/b2bOrder.ts:20 | 0.6 | `safeEval` of B2B order data in `vm` (RCE/DoS) |
| F-013 | MEDIUM | path-traversal | routes/logfileServer.ts:11 | 0.6 | Path traversal in log/quarantine serving |
| F-014 | LOW | information-disclosure | routes/search.ts:43 | 0.5 | DB schema disclosure via `sqlite_master` |

Summary: 14 total — 7 HIGH, 6 MEDIUM, 1 LOW, 0 low-confidence.

## Highlights

**F-001 / F-002 — SQL injection.** `login.ts:31` and `search.ts:19` interpolate
request data (`req.body.email`, search `q`) directly into raw
`sequelize.query` strings. `' OR 1=1--` in login authenticates as admin; UNION
payloads in search dump the Users/Cards tables. `search.ts:43` also exposes
`SELECT sql FROM sqlite_master`.

**F-003 / F-010 — JWT trust chain.** The RSA private key is committed at
`insecurity.ts:17` (used by `authorize()` at :50), so any role can be forged.
`decode()` at :52 returns the payload with no signature check and is consumed in
role checks (`:150-166`).

**F-004 / F-013 — Path traversal.** `res.sendFile(path.resolve('<dir>/', file))`
with a user-controlled `file` and only a base-dir prefix
(`fileServer.ts:30`, `logfileServer.ts:11`, `quarantineServer.ts:11`).

**F-005 / F-011 — File upload.** Uploaded XML parsed with `noent:true`
(`fileUpload.ts:80`) → XXE local file disclosure (code checks the result against
`/etc/passwd`); YAML loaded at `:114` → billion-laughs DoS.

**F-007 — SSRF.** `await fetch(req.body.imageUrl)` (`profileImageUrlUpload.ts:21`)
with no host/scheme allowlist → cloud-metadata / intranet probing.

**F-012 — Server-side eval.** `vm.runInContext('safeEval(orderLinesData)', …)`
(`b2bOrder.ts:20`) on attacker data: sandbox-escape RCE is possible, CPU-DoS is
near-certain.

**F-006 / F-008 / F-009 — Crypto/redirect.** Unsalted MD5 password hashing
(`:37`), hardcoded HMAC secret (`:38`), and a substring `includes()` redirect
allowlist (`:131`).

---
**Next:** `/triage benchmarks/anthropics/fable/juice-shop/VULN-FINDINGS.json --repo juice-shop`
