# Triage Report — juice-shop

14 in → 0 duplicates, 3 false positives, 11 confirmed (4 high / 5 med / 2 low), 2 need manual test.

Context: auto; environment = Internet-facing web service (HTTP untrusted); scoring = derived HIGH/MEDIUM/LOW; precision noise policy.

> **Run note:** Subagent verifier fan-out was unavailable (Claude Fable 5 not
> available for spawning). Adversarial verification was performed inline by the
> Fable orchestrator; verifier independence is reduced and `votes_per_finding` = 1.
> Every cited control (path guards, `notevil`, `vm` timeouts, the `verify()`
> ordering) was re-read from source during verification.

## Act on these

### [HIGH] SQL injection in login → authentication bypass  (f001)
`routes/login.ts:31` | sql-injection | claimed HIGH (alignment +5) | confidence 9.5/10
**Owner:** component: routes/; no CODEOWNERS; no git history (flattened)
**Verdict:** exploitable, votes {tp:1, fp:0, cv:0} · **Threat:** T1
**Preconditions:** none (unauthenticated)
**Why:** `req.body.email` interpolated unescaped into a raw `sequelize.query`; `' OR 1=1--` logs in as admin.

### [HIGH] SQL injection in product search → DB exfiltration  (f002)
`routes/search.ts:19` | sql-injection | claimed HIGH (alignment +5) | confidence 9.5/10
**Verdict:** exploitable · **Threat:** T1 · **Preconditions:** none (unauthenticated)
**Why:** search `q` interpolated into raw SQL; UNION extraction of Users/Cards. `search.ts:43` leaks the schema (f014).

### [HIGH] Hardcoded RSA private key → JWT forgery for any role  (f003)
`lib/insecurity.ts:17` | hardcoded-secret | claimed HIGH (alignment +5) | confidence 9.0/10
**Verdict:** exploitable · **Threat:** T2 · **Preconditions:** none (key is public)
**Why:** Private key is a source literal used by `authorize()` (:50); anyone can mint a valid `role=admin` token. Root cause of the JWT-trust failure (f010 is a misread symptom).

### [HIGH] XXE local file disclosure via uploaded XML (`noent:true`)  (f005)
`routes/fileUpload.ts:80` | xxe | claimed HIGH (alignment +4) | confidence 8.5/10
**Verdict:** exploitable · **Threat:** T4
**Why:** `libxml.parseXml(data,{noent:true})` substitutes external entities on uploaded XML; the `vm` does not stop expansion, and line 82 reflects the result (checked against `/etc/passwd`). `SYSTEM` entity reads local files.

### [MEDIUM] Poison-null-byte file-type bypass exposes sensitive `ftp/` files  (f004)
`routes/fileServer.ts:30` | path-traversal | claimed HIGH (alignment -1) | confidence 7.0/10
**Verdict:** exploitable · **Threat:** T3
**Preconditions:** append `%00`+allowlisted ext; target under `ftp/`
**Why:** **Corrected** — `/` is blocked (line 15) and a `.md/.pdf` allowlist enforced (line 24), so arbitrary traversal is NOT possible. The real bug is `cutOffPoisonNullByte` (line 25): `…bak%00.md` passes the check then truncates, serving non-allowlisted backups/`.pyc` within `ftp/`. HIGH→MEDIUM (confined to `ftp/`).

### [MEDIUM] Unsalted MD5 password hashing  (f006)
`lib/insecurity.ts:37` | weak-crypto | claimed MEDIUM (alignment +2) | confidence 8.5/10
**Verdict:** exploitable · **Threat:** T8 · **Preconditions:** obtain hashes first (via f001/f002)
**Why:** `md5(data)` unsalted; trivially cracked offline after a DB dump.

### [MEDIUM] SSRF via profile-image URL fetch  (f007)
`routes/profileImageUrlUpload.ts:21` | ssrf | claimed HIGH (alignment -1) | confidence 8.0/10
**Verdict:** exploitable · **Threat:** T5 · **Preconditions:** authenticated
**Why:** `await fetch(req.body.imageUrl)` with no scheme/host allowlist (the `url.match` at :17 is challenge detection, not a guard). Reaches intranet/metadata. High impact, but the auth requirement caps derived severity at MEDIUM.

### [MEDIUM] Server-side eval / DoS via `safeEval` of B2B order data  (f012)
`routes/b2bOrder.ts:20` | code-injection | claimed HIGH (alignment -2) | confidence 6.0/10
**Verdict:** needs_manual_test · **Threat:** T6
**Preconditions:** rce challenge flag enabled (:15); RCE additionally needs a `notevil`/`vm` escape
**Why:** **Corrected** — eval runs inside `notevil` `safeEval` + a 2s `vm` timeout, and the code handles both the infinite-loop and timeout cases (:23-28). Arbitrary-code RCE requires a notevil escape (version-dependent); near-certain realistic impact is CPU-DoS. HIGH→MEDIUM.
> Recommend a human PoC to confirm/deny a notevil sandbox escape on the deployed Node version.

### [MEDIUM] Hardcoded HMAC secret  (f008)
`lib/insecurity.ts:38` | hardcoded-secret | claimed MEDIUM (alignment +1) | confidence 7.0/10
**Verdict:** needs_manual_test · **Threat:** T8
**Why:** Static committed HMAC key lets an attacker forge whatever it protects; confirm which decisions consume `hmac()`.
> Recommend tracing `hmac()` consumers to pin the concrete forgeable artifact.

### [LOW] YAML bomb DoS on file upload  (f011)
`routes/fileUpload.ts:114` | dos | claimed MEDIUM (alignment -1) | confidence 6.5/10
**Verdict:** mitigated · **Threat:** T9
**Why:** Recursive YAML expansion is real, but the 2s `vm` timeout + length guard bound per-request cost; meaningful exhaustion is volumetric. MEDIUM→LOW.

### [LOW] Database schema disclosure via `sqlite_master`  (f014)
`routes/search.ts:43` | information-disclosure | claimed LOW (alignment +1) | confidence 6.0/10
**Verdict:** exploitable · **Threat:** T1
**Why:** Surfaces table/column names; low standalone impact, accelerates f002.

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f009 | Open redirect (substring allowlist) | lib/insecurity.ts:131 | Real bug (`url.includes()` bypassable) but open redirect is exclusion rule 12 (low-impact nuisance); dropped under precision policy. Captured as threat T10. |
| f010 | JWT decoded without verification in role checks | lib/insecurity.ts:52 | misread_code — role checks (:150-166) call `verify(...) && decode(...)`, and `verify()` (:51) runs `jws.verify` against the public key first. The real trust failure is the committed key (f003). |
| f013 | Path traversal in log/quarantine serving | routes/logfileServer.ts:11 | already_handled — both routes reject filenames containing `/` (:10), blocking traversal out of `logs/`/`ftp/quarantine/`; no extension/null-byte bypass exists, so no escalation beyond intended in-dir serving. |
