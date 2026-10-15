# OneVault (share-shield) Security Policy & Threat Model

*Version: 1.0 | Classification: Application Security Whitepaper*

OneVault is an educational, zero-knowledge, one-time secret sharing vault API. This document details the threat model, mitigation architecture, OWASP compliance mapping, and inherent system limitations.

---

## 1. Threat Model & Mitigations (SRS Section 6.1)

| Threat ID | Threat Category | Attack Vector | Architecture Mitigation | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Token Guessing / Enumeration** | Brute-force scanning of 32-byte share tokens. | 256 bits of CSPRNG entropy ($2^{256}$ search space). Per-IP rate limiting (10–30 req/min). | `tests/unit/crypto.test.ts`, `tests/integration/secrets.create-status.test.ts` |
| **TH-02** | **Database Compromise / Leak** | Attacker dumps entire PostgreSQL database. | Zero-knowledge design: database stores **only** SHA-256 digests (`token_hash`, `revoke_token_hash`) and encrypted ciphertext. Plaintext and decryption keys are **never** stored or sent to API. | `tests/integration/secrets.create-status.test.ts` (full DB column scan) |
| **TH-03** | **Concurrent Consumption / Race Condition** | Attacker fires concurrent requests to read one-time secret multiple times. | Single conditional PostgreSQL statement with `FOR UPDATE` row locking (`consumed_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()`). Zeroizes `ciphertext` and `iv` to `NULL` in the claiming update. | `tests/concurrency/secrets.concurrency.test.ts` (30 parallel requests $\times$ 5 runs) |
| **TH-04** | **Cross-Site Scripting (XSS)** | Injection of malicious scripts in web responses. | Strict Content Security Policy (`default-src 'none'; frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, and client contract mandates pure text decoding (`TextDecoder`). | `tests/integration/foundation.test.ts` |
| **TH-05** | **Link / Fragment Leakage** | Decryption key fragment leaking via Referrer headers or history. | `Referrer-Policy: no-referrer` header on all endpoints. Key resides exclusively in the client-side URL fragment (`#<key>`) which HTTP never transmits. Fragment is immediately scrubbed via `history.replaceState()`. | `tests/integration/foundation.test.ts` |
| **TH-06** | **Logging & Audit Leakage** | Plaintext, keys, raw tokens, or headers written to disk/syslog. | Audit-safe logging: logs parameterized route templates (`/api/v1/secrets/:token/consume`), method, status, and latency. Request bodies, cookies, query strings, and authorization tokens are strictly redacted. | `tests/integration/foundation.test.ts`, `tests/integration/secrets.consume-revoke-cleanup.test.ts` |
| **TH-07** | **Denial of Service / Large Payloads** | Memory exhaustion via oversized bodies or request flooding. | Strict payload caps (`16 KiB` JSON body limit, `10 KiB` maximum plaintext). Tiered rate limiters (Global, Create, Status, Consume, Revoke). | `tests/integration/foundation.test.ts`, `tests/integration/secrets.create-status.test.ts` |
| **TH-08** | **Existence & State Oracles** | Attacker probes API to discern if a token exists, is expired, consumed, or revoked. | Uniform Unavailable Response: unknown, expired, consumed, and revoked tokens return byte-identical HTTP 404 (`SECRET_UNAVAILABLE`). | `tests/integration/secrets.create-status.test.ts`, `tests/integration/secrets.consume-revoke-cleanup.test.ts` |
| **TH-09** | **Timing Attack Side-Channels** | Measuring string comparison latency to deduce token/hash bytes. | Constant-time hash verification via `crypto.timingSafeEqual` in `constantTimeEqual()`. | `tests/unit/crypto.test.ts` |
| **TH-10** | **HTTP Caching of Secrets** | Intermediate proxies or browsers caching sensitive responses. | Universal `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`, `Pragma: no-cache`, `Expires: 0` headers. | `tests/integration/foundation.test.ts` |
| **TH-11** | **Rate Limit Bypass (IP Spoofing)** | Attacker fakes `X-Forwarded-For` headers to cycle rate limit counters. | Explicit `trust proxy` configuration: boolean `true` is rejected. Client IPs are normalized and hashed with a secret salt (`IP_HASH_SALT`). | `tests/unit/env.test.ts`, `tests/integration/foundation.test.ts` |
| **TH-12** | **ORM & Query Log Leakage** | Database client logging query parameters containing token hashes or ciphertext. | Drizzle ORM query logger is explicitly disabled (`logger: false`). Driver connection string logging is redacted. | `src/db/client.ts`, `tests/integration/db.test.ts` |
| **TH-13** | **Error Reflection Leakage** | Framework error handlers echoing invalid request bodies or stack traces. | Centralized `errorHandler` maps all exceptions to coarse error codes (`VALIDATION_ERROR`, `INTERNAL_ERROR`), never echoing body properties or stack traces. | `tests/integration/foundation.test.ts` |

---

## 2. OWASP Top 10 (2021) Mapping

1. **A01:2021 — Broken Access Control**: Strict capability-based revocation (requires 32-byte high-entropy revoke token; prevents IDOR). At-most-once consumption locks out subsequent access.
2. **A02:2021 — Cryptographic Failures**: Authenticated encryption (`AES-256-GCM`), 12-byte fresh IVs per secret, SHA-256 token hashing, HSTS in production, and TLS certificate validation.
3. **A03:2021 — Injection**: Zero raw string concatenation in SQL queries. 100% parameterized queries via Drizzle ORM. Prototype pollution protection hook on JSON body parsing. Strict Zod type bounds on all inputs.
4. **A04:2021 — Insecure Design**: Zero-knowledge architecture by design. Server never receives plaintext or keys; single-statement conditional atomic state transitions.
5. **A05:2021 — Security Misconfiguration**: Strict Helmet security headers, removal of `X-Powered-By`, fail-fast Zod environment validation, and least-privilege PostgreSQL roles.
6. **A06:2021 — Vulnerable and Outdated Components**: Pinned dependencies in `package.json`, locked `package-lock.json`, and regular `npm audit` dependency reviews.
7. **A07:2021 — Identification and Authentication Failures**: Revoke capability uses 256 bits of entropy and constant-time comparison. Rate limiting mitigates brute force.
8. **A08:2021 — Software and Data Integrity Failures**: AES-GCM 128-bit authentication tag guarantees ciphertext integrity against tampering. Commit verification and automated CI testing.
9. **A09:2021 — Security Logging and Monitoring Failures**: High-fidelity structured JSON audit logging (Pino) recording request IDs, route templates, status codes, and latency without leaking sensitive data.
10. **A10:2021 — Server-Side Request Forgery (SSRF)**: The API initiates no outbound HTTP requests to external or user-specified URLs.

---

## 3. OWASP API Security Top 10 (2023) Mapping

1. **API1:2023 — Broken Object Level Authorization (BOLA)**: Secrets are addressed by 256-bit unguessable tokens; revocation requires matching 256-bit capability. Uniform 404 prevents object enumeration.
2. **API2:2023 — Broken Authentication**: Capability-based revocation validates 32-byte unpadded base64url bearer credentials using constant-time equality.
3. **API3:2023 — Broken Object Property Level Authorization**: Strict schemas (`.strict()`) reject any unexpected properties (`__proto__`, `key`, `plaintext`, internal fields). State fields are server-managed.
4. **API4:2023 — Unrestricted Resource Consumption**: Strict 16 KiB body parser limit, 10 KiB plaintext limit, and route-specific rate limiters (Create: 10/min, Status: 30/min, Consume: 15/min, Revoke: 15/min).
5. **API5:2023 — Broken Function Level Authorization**: Status check cannot retrieve ciphertext or consume secrets. Separate HTTP methods for lifecycle stages.
6. **API6:2023 — Unrestricted Access to Sensitive Business Flows**: One-time atomic consume guarantees at-most-once delivery.
7. **API7:2023 — Server-Side Request Forgery**: No outbound network requests.
8. **API8:2023 — Security Misconfiguration**: CORS allowlist forbids wildcards with credentials; default-deny CSP; explicit trust proxy validation.
9. **API9:2023 — Improper Inventory Management**: Versioned route prefix `/api/v1` with strict schema validation.
10. **API10:2023 — Unsafe Consumption of APIs**: Does not consume external third-party APIs.

---

## 4. Passkey Protection Security Model & Disclosures

OneVault protects access to active secret ciphertexts with an mandatory 6-digit numeric passkey generated server-side using CSPRNG (`crypto.randomInt(0, 1_000_000)` zero-padded).

### 4.1 Honest Threat & Cryptographic Analysis
- **The passkey is an access gate, not encryption**:
  The passkey does NOT encrypt or decrypt the secret. It serves strictly as an authorization gate on the server before the server releases the ciphertext. Client-side end-to-end encryption is performed exclusively with the 256-bit AES-GCM key in the URL fragment (`#<key>`).
- **The attempt limit is what makes a 6-digit code safe**:
  A 6-digit numeric space contains only $1,000,000$ possible combinations ($10^6$). In an offline setting, a million combinations can be searched in milliseconds. The security of this mechanism relies strictly on the server's atomic attempt bounding (`PASSKEY_MAX_ATTEMPTS`, default 5) enforced via PostgreSQL row locks (`SELECT ... FOR UPDATE`).
- **Database & Pepper Leak Analysis**:
  Passkeys are stored as `HMAC-SHA256(PASSKEY_PEPPER, tokenHash || ":" || passkey)`. The `tokenHash` serves as a per-secret salt.
  - If the database leaks without `PASSKEY_PEPPER`, an attacker cannot brute-force the passkey because HMAC-SHA256 requires the secret pepper.
  - If **both** the database and the environment pepper leak, an attacker can offline brute-force the 6-digit passkey ($10^6$ hashes). However, **the attacker still lacks the 256-bit fragment key**, so they CANNOT decrypt the ciphertext even if they recover the passkey.
- **Link Holder Denial of Service (Burning Secrets)**:
  Any holder of the share link (`/s/<token>`) can intentionally exhaust the 5 attempts by submitting 5 incorrect passkeys, causing the secret to be permanently locked and destroyed (`ciphertext = NULL`, `iv = NULL`). This is an **accepted trade-off**: an attacker holding the token could already consume the secret under the original one-time model. Out-of-band passkey verification prevents the attacker from *reading* the secret, even if they burn it.

---

## 5. Inherent Security Limitations (SRS Section 6.1 & 6.2)

Users, developers, and operators must understand the fundamental physical and cryptographic boundaries of a one-time link system:

1. **Compromised Endpoints**: Client-side encryption relies entirely on the integrity of the browser environment. If the creator or recipient machine is infected with malware, keyloggers, screen recording software, or malicious browser extensions, plaintext or keys can be intercepted at the time of entry or display.
2. **Recipient Copying & Redistribution**: Once a secret is decrypted and displayed on the recipient's screen, the API cannot prevent the recipient from copying the plaintext to clipboard, taking a screenshot, printing, photographing the screen, or forwarding the content.
3. **Link Interception & Transmission Channels**: If the creator transmits the full share link (`/s/<token>#<key>`) and the passkey over the same communication channel, an eavesdropper can intercept both. The passkey MUST be delivered via a distinct out-of-band channel (e.g., voice call, Signal, SMS).
4. **Physical Database Backups & Write-Ahead Logs (WAL)**: While PostgreSQL rows are deleted by the cleanup job and ciphertexts are zeroized to `NULL` upon consumption or lockout, database write-ahead logs and physical backup snapshots may retain historical data until the backup retention window expires (disclosed under NFR-12).
