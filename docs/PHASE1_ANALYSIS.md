# Phase 1: Analysis, Threat Model & Architecture Decisions

**Project:** OneVault (`share-shield`) — One-Time Secret Sharing Vault (Backend Only)  
**Document Version:** 1.0.0  
**Status:** Completed Analysis & Architecture Baseline  

---

## 1. Summary of SRS.md and Api_Reference.md

### 1.1 Endpoints Specification

All endpoints are prefixed with `/api/v1` and strictly serve/accept `application/json; charset=utf-8`.

| Method | Path | Auth | Rate-Limit Class | Purpose / Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Utility / Health (60 req/min) | Liveness and readiness probe. Returns minimal `{ "status": "ok" }`. Exposes no infrastructure or credential data. |
| `POST` | `/secrets` | Public | Mutation / Create (10 req/min) | Accepts client-generated share token, revoke token, ciphertext, IV, and expiry enum. Hashes tokens with SHA-256 and persists record. |
| `GET` | `/secrets/:token/status` | Public | Read / Status (30 req/min) | Checks secret availability without revealing ciphertext. Returns generic 404 if invalid, expired, consumed, or revoked. |
| `POST` | `/secrets/:token/consume` | Public | Sensitive / Atomic (15 req/min) | Atomically claims the secret in a single conditional SQL statement. Returns ciphertext and IV at most once. Subsequent calls return 404. |
| `DELETE` | `/secrets/:token` | Bearer Token (`Authorization: Bearer <revokeToken>`) | Revoke / Mutation (15 req/min) | Revokes an active secret using the creator's revoke capability token. Wipes ciphertext and sets revocation timestamp. Returns 204 No Content. |

---

### 1.2 Data Entities

#### `Secret` (Primary Entity)
Represents the encrypted secret envelope and its lifecycle state.

* `id` (`UUID`): Primary key, generated server-side (`gen_random_uuid()`).
* `tokenHash` (`BYTEA` or `CHAR(64)`): Unique SHA-256 digest of the raw 32-byte decoded share token. Never stores the raw token.
* `revokeTokenHash` (`BYTEA` or `CHAR(64)`): SHA-256 digest of the raw 32-byte decoded creator revoke token. Never stores the raw revoke token.
* `ciphertext` (`BYTEA` or `TEXT` base64url, nullable upon consumption/revocation): AES-GCM encrypted payload including the 16-byte authentication tag.
* `iv` (`BYTEA` or `TEXT` base64url, nullable upon consumption/revocation): 12-byte initialization vector.
* `payloadVersion` (`INTEGER`, default `1`): Schema version for encryption algorithm and payload structure.
* `expiresAt` (`TIMESTAMPTZ`): UTC expiration deadline computed at creation via server/DB time.
* `createdAt` (`TIMESTAMPTZ`, default `NOW()`): Creation timestamp.
* `consumedAt` (`TIMESTAMPTZ`, nullable): Set atomically upon successful first consumption.
* `revokedAt` (`TIMESTAMPTZ`, nullable): Set upon successful revocation by the creator.
* `maxViews` (`INTEGER`, default `1`): Maximum permitted retrieval count (enforced to 1 in MVP).

#### Optional Account Entities (SRS 7.2 / Phase 6 Extension)
* `User`: `id` (`UUID`), `email` (`VARCHAR`), `passwordHash` (`VARCHAR`), `createdAt` (`TIMESTAMPTZ`).
* `SecretOwnership`: `secretId` (`UUID`), `userId` (`UUID`), `revokeTokenHash` (`BYTEA`).

---

### 1.3 Core Business Rules

1. **Zero Knowledge / Plaintext Secrecy:** Decryption keys and plaintext are never received, stored, or processed by the server. The server stores only ciphertext, IV, and SHA-256 token digests.
2. **Strict Single Consumption:** At most one consumer request may retrieve the ciphertext. Subsequent or concurrent requests must fail with a generic unavailable response.
3. **Atomic State Transition:** Consumption must occur in a single conditional statement (no read-then-write race window).
4. **Server-Side Authority on Expiry:** Expiration is calculated and evaluated strictly using database/server system clock (`NOW()`), never relying on client-supplied timestamps.
5. **Allowed Expiry Durations:** Exactly 600s (10m), 3600s (1h), 86400s (24h), or 604800s (7d). Default: 3600s.
6. **Payload Size Cap:** Plaintext maximum is 10 KiB. Request JSON bodies are capped at 16 KiB.
7. **Uniform State Masking:** Non-existent, expired, consumed, and revoked secrets return identical generic 404 responses (`SECRET_UNAVAILABLE`) with identical bodies to eliminate state discovery.
8. **Logging Minimization:** Request bodies, query parameters, authorization headers, cookies, plaintext, and raw tokens are forbidden from logs and error handlers.

---

### 1.4 Division of Responsibilities: Backend vs. Frontend

#### Frontend-Only Requirements (Excluded from Backend Implementation)
* **FR-02 (Client-Side Encryption):** Generating a 256-bit AES-GCM key and 12-byte IV using the Web Crypto API; encrypting plaintext locally.
* **FR-03 (Share Link Assembly):** Constructing the full share URL (`https://host/s/<token>#<key>`) with the encryption key residing solely in the URL fragment (`#`).
* **FR-07 (Client-Side Decryption):** Extracting the fragment key from the browser address bar, wiping the fragment from history via `history.replaceState`, and decrypting ciphertext locally.
* **FR-10 (Copy UI & User Guidance):** Clipboard handling and visual security warnings.
* **UI Output Escaping:** Ensuring decrypted plaintext is injected strictly as text (never HTML) to prevent DOM XSS.

#### Backend Requirements
* **FR-01 / FR-04 (Persistence & Validation):** Validating incoming schemas and storing token hashes, ciphertext, IV, and lifecycle metadata.
* **FR-05 (Availability Probe):** Exposing `GET /api/v1/secrets/:token/status` without leaking ciphertext.
* **FR-06 (Atomic Consumption):** Executing atomic conditional claim in PostgreSQL and returning ciphertext once.
* **FR-08 (Server Expiry Validation):** Enforcing DB-level expiration gates.
* **FR-09 (Creator Revocation):** Authenticating and executing secret revocation using the creator's revoke capability token.
* **FR-12 (Health Monitoring):** Providing clean, unprivileged health check endpoints.
* **FR-13 (Input Sanitization):** Enforcing strict Zod validation on params, headers, and bodies; rejecting unknown keys.
* **FR-14 (Abuse Prevention):** Enforcing route-specific rate limits.
* **FR-15 (Audit-Safe Telemetry):** Structured logging using route templates and coarse error codes.
* **Lifecycle Purge:** Background automated deletion of expired, consumed, and revoked records.

#### Required Frontend Contract with Backend
1. **Share Token Format:** 32 cryptographically random bytes encoded as unpadded base64url (`^[A-Za-z0-9_-]{43}$`).
2. **Revoke Token Format:** 32 cryptographically random bytes encoded as unpadded base64url (`^[A-Za-z0-9_-]{43}$`).
3. **IV Format:** Exactly 12 raw bytes encoded as unpadded base64url (`^[A-Za-z0-9_-]{16}$`).
4. **Ciphertext Format:** AES-GCM encrypted payload concatenated with the 16-byte authentication tag, encoded as unpadded base64url (`^[A-Za-z0-9_-]{23,13675}$`).
5. **Revocation Transmission:** Transmitted strictly in the `Authorization: Bearer <revokeToken>` header on `DELETE /api/v1/secrets/:token`.
6. **URL Fragment Privacy:** The decryption key must **never** be sent in query parameters, headers, or request bodies.

---

## 2. Comprehensive Threat Model & Planned Mitigations

| Threat ID | Threat Name & Description | Attack Vector / Impact | Planned Mitigation |
| :--- | :--- | :--- | :--- |
| **TH-01** | **Token Guessing** | Attacker brute-forces bearer share tokens to retrieve active secrets. | Tokens are 32 bytes of cryptographically secure random entropy (256 bits; $2^{256}$ keyspace). Rate limits on `/status` (30/min) and `/consume` (15/min) per IP restrict guessing throughput. |
| **TH-02** | **Database Compromise (Leak)** | Attacker gains full read access to database dumps or PostgreSQL storage. | Server stores only SHA-256 digests of share and revoke tokens. Plaintext is never stored; decryption keys never touch the server. Ciphertext is wiped immediately upon consumption/revocation. |
| **TH-03** | **Concurrent Consumption Race** | Attacker launches simultaneous parallel requests to `/consume` to retrieve payload twice. | Atomically evaluated in PostgreSQL via a single conditional statement: `UPDATE secrets SET consumed_at = NOW() WHERE token_hash = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > NOW() RETURNING ...`. PostgreSQL row locks ensure exactly one transaction succeeds. |
| **TH-04** | **XSS & Link Leakage** | Decrypted secret or share URL leaks via Referrer headers, browser history, or script injection. | Security headers applied globally: `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`. API produces strictly `application/json`. |
| **TH-05** | **Logging & Telemetry Leakage** | Plaintext, raw tokens, or credentials appear in console logs, APM, or disk logs. | Structured logger logs only request ID, HTTP method, route **template** (`/api/v1/secrets/:token/consume`), response status, latency, and coarse error codes. Request bodies, query parameters, Authorization headers, and real URLs are strictly excluded. |
| **TH-06** | **Brute Force & DoS** | Flooding endpoints with large payloads or excessive traffic to exhaust memory/CPU. | `express.json({ limit: '16kb' })` rejects oversized bodies with HTTP 413. Route-specific `express-rate-limit` prevents resource exhaustion. Strict Zod schemas fail-fast before database access. |
| **TH-07** | **Compromised Client** | Malware, malicious extensions, or clipboard scrapers capture keys in the browser. | Documented architectural boundary. Server adheres to zero-knowledge principles. Transient memory usage recommendations and prompt zeroization minimize client-side exposure. |
| **TH-08** | **Existence Oracles** | Attacker probes tokens to discern whether a secret was consumed, revoked, expired, or never existed. | Uniform response enforcement: every unavailable condition returns identical HTTP 404 with code `SECRET_UNAVAILABLE` and identical JSON schema. |
| **TH-09** | **Timing Differences** | Attacker measures latency differences between token hash lookup, record evaluation, and error generation. | SHA-256 token hashing occurs unconditionally. Database queries execute single-query indexed lookups. Revocation token comparisons in memory use `crypto.timingSafeEqual`. |
| **TH-10** | **Cache Leakage** | Intermediate proxies, CDNs, or browser caches store sensitive status or ciphertext responses. | Global middleware injects `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`, `Pragma: no-cache`, `Expires: 0`, and `Surrogate-Control: no-store` on all API responses. |
| **TH-11** | **Rate-Limit Bypass via Spoofed Headers** | Attacker crafts arbitrary `X-Forwarded-For` headers to reset IP rate limit buckets. | Explicit Express `trust proxy` configuration: disabled (`false`) in direct environments; restricted to explicit trusted reverse proxy IP/CIDR or hop counts in production. Untrusted forward headers are disregarded. |
| **TH-12** | **ORM / Query Parameter Logging** | Drizzle ORM or PostgreSQL `pg` driver logs queries along with bind parameters (hashes, ciphertext). | Drizzle ORM query logger is completely disabled in production (`logger: false`). In development/test, bind parameters are stripped. Logging of SQL parameters is forbidden. |
| **TH-13** | **Error Handlers Echoing Input** | Central error handlers or validation formatters echo malformed input payloads back to the client. | Custom error handler processes Zod errors and emits only validation failure codes and affected field paths (e.g. `path: "ciphertext"`, `issue: "invalid_length"`). Raw received values (`error.received` / `req.body`) are never echoed in HTTP responses. |

---

## 3. Resolution of Architectural Gaps & Decisions

### 3a. Revoke Capability
* **Options Considered:**
  1. *Server-generated revoke token:* Server creates revoke token on `POST /secrets` and returns it in the 201 response.
  2. *Client-generated revoke token:* Client generates 32 cryptographically secure random bytes (base64url), passes `revokeToken` in the creation payload, and server stores only `SHA-256(revokeToken)`.
  3. *Share token as revoke token:* Using the share token itself to authorize revocation.
* **Decision:** **Option 2 (Client-generated revoke token)**.
* **Transmission:** The creator provides the token via the HTTP header `Authorization: Bearer <creator-revoke-token>` on `DELETE /api/v1/secrets/:token`.
* **Storage:** Stored as `revoke_token_hash` (`BYTEA`, 32 bytes) directly on the `secrets` table.
* **Rationale:** Aligns with decentralized zero-knowledge generation. Transmitting via `Authorization: Bearer` keeps secrets out of URLs, query strings, and body logs. Storing `revoke_token_hash` directly on the `secrets` table enables anonymous creator revocation in MVP without relying on optional user account tables.

---

### 3b. Revoke Edge Cases & Oracle Prevention
* **Options Considered:**
  1. *Differentiated responses:* Return 401 for missing header, 403 for invalid revoke token, 404 for non-existent secret, 410 for consumed/expired secret. (Leaks secret lifecycle state).
  2. *Blind 404:* Return 404 for all failures, including invalid revoke token. (Violates Api_Reference section 8 and test case API-14).
  3. *Secure State-Gated Validation:*
     - Syntactically missing header: `401 UNAUTHENTICATED`.
     - Syntactically malformed header/token format: `400 VALIDATION_ERROR`.
     - If the secret is unavailable (does not exist, expired, already consumed, or already revoked): Return `404 SECRET_UNAVAILABLE` regardless of revoke token validity.
     - If the secret is active/available, but the revoke token hash does not match: Return `403 REVOKE_NOT_AUTHORIZED` (record remains untouched).
     - If the secret is active/available and the revoke token hash matches: Revoke, zeroize, and return `204 No Content`.
* **Decision:** **Option 3 (Secure State-Gated Validation)**.
* **Rationale:** A caller possessing the public share token already knows if the secret is active via `GET /status` (which returns 200 vs 404). Therefore, returning 403 on an active secret with an invalid revoke token leaks zero new information, while returning 404 on all unavailable secrets prevents creating an existence oracle for past or expired secrets.

---

### 3c. Unavailable Responses: Uniform Masking
* **Conflict:** FR-11 suggests handling distinct UI states (expired, consumed, revoked), whereas SRS Section 3.1 & 8, Invariant 4, and Api_Reference Section 2.2 require generic responses.
* **Decision:** **Strict uniform response across all endpoints.**
  * HTTP Status: `404 Not Found`
  * Body:
    ```json
    {
      "error": {
        "code": "SECRET_UNAVAILABLE",
        "message": "This secret is unavailable.",
        "requestId": "req_01J..."
      }
    }
    ```
* **Rationale:** Eliminates information leakage. Callers cannot determine if a link was previously valid, consumed by someone else, revoked by the creator, expired by time, or fabricated. The frontend UI conveys distinct states only when locally known (e.g. immediately after local consumption).

---

### 3d. Malformed Token vs. Unknown Token
* **Specification:** Token must be exactly 32 random bytes, base64url-encoded without padding: regex `^[A-Za-z0-9_-]{43}$`.
* **Decision:**
  * **Malformed Token:** Any token failing syntactic validation (e.g. length $\neq 43$, invalid characters like `+`, `/`, `=`, `%`) is rejected by Zod validation middleware with **HTTP 400 `VALIDATION_ERROR`** before database interaction.
  * **Unknown Token:** A syntactically valid 43-character token that does not correspond to an active record in the database returns **HTTP 404 `SECRET_UNAVAILABLE`**.
* **Rationale:** Protects database resources against malformed inputs and DoS, while preserving uniform masking for all syntactically valid tokens.

---

### 3e. Expiry Input Schema
* **Specification:** Client submits an integer enumeration representing lifetime in seconds.
* **Decision:**
  * Field: `expiresInSeconds`
  * Schema: `z.union([z.literal(600), z.literal(3600), z.literal(86400), z.literal(604800)])`
  * Default: If omitted in request body, defaults to `3600` (1 hour).
  * Storage: Server calculates `expiresAt = NOW() + (expiresInSeconds * INTERVAL '1 second')` and returns the ISO 8601 UTC timestamp in the 201 response.
* **Rationale:** Completely eliminates client-clock drift attacks and enforces SRS Section 8 business rules.

---

### 3f. Payload Size Limits & Derivations
* **Derivation:**
  * Maximum Plaintext: $10\text{ KiB} = 10,240\text{ bytes}$.
  * AES-GCM Tag: 16 bytes.
  * Minimum Plaintext: 1 byte $\rightarrow$ Ciphertext raw bytes: $1 + 16 = 17\text{ bytes}$.
  * Maximum Plaintext: $10,240\text{ bytes} \rightarrow$ Ciphertext raw bytes: $10,240 + 16 = 10,256\text{ bytes}$.
  * Base64url character lengths ($\lceil n \times 4/3 \rceil$ without padding):
    * Min Ciphertext Length: $\lceil 17 \times 4 / 3 \rceil = 23\text{ chars}$.
    * Max Ciphertext Length: $\lceil 10,256 \times 4 / 3 \rceil = 13,675\text{ chars}$.
  * IV: Exactly 12 raw bytes $\rightarrow$ Exactly $12 \times 4 / 3 = 16\text{ chars}$ base64url (`^[A-Za-z0-9_-]{16}$`).
* **Enforced Limits:**
  * `express.json({ limit: '16kb' })`: Rejects oversized JSON payloads with HTTP 413 `PAYLOAD_TOO_LARGE`.
  * Zod String Lengths:
    * `token`: exactly 43 chars (`^[A-Za-z0-9_-]{43}$`).
    * `revokeToken`: exactly 43 chars (`^[A-Za-z0-9_-]{43}$`).
    * `iv`: exactly 16 chars (`^[A-Za-z0-9_-]{16}$`).
    * `ciphertext`: min 23 chars, max 13,675 chars (`^[A-Za-z0-9_-]{23,13675}$`).

---

### 3g. Ciphertext Zeroization (Retention Decision)
* **Options Considered:**
  1. *Retain ciphertext until scheduled cleanup:* Keep ciphertext in database row until an hourly/daily cron job purges the row.
  2. *Wipe ciphertext and IV immediately upon consumption and revocation (Zeroization):* Clear ciphertext and IV in the database row as part of consumption/revocation, leaving only metadata until cleanup.
* **Decision:** **Option 2 (Immediate Zeroization)**.
* **Implementation & Schema Impact:**
  * Schema: `ciphertext` and `iv` columns are marked nullable (`BYTEA NULL` or `TEXT NULL`).
  * On Revoke: `UPDATE secrets SET revoked_at = NOW(), ciphertext = NULL, iv = NULL WHERE id = $1;`
  * On Consume: To satisfy Non-Negotiable Invariant 3 (single atomic statement in PostgreSQL) while zeroizing, we execute:
    ```sql
    UPDATE secrets
    SET consumed_at = NOW(),
        ciphertext = NULL,
        iv = NULL
    WHERE token_hash = $1
      AND consumed_at IS NULL
      AND revoked_at IS NULL
      AND expires_at > NOW()
    RETURNING (SELECT ciphertext FROM secrets WHERE token_hash = $1) AS old_ciphertext,
              (SELECT iv FROM secrets WHERE token_hash = $1) AS old_iv,
              payload_version;
    ```
    *(Or capture ciphertext in a CTE: `WITH target AS (...) UPDATE secrets ... RETURNING target.ciphertext`).*
* **Rationale:** Satisfies NFR-10 (Data minimization) and defense-in-depth: if the database is breached after a secret is consumed or revoked, no encrypted payload remains to be attacked.

---

### 3h. Duplicate Token Hash Collision on Creation
* **Scenario:** An incoming token collides with an existing `token_hash` unique constraint ($P \approx 2^{-256}$, indicating replay or attack).
* **Decision:** Catch PostgreSQL unique constraint violation (`23505`). Return **HTTP 400 `VALIDATION_ERROR`** with generic message `"Request could not be processed"`.
* **Rationale:** Never return HTTP 409 Conflict or expose constraint error details, preventing attackers from probing for hash existence.

---

### 3i. IP Handling & Privacy-Preserving Rate Limiting
* **Decision:**
  * **Reverse Proxy Trust:** `app.set('trust proxy', config.TRUST_PROXY)`. Default in development/local is `false`. In production, configured strictly to trusted reverse proxy hop counts or CIDR ranges.
  * **Client IP Hashing:** The rate limiter identifies clients using a one-way truncated hash: `SHA-256(clientIP + dailySecretSalt).slice(0, 16)`.
  * **Storage & TTL:** Stored solely in memory or Redis with a sliding-window TTL matching the rate-limit window (e.g. 60 seconds).
  * **Audit Exemption:** IP addresses are never persisted to PostgreSQL and never logged in application telemetry.

---

### 3j. Global Response Caching Policy
* **Decision:** Global middleware sets strict anti-caching headers on all routes:
  ```http
  Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
  Pragma: no-cache
  Expires: 0
  Surrogate-Control: no-store
  ```
* **Rationale:** Guarantees that intermediary caches, shared proxies, and browser caches never persist sensitive secret metadata, error codes, or payloads.

---

### 3k. `maxViews` Policy
* **Decision:** `maxViews` is **NOT** client-settable.
* **Schema Policy:** Request Zod schema enforces `.strict()`, rejecting any payload containing `maxViews` with HTTP 400 `VALIDATION_ERROR`.
* **Database Default:** Column defaults to `1` and cannot be modified.
* **Rationale:** Strict adherence to MVP scope and Non-Negotiable Invariant 3.

---

### 3l. Optional FR-16 (Account Dashboard)
* **Status in Api_Reference.md:** `Api_Reference.md` defines zero endpoints for user authentication, registration, or dashboard access.
* **Decision:** In accordance with Standing Rule ("No features or endpoints beyond the documents"), the core implementation (Phases 2–5) will focus exclusively on the anonymous vault. In Phase 6, a formal API specification for FR-16 will be proposed and reviewed prior to writing any account code.

---

### 3m. Multi-Instance Safe Cleanup Job
* **Decision:**
  * Background worker runs periodically (e.g. every 15 minutes).
  * Concurrency Safety: Uses PostgreSQL transaction-level advisory locks (`pg_try_advisory_xact_lock('onevault_cleanup'::regclass::bigint)`). If an instance fails to acquire the lock, it immediately skips the run.
  * Batching: Deletes in batches of 1,000 rows to prevent long-lived table locks:
    ```sql
    DELETE FROM secrets
    WHERE id IN (
      SELECT id FROM secrets
      WHERE (consumed_at IS NOT NULL
         OR revoked_at IS NOT NULL
         OR expires_at <= NOW())
      LIMIT 1000
    );
    ```
* **Rationale:** Ensures clean garbage collection without racing, table bloat, or lock contention across distributed instances.

---

## 4. Architecture, Folder Structure & DB Schema

### 4.1 Folder Structure

```text
/home/gech/PROJECT/share-shield/
├── docs/
│   └── PHASE1_ANALYSIS.md
├── drizzle/
│   └── migrations/
├── src/
│   ├── config/
│   │   └── env.ts                  # Zod validated environment configuration
│   ├── db/
│   │   ├── client.ts               # pg Pool & Drizzle ORM instance
│   │   ├── schema.ts               # Drizzle PostgreSQL schema definitions
│   │   └── index.ts
│   ├── middleware/
│   │   ├── cache-control.ts        # Global Cache-Control: no-store
│   │   ├── error-handler.ts        # Centralized secure error middleware
│   │   ├── rate-limiter.ts         # express-rate-limit factories
│   │   ├── request-id.ts           # UUID/NanoID request tracker
│   │   ├── request-logger.ts       # Audit-safe logging middleware
│   │   ├── security-headers.ts     # Helmet & custom security headers
│   │   └── validate.ts             # Generic Zod validation middleware
│   ├── lib/
│   │   ├── crypto.ts               # Token hashing & timing-safe utilities
│   │   └── logger.ts               # Pino structured safe logger
│   ├── modules/
│   │   ├── health/
│   │   │   ├── health.controller.ts
│   │   │   └── health.routes.ts
│   │   └── secrets/
│   │       ├── secrets.controller.ts
│   │       ├── secrets.repository.ts
│   │       ├── secrets.routes.ts
│   │       ├── secrets.schemas.ts
│   │       └── secrets.service.ts
│   ├── jobs/
│   │   └── cleanup.ts              # Advisory-locked background purger
│   ├── app.ts                      # Express app configuration & middleware
│   └── server.ts                   # HTTP listener & graceful shutdown
├── tests/
│   ├── unit/
│   │   ├── crypto.test.ts
│   │   └── schemas.test.ts
│   ├── integration/
│   │   ├── health.test.ts
│   │   ├── secrets.create.test.ts
│   │   ├── secrets.status.test.ts
│   │   ├── secrets.consume.test.ts
│   │   ├── secrets.revoke.test.ts
│   │   └── cleanup.test.ts
│   └── concurrency/
│       └── secrets.consume-race.test.ts
├── drizzle.config.ts
├── vitest.config.ts
├── tsconfig.json
└── package.json
```

---

### 4.2 Database Schema Outline (Drizzle ORM)

```typescript
import { pgTable, uuid, text, integer, timestamp, index, uniqueIndex, customType } from 'drizzle-orm/pg-core';

// Custom BYTEA type for raw SHA-256 binary digests
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return 'bytea';
  },
  toDriver(val: Buffer): Buffer {
    return val;
  },
  fromDriver(val: Buffer): Buffer {
    return val;
  },
});

export const secrets = pgTable(
  'secrets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tokenHash: bytea('token_hash').notNull(),
    revokeTokenHash: bytea('revoke_token_hash').notNull(),
    ciphertext: text('ciphertext'), // nullable upon zeroization
    iv: text('iv'),                 // nullable upon zeroization
    payloadVersion: integer('payload_version').notNull().default(1),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    maxViews: integer('max_views').notNull().default(1),
  },
  (table) => ({
    tokenHashIdx: uniqueIndex('secrets_token_hash_idx').on(table.tokenHash),
    expiresAtIdx: index('secrets_expires_at_idx').on(table.expiresAt),
    cleanupIdx: index('secrets_cleanup_idx').on(table.consumedAt, table.revokedAt, table.expiresAt),
  })
);
```

---

### 4.3 Confirmation of Implementation Phases

* **Phase 1: Analysis, Threat Model & Decisions** *(Current Phase)*
* **Phase 2: Foundation**
  * Node.js LTS, TypeScript strict mode, Express, pinned secure dependencies.
  * Zod environment config (`env.ts`).
  * Pino safe logger (redacted, route templates).
  * Request ID middleware, Security headers (Helmet), Cache-Control, Rate limiting.
  * Central error handler and Zod validation middleware.
  * Health check endpoint (`GET /api/v1/health`).
  * Vitest + Supertest testing harness.
* **Phase 3: Database & Repositories**
  * PostgreSQL connection pool via `pg`.
  * Drizzle ORM schema, migration scripts, rollback strategy.
  * Secrets repository with parameterized queries.
  * Database integration tests.
* **Phase 4: Create & Status Endpoints**
  * Zod validation schemas for `POST /api/v1/secrets` and `GET /api/v1/secrets/:token/status`.
  * SHA-256 token hashing service.
  * Service layer logic for creation and status checking.
  * Comprehensive unit and integration test suite.
* **Phase 5: Consume, Revoke & Cleanup**
  * Single atomic conditional `UPDATE` consumption logic (`POST /api/v1/secrets/:token/consume`).
  * Revocation endpoint with Bearer token authentication (`DELETE /api/v1/secrets/:token`).
  * Immediate zeroization of ciphertext and IV.
  * Scheduled cleanup job with PostgreSQL advisory locks.
  * Concurrency race condition tests (two simultaneous consumes, asserting exactly one succeeds).
* **Phase 6: Optional Accounts (FR-16)**
  * Contract proposal and review before implementation.
  * User authentication schema and repository.
  * Metadata listing and authenticated revocation.
* **Phase 7: Security Audit, Docker & Documentation**
  * Verification against all 7 Non-Negotiable Invariants and OWASP Top 10.
  * Multi-stage Dockerfile and docker-compose.
  * API documentation and test coverage reports.
