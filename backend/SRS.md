*Version 1.0 \| Node.js, Express, TypeScript, Drizzle ORM, PostgreSQL*

# Document control

  ---------------------------------------------------------------------
  Field                              Value
  ---------------------------------- ----------------------------------
  Project name                       share-shield --- One-time Secret
                                     Sharing Vault

  Document                           Software Requirements
                                     Specification (SRS)

  Version / status                   1.0 / Initial baseline for
                                     implementation

  Audience                           Developer, reviewer, tester,
                                     project supervisor

  Target release                     MVP suitable for a
                                     learning/portfolio project
  ---------------------------------------------------------------------

# 1. Introduction

## 1.1 Purpose

This document defines the functional, non-functional, security, data,
and operational requirements for share-shield, a web application that allows
a person to share a sensitive text secret through a time-limited link. A
secret can be configured for one successful retrieval, an expiry time,
and an optional passphrase in a later iteration.

## 1.2 Product scope

share-shield is not a general password manager. Its primary job is temporary
transfer of sensitive text such as temporary credentials, API keys,
recovery codes, or private notes. The MVP focuses on text secrets, short
expiry windows, one-time retrieval, and a minimal owner dashboard. File
uploads, team vaults, browser extensions, and enterprise identity are
out of scope.

## 1.3 Definitions

  ---------------------------------------------------------------------
  Term                               Definition
  ---------------------------------- ----------------------------------
  Secret                             Sensitive text the creator wants
                                     to share temporarily.

  Share token                        Cryptographically random bearer
                                     token used to locate a secret.

  Token hash                         One-way digest stored by the API
                                     instead of the raw share token.

  Ciphertext                         Encrypted secret payload stored by
                                     the service.

  One-time retrieval                 At most one request successfully
                                     claims the secret payload.

  Client-side encryption             Browser encrypts/decrypts content;
                                     the server stores ciphertext and
                                     does not receive the decryption
                                     key.

  Passkey                            Server-generated 6-digit numeric
                                     access code shared out-of-band to
                                     gate release of ciphertext.

  MVP                                Minimum viable product described
                                     in this specification.
  ---------------------------------------------------------------------

# 2. Product overview

## 2.1 Product perspective

share-shield consists of a browser frontend, a REST API, PostgreSQL, and
optional Redis-based rate limiting. The browser creates a random secret
token and encryption key. The server receives the token only to hash it
for lookup and receives ciphertext rather than plaintext. The encryption
key is placed in the URL fragment (after #), which browsers do not send
in HTTP requests. The recipient's browser uses the fragment key to
decrypt the ciphertext after the server authorizes retrieval.

Important limitation: this design reduces the server's access to
plaintext, but does not protect a secret from a compromised browser,
malicious browser extension, compromised frontend assets, screenshots,
recipient copying, or an attacker who obtains both the complete link and
ciphertext before consumption.

## 2.2 User classes

-   Creator: creates a secret and shares the generated URL.

-   Recipient: opens the link and retrieves the secret if it remains
    available.

-   Operator/developer: configures deployment, monitors service health,
    and responds to faults; must not have a routine feature to read
    plaintext secrets.

## 2.3 Operating environment

-   Modern desktop and mobile browsers with Web Crypto API support.

-   Node.js LTS runtime with TypeScript and Express.

-   PostgreSQL database accessed through Drizzle ORM and node-postgres
    (pg).

-   HTTPS in deployed environments; local HTTP is acceptable only for
    localhost development.

-   Optional Redis for distributed rate limiting; MVP may use a rate
    limiter backed by Redis when deployed across multiple instances.

## 2.4 Recommended technology stack

  -----------------------------------------------------------------------
  Layer                   Technology              Purpose
  ----------------------- ----------------------- -----------------------
  Frontend                React + TypeScript +    Single-page user
                          Vite                    interface

  Styling                 Tailwind CSS            Responsive UI styling

  API                     Node.js + Express +     REST endpoints and
                          TypeScript              middleware

  Validation              Zod                     Validate request
                                                  bodies, params, and
                                                  environment variables

  Database                PostgreSQL              Users, secret metadata,
                                                  token digests,
                                                  ciphertext

  ORM/migrations          Drizzle ORM + Drizzle   Typed queries and
                          Kit                     versioned schema
                                                  migrations

  Database driver         pg                      PostgreSQL connection
                                                  pool

  Authentication          JWT in secure HttpOnly  Optional
                          cookie or server        account/dashboard
                          session                 authentication

  Security                Web Crypto API;         Client-side encryption
                          crypto.randomBytes on   and secure token
                          server; Argon2id or     generation
                          bcrypt for passwords    

  Rate limiting           express-rate-limit for  Reduce brute force and
                          local/single instance;  abuse
                          Redis store for         
                          multi-instance          

  Testing                 Vitest or Jest +        Unit and API
                          Supertest               integration tests

  Deployment              Docker; frontend static Repeatable deployment
                          hosting; Node API +     
                          managed PostgreSQL      
  -----------------------------------------------------------------------

# 3. System architecture

> Creator browser ── encrypt with Web Crypto ──\> ciphertext + token
> digest ──\> Express API ──\> PostgreSQL\
> │ │ │\
> └── share URL: /s/\<token\>#\<key\> └── stores no raw token/key\
> \
> Recipient browser ── GET metadata ──\> API\
> Recipient browser ── POST consume ──\> API (atomic one-time claim;
> returns ciphertext)\
> Recipient browser ── decrypt ciphertext locally using URL-fragment key

## 3.1 Architectural rules

-   The raw share token is never stored in the database; store
    SHA-256(token) as a lookup digest.

-   The encryption key is generated in the browser, never included in
    the API request, and never stored server-side.

-   The key must be in the URL fragment, not a query parameter or path
    segment.

-   The API must never log request bodies, ciphertext payloads, tokens,
    keys, or secret plaintext.

-   One-time consumption must be atomic in PostgreSQL so concurrent
    requests cannot both receive the payload.

-   The API should return generic unavailable responses for invalid,
    expired, consumed, revoked, or locked tokens to reduce information
    leakage, with the sole exception of active secrets where an incorrect
    passkey returns a 403 status with remaining attempts to the token holder.

-   The passkey acts strictly as an access gate (second-channel factor)
    and not as an encryption key; release of ciphertext is gated by server
    verification of the peppered passkey HMAC.

-   The passkey is generated server-side via a cryptographically secure
    random number generator, returned once to the creator, and never
    stored in plaintext. It is stored as an HMAC-SHA256 digest keyed with
    a high-entropy server pepper and bound to the token hash.

-   Passkey verification must strictly bound incorrect attempts (default 5).
    Upon reaching the limit, the secret is locked immediately and its
    ciphertext and IV are permanently wiped (zeroized).

# 4. Functional requirements

  -----------------------------------------------------------------------
  ID                      Requirement             Description
  ----------------------- ----------------------- -----------------------
  FR-01                   Create secret           The creator can submit
                                                  non-empty text up to
                                                  the configured limit
                                                  and select an expiry
                                                  duration. The API generates
                                                  a 6-digit passkey returned
                                                  only in the creation response.

  FR-01b                  Passkey generation      The API generates a
                                                  cryptographically secure
                                                  6-digit passkey (000000-999999),
                                                  stores only its peppered HMAC
                                                  digest, and returns the
                                                  plaintext passkey once.

  FR-02                   Encrypt in browser      The frontend encrypts
                                                  the secret with AES-GCM
                                                  using a
                                                  cryptographically
                                                  secure random key
                                                  before sending data to
                                                  the API.

  FR-03                   Generate share link     The frontend generates
                                                  a high-entropy random
                                                  token and constructs a
                                                  URL containing the
                                                  token in the path and
                                                  the decryption key in
                                                  the fragment.

  FR-04                   Store metadata          The API stores only a
                                                  token digest, passkey
                                                  digest, ciphertext, nonce/IV,
                                                  timestamps, expiry, and
                                                  state metadata.

  FR-05                   Preview availability    The recipient can
                                                  request non-sensitive
                                                  availability metadata
                                                  including passkeyRequired
                                                  without receiving
                                                  ciphertext.

  FR-06                   Consume secret          The recipient submits
                                                  the 6-digit passkey.
                                                  The server atomically
                                                  verifies the passkey, claims
                                                  a valid secret, and returns
                                                  ciphertext at most once.

  FR-06b                  Passkey attempt limits  The server tracks failed
                                                  passkey attempts. Each
                                                  invalid attempt decrements
                                                  remaining attempts and
                                                  returns HTTP 403. When the
                                                  limit is reached, the secret
                                                  is permanently locked and
                                                  ciphertext is zeroized.

  FR-07                   Decrypt locally         The recipient browser
                                                  decrypts the returned
                                                  ciphertext locally
                                                  using the key from the
                                                  fragment and displays
                                                  the plaintext.

  FR-08                   Expiry                  Secrets whose expiresAt
                                                  is at or before current
                                                  server time cannot be
                                                  consumed.

  FR-08b                  Lockout invalidation    Locked secrets are
                                                  permanently unavailable
                                                  and return uniform 404
                                                  on subsequent attempts.

  FR-09                   Manual revoke           A creator can revoke a
                                                  secret using a
                                                  creator-only revoke
                                                  token retained locally;
                                                  account-based
                                                  management may be added
                                                  later.

  FR-10                   Copy link               The UI provides a
                                                  copy-link action and
                                                  explains that anyone
                                                  with the full link may
                                                  be able to access the
                                                  secret.

  FR-11                   Error states            The UI handles invalid,
                                                  expired, already
                                                  consumed, revoked,
                                                  malformed, and
                                                  network-failure states
                                                  without revealing
                                                  unnecessary details.

  FR-12                   Health check            The API exposes a
                                                  health endpoint that
                                                  reports service health
                                                  without exposing
                                                  credentials or
                                                  infrastructure secrets.

  FR-13                   Input validation        All API inputs are
                                                  validated server-side
                                                  using schemas; frontend
                                                  validation is only a
                                                  usability aid.

  FR-14                   Rate limiting           The API applies rate
                                                  limits to create,
                                                  availability, consume,
                                                  and authentication
                                                  endpoints.

  FR-15                   Audit-safe logs         The service logs
                                                  request IDs, route,
                                                  status, latency, and
                                                  coarse error codes, but
                                                  never secret content or
                                                  bearer tokens.

  FR-16                   Account dashboard       Authenticated users can
                          (optional MVP           view their own secret
                          extension)              metadata and revoke
                                                  secrets, but never
                                                  retrieve plaintext from
                                                  the dashboard.
  -----------------------------------------------------------------------

# 5. Non-functional requirements

  ---------------------------------------------------------------------
  ID                                 Requirement
  ---------------------------------- ----------------------------------
  NFR-01 Security                    Use HTTPS in production, secure
                                     headers, strict CORS allow-list,
                                     input validation, parameterized
                                     ORM queries, and secrets in
                                     environment/secret manager.

  NFR-02 Confidentiality             Secret plaintext and decryption
                                     keys must not be sent to or stored
                                     by the API in the client-side
                                     encryption design.

  NFR-03 Integrity                   Use AES-GCM authenticated
                                     encryption; reject decryption if
                                     authentication fails.

  NFR-04 One-time guarantee          Concurrent consume requests must
                                     result in no more than one
                                     successful payload response.

  NFR-05 Availability                For the MVP, target 99%
                                     availability during a demo period;
                                     production SLOs require real
                                     monitoring and hosting
                                     commitments.

  NFR-06 Performance                 Typical metadata and consume
                                     requests should complete within
                                     500 ms at low load, excluding
                                     network latency and client
                                     decryption.

  NFR-07 Usability                   A first-time user should be able
                                     to create and copy a secret link
                                     without documentation.

  NFR-08 Compatibility               Support current stable Chrome,
                                     Firefox, and Chromium-based
                                     browsers with Web Crypto API.

  NFR-09 Maintainability             Use controller/service/repository
                                     separation, TypeScript strict
                                     mode, linting, tests, and
                                     migration files.

  NFR-10 Data minimization           Collect no recipient account data
                                     by default; avoid IP retention
                                     unless operationally necessary and
                                     disclosed.

  NFR-11 Accessibility               Keyboard-operable controls,
                                     visible focus, labels, and status
                                     messages understandable by screen
                                     readers.

  NFR-12 Recovery                    Expired/consumed records can be
                                     purged by scheduled cleanup;
                                     backups and retention policies
                                     must be documented.
  ---------------------------------------------------------------------

# 6. Security requirements and threat model

## 6.1 Threats to address

-   Token guessing: use at least 256 bits of cryptographically secure
    randomness and apply rate limiting.

-   Database leak: store only token hashes and ciphertext; keep
    decryption keys out of the database.

-   Replay/concurrent consumption: claim the secret in a transaction
    with a row lock or a single conditional UPDATE \... RETURNING
    statement.

-   Cross-site scripting: apply CSP and output escaping; never inject
    decrypted text as HTML.

-   Link leakage: use Referrer-Policy: no-referrer, avoid third-party
    scripts on secret pages, and warn users not to share the complete
    URL publicly.

-   Logging leakage: redact Authorization, Cookie, token path segments,
    request bodies, and query strings from logs.

-   Brute-force and denial of service: rate limit and cap payload size;
    add abuse monitoring.

-   Compromised client: explicitly state that client-side encryption
    does not protect against compromised endpoints or malicious frontend
    code.

## 6.2 Cryptographic design

1.  Generate a 32-byte AES key with crypto.getRandomValues in the
    browser.

2.  Generate a unique 12-byte IV for each AES-GCM encryption.

3.  Encrypt UTF-8 plaintext using Web Crypto AES-GCM; store the
    ciphertext (including authentication tag as returned by Web Crypto)
    and IV.

4.  Generate a 32-byte random share token. Encode it using base64url
    without padding.

5.  Send the token to the API only over HTTPS so the API can compute
    SHA-256(token) and store that digest. Do not log the raw token.

6.  Construct the share URL as
    https://host/s/\<token\>#\<base64url-key\>. URL fragments are not
    sent in HTTP requests.

7.  On retrieval, the API atomically marks the record consumed and
    returns ciphertext and IV. The browser reads the key from the
    fragment and decrypts locally.

8.  Immediately remove the fragment from the visible address bar after
    reading it where feasible, while retaining the key in memory for the
    current reveal flow. Warn users that browser history, clipboard
    managers, extensions, and screenshots may still expose links.

This design is educational and should be reviewed before handling
high-value production secrets. A one-time link cannot prevent a
recipient from copying the plaintext after reveal.

## 6.3 Password protection decision

Do not implement a server-side password hash as if it encrypted the
secret. For a later password-protected mode, derive a key in the browser
from a user passphrase using a suitable password-based KDF (for example
PBKDF2 via Web Crypto with a strong iteration count, or a reviewed
Argon2 implementation), then encrypt client-side. Never send the
passphrase to the API. Carefully version the encryption metadata and
test compatibility.

## 6.4 Passkey protection and threat analysis

### 6.4.1 Architectural Role: Access Gate vs. Encryption
The 6-digit passkey is strictly an **access gate** evaluated by the server
prior to releasing the ciphertext; it is **not** an encryption key. The secret
plaintext remains protected by client-side AES-256-GCM using the key in the
URL fragment. The passkey enables two-channel security:
- Channel 1 (e.g., email, messaging): carries the share link `/s/<token>#<key>`.
- Channel 2 (e.g., SMS, phone call, Signal, in-person): carries the 6-digit passkey.
An attacker intercepting Channel 1 possesses the URL fragment key and token,
but cannot obtain the ciphertext without the passkey.

### 6.4.2 Threat Analysis & Mitigations

1.  **Online Guessing (Brute Force):**
    A 6-digit numeric passkey has only 1,000,000 possibilities ($10^6$).
    Without strict bounding, an attacker holding the token could guess it
    in minutes.
    *Mitigation:* The server strictly limits incorrect attempts via
    `PASSKEY_MAX_ATTEMPTS` (default 5, configurable between 3 and 10).
    Failed attempts are tracked atomically in PostgreSQL across all IP
    addresses. Upon reaching the limit, the secret is locked (`lockedAt = NOW()`),
    and its ciphertext and IV are permanently wiped. With at most 5 attempts,
    an online attacker's probability of success is at most $5 / 1,000,000 = 0.0005\%$.
    Additionally, standard per-IP rate limiting (15 req/min) prevents fast
    bursts.

2.  **Database Leak (Without Pepper):**
    If an attacker acquires a database dump, a 6-digit keyspace without a
    secret key can be precomputed or searched in fractions of a second
    ($10^6$ SHA-256 operations takes $< 10\text{ ms}$).
    *Mitigation:* Passkeys are stored as `HMAC-SHA256(key = PASSKEY_PEPPER, data = tokenHash || ":" || passkey)`.
    `PASSKEY_PEPPER` is a high-entropy server secret ($\ge 32$ random bytes)
    held exclusively in environment variables and never written to the
    database. Without the pepper, the attacker cannot verify candidate
    passkeys against the stored hashes.

3.  **Pepper Leak:**
    If both the database dump and the `PASSKEY_PEPPER` are compromised,
    an attacker could brute-force the 6-digit passkey for active rows.
    *Mitigation:* The passkey is bound to the unique `tokenHash` (`tokenHash || ":" || passkey`),
    preventing global precomputed rainbow tables across secrets. More
    importantly, client-side encryption remains intact: even if the passkey
    hash is inverted, the attacker still cannot decrypt the ciphertext without
    the AES-GCM key stored exclusively in the creator/recipient URL fragments.
    Immediate zeroization on consumption/revocation/lockout further limits
    exposure to only active, unclaimed rows.

4.  **Existence Oracle & Departure from Uniform Response:**
    For general requests, the API returns a uniform 404 `SECRET_UNAVAILABLE`.
    However, when an available secret is targeted with an incorrect passkey,
    the endpoint returns HTTP 403 `PASSKEY_INVALID` along with `attemptsRemaining`.
    *Justification & Security Model:* To trigger this 403 response, the
    caller must already possess the full, cryptographically random 256-bit
    share token (`token`). Because $2^{256}$ prevents blind token guessing,
    the caller already knows the secret exists (they can also query `GET /status`).
    Returning 403 with `attemptsRemaining` provides essential usability for
    legitimate recipients who mistype a digit, informing them how many tries
    remain before the secret is destroyed, without providing any advantage to
    an attacker who lacks the token. Unrecognized tokens, expired secrets,
    or already locked/consumed secrets still produce uniform 404 responses.

5.  **Lockout Denial of Service (DoS):**
    Any person possessing the share link can intentionally submit 5 incorrect
    passkeys to burn the secret, preventing the legitimate recipient from
    accessing it.
    *Acceptable Security Trade-off:* This is an inherent, mathematically
    unavoidable property of short-passcode attempt bounding. Priority is
    given to **confidentiality over availability**: an attacker who intercepted
    the link cannot read the secret, and burning the secret alerts the creator
    and recipient that communication was compromised. Creators are instructed
    to transmit links only over reasonably confidential channels.

6.  **Timing Side-Channels:**
    Discrepancies in response times could potentially reveal valid tokens
    or passkey comparison progress.
    *Mitigation:* The candidate HMAC is computed unconditionally prior to
    database lookup or evaluation. Hash comparisons utilize timing-safe
    constructs or strict equality over fixed-length 32-byte digests.
    Database queries operate on single indexed lookups with consistent
    row-locking paths.

7.  **Logging and Telemetry Leakage:**
    Raw passkeys in request/response bodies or query logs would defeat
    the access gate.
    *Mitigation:* Passkeys are strictly prohibited from logs. The logger
    redaction filter includes `passkey` alongside tokens, keys, and
    ciphertext. Passkeys are passed exclusively in JSON request/response
    bodies over TLS, never in URLs.

# 7. Data requirements

## 7.1 Secret records

  -----------------------------------------------------------------------
  Field                   Type                    Rules / notes
  ----------------------- ----------------------- -----------------------
  id                      UUID                    Primary key

  tokenHash               CHAR(64) or BYTEA       Unique SHA-256 digest
                                                  of raw token; never
                                                  store raw token

  revokeTokenHash         BYTEA                   SHA-256 digest of
                                                  creator revoke token

  passkeyHash             BYTEA                   32-byte HMAC-SHA256
                                                  digest with pepper;
                                                  CHECK length = 32

  failedAttempts          INTEGER                 Default 0; tracks wrong
                                                  guesses; CHECK >= 0

  lockedAt                TIMESTAMPTZ nullable    Set when failed attempts
                                                  reach maximum threshold

  ciphertext              BYTEA or TEXT base64url Encrypted payload only;
                                                  zeroized on consume,
                                                  revoke, or lockout

  iv                      BYTEA or TEXT           AES-GCM 12-byte IV;
                                                  zeroized on consume,
                                                  revoke, or lockout

  expiresAt               TIMESTAMPTZ             Required; server checks
                                                  at consume time

  createdAt               TIMESTAMPTZ             Server generated

  consumedAt              TIMESTAMPTZ nullable    Set atomically on
                                                  successful consume

  revokedAt               TIMESTAMPTZ nullable    Set by creator revoke
                                                  capability

  maxViews                INTEGER                 MVP default 1; keep
                                                  simple and enforce
                                                  one-time behavior

  payloadVersion          INTEGER                 Allows future crypto
                                                  format migrations
  -----------------------------------------------------------------------

## 7.2 Optional creator account tables

  -----------------------------------------------------------------------
  Table                   Key fields              Purpose
  ----------------------- ----------------------- -----------------------
  users                   id, email,              Optional account-based
                          passwordHash, createdAt dashboard

  secret_ownership        secretId, userId,       Ownership and
                          revokeTokenHash         revocation; only
                                                  metadata exposed
  -----------------------------------------------------------------------

## 7.3 Data lifecycle

-   A secret is available only if not expired, not revoked, not consumed,
    and not locked.

-   Successful consume transitions the record to consumed in the same
    atomic transaction that returns the ciphertext, immediately wiping
    ciphertext and IV.

-   Exceeding the maximum allowed passkey attempts immediately transitions
    the record to locked (`lockedAt = NOW()`), wiping ciphertext and IV.

-   A cleanup task deletes expired/consumed/revoked/locked records after
    the configured retention period.

-   Backups may retain deleted database pages until backup expiration;
    disclose this limitation and set backup retention deliberately.

# 8. Business rules

-   Default expiry: 1 hour; allowed MVP choices: 10 minutes, 1 hour, 24
    hours, and 7 days.

-   Maximum plaintext size: 10 KiB for MVP (configure consistently in
    frontend and API).

-   No file uploads in MVP.

-   A successful consume returns ciphertext once; any subsequent consume
    returns a generic 404/410-style unavailable response.

-   Expiry is evaluated using server time, not client time.

-   Passkey generation is mandatory for all secrets: server generates a
    random 6-digit numeric string (000000-999999) using CSPRNG and returns it
    once in the creation response.

-   Passkeys are stored exclusively as `HMAC-SHA256(PASSKEY_PEPPER, tokenHash || ":" || passkey)`.
    Neither raw passkeys nor the pepper are ever stored in the database.

-   Passkey attempts are bounded by `PASSKEY_MAX_ATTEMPTS` (default 5,
    configurable 3-10). Incorrect attempts on an active secret return HTTP 403
    `PASSKEY_INVALID` with remaining attempts. When attempts are exhausted,
    the secret transitions to locked (`lockedAt = NOW()`), and `ciphertext` and
    `iv` are wiped immediately.

-   No secret plaintext, encryption key, raw share token, passkey, or
    pepper may appear in application logs, analytics, error trackers, or
    database records.

-   Creation response returns the share URL and passkey only once; the
    server should not reconstruct or persist the complete URL.

# 9. API overview

  -----------------------------------------------------------------------------
  Method         Path                             Purpose        Auth
  -------------- -------------------------------- -------------- --------------
  GET            /api/v1/health                   Health check   Public

  POST           /api/v1/secrets                  Create secret  Public with
                                                  record; return rate limit
                                                  passkey once   

  GET            /api/v1/secrets/:token/status    Check whether  Public with
                                                  token is       rate limit
                                                  available &    
                                                  requires       
                                                  passkey        

  POST           /api/v1/secrets/:token/consume   Verify passkey Public with
                                                  and atomically rate limit
                                                  claim payload  

  DELETE         /api/v1/secrets/:token           Revoke secret  Revoke token
                                                  using separate required
                                                  revoke         
                                                  capability     
  -----------------------------------------------------------------------------

# 10. Acceptance criteria

9.  A creator can enter text and generate a link that contains a random
    token and client-side decryption key.

10. The API database contains ciphertext and token digest, not
    plaintext, raw token, or encryption key.

11. A recipient with a valid link can retrieve ciphertext once and
    decrypt it in the browser.

12. A second or concurrent consume attempt cannot retrieve the
    ciphertext again.

13. Expired, revoked, and locked secrets cannot be consumed.

14. Malformed requests return structured 4xx responses and do not crash
    the server.

15. The application applies rate limits, HTTPS in deployment, safe
    headers, CORS restrictions, and payload-size limits.

16. Automated tests cover valid retrieval, expired retrieval, consumed
    retrieval, invalid token, concurrent consume, invalid payload, and
    crypto tampering.

17. Logs and error reports do not include secret content, keys, raw
    tokens, passkeys, or request bodies.

18. The API generates a random 6-digit passkey on secret creation, returns
    it once in the response, and stores only its peppered HMAC digest.

19. A consume request requires the correct 6-digit passkey; incorrect
    guesses decrement remaining attempts and return HTTP 403 with attempts remaining.

20. Reaching the maximum failed passkey attempts permanently locks the
    secret, wipes ciphertext and IV, and returns 404 to all future requests.

# 11. Testing strategy

-   Unit tests: token generation/digest, expiry predicate, Zod schemas,
    crypto encode/decode helpers.

-   Integration tests: create, status, consume, revoke, expiry, and
    database transaction behavior using a test PostgreSQL database.

-   Concurrency test: send two consume requests simultaneously and
    assert exactly one succeeds.

-   Security tests: malformed UUID/token, oversized payload, SQL
    injection-shaped strings, CORS rejection, rate limit, and token/key
    redaction.

-   Frontend tests: encryption/decryption round trip, wrong key,
    tampered ciphertext, missing fragment, and error-state rendering.

-   Manual acceptance test: create a link in one browser profile, open
    it in another, reveal once, then verify it cannot be opened again.

# 12. Delivery plan (7 days)

  ---------------------------------------------------------------------
  Day                                Deliverable
  ---------------------------------- ----------------------------------
  1                                  Repository, TypeScript/Express
                                     setup, PostgreSQL, Drizzle schema
                                     and migrations

  2                                  Create/status endpoints, Zod
                                     validation, token hashing, expiry
                                     rules

  3                                  Browser Web Crypto
                                     encryption/decryption and
                                     share-link flow

  4                                  Atomic consume endpoint, revoke
                                     capability, cleanup policy

  5                                  React pages, responsive UI,
                                     loading/error states

  6                                  Security headers, rate limiting,
                                     tests, logging redaction

  7                                  Docker/deployment, README, API
                                     examples, demo and final review
  ---------------------------------------------------------------------

# 13. Out of scope / future work

-   File uploads and large binary secrets.

-   Multi-recipient secrets and view-counts greater than one.

-   Enterprise SSO, organizations, billing, admin console.

-   Browser extension and mobile applications.

-   Email delivery of secret links.

-   Formal security audit or certification.

-   Guaranteeing that a recipient cannot copy or photograph revealed
    plaintext.

# 14. Official technical references

Drizzle ORM PostgreSQL setup:
https://orm.drizzle.team/docs/get-started/postgresql-new

Drizzle migrations: https://orm.drizzle.team/docs/migrations

Web Crypto API:
https://developer.mozilla.org/docs/Web/API/Web_Crypto_API

Node.js crypto: https://nodejs.org/api/crypto.html

Express production security:
https://expressjs.com/en/advanced/best-practice-security.html
