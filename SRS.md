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
    expired, consumed, or revoked tokens to reduce information leakage.

# 4. Functional requirements

  -----------------------------------------------------------------------
  ID                      Requirement             Description
  ----------------------- ----------------------- -----------------------
  FR-01                   Create secret           The creator can submit
                                                  non-empty text up to
                                                  the configured limit
                                                  and select an expiry
                                                  duration.

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
                                                  token digest,
                                                  ciphertext, nonce/IV,
                                                  timestamps, expiry, and
                                                  state metadata.

  FR-05                   Preview availability    The recipient can
                                                  request non-sensitive
                                                  availability metadata
                                                  without receiving
                                                  ciphertext.

  FR-06                   Consume secret          The recipient can make
                                                  a consume request. The
                                                  server atomically
                                                  claims a valid secret
                                                  and returns ciphertext
                                                  at most once.

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

# 7. Data requirements

## 7.1 Secret records

  -----------------------------------------------------------------------
  Field                   Type                    Rules / notes
  ----------------------- ----------------------- -----------------------
  id                      UUID                    Primary key

  tokenHash               CHAR(64) or BYTEA       Unique SHA-256 digest
                                                  of raw token; never
                                                  store raw token

  ciphertext              BYTEA or TEXT base64url Encrypted payload only

  iv                      BYTEA or TEXT           AES-GCM 12-byte IV

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

-   A secret is available only if not expired, not revoked, and not
    consumed.

-   Successful consume transitions the record to consumed in the same
    transaction that returns the ciphertext.

-   A cleanup task deletes expired/consumed/revoked ciphertext after a
    short configured retention period (e.g. 24 hours), unless the
    project policy requires immediate deletion.

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

-   No secret plaintext, encryption key, raw share token, or passphrase
    may appear in application logs, analytics, error trackers, or
    database records.

-   Creation response returns the share URL only once; the server should
    not reconstruct or persist the complete URL.

# 9. API overview

  -----------------------------------------------------------------------------
  Method         Path                             Purpose        Auth
  -------------- -------------------------------- -------------- --------------
  GET            /api/v1/health                   Health check   Public

  POST           /api/v1/secrets                  Create secret  Public with
                                                  record from    rate limit
                                                  ciphertext     

  GET            /api/v1/secrets/:token/status    Check whether  Public with
                                                  token is       rate limit
                                                  available      

  POST           /api/v1/secrets/:token/consume   Atomically     Public with
                                                  consume and    rate limit
                                                  return         
                                                  ciphertext     

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

13. Expired and revoked secrets cannot be consumed.

14. Malformed requests return structured 4xx responses and do not crash
    the server.

15. The application applies rate limits, HTTPS in deployment, safe
    headers, CORS restrictions, and payload-size limits.

16. Automated tests cover valid retrieval, expired retrieval, consumed
    retrieval, invalid token, concurrent consume, invalid payload, and
    crypto tampering.

17. Logs and error reports do not include secret content, keys, raw
    tokens, or request bodies.

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
