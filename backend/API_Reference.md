*Version 1.0 \| REST API v1 \| JSON over HTTPS*

# 1. Conventions

-   Base URL: https://api.example.com/api/v1 (replace with your deployed
    URL).

-   Content-Type: application/json; charset=utf-8.

-   All timestamps are ISO 8601 UTC strings.

-   The API stores ciphertext only. Encryption and decryption happen in
    the browser.

-   The share URL is assembled by the frontend as /s/{token}#{key}; the
    key fragment must never be sent to the API.

-   Use TLS in deployed environments. Never log tokens, ciphertext
    bodies, keys, or secret plaintext.

-   The API version is included in the path to make future changes
    explicit.

# 2. Standard response shapes

## 2.1 Success

> {\
> \"data\": { \"\...\": \"\...\" },\
> \"requestId\": \"req_01J\...\"\
> }

## 2.2 Error

> {\
> \"error\": {\
> \"code\": \"SECRET_UNAVAILABLE\",\
> \"message\": \"This secret is unavailable.\",\
> \"requestId\": \"req_01J\...\"\
> }\
> }

Do not return stack traces, database errors, token digests, raw tokens,
or secret contents in error responses.

# 3. Endpoints summary

  -----------------------------------------------------------------------------
  Method          Endpoint                   Success         Purpose
  --------------- -------------------------- --------------- ------------------
  GET             /health                    200             Health/readiness
                                                             response

  POST            /secrets                   201             Create a
                                                             ciphertext record

  GET             /secrets/{token}/status    200             Return
                                                             availability only

  POST            /secrets/{token}/consume   200             Atomically claim
                                                             and return
                                                             ciphertext once

  DELETE          /secrets/{token}           204             Revoke using a
                                                             separate revoke
                                                             capability
  -----------------------------------------------------------------------------

# 4. GET /health

Purpose: basic health check for a load balancer or developer. Keep the
output minimal.

Response 200:

> {\
> \"data\": {\
> \"status\": \"ok\"\
> },\
> \"requestId\": \"req_abc123\"\
> }

Do not expose environment variables, database URLs, internal hostnames,
or dependency credentials.

# 5. POST /secrets

Purpose: store encrypted content and return a generated token once. The
frontend encrypts plaintext first and generates the token locally.

Request body:

> {\
> \"token\": \"\<base64url-encoded 32-byte random token\>\",\
> \"ciphertext\": \"\<base64url-encoded AES-GCM ciphertext\>\",\
> \"iv\": \"\<base64url-encoded 12-byte IV\>\",\
> \"expiresInSeconds\": 3600,\
> \"payloadVersion\": 1\
> }

Validation:

-   token must decode to exactly 32 random bytes; API hashes the raw
    decoded bytes with SHA-256 and stores only the digest.

-   ciphertext must be non-empty, valid base64url, and within the
    configured request limit.

-   iv must decode to exactly 12 bytes.

-   expiresInSeconds must be one of 600, 3600, 86400, or 604800.

-   payloadVersion must equal a supported version (initially 1).

-   Reject unknown fields or define an explicit policy for them; do not
    silently accept malformed crypto metadata.

Response 201:

> {\
> \"data\": {\
> \"created\": true,\
> \"expiresAt\": \"2026-10-09T12:23:00.000Z\",\
> \"sharePath\": \"/s/\<token\>\"\
> },\
> \"requestId\": \"req_abc123\"\
> }

Implementation note: returning the token in the response is unnecessary
if the browser already generated it. Returning sharePath is optional;
the browser should assemble the full URL and append #\<key\> locally.
Never return or persist the key.

Errors: 400 VALIDATION_ERROR; 413 PAYLOAD_TOO_LARGE; 429 RATE_LIMITED;
500 INTERNAL_ERROR.

# 6. GET /secrets/{token}/status

Purpose: show a generic availability state without returning ciphertext
or sensitive metadata.

Response 200:

> {\
> \"data\": {\
> \"available\": true,\
> \"expiresAt\": \"2026-10-09T12:23:00.000Z\"\
> },\
> \"requestId\": \"req_abc123\"\
> }

For invalid, expired, consumed, or revoked tokens, return a generic
response such as 404 SECRET_UNAVAILABLE. Avoid distinguishing the reason
to an unauthenticated caller.

# 7. POST /secrets/{token}/consume

Purpose: atomically mark a secret as consumed and return its ciphertext
and IV. This endpoint must be designed for at-most-once retrieval.

Request body: empty JSON object or no body.

Response 200:

> {\
> \"data\": {\
> \"ciphertext\": \"\<base64url-encoded AES-GCM ciphertext\>\",\
> \"iv\": \"\<base64url-encoded 12-byte IV\>\",\
> \"payloadVersion\": 1\
> },\
> \"requestId\": \"req_abc123\"\
> }

The browser decrypts locally using the key extracted from the URL
fragment. The fragment is never sent with this request.

Errors: 404 SECRET_UNAVAILABLE; 429 RATE_LIMITED; 500 INTERNAL_ERROR.

## 7.1 Required atomic behavior

Use a single transaction. One possible approach is SELECT \... FOR
UPDATE, validate expiry/revocation/consumption, set consumed_at, and
return the ciphertext before committing. Alternatively use a carefully
designed conditional UPDATE \... RETURNING statement. A plain read
followed by a separate update is not sufficient because two requests can
race.

> BEGIN;\
> SELECT id, ciphertext, iv, expires_at, consumed_at, revoked_at\
> FROM secrets\
> WHERE token_hash = \$1\
> FOR UPDATE;\
> \-- if missing, expired, consumed, or revoked: ROLLBACK and return
> generic 404\
> UPDATE secrets SET consumed_at = NOW() WHERE id = \$2;\
> COMMIT;\
> \-- return ciphertext and iv only to the request that successfully
> claimed it

Implementation note: decide whether commit happens before response. It
should: if the client disconnects after commit, the secret may be
consumed without being seen. This is a deliberate security/usability
trade-off for one-time semantics.

# 8. DELETE /secrets/{token}

Purpose: revoke a secret before it is opened. Because the share token is
public to anyone holding the link, do not use it alone as the revoke
credential.

Headers:

> Authorization: Bearer \<creator-revoke-token\>

The creator-revoke-token is a separate high-entropy random capability
generated at creation; store only its digest. Do not put it in the
public share URL. For an account-based version, authorize via the
authenticated owner instead.

Response 204: no response body.

Errors: 401/403 REVOKE_NOT_AUTHORIZED; 404 SECRET_UNAVAILABLE; 429
RATE_LIMITED.

# 9. Token and cryptographic format

-   Generate share token with crypto.getRandomValues(new Uint8Array(32))
    in the browser; encode base64url without padding.

-   Generate AES key with crypto.subtle.generateKey({ name: \'AES-GCM\',
    length: 256 }, true, \[\'encrypt\', \'decrypt\'\]) or import a
    32-byte random key, according to the chosen export/import flow.

-   Use a fresh 12-byte IV for each encryption. Never reuse an IV with
    the same AES-GCM key.

-   Store tokenHash = SHA-256(raw token bytes) in PostgreSQL; choose a
    consistent encoding (e.g. BYTEA or lowercase hex CHAR(64)).

-   Share URL: https://app.example.com/s/{token}#{keyBase64Url}.
    Fragment content is client-side only and is not sent in HTTP
    requests.

-   When the page loads, read the fragment, validate its format, and
    remove it from the visible address bar with history.replaceState
    where practical. Keep key only in memory for the reveal flow.

-   Avoid analytics, third-party scripts, external fonts, and embedded
    content on the secret reveal page where possible.

# 10. Suggested database schema

> secrets\
> \-\-\-\-\-\--\
> id UUID PRIMARY KEY\
> token_hash BYTEA UNIQUE NOT NULL\
> ciphertext BYTEA NOT NULL\
> iv BYTEA NOT NULL\
> payload_version INTEGER NOT NULL DEFAULT 1\
> expires_at TIMESTAMPTZ NOT NULL\
> created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
> consumed_at TIMESTAMPTZ NULL\
> revoked_at TIMESTAMPTZ NULL\
> revoke_token_hash BYTEA NULL

Recommended indexes: unique index on token_hash; index on expires_at for
cleanup; optionally index on (consumed_at, expires_at) if query patterns
justify it.

# 11. Status and error codes

  -----------------------------------------------------------------------
  HTTP                   Code                     Meaning
  ---------------------- ------------------------ -----------------------
  400                    VALIDATION_ERROR         Request body, token, or
                                                  parameter is malformed

  401                    UNAUTHENTICATED          Authentication required
                                                  for a protected feature

  403                    REVOKE_NOT_AUTHORIZED    Revoke capability is
                                                  invalid or absent

  404                    SECRET_UNAVAILABLE       Secret does not exist,
                                                  expired, consumed, or
                                                  revoked

  413                    PAYLOAD_TOO_LARGE        Request exceeds payload
                                                  limit

  415                    UNSUPPORTED_MEDIA_TYPE   Request is not JSON
                                                  where JSON is required

  429                    RATE_LIMITED             Rate limit exceeded;
                                                  may include Retry-After

  500                    INTERNAL_ERROR           Unexpected server error
  -----------------------------------------------------------------------

# 12. Security and HTTP behavior

-   Use HTTPS and HSTS in production.

-   Set Content-Security-Policy, X-Content-Type-Options: nosniff,
    Referrer-Policy: no-referrer, and a suitable Permissions-Policy.

-   Set Cache-Control: no-store on status/consume responses and secret
    pages.

-   Use strict CORS with the exact frontend origin; never combine
    wildcard origin with credentials.

-   Set express.json({ limit: \'16kb\' }) or a carefully chosen limit
    consistent with ciphertext overhead.

-   Apply route-specific rate limits to create, status, consume, and
    revoke operations.

-   Never log raw tokens, authorization headers, cookie values,
    encryption keys, or request bodies.

-   Do not include third-party analytics or external scripts on the
    reveal page.

-   Treat every share link as a bearer credential; anyone possessing it
    can attempt retrieval.

# 13. Example client flow

1.  Creator types secret text in the React UI.

2.  Browser generates an AES-GCM key and 12-byte IV, encrypts text with
    Web Crypto, and generates a random 32-byte share token.

3.  Browser POSTs token, ciphertext, IV, and expiry to /api/v1/secrets
    over HTTPS.

4.  API validates, hashes the token, stores only its digest and
    ciphertext metadata, then responds 201.

5.  Browser builds /s/{token}#{key}; creator copies and shares the URL.

6.  Recipient browser extracts token from path and key from fragment; it
    requests status and shows a generic availability screen.

7.  When recipient chooses Reveal, browser POSTs to consume. API
    atomically consumes and returns ciphertext and IV.

8.  Browser decrypts locally, displays plaintext as text (never HTML),
    and clears the key from memory when the reveal flow ends.

9.  A second consume attempt receives 404 SECRET_UNAVAILABLE.

# 14. Test cases

  -----------------------------------------------------------------------
  ID                      Scenario                Expected result
  ----------------------- ----------------------- -----------------------
  API-01                  Valid create payload    201; token digest and
                                                  ciphertext stored

  API-02                  Malformed token         400; no database insert
                          encoding                

  API-03                  Invalid IV length       400

  API-04                  Unsupported expiry      400

  API-05                  Valid status request    200 available=true; no
                                                  ciphertext

  API-06                  Expired token           Generic 404 unavailable
                          status/consume          

  API-07                  First consume           200 with ciphertext and
                                                  IV

  API-08                  Second consume          404 unavailable

  API-09                  Two simultaneous        Exactly one 200
                          consumes                response

  API-10                  Tampered ciphertext     Browser decryption
                                                  fails; plaintext not
                                                  shown

  API-11                  Wrong/missing fragment  Browser reports unable
                          key                     to decrypt; API never
                                                  receives key

  API-12                  Oversized request       413

  API-13                  Rate limit exceeded     429 with Retry-After
                                                  where supported

  API-14                  Invalid revoke          403; record remains
                          capability              available

  API-15                  Log inspection          No token, key,
                                                  ciphertext body, or
                                                  plaintext in logs
  -----------------------------------------------------------------------

# 15. Implementation notes for Express + Drizzle

-   Use src/routes, src/controllers, src/services, src/db/schema.ts,
    src/middleware, and src/lib directories.

-   Keep controller functions thin: validate request, call service, map
    service result to HTTP response.

-   Put token hashing, expiry checks, and consume transaction logic in
    the service layer.

-   Use Drizzle Kit migrations in version control; prefer generate +
    migrate for shared environments. Use push mainly for local
    prototyping.

-   Use a PostgreSQL transaction with row locking or conditional update
    to guarantee one-time retrieval.

-   Use Zod for request and environment validation; use a centralized
    error middleware.

-   Use Supertest for HTTP integration tests and a real test PostgreSQL
    database for concurrency tests.

# 16. Official technical references

Drizzle ORM PostgreSQL setup:
https://orm.drizzle.team/docs/get-started/postgresql-new

Drizzle ORM migrations: https://orm.drizzle.team/docs/migrations

Web Crypto API:
https://developer.mozilla.org/docs/Web/API/Web_Crypto_API

Node.js crypto: https://nodejs.org/api/crypto.html

Express production security:
https://expressjs.com/en/advanced/best-practice-security.html
