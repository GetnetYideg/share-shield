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

  POST            /secrets                   201             Create secret
                                                             record; return
                                                             passkey once

  GET             /secrets/{token}/status    200             Return
                                                             availability &
                                                             passkey requirement

  POST            /secrets/{token}/consume   200             Verify passkey,
                                                             atomically claim
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
frontend encrypts plaintext first and generates the token locally. The API
generates a random 6-digit numeric passkey and returns it once to the creator.

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
> \"sharePath\": \"/s/\<token\>\",\
> \"passkey\": \"123456\"\
> },\
> \"requestId\": \"req_abc123\"\
> }

Implementation note: returning the token in the response is unnecessary
if the browser already generated it. Returning sharePath is optional;
the browser should assemble the full URL and append #\<key\> locally.
Never return or persist the key.
The server generates a 6-digit numeric passkey using a cryptographically
secure random number generator (`crypto.randomInt(0, 1_000_000)` zero-padded).
The passkey is returned once in the creation response and is NEVER stored in
plaintext on the server, NEVER logged, and NEVER returned again. The creator
must transmit this passkey to the recipient via an out-of-band channel.

Errors: 400 VALIDATION_ERROR; 413 PAYLOAD_TOO_LARGE; 429 RATE_LIMITED;
500 INTERNAL_ERROR.

# 6. GET /secrets/{token}/status

Purpose: show a generic availability state and whether a passkey is required
without returning ciphertext or sensitive metadata. This endpoint is strictly
read-only; it never checks passkeys, never consumes attempts, and never mutates
state.

Response 200:

> {\
> \"data\": {\
> \"available\": true,\
> \"expiresAt\": \"2026-10-09T12:23:00.000Z\",\
> \"passkeyRequired\": true\
> },\
> \"requestId\": \"req_abc123\"\
> }

For invalid, expired, consumed, revoked, or locked tokens, return a generic
response such as 404 SECRET_UNAVAILABLE. Avoid distinguishing the reason
to an unauthenticated caller.

# 7. POST /secrets/{token}/consume

Purpose: atomically verify the 6-digit passkey, mark a secret as consumed,
and return its ciphertext and IV. This endpoint must be designed for at-most-once
retrieval and bounded attempt verification.

Request body:

> {\
> \"passkey\": \"123456\"\
> }

Validation:

-   passkey must be a string containing exactly 6 decimal digits (`/^\d{6}$/`).
-   Syntactically invalid or missing passkeys fail Zod schema validation
    immediately with HTTP 400 VALIDATION_ERROR before database execution;
    they do NOT count against the secret's attempt limit.

Response 200 (Success):

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

Response 403 (Incorrect Passkey on Active Secret):

> {\
> \"error\": {\
> \"code\": \"PASSKEY_INVALID\",\
> \"message\": \"Incorrect passkey.\",\
> \"attemptsRemaining\": 4,\
> \"requestId\": \"req_abc123\"\
> }\
> }

When wrong attempts reach PASSKEY_MAX_ATTEMPTS (e.g. 5), the secret is
permanently locked (`locked_at = NOW()`), ciphertext and IV are zeroized,
and the response returns `attemptsRemaining: 0`. Any subsequent request to
this secret returns generic 404 SECRET_UNAVAILABLE.

Response 404 (Secret Unavailable):

> {\
> \"error\": {\
> \"code\": \"SECRET_UNAVAILABLE\",\
> \"message\": \"This secret is unavailable.\",\
> \"requestId\": \"req_abc123\"\
> }\
> }

Returned uniformly if the secret is unknown, expired, already consumed,
revoked, or locked from prior failed attempts.

Errors: 400 VALIDATION_ERROR; 403 PASSKEY_INVALID; 404 SECRET_UNAVAILABLE;
429 RATE_LIMITED; 500 INTERNAL_ERROR.

## 7.1 Required atomic behavior

Verification and state transitions must occur atomically inside a single database
transaction with a row lock (`FOR UPDATE`) or single atomic CTE statement to eliminate
race conditions between concurrent guesses:

1. Application computes candidate hash:
   `candidateHash = HMAC-SHA256(key = PASSKEY_PEPPER, data = tokenHash || ":" || passkey)`
2. Transaction acquires exclusive row lock:
   > BEGIN;\
   > SELECT id, ciphertext, iv, expires_at, consumed_at, revoked_at, locked_at, passkey_hash, failed_attempts\
   > FROM secrets\
   > WHERE token_hash = \$1\
   > FOR UPDATE;
3. Status evaluation:
   - If missing, expired (`expires_at <= NOW()`), consumed, revoked, or locked (`locked_at IS NOT NULL`):
     ROLLBACK and return uniform 404 SECRET_UNAVAILABLE.
   - If available and candidateHash matches stored `passkey_hash`:
     > UPDATE secrets\
     > SET consumed_at = NOW(), ciphertext = NULL, iv = NULL\
     > WHERE id = \$2;\
     > COMMIT;
     Return ciphertext and IV (200 OK).
   - If available and candidateHash does NOT match:
     Increment failed attempts:
     > UPDATE secrets\
     > SET failed_attempts = failed_attempts + 1,\
     >     locked_at = CASE WHEN failed_attempts + 1 >= \$max_attempts THEN NOW() ELSE NULL END,\
     >     ciphertext = CASE WHEN failed_attempts + 1 >= \$max_attempts THEN NULL ELSE ciphertext END,\
     >     iv = CASE WHEN failed_attempts + 1 >= \$max_attempts THEN NULL ELSE iv END\
     > WHERE id = \$2\
     > RETURNING failed_attempts;
     > COMMIT;
     Calculate `attemptsRemaining = MAX(0, max_attempts - updated_failed_attempts)`.
     Return 403 PASSKEY_INVALID with `attemptsRemaining`.

Implementation note: commit happens before the response is returned. If the
client disconnects after commit on a successful consume, the secret is consumed
without being read; if on the final failed attempt, the secret is locked and destroyed.
This is a deliberate security trade-off for one-time semantics and attempt bounding.

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
> revoke_token_hash BYTEA NOT NULL\
> passkey_hash BYTEA NOT NULL\
> failed_attempts INTEGER NOT NULL DEFAULT 0\
> locked_at TIMESTAMPTZ NULL\
> ciphertext BYTEA NULL\
> iv BYTEA NULL\
> payload_version INTEGER NOT NULL DEFAULT 1\
> expires_at TIMESTAMPTZ NOT NULL\
> created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
> consumed_at TIMESTAMPTZ NULL\
> revoked_at TIMESTAMPTZ NULL

Recommended constraints: CHECK constraints on `length(passkey_hash) = 32` and
`failed_attempts >= 0`. Recommended indexes: unique index on token_hash; index
on expires_at for cleanup; composite index on (consumed_at, revoked_at, locked_at, expires_at)
for cleanup sweep performance.

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

  403                    PASSKEY_INVALID          Incorrect passkey for
                                                  an active secret;
                                                  includes attemptsRemaining

  404                    SECRET_UNAVAILABLE       Secret does not exist,
                                                  expired, consumed,
                                                  revoked, or locked

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
