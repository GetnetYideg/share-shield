# OneVault (share-shield) API Reference

*Version: 1.0 | Protocol: REST JSON over HTTPS | Base Path: `/api/v1`*

All API endpoints enforce strict JSON schemas, rejection of unknown fields, HTTPS in production, and zero-knowledge storage. Decryption keys and secret plaintexts are **never** accepted or processed by this API.

---

## Standard Response Envelopes

### Success (`2xx`)
```json
{
  "data": { ... },
  "requestId": "req_01JABCDEF1234567"
}
```

### Error (`4xx` / `5xx`)
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Detailed safe error description.",
    "requestId": "req_01JABCDEF1234567"
  }
}
```

---

## Endpoints

### 1. Health & Readiness Check

Check the API process and PostgreSQL database connectivity.

- **Method**: `GET`
- **Path**: `/api/v1/health`
- **Auth**: None (Public)
- **Rate Limit**: Global limiter

#### Request
```bash
curl -X GET "https://api.example.com/api/v1/health" \
  -H "Accept: application/json"
```

#### Success Response (`200 OK`)
```json
{
  "data": {
    "status": "ok"
  },
  "requestId": "req_01JEXAMPLEHEALTH01"
}
```

#### Degraded Response (`503 Service Unavailable`)
```json
{
  "data": {
    "status": "degraded",
    "database": "down"
  },
  "requestId": "req_01JEXAMPLEHEALTH02"
}
```

---

### 2. Create Secret

Store an encrypted ciphertext record and register its SHA-256 digest.

- **Method**: `POST`
- **Path**: `/api/v1/secrets`
- **Auth**: None (Public)
- **Rate Limit**: `10 req / minute`
- **Payload Max**: `16 KiB` total JSON body

#### Request Headers
- `Content-Type: application/json`

#### Request Body
```json
{
  "token": "PLACEHOLDER_43_CHAR_BASE64URL_SHARE_TOKEN",
  "ciphertext": "PLACEHOLDER_BASE64URL_ENCRYPTED_CIPHERTEXT",
  "iv": "PLACEHOLDER_16_CHAR_IV",
  "expiresInSeconds": 3600,
  "payloadVersion": 1,
  "revokeToken": "PLACEHOLDER_43_CHAR_BASE64URL_REVOKE_TOKEN"
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `token` | String | 43 characters base64url unpadded (32 raw random bytes). |
| `ciphertext` | String | Base64url AES-GCM ciphertext (23 to 13,675 chars). |
| `iv` | String | 16 characters base64url unpadded (12 raw bytes). |
| `expiresInSeconds` | Number | Allowed durations: `600` (10m), `3600` (1h), `86400` (24h), `604800` (7d). |
| `payloadVersion` | Number | Must equal `1`. |
| `revokeToken` | String | 43 characters base64url unpadded (32 raw random bytes). |

#### Curl Example
```bash
curl -X POST "https://api.example.com/api/v1/secrets" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV",
    "ciphertext": "u8W2rY6xP9kM3nQ7tL5vB2cE9fG4hJ1kM8nP5qS7uV3wX2yB0cE5fG8hJ2kM4nP6",
    "iv": "X8vQ3z9K8mN2pL7r",
    "expiresInSeconds": 3600,
    "payloadVersion": 1,
    "revokeToken": "7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL"
  }'
```

#### Success Response (`201 Created`)
```json
{
  "data": {
    "created": true,
    "expiresAt": "2026-10-14T11:30:00.000Z"
  },
  "requestId": "req_01JCREATEEXAMPLE01"
}
```

---

### 3. Preview Secret Status

Check availability of a secret without retrieving ciphertext or marking it consumed.

- **Method**: `GET`
- **Path**: `/api/v1/secrets/:token/status`
- **Auth**: None (Public)
- **Rate Limit**: `30 req / minute`

#### Curl Example
```bash
curl -X GET "https://api.example.com/api/v1/secrets/4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV/status" \
  -H "Accept: application/json"
```

#### Success Response (`200 OK`)
```json
{
  "data": {
    "available": true,
    "expiresAt": "2026-10-14T11:30:00.000Z"
  },
  "requestId": "req_01JSTATUSEXAMPLE01"
}
```

#### Unavailable Response (`404 Not Found`)
*Returned identically for unknown, expired, already consumed, or revoked secrets (Invariant 4).*
```json
{
  "error": {
    "code": "SECRET_UNAVAILABLE",
    "message": "This secret is unavailable or has already been viewed.",
    "requestId": "req_01JSTATUSEXAMPLE02"
  }
}
```

---

### 4. Consume Secret (Atomic Claim)

Atomically retrieves the ciphertext and marks the secret consumed in a single atomic transaction. Ciphertext and IV are wiped to `NULL` upon successful claim.

- **Method**: `POST`
- **Path**: `/api/v1/secrets/:token/consume`
- **Auth**: None (Public)
- **Rate Limit**: `15 req / minute`
- **Request Body**: Must be empty JSON object `{}` or omitted.

#### Curl Example
```bash
curl -X POST "https://api.example.com/api/v1/secrets/4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV/consume" \
  -H "Content-Type: application/json" \
  -d '{}'
```

#### Success Response (`200 OK`)
*Returned strictly ONCE across all concurrent or sequential attempts.*
```json
{
  "data": {
    "ciphertext": "u8W2rY6xP9kM3nQ7tL5vB2cE9fG4hJ1kM8nP5qS7uV3wX2yB0cE5fG8hJ2kM4nP6",
    "iv": "X8vQ3z9K8mN2pL7r",
    "payloadVersion": 1
  },
  "requestId": "req_01JCONSUMEEXAMPLE1"
}
```

#### Second / Unavailable Response (`404 Not Found`)
*Any subsequent request receives the uniform 404 response.*
```json
{
  "error": {
    "code": "SECRET_UNAVAILABLE",
    "message": "This secret is unavailable or has already been viewed.",
    "requestId": "req_01JCONSUMEEXAMPLE2"
  }
}
```

---

### 5. Revoke Secret

Allows the creator to revoke an unconsumed secret using their locally stored `revokeToken`.

- **Method**: `DELETE`
- **Path**: `/api/v1/secrets/:token`
- **Auth**: `Authorization: Bearer <revokeToken>`
- **Rate Limit**: `15 req / minute`

#### Curl Example
```bash
curl -X DELETE "https://api.example.com/api/v1/secrets/4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV" \
  -H "Authorization: Bearer 7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL"
```

#### Success Response (`204 No Content`)
*Empty response body.*

#### Mismatching Revoke Token (`403 Forbidden`)
*Returned if the secret is currently active but the revoke token is incorrect.*
```json
{
  "error": {
    "code": "REVOKE_NOT_AUTHORIZED",
    "message": "The provided revoke token is invalid.",
    "requestId": "req_01JREVOKEEX01"
  }
}
```

#### Already Unavailable Response (`404 Not Found`)
*Returned if the secret is already expired, consumed, revoked, or non-existent (Non-Oracle rule).*
```json
{
  "error": {
    "code": "SECRET_UNAVAILABLE",
    "message": "This secret is unavailable or has already been viewed.",
    "requestId": "req_01JREVOKEEX02"
  }
}
```

---

## Error Codes Matrix

| HTTP Status | Code | Description |
| :--- | :--- | :--- |
| `400` | `VALIDATION_ERROR` | Malformed base64url, invalid parameter, or unexpected fields. |
| `401` | `UNAUTHENTICATED` | Missing required `Authorization: Bearer <token>` header on revocation. |
| `403` | `REVOKE_NOT_AUTHORIZED` | Revoke token digest does not match the stored secret digest. |
| `404` | `SECRET_UNAVAILABLE` | Secret non-existent, expired, already consumed, or revoked. |
| `404` | `NOT_FOUND` | Unmatched API route. |
| `413` | `PAYLOAD_TOO_LARGE` | Request payload exceeds 16 KiB limit. |
| `415` | `UNSUPPORTED_MEDIA_TYPE` | Content-Type is not `application/json`. |
| `429` | `RATE_LIMITED` | Rate limit window exceeded for IP bucket. |
| `500` | `INTERNAL_ERROR` | Unexpected server error. |
| `503` | `SERVICE_UNAVAILABLE` | Database health probe failure. |
