# OneVault (share-shield) — Client Cryptographic & Transport Contract

*Specification Version: 1.0 | Protocol: REST JSON over HTTPS | Target: Browser / Client SDK*

This document defines the strict cryptographic and transport contract that client applications (e.g. React frontend, CLI, mobile SDK) must implement when communicating with the OneVault API. 

The API operates under a **Zero-Knowledge Architecture**: the server never accepts, logs, or stores plaintext, decryption keys, or raw tokens.

---

## 1. Cryptographic Specifications

| Parameter | Specification | Details / Standard |
| :--- | :--- | :--- |
| **Cipher Algorithm** | `AES-GCM` (authenticated) | NIST SP 800-38D |
| **Key Length** | 256 bits (32 bytes) | Generated using cryptographically secure random values |
| **IV / Nonce** | 96 bits (12 bytes) | **MUST be fresh and unique for every encryption.** Never reuse an IV with the same key. |
| **Authentication Tag** | 128 bits (16 bytes) | Standard tag returned by Web Crypto `AES-GCM` appended to ciphertext |
| **Share Token** | 256 bits (32 bytes) | CSPRNG random bytes, base64url encoded without padding |
| **Revoke Token** | 256 bits (32 bytes) | CSPRNG random bytes, base64url encoded without padding |
| **Encoding Standard** | RFC 4648 Base64URL | Unpadded canonical characters `[A-Za-z0-9_-]` |
| **Payload Version** | Integer `1` | Denotes AES-256-GCM authenticated envelope |

---

## 2. Token & Key Generation Rules

### 2.1 Share Token
- Generate 32 bytes using `crypto.getRandomValues(new Uint8Array(32))`.
- Encode using base64url without padding (`=`):
  - Result is **exactly 43 characters** matching regex `^[A-Za-z0-9_-]{43}$`.
- The raw share token is transmitted to the server **once** in the POST body to calculate its SHA-256 digest.

### 2.2 Decryption Key
- Generate a 256-bit AES key using Web Crypto:
  ```typescript
  const key = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  ```
- Export raw 32 bytes and encode as unpadded base64url (43 characters).
- **CRITICAL INVARIANT**: The decryption key is **NEVER** transmitted to the server in any header, path, query parameter, or JSON body. It resides exclusively on the client and inside the URL fragment.

### 2.3 Creator Revoke Token
- Generate 32 bytes using `crypto.getRandomValues(new Uint8Array(32))`.
- Encode using unpadded base64url (exact 43 characters).
- Sent in the initial `POST /api/v1/secrets` body under `revokeToken`. The server hashes it immediately with SHA-256 and discards the raw token.
- The creator's client application stores the raw `revokeToken` in local state or browser storage (`localStorage` / `sessionStorage`) so the creator can revoke the link before consumption.

---

## 3. Encryption Workflow (Browser Client)

1. **Input Validation**:
   - Secret text must be UTF-8 string up to **10 KiB (10,240 bytes)**.
   - Select expiry from allowed durations: `600` (10m), `3600` (1h), `86400` (24h), `604800` (7d).
2. **IV Generation**:
   - Generate a fresh 12-byte IV:
     ```typescript
     const iv = window.crypto.getRandomValues(new Uint8Array(12));
     ```
3. **Encryption**:
   ```typescript
   const encodedPlaintext = new TextEncoder().encode(secretText);
   const cipherBuffer = await window.crypto.subtle.encrypt(
     { name: 'AES-GCM', iv },
     key,
     encodedPlaintext
   );
   ```
   *(Note: Web Crypto automatically appends the 16-byte authentication tag to `cipherBuffer`)*.
4. **Encoding**:
   - Convert `cipherBuffer` to unpadded base64url.
     - Min length: 23 characters (1 byte plaintext + 16 bytes tag = 17 bytes $\to$ 23 base64url chars).
     - Max length: 13,675 characters (10,240 bytes plaintext + 16 bytes tag = 10,256 bytes $\to$ 13,675 base64url chars).
   - Convert `iv` to unpadded base64url (**exactly 16 characters**).
5. **API Dispatch**:
   - Send `POST /api/v1/secrets` with:
     ```json
     {
       "token": "<43-char-share-token>",
       "ciphertext": "<base64url-ciphertext>",
       "iv": "<16-char-iv>",
       "expiresInSeconds": 3600,
       "payloadVersion": 1,
       "revokeToken": "<43-char-revoke-token>"
     }
     ```
   - Server returns:
     ```json
     {
       "data": {
         "created": true,
         "expiresAt": "2026-10-09T12:23:00.000Z",
         "passkey": "123456"
       },
       "requestId": "req_..."
     }
     ```
6. **Share URL & Passkey Presentation**:
   - Construct the link:
     ```text
     https://app.example.com/s/{shareToken}#{keyBase64Url}
     ```
   - Present the link and the 6-digit passkey to the creator on separate cards.
   - Instruct the creator to transmit the passkey via an out-of-band channel (voice, Signal, SMS) distinct from the link.

---

## 4. Decryption & Retrieval Workflow (Recipient Client)

1. **URL Parsing & Key Extraction**:
   - Recipient navigates to `https://app.example.com/s/<token>#<keyBase64Url>`.
   - The recipient's browser reads `window.location.hash` (`#<keyBase64Url>`).
   - **Immediately strip the fragment from the address bar** to prevent link leakage via browser history, shoulder surfing, or screen recordings:
     ```typescript
     if (window.location.hash) {
       const keyFragment = window.location.hash.substring(1);
       window.history.replaceState(null, '', window.location.pathname);
       // Store keyFragment in memory only (never sessionStorage/localStorage)
     }
     ```
2. **Availability Check**:
   - Send `GET /api/v1/secrets/<token>/status`.
   - If response is `200` with `available: true` and `passkeyRequired: true`, render the 6-digit numeric passkey input.
   - If response is `404`, display generic message: *"This secret is unavailable or has already been viewed."*
3. **Passkey Entry & Consumption**:
   - Recipient enters the 6-digit passkey and clicks *"Reveal Secret"*.
   - Send `POST /api/v1/secrets/<token>/consume` with strict JSON body:
     ```json
     {
       "passkey": "123456"
     }
     ```
   - Response handling:
     - **403 `PASSKEY_INVALID`**: Display *"Incorrect passkey. N attempts remaining"*. When `attemptsRemaining: 0`, secret is locked and destroyed; show generic unavailable message.
     - **404 `SECRET_UNAVAILABLE`**: Display generic unavailable message.
     - **200 OK**: Receive ciphertext and IV:
       ```json
       {
         "data": {
           "ciphertext": "<base64url-ciphertext>",
           "iv": "<16-char-iv>",
           "payloadVersion": 1
         },
         "requestId": "req_..."
       }
       ```
   - Browser imports key:
     ```typescript
     const key = await window.crypto.subtle.importKey(
       'raw',
       decodeBase64Url(keyFragment),
       { name: 'AES-GCM' },
       false,
       ['decrypt']
     );
     ```
   - Browser decrypts ciphertext:
     ```typescript
     const decryptedBuffer = await window.crypto.subtle.decrypt(
       { name: 'AES-GCM', iv: decodeBase64Url(res.data.iv) },
       key,
       decodeBase64Url(res.data.ciphertext)
     );
     const plaintext = new TextDecoder().decode(decryptedBuffer);
     ```
   - If `decrypt()` throws (authentication tag mismatch), report integrity failure.
4. **Memory Hygiene**:
   - Render `plaintext` as pure text (never `innerHTML` to avoid XSS).
   - Clear plaintext and key variables from JavaScript memory when the user navigates away or closes the tab.

---

## 5. Creator Revocation Workflow

1. Creator triggers revocation for a previously stored secret.
2. Send `DELETE /api/v1/secrets/<token>` with header:
   ```http
   Authorization: Bearer <43-char-revoke-token>
   ```
3. Server returns:
   - `204 No Content`: Secret was successfully revoked and wiped.
   - `403 REVOKE_NOT_AUTHORIZED`: Invalid revoke token.
   - `404 SECRET_UNAVAILABLE`: Secret already expired, consumed, revoked, or non-existent.
