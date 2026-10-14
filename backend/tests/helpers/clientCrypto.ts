import crypto from 'node:crypto';

const { subtle } = crypto.webcrypto;

export interface ClientEncryptedPayload {
  plaintext: string;
  token: string;
  revokeToken: string;
  key: string;
  iv: string;
  ciphertext: string;
  shareUrl: string;
}

/**
 * Simulates browser-side Web Crypto operations (SRS section 6.2).
 * 1. Generates 32-byte random AES key
 * 2. Generates unique 12-byte IV
 * 3. Encrypts UTF-8 plaintext using AES-GCM
 * 4. Generates 32-byte base64url share token and revoke token
 * 5. Constructs share link /s/<token>#<key>
 */
export async function createClientSecret(
  plaintext: string,
  baseUrl = 'https://app.example.com'
): Promise<ClientEncryptedPayload> {
  // 1. Generate 32-byte AES key
  const rawKey = crypto.randomBytes(32);
  const cryptoKey = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt',
  ]);

  // 2. Generate unique 12-byte IV
  const rawIv = crypto.randomBytes(12);

  // 3. Encrypt UTF-8 plaintext
  const plaintextEncoded = new TextEncoder().encode(plaintext);
  const encryptedBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv: rawIv },
    cryptoKey,
    plaintextEncoded
  );

  // 4. Generate random 32-byte bearer tokens
  const rawToken = crypto.randomBytes(32);
  const rawRevokeToken = crypto.randomBytes(32);

  const keyBase64Url = rawKey.toString('base64url');
  const ivBase64Url = rawIv.toString('base64url');
  const ciphertextBase64Url = Buffer.from(encryptedBuffer).toString('base64url');
  const tokenBase64Url = rawToken.toString('base64url');
  const revokeTokenBase64Url = rawRevokeToken.toString('base64url');

  // 5. Construct URL with key in fragment
  const shareUrl = `${baseUrl}/s/${tokenBase64Url}#${keyBase64Url}`;

  return {
    plaintext,
    token: tokenBase64Url,
    revokeToken: revokeTokenBase64Url,
    key: keyBase64Url,
    iv: ivBase64Url,
    ciphertext: ciphertextBase64Url,
    shareUrl,
  };
}

/**
 * Simulates browser-side decryption using the fragment key and returned ciphertext + IV.
 */
export async function decryptClientSecret(
  ciphertextBase64Url: string,
  ivBase64Url: string,
  keyBase64Url: string
): Promise<string> {
  const rawKey = Buffer.from(keyBase64Url, 'base64url');
  const rawIv = Buffer.from(ivBase64Url, 'base64url');
  const rawCiphertext = Buffer.from(ciphertextBase64Url, 'base64url');

  const cryptoKey = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);

  const decryptedBuffer = await subtle.decrypt(
    { name: 'AES-GCM', iv: rawIv },
    cryptoKey,
    rawCiphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}
