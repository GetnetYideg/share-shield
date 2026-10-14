/**
 * Client-Side Cryptographic Module for ShareShield (SRS §6.2)
 *
 * Implements Web Crypto AES-256-GCM authenticated encryption.
 * Strictly enforces zero-knowledge: encryption keys and plaintexts are never
 * transmitted over the network or persisted to browser storage.
 */

export interface EncryptedPayload {
  token: string;
  keyBase64Url: string;
  ciphertext: string;
  iv: string;
  revokeToken: string;
  payloadVersion: number;
}

/**
 * Encodes an ArrayBuffer or Uint8Array into unpadded Base64URL string (RFC 4648 §5).
 */
export function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decodes an unpadded Base64URL string into a Uint8Array.
 */
export function base64UrlToBuffer(base64url: string): Uint8Array {
  // Add required base64 padding
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generates 32 cryptographically secure random bytes as unpadded Base64URL (43 chars).
 */
export function generateRandomToken(): string {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  return bufferToBase64Url(bytes);
}

/**
 * Generates a fresh 12-byte IV for AES-GCM as unpadded Base64URL (16 chars).
 * MUST be unique for every encryption.
 */
export function generateIv(): { ivBytes: Uint8Array; ivBase64Url: string } {
  const ivBytes = new Uint8Array(12);
  window.crypto.getRandomValues(ivBytes);
  return {
    ivBytes,
    ivBase64Url: bufferToBase64Url(ivBytes),
  };
}

/**
 * Generates a fresh 256-bit AES-GCM CryptoKey using Web Crypto API.
 */
export async function generateAesKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Exports a CryptoKey to raw bytes and encodes as unpadded Base64URL (43 chars).
 */
export async function exportKey(key: CryptoKey): Promise<string> {
  const rawKeyBuffer = await window.crypto.subtle.exportKey('raw', key);
  return bufferToBase64Url(rawKeyBuffer);
}

/**
 * Imports a raw 32-byte Base64URL key into an AES-GCM CryptoKey.
 */
export async function importKey(keyBase64Url: string): Promise<CryptoKey> {
  const rawBytes = base64UrlToBuffer(keyBase64Url);
  if (rawBytes.byteLength !== 32) {
    throw new Error('Invalid key length: expected 32 bytes.');
  }
  return window.crypto.subtle.importKey(
    'raw',
    rawBytes as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
}

/**
 * Encrypts secret plaintext using AES-256-GCM with a fresh 12-byte IV.
 * Web Crypto automatically calculates and appends the 128-bit authentication tag.
 */
export async function encryptSecret(plaintext: string): Promise<EncryptedPayload> {
  // 1. Generate AES-256-GCM Key
  const key = await generateAesKey();
  const keyBase64Url = await exportKey(key);

  // 2. Generate unique 12-byte IV
  const { ivBytes, ivBase64Url } = generateIv();

  // 3. Encrypt UTF-8 encoded text
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(plaintext);

  const cipherBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes as unknown as BufferSource },
    key,
    encodedData
  );

  const ciphertextBase64Url = bufferToBase64Url(cipherBuffer);

  // 4. Generate 32-byte share token and 32-byte revoke token
  const token = generateRandomToken();
  const revokeToken = generateRandomToken();

  return {
    token,
    keyBase64Url,
    ciphertext: ciphertextBase64Url,
    iv: ivBase64Url,
    revokeToken,
    payloadVersion: 1,
  };
}

/**
 * Decrypts AES-256-GCM ciphertext using the in-memory decryption key and IV.
 * Throws an error if the authentication tag fails (tampering detection).
 */
export async function decryptSecret(
  ciphertextBase64Url: string,
  ivBase64Url: string,
  keyBase64Url: string
): Promise<string> {
  const key = await importKey(keyBase64Url);
  const iv = base64UrlToBuffer(ivBase64Url);
  const cipherBytes = base64UrlToBuffer(ciphertextBase64Url);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    cipherBytes as unknown as BufferSource
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}
