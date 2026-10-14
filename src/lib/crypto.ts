import crypto from 'node:crypto';
import { ValidationError } from './errors.js';

const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

/**
 * Validates that a string is strictly canonical base64url encoded:
 * - Contains only [A-Za-z0-9_-]
 * - No padding characters ('=')
 * - When decoded and re-encoded, produces the exact original string (canonical form, no extra bits)
 * - If expectedByteLength is provided, decodes to exactly that number of bytes
 */
export function isCanonicalBase64Url(str: string, expectedByteLength?: number): boolean {
  if (typeof str !== 'string' || str.length === 0) {
    return false;
  }

  if (!BASE64URL_REGEX.test(str)) {
    return false;
  }

  try {
    const buf = Buffer.from(str, 'base64url');
    if (buf.length === 0) {
      return false;
    }

    if (expectedByteLength !== undefined && buf.length !== expectedByteLength) {
      return false;
    }

    // Canonical verification: reject non-canonical trailing bits
    return buf.toString('base64url') === str;
  } catch {
    return false;
  }
}

/**
 * Decodes a canonical base64url string to Buffer.
 * Throws ValidationError if the string is non-canonical or has an unexpected byte length.
 */
export function decodeBase64Url(
  str: string,
  expectedByteLength?: number,
  fieldName = 'input'
): Buffer {
  if (!isCanonicalBase64Url(str, expectedByteLength)) {
    const expectedDesc =
      expectedByteLength !== undefined ? ` (${expectedByteLength} bytes)` : '';
    throw new ValidationError(
      `Invalid ${fieldName}: must be canonical unpadded base64url${expectedDesc}.`
    );
  }

  return Buffer.from(str, 'base64url');
}

/**
 * Computes SHA-256 digest of raw binary bytes (Invariant 1 & 3).
 * Returns raw 32-byte binary Buffer.
 */
export function hashToken(rawTokenBytes: Buffer): Buffer {
  if (!Buffer.isBuffer(rawTokenBytes) || rawTokenBytes.length === 0) {
    throw new ValidationError('Token bytes must be a non-empty Buffer.');
  }
  return crypto.createHash('sha256').update(rawTokenBytes).digest();
}

/**
 * Decodes a 32-byte canonical base64url token and returns its 32-byte SHA-256 digest.
 */
export function hashTokenFromBase64Url(
  tokenBase64Url: string,
  fieldName = 'token'
): Buffer {
  const rawBytes = decodeBase64Url(tokenBase64Url, 32, fieldName);
  return hashToken(rawBytes);
}

/**
 * Constant-time comparison helper protecting against timing attacks (TH-09).
 * Safely compares two buffers in constant time even if their lengths differ.
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false;
  }

  // To prevent timing leakage when lengths differ, compare a against a dummy buffer
  // of identical length to a, but always return false.
  if (a.length !== b.length) {
    const dummy = Buffer.alloc(a.length, 0);
    crypto.timingSafeEqual(a, dummy);
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}
