import { z } from 'zod';
import { isCanonicalBase64Url } from '../../lib/crypto.js';
import { UnauthenticatedError, ValidationError } from '../../lib/errors.js';

// Base64url regex matching exact 43 chars for 32-byte tokens
const TOKEN_REGEX = /^[A-Za-z0-9_-]{43}$/;
// Base64url regex matching exact 16 chars for 12-byte IV
const IV_REGEX = /^[A-Za-z0-9_-]{16}$/;
// Base64url regex matching ciphertext bounds (23 to 13,675 chars derived from 10 KiB max plaintext)
const CIPHERTEXT_REGEX = /^[A-Za-z0-9_-]{23,13675}$/;

/**
 * Validates the :token route parameter (32 raw random bytes in canonical base64url).
 */
export const tokenParamSchema = z
  .object({
    token: z
      .string({ required_error: 'Token parameter is required' })
      .regex(TOKEN_REGEX, 'Token must be a 43-character base64url string')
      .refine((val) => isCanonicalBase64Url(val, 32), {
        message: 'Token must decode to exactly 32 bytes with canonical base64url encoding',
      }),
  })
  .strict();

export type TokenParam = z.infer<typeof tokenParamSchema>;

/**
 * Validates POST /api/v1/secrets creation body (strict mode: rejects unknown fields).
 */
export const createSecretBodySchema = z
  .object({
    token: z
      .string({ required_error: 'token is required' })
      .regex(TOKEN_REGEX, 'token must be a 43-character base64url string')
      .refine((val) => isCanonicalBase64Url(val, 32), {
        message: 'token must decode to exactly 32 bytes with canonical base64url encoding',
      }),
    revokeToken: z
      .string({ required_error: 'revokeToken is required' })
      .regex(TOKEN_REGEX, 'revokeToken must be a 43-character base64url string')
      .refine((val) => isCanonicalBase64Url(val, 32), {
        message: 'revokeToken must decode to exactly 32 bytes with canonical base64url encoding',
      }),
    ciphertext: z
      .string({ required_error: 'ciphertext is required' })
      .min(23, 'ciphertext must be at least 23 characters')
      .max(13675, 'ciphertext exceeds maximum allowed length of 13,675 characters')
      .regex(CIPHERTEXT_REGEX, 'ciphertext must be a valid base64url string')
      .refine((val) => isCanonicalBase64Url(val), {
        message: 'ciphertext must be valid canonical base64url',
      }),
    iv: z
      .string({ required_error: 'iv is required' })
      .regex(IV_REGEX, 'iv must be a 16-character base64url string')
      .refine((val) => isCanonicalBase64Url(val, 12), {
        message: 'iv must decode to exactly 12 bytes with canonical base64url encoding',
      }),
    expiresInSeconds: z
      .union([z.literal(600), z.literal(3600), z.literal(86400), z.literal(604800)])
      .default(3600),
    payloadVersion: z.literal(1).default(1),
  })
  .strict();

export type CreateSecretInput = z.infer<typeof createSecretBodySchema>;

/**
 * Validates query parameters on GET /api/v1/secrets/:token/status.
 */
export const statusQuerySchema = z.object({}).strict();

/**
 * Validates body on POST /api/v1/secrets/:token/consume (empty-strict).
 */
export const consumeBodySchema = z.object({}).strict();

/**
 * Parses and validates the creator revoke token from the Authorization header (Phase 1 decision 3a & 3b).
 * Throws UnauthenticatedError (401) if missing.
 * Throws ValidationError (400) if malformed.
 */
export function parseRevokeTokenFromHeader(header: string | undefined): string {
  if (!header || header.trim() === '') {
    throw new UnauthenticatedError('Authorization header is required.');
  }

  const match = header.match(/^Bearer\s+([A-Za-z0-9_-]+)$/i);
  if (!match || !match[1]) {
    throw new ValidationError('Authorization header must be in format Bearer <revokeToken>.');
  }

  const token = match[1];
  if (!isCanonicalBase64Url(token, 32)) {
    throw new ValidationError(
      'Revoke token must decode to exactly 32 bytes with canonical base64url encoding.'
    );
  }

  return token;
}
