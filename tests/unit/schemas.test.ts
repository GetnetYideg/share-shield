import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  tokenParamSchema,
  createSecretBodySchema,
  statusQuerySchema,
} from '../../src/modules/secrets/secrets.schemas.js';

describe('Secrets Zod Schemas (src/modules/secrets/secrets.schemas.ts)', () => {
  const validToken = crypto.randomBytes(32).toString('base64url');
  const validRevokeToken = crypto.randomBytes(32).toString('base64url');
  const validIv = crypto.randomBytes(12).toString('base64url'); // exactly 16 chars
  const validCiphertext = crypto.randomBytes(50).toString('base64url'); // valid length > 23

  describe('tokenParamSchema', () => {
    it('accepts a valid 43-character canonical base64url token', () => {
      const result = tokenParamSchema.safeParse({ token: validToken });
      expect(result.success).toBe(true);
    });

    it('rejects tokens of wrong length', () => {
      const tooShort = validToken.slice(0, 42);
      expect(tokenParamSchema.safeParse({ token: tooShort }).success).toBe(false);

      const tooLong = validToken + 'a';
      expect(tokenParamSchema.safeParse({ token: tooLong }).success).toBe(false);
    });

    it('rejects unknown fields in params (strict mode)', () => {
      const result = tokenParamSchema.safeParse({ token: validToken, extra: 'bad' });
      expect(result.success).toBe(false);
    });
  });

  describe('createSecretBodySchema', () => {
    it('accepts a valid create payload and applies defaults', () => {
      const payload = {
        token: validToken,
        revokeToken: validRevokeToken,
        ciphertext: validCiphertext,
        iv: validIv,
      };

      const result = createSecretBodySchema.safeParse(payload);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.expiresInSeconds).toBe(3600);
        expect(result.data.payloadVersion).toBe(1);
      }
    });

    it('accepts supported expiresInSeconds enum values (600, 3600, 86400, 604800)', () => {
      for (const seconds of [600, 3600, 86400, 604800]) {
        const result = createSecretBodySchema.safeParse({
          token: validToken,
          revokeToken: validRevokeToken,
          ciphertext: validCiphertext,
          iv: validIv,
          expiresInSeconds: seconds,
        });
        expect(result.success).toBe(true);
      }
    });

    it('rejects unsupported expiresInSeconds values', () => {
      const result = createSecretBodySchema.safeParse({
        token: validToken,
        revokeToken: validRevokeToken,
        ciphertext: validCiphertext,
        iv: validIv,
        expiresInSeconds: 1200, // not in enum
      });
      expect(result.success).toBe(false);
    });

    it('rejects unknown fields like decryptionKey or plaintext (Invariant 2)', () => {
      const result = createSecretBodySchema.safeParse({
        token: validToken,
        revokeToken: validRevokeToken,
        ciphertext: validCiphertext,
        iv: validIv,
        decryptionKey: 'FORBIDDEN_KEY',
      });
      expect(result.success).toBe(false);
    });

    it('rejects client-specified maxViews (Invariant 2)', () => {
      const result = createSecretBodySchema.safeParse({
        token: validToken,
        revokeToken: validRevokeToken,
        ciphertext: validCiphertext,
        iv: validIv,
        maxViews: 2,
      });
      expect(result.success).toBe(false);
    });

    it('rejects invalid IV length (must be 16 chars base64url = 12 raw bytes)', () => {
      const badIv = crypto.randomBytes(16).toString('base64url'); // 16 bytes instead of 12
      const result = createSecretBodySchema.safeParse({
        token: validToken,
        revokeToken: validRevokeToken,
        ciphertext: validCiphertext,
        iv: badIv,
      });
      expect(result.success).toBe(false);
    });

    it('rejects ciphertext shorter than 23 characters', () => {
      const shortCiphertext = 'too_short';
      const result = createSecretBodySchema.safeParse({
        token: validToken,
        revokeToken: validRevokeToken,
        ciphertext: shortCiphertext,
        iv: validIv,
      });
      expect(result.success).toBe(false);
    });
  });

  describe('statusQuerySchema', () => {
    it('accepts empty query object', () => {
      expect(statusQuerySchema.safeParse({}).success).toBe(true);
    });

    it('rejects query parameters (strict mode)', () => {
      expect(statusQuerySchema.safeParse({ key: 'leak' }).success).toBe(false);
    });
  });
});
