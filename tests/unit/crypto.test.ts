import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  isCanonicalBase64Url,
  decodeBase64Url,
  hashToken,
  hashTokenFromBase64Url,
  constantTimeEqual,
} from '../../src/lib/crypto.js';
import { ValidationError } from '../../src/lib/errors.js';

describe('Cryptographic Utilities (src/lib/crypto.ts)', () => {
  describe('isCanonicalBase64Url & decodeBase64Url', () => {
    it('accepts valid unpadded canonical base64url strings', () => {
      const raw32 = crypto.randomBytes(32);
      const token = raw32.toString('base64url');
      expect(isCanonicalBase64Url(token, 32)).toBe(true);

      const decoded = decodeBase64Url(token, 32);
      expect(decoded.length).toBe(32);
      expect(decoded).toEqual(raw32);
    });

    it('rejects base64 strings containing padding (=)', () => {
      const padded = Buffer.from('hello world').toString('base64');
      if (padded.includes('=')) {
        expect(isCanonicalBase64Url(padded)).toBe(false);
        expect(() => decodeBase64Url(padded)).toThrow(ValidationError);
      }
    });

    it('rejects strings with standard base64 characters (+, /)', () => {
      expect(isCanonicalBase64Url('abc+123')).toBe(false);
      expect(isCanonicalBase64Url('abc/123')).toBe(false);
      expect(() => decodeBase64Url('abc+123')).toThrow(ValidationError);
    });

    it('rejects strings with wrong length when expectedByteLength is provided', () => {
      const raw31 = crypto.randomBytes(31).toString('base64url');
      expect(isCanonicalBase64Url(raw31, 32)).toBe(false);
      expect(() => decodeBase64Url(raw31, 32)).toThrow(ValidationError);

      const raw33 = crypto.randomBytes(33).toString('base64url');
      expect(isCanonicalBase64Url(raw33, 32)).toBe(false);
    });

    it('rejects empty, null, or non-string inputs', () => {
      expect(isCanonicalBase64Url('')).toBe(false);
      expect(isCanonicalBase64Url(null as unknown as string)).toBe(false);
      expect(isCanonicalBase64Url(undefined as unknown as string)).toBe(false);
      expect(() => decodeBase64Url('')).toThrow(ValidationError);
    });

    it('rejects unicode characters and whitespace', () => {
      expect(isCanonicalBase64Url('hello world')).toBe(false);
      expect(isCanonicalBase64Url('abc✨123')).toBe(false);
      expect(isCanonicalBase64Url('abc\n123')).toBe(false);
      expect(isCanonicalBase64Url('abc\t123')).toBe(false);
    });

    it('rejects huge non-base64url inputs', () => {
      const hugeBadString = 'A'.repeat(50000) + '!';
      expect(isCanonicalBase64Url(hugeBadString)).toBe(false);
    });

    it('rejects non-canonical base64url encodings (unused bits not zeroed)', () => {
      // In base64url, single character encoded cannot have arbitrary trailing bits
      // "A" decodes to empty or partial bits where re-encoding might not match
      expect(isCanonicalBase64Url('A')).toBe(false);
      expect(isCanonicalBase64Url('?')).toBe(false);
    });
  });

  describe('SHA-256 Token Hashing Determinism (Invariant 1)', () => {
    it('deterministically hashes raw bytes to identical 32-byte digests', () => {
      const rawBytes = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
      const hash1 = hashToken(rawBytes);
      const hash2 = hashToken(rawBytes);

      expect(hash1.length).toBe(32);
      expect(hash2.length).toBe(32);
      expect(hash1.equals(hash2)).toBe(true);
    });

    it('produces distinct digests for distinct tokens', () => {
      const tokenA = crypto.randomBytes(32);
      const tokenB = crypto.randomBytes(32);

      const hashA = hashToken(tokenA);
      const hashB = hashToken(tokenB);

      expect(hashA.equals(hashB)).toBe(false);
    });

    it('hashTokenFromBase64Url decodes and produces exact SHA-256 digest', () => {
      const rawBytes = crypto.randomBytes(32);
      const base64UrlToken = rawBytes.toString('base64url');

      const directHash = crypto.createHash('sha256').update(rawBytes).digest();
      const helperHash = hashTokenFromBase64Url(base64UrlToken);

      expect(helperHash.equals(directHash)).toBe(true);
    });
  });

  describe('Constant-Time Comparison (TH-09)', () => {
    it('returns true for identical buffers', () => {
      const buf1 = Buffer.from('a-secret-digest-value-1234567890');
      const buf2 = Buffer.from('a-secret-digest-value-1234567890');
      expect(constantTimeEqual(buf1, buf2)).toBe(true);
    });

    it('returns false for buffers with differing content of same length', () => {
      const buf1 = Buffer.from('a-secret-digest-value-1234567890');
      const buf2 = Buffer.from('a-secret-digest-value-1234567891');
      expect(constantTimeEqual(buf1, buf2)).toBe(false);
    });

    it('returns false for buffers of different lengths without throwing', () => {
      const buf1 = Buffer.from('short');
      const buf2 = Buffer.from('much longer buffer content');
      expect(constantTimeEqual(buf1, buf2)).toBe(false);
    });
  });
});
