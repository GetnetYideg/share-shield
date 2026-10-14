import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { sql } from 'drizzle-orm';
import {
  setupTestDatabase,
  cleanTestDatabase,
  teardownTestDatabase,
  getTestConfig,
  assertTestDatabase,
} from '../helpers/db.js';
import { getDb } from '../../src/db/client.js';
import { secrets } from '../../src/db/schema.js';
import { SecretsRepository } from '../../src/modules/secrets/secrets.repository.js';
import { hashToken } from '../../src/lib/crypto.js';

describe('Database Layer & Schema Constraints Integration Tests', () => {
  const config = getTestConfig();
  const db = getDb(config);
  const repository = new SecretsRepository();

  beforeAll(async () => {
    await setupTestDatabase();
  });

  beforeEach(async () => {
    await cleanTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  describe('Non-Test Database Guard (Safety Check)', () => {
    it('refuses to run when NODE_ENV is not test', () => {
      expect(() =>
        assertTestDatabase('postgresql://localhost:5432/onevault_test', 'production')
      ).toThrow(/Safety guard violation: NODE_ENV must be 'test'/);
    });

    it('refuses to run against non-test database names', () => {
      expect(() => assertTestDatabase('postgresql://localhost:5432/onevault_prod', 'test')).toThrow(
        /Safety guard violation: Refusing to run tests against non-test database/
      );
    });
  });

  describe('SecretsRepository create & findForStatus', () => {
    it('creates a secret and queries it for status without selecting ciphertext or iv (Invariant 1 & FR-05)', async () => {
      const rawToken = crypto.randomBytes(32);
      const tokenHash = hashToken(rawToken);
      const revokeTokenHash = hashToken(crypto.randomBytes(32));
      const ciphertext = Buffer.from('encrypted-payload-bytes');
      const iv = crypto.randomBytes(12);

      const created = await repository.create(db, {
        tokenHash,
        revokeTokenHash,
        ciphertext,
        iv,
        expiresInSeconds: 3600,
        payloadVersion: 1,
      });

      expect(created.id).toBeDefined();
      expect(created.expiresAt).toBeInstanceOf(Date);
      expect(created.expiresAt.getTime()).toBeGreaterThan(Date.now());

      const statusRecord = await repository.findForStatus(db, tokenHash);
      expect(statusRecord).not.toBeNull();
      if (statusRecord) {
        expect(statusRecord.id).toBe(created.id);
        expect(statusRecord.expiresAt).toEqual(created.expiresAt);
        expect(statusRecord.consumedAt).toBeNull();
        expect(statusRecord.revokedAt).toBeNull();
        // NON-NEGOTIABLE: ciphertext and iv must never be in status query
        expect((statusRecord as Record<string, unknown>).ciphertext).toBeUndefined();
        expect((statusRecord as Record<string, unknown>).iv).toBeUndefined();
      }
    });

    it('returns null when querying status for unknown token hash', async () => {
      const unknownHash = hashToken(crypto.randomBytes(32));
      const record = await repository.findForStatus(db, unknownHash);
      expect(record).toBeNull();
    });
  });

  describe('Database-Level Constraints Enforcement', () => {
    const validTokenHash = hashToken(crypto.randomBytes(32));
    const validRevokeTokenHash = hashToken(crypto.randomBytes(32));
    const validIv = crypto.randomBytes(12);
    const validCiphertext = Buffer.from('valid-ciphertext');

    it('enforces check_max_views (rejects max_views != 1)', async () => {
      await expect(
        db.insert(secrets).values({
          tokenHash: hashToken(crypto.randomBytes(32)),
          revokeTokenHash: validRevokeTokenHash,
          ciphertext: validCiphertext,
          iv: validIv,
          maxViews: 2, // Violates check_max_views
          expiresAt: new Date(Date.now() + 3600000),
        })
      ).rejects.toThrow(/check_max_views/);
    });

    it('enforces check_payload_version (rejects payload_version != 1)', async () => {
      await expect(
        db.insert(secrets).values({
          tokenHash: hashToken(crypto.randomBytes(32)),
          revokeTokenHash: validRevokeTokenHash,
          ciphertext: validCiphertext,
          iv: validIv,
          payloadVersion: 2, // Violates check_payload_version
          expiresAt: new Date(Date.now() + 3600000),
        })
      ).rejects.toThrow(/check_payload_version/);
    });

    it('enforces check_token_hash_length (rejects token_hash != 32 bytes)', async () => {
      const badTokenHash = crypto.randomBytes(16); // 16 bytes instead of 32
      await expect(
        db.insert(secrets).values({
          tokenHash: badTokenHash,
          revokeTokenHash: validRevokeTokenHash,
          ciphertext: validCiphertext,
          iv: validIv,
          expiresAt: new Date(Date.now() + 3600000),
        })
      ).rejects.toThrow(/check_token_hash_length/);
    });

    it('enforces check_revoke_token_hash_length (rejects revoke_token_hash != 32 bytes)', async () => {
      const badRevokeHash = crypto.randomBytes(31); // 31 bytes instead of 32
      await expect(
        db.insert(secrets).values({
          tokenHash: hashToken(crypto.randomBytes(32)),
          revokeTokenHash: badRevokeHash,
          ciphertext: validCiphertext,
          iv: validIv,
          expiresAt: new Date(Date.now() + 3600000),
        })
      ).rejects.toThrow(/check_revoke_token_hash_length/);
    });

    it('enforces check_iv_length (rejects iv != 12 bytes)', async () => {
      const badIv = crypto.randomBytes(16); // 16 bytes instead of 12
      await expect(
        db.insert(secrets).values({
          tokenHash: hashToken(crypto.randomBytes(32)),
          revokeTokenHash: validRevokeTokenHash,
          ciphertext: validCiphertext,
          iv: badIv,
          expiresAt: new Date(Date.now() + 3600000),
        })
      ).rejects.toThrow(/check_iv_length/);
    });

    it('enforces check_expires_after_created (rejects expires_at <= created_at)', async () => {
      await expect(
        db.insert(secrets).values({
          tokenHash: hashToken(crypto.randomBytes(32)),
          revokeTokenHash: validRevokeTokenHash,
          ciphertext: validCiphertext,
          iv: validIv,
          // expiresAt in the past relative to now/createdAt
          expiresAt: sql`NOW() - INTERVAL '1 hour'`,
        })
      ).rejects.toThrow(/check_expires_after_created/);
    });

    it('enforces unique index secrets_token_hash_idx', async () => {
      const sharedHash = validTokenHash;

      await db.insert(secrets).values({
        tokenHash: sharedHash,
        revokeTokenHash: validRevokeTokenHash,
        ciphertext: validCiphertext,
        iv: validIv,
        expiresAt: new Date(Date.now() + 3600000),
      });

      await expect(
        db.insert(secrets).values({
          tokenHash: sharedHash, // Duplicate token hash
          revokeTokenHash: hashToken(crypto.randomBytes(32)),
          ciphertext: validCiphertext,
          iv: validIv,
          expiresAt: new Date(Date.now() + 3600000),
        })
      ).rejects.toThrow(/secrets_token_hash_idx/);
    });
  });
});
