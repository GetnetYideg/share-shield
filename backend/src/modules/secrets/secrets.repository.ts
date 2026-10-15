import { eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../db/schema.js';
import { secrets } from '../../db/schema.js';
import { constantTimeEqual } from '../../lib/crypto.js';

export interface CreateSecretRepositoryInput {
  tokenHash: Buffer;
  revokeTokenHash: Buffer;
  passkeyHash: Buffer;
  ciphertext: Buffer;
  iv: Buffer;
  expiresInSeconds: number;
  payloadVersion?: number;
}

export interface CreatedSecretRecord {
  id: string;
  expiresAt: Date;
}

export interface SecretStatusRecord {
  id: string;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
  lockedAt: Date | null;
}

export interface SecretRevokeRecord {
  id: string;
  revokeTokenHash: Buffer;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
  lockedAt: Date | null;
}

export type ConsumeResult =
  | { status: 'UNAVAILABLE' }
  | { status: 'INVALID_PASSKEY'; attemptsRemaining: number }
  | { status: 'CONSUMED'; ciphertext: Buffer; iv: Buffer; payloadVersion: number };

function normalizeBytea(val: unknown): Buffer {
  if (Buffer.isBuffer(val)) {
    return val;
  }
  if (typeof val === 'string') {
    if (val.startsWith('\\x')) {
      return Buffer.from(val.slice(2), 'hex');
    }
    return Buffer.from(val, 'hex');
  }
  return Buffer.from(val as Uint8Array);
}

export class SecretsRepository {
  /**
   * Persists a new encrypted secret envelope with its peppered passkey hash.
   * Expiry timestamp is strictly derived from PostgreSQL database time (NOW()) per Invariant 5.
   */
  async create(
    db: NodePgDatabase<typeof schema>,
    input: CreateSecretRepositoryInput
  ): Promise<CreatedSecretRecord> {
    const payloadVersion = input.payloadVersion ?? 1;

    const [inserted] = await db
      .insert(secrets)
      .values({
        tokenHash: input.tokenHash,
        revokeTokenHash: input.revokeTokenHash,
        passkeyHash: input.passkeyHash,
        failedAttempts: 0,
        ciphertext: input.ciphertext,
        iv: input.iv,
        payloadVersion,
        maxViews: 1,
        // Invariant 5: Expiry evaluated strictly in database time
        expiresAt: sql`NOW() + (${input.expiresInSeconds} * INTERVAL '1 second')`,
      })
      .returning({
        id: secrets.id,
        expiresAt: secrets.expiresAt,
      });

    if (!inserted) {
      throw new Error('Failed to insert secret record.');
    }

    return inserted;
  }

  /**
   * Queries secret availability status.
   * NON-NEGOTIABLE SECURITY INVARIANT:
   * Selects ONLY status metadata (id, expiresAt, consumedAt, revokedAt, lockedAt).
   * NEVER selects ciphertext, iv, or keys (Invariant 1 & FR-05).
   */
  async findForStatus(
    db: NodePgDatabase<typeof schema>,
    tokenHash: Buffer
  ): Promise<SecretStatusRecord | null> {
    const [record] = await db
      .select({
        id: secrets.id,
        expiresAt: secrets.expiresAt,
        consumedAt: secrets.consumedAt,
        revokedAt: secrets.revokedAt,
        lockedAt: secrets.lockedAt,
      })
      .from(secrets)
      .where(eq(secrets.tokenHash, tokenHash))
      .limit(1);

    return record ?? null;
  }

  /**
   * Atomically verifies the passkey, updates attempt counters or consumes the secret
   * within a single PostgreSQL transaction with row-level locking (FOR UPDATE).
   * - If unavailable (missing, expired, consumed, revoked, locked): returns { status: 'UNAVAILABLE' }.
   * - If candidate passkey matches: marks consumed_at = NOW(), zeroes ciphertext/iv, returns { status: 'CONSUMED' }.
   * - If candidate passkey mismatches: increments failed_attempts. If threshold reached, sets locked_at = NOW()
   *   and zeroes ciphertext/iv. Returns { status: 'INVALID_PASSKEY', attemptsRemaining }.
   */
  async consumeWithPasskey(
    db: NodePgDatabase<typeof schema>,
    tokenHash: Buffer,
    candidatePasskeyHash: Buffer,
    maxAttempts: number
  ): Promise<ConsumeResult> {
    return db.transaction(async (tx) => {
      const result = await tx.execute(sql`
        SELECT id, ciphertext, iv, payload_version, passkey_hash, failed_attempts,
               (expires_at <= NOW()) AS is_expired,
               consumed_at, revoked_at, locked_at
        FROM secrets
        WHERE token_hash = ${tokenHash}
        FOR UPDATE
      `);

      if (result.rows.length === 0) {
        return { status: 'UNAVAILABLE' };
      }

      const row = result.rows[0] as {
        id: string;
        ciphertext: unknown;
        iv: unknown;
        payload_version: number;
        passkey_hash: unknown;
        failed_attempts: number;
        is_expired: boolean;
        consumed_at: unknown;
        revoked_at: unknown;
        locked_at: unknown;
      };

      if (
        row.is_expired ||
        row.consumed_at !== null ||
        row.revoked_at !== null ||
        row.locked_at !== null
      ) {
        return { status: 'UNAVAILABLE' };
      }

      const storedPasskeyHash = normalizeBytea(row.passkey_hash);
      const isMatch = constantTimeEqual(candidatePasskeyHash, storedPasskeyHash);

      if (isMatch) {
        await tx.execute(sql`
          UPDATE secrets
          SET consumed_at = NOW(),
              ciphertext = NULL,
              iv = NULL
          WHERE id = ${row.id}
        `);

        return {
          status: 'CONSUMED',
          ciphertext: normalizeBytea(row.ciphertext),
          iv: normalizeBytea(row.iv),
          payloadVersion: Number(row.payload_version),
        };
      } else {
        const currentFailed = Number(row.failed_attempts);
        const newFailed = currentFailed + 1;
        const isLocked = newFailed >= maxAttempts;

        await tx.execute(sql`
          UPDATE secrets
          SET failed_attempts = ${newFailed},
              locked_at = CASE WHEN ${isLocked} THEN NOW() ELSE NULL END,
              ciphertext = CASE WHEN ${isLocked} THEN NULL ELSE ciphertext END,
              iv = CASE WHEN ${isLocked} THEN NULL ELSE iv END
          WHERE id = ${row.id}
        `);

        const attemptsRemaining = Math.max(0, maxAttempts - newFailed);
        return {
          status: 'INVALID_PASSKEY',
          attemptsRemaining,
        };
      }
    });
  }

  /**
   * Queries metadata required for revocation authorization.
   * NEVER selects ciphertext or iv.
   */
  async findForRevoke(
    db: NodePgDatabase<typeof schema>,
    tokenHash: Buffer
  ): Promise<SecretRevokeRecord | null> {
    const [record] = await db
      .select({
        id: secrets.id,
        revokeTokenHash: secrets.revokeTokenHash,
        expiresAt: secrets.expiresAt,
        consumedAt: secrets.consumedAt,
        revokedAt: secrets.revokedAt,
        lockedAt: secrets.lockedAt,
      })
      .from(secrets)
      .where(eq(secrets.tokenHash, tokenHash))
      .limit(1);

    if (!record) {
      return null;
    }

    return {
      id: record.id,
      revokeTokenHash: normalizeBytea(record.revokeTokenHash),
      expiresAt: record.expiresAt,
      consumedAt: record.consumedAt,
      revokedAt: record.revokedAt,
      lockedAt: record.lockedAt,
    };
  }

  /**
   * Atomically marks a secret as revoked and wipes ciphertext and IV (Phase 1 decision 3g).
   */
  async revoke(db: NodePgDatabase<typeof schema>, id: string): Promise<boolean> {
    const result = await db.execute(sql`
      UPDATE secrets
      SET revoked_at = NOW(),
          ciphertext = NULL,
          iv = NULL
      WHERE id = ${id}
        AND revoked_at IS NULL
        AND consumed_at IS NULL
        AND locked_at IS NULL
        AND expires_at > NOW()
      RETURNING id;
    `);

    return result.rows.length > 0;
  }

  /**
   * Batch deletes expired, consumed, revoked, and locked records exceeding retention period.
   * Safe across multiple instances via FOR UPDATE SKIP LOCKED.
   */
  async cleanupExpiredAndConsumed(
    db: NodePgDatabase<typeof schema>,
    retentionHours: number,
    batchSize = 1000
  ): Promise<number> {
    const result = await db.execute(sql`
      DELETE FROM secrets
      WHERE id IN (
        SELECT id
        FROM secrets
        WHERE (
          (consumed_at IS NOT NULL AND consumed_at <= NOW() - (${retentionHours} || ' hours')::interval)
          OR (revoked_at IS NOT NULL AND revoked_at <= NOW() - (${retentionHours} || ' hours')::interval)
          OR (locked_at IS NOT NULL AND locked_at <= NOW() - (${retentionHours} || ' hours')::interval)
          OR (expires_at <= NOW() - (${retentionHours} || ' hours')::interval)
        )
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING id;
    `);

    return result.rows.length;
  }
}
