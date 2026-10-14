import { eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../db/schema.js';
import { secrets } from '../../db/schema.js';

export interface CreateSecretRepositoryInput {
  tokenHash: Buffer;
  revokeTokenHash: Buffer;
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
}

export interface SecretRevokeRecord {
  id: string;
  revokeTokenHash: Buffer;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
}

export interface ConsumedSecretRecord {
  ciphertext: Buffer;
  iv: Buffer;
  payloadVersion: number;
}

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
   * Persists a new encrypted secret envelope.
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
   * Selects ONLY status metadata (id, expiresAt, consumedAt, revokedAt).
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
      })
      .from(secrets)
      .where(eq(secrets.tokenHash, tokenHash))
      .limit(1);

    return record ?? null;
  }

  /**
   * Atomically claims and consumes a secret in a single conditional statement (Invariant 3 & Phase 1 decision 3g).
   * Atomically updates consumed_at = NOW(), wipes ciphertext = NULL, iv = NULL,
   * and returns the prior ciphertext and IV.
   * Guarantees at-most-once consumption: concurrent requests cannot both receive the payload.
   */
  async consume(
    db: NodePgDatabase<typeof schema>,
    tokenHash: Buffer
  ): Promise<ConsumedSecretRecord | null> {
    const result = await db.execute(sql`
      WITH target AS (
        SELECT id, ciphertext, iv, payload_version
        FROM secrets
        WHERE token_hash = ${tokenHash}
          AND consumed_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > NOW()
        FOR UPDATE
      )
      UPDATE secrets s
      SET consumed_at = NOW(),
          ciphertext = NULL,
          iv = NULL
      FROM target
      WHERE s.id = target.id
      RETURNING target.ciphertext, target.iv, target.payload_version;
    `);

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0] as {
      ciphertext: unknown;
      iv: unknown;
      payload_version: number;
    };

    return {
      ciphertext: normalizeBytea(row.ciphertext),
      iv: normalizeBytea(row.iv),
      payloadVersion: Number(row.payload_version),
    };
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
        AND expires_at > NOW()
      RETURNING id;
    `);

    return result.rows.length > 0;
  }

  /**
   * Batch deletes expired, consumed, and revoked records exceeding retention period.
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
