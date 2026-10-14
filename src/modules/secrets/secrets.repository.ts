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
}
