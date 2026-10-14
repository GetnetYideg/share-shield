import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../db/schema.js';
import { SecretsRepository } from './secrets.repository.js';
import type { CreateSecretInput } from './secrets.schemas.js';
import {
  hashTokenFromBase64Url,
  decodeBase64Url,
} from '../../lib/crypto.js';
import { SecretUnavailableError, ValidationError } from '../../lib/errors.js';

export interface SecretCreatedResult {
  created: boolean;
  expiresAt: Date;
}

export interface SecretStatusResult {
  available: boolean;
  expiresAt: Date;
}

export class SecretsService {
  constructor(private readonly repository: SecretsRepository = new SecretsRepository()) {}

  /**
   * Encapsulates secret creation logic (FR-01, FR-04).
   * 1. Decodes and hashes token and revokeToken with SHA-256 (Invariant 1).
   * 2. Decodes ciphertext and IV from canonical base64url.
   * 3. Persists record in PostgreSQL with DB-evaluated expiresAt.
   * 4. Masks duplicate token hash collision (Phase 1 decision 3h).
   */
  async createSecret(
    db: NodePgDatabase<typeof schema>,
    input: CreateSecretInput
  ): Promise<SecretCreatedResult> {
    const tokenHash = hashTokenFromBase64Url(input.token, 'token');
    const revokeTokenHash = hashTokenFromBase64Url(input.revokeToken, 'revokeToken');
    const ciphertext = decodeBase64Url(input.ciphertext, undefined, 'ciphertext');
    const iv = decodeBase64Url(input.iv, 12, 'iv');

    try {
      const created = await this.repository.create(db, {
        tokenHash,
        revokeTokenHash,
        ciphertext,
        iv,
        expiresInSeconds: input.expiresInSeconds,
        payloadVersion: input.payloadVersion,
      });

      return {
        created: true,
        expiresAt: created.expiresAt,
      };
    } catch (err) {
      // Postgres error code 23505 = unique_violation
      const pgError = err as { code?: string; constraint?: string };
      if (pgError.code === '23505' || pgError.constraint === 'secrets_token_hash_idx') {
        // Phase 1 decision 3h: Never confirm or deny token existence on duplicate collision
        throw new ValidationError('Request could not be processed.');
      }
      throw err;
    }
  }

  /**
   * Retrieves secret availability status without exposing sensitive payloads (FR-05, Invariant 4).
   * Returns generic 404 SECRET_UNAVAILABLE if missing, expired, consumed, or revoked.
   */
  async getSecretStatus(
    db: NodePgDatabase<typeof schema>,
    token: string
  ): Promise<SecretStatusResult> {
    const tokenHash = hashTokenFromBase64Url(token, 'token');
    const record = await this.repository.findForStatus(db, tokenHash);

    if (!record) {
      throw new SecretUnavailableError();
    }

    // Invariant 4: Uniform masking for consumed, revoked, or expired secrets
    if (record.consumedAt !== null || record.revokedAt !== null) {
      throw new SecretUnavailableError();
    }

    if (record.expiresAt.getTime() <= Date.now()) {
      throw new SecretUnavailableError();
    }

    return {
      available: true,
      expiresAt: record.expiresAt,
    };
  }
}
