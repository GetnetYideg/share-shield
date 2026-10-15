import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../db/schema.js';
import { SecretsRepository } from './secrets.repository.js';
import type { CreateSecretInput } from './secrets.schemas.js';
import {
  hashTokenFromBase64Url,
  decodeBase64Url,
  constantTimeEqual,
  generatePasskey,
  hashPasskey,
} from '../../lib/crypto.js';
import {
  SecretUnavailableError,
  ValidationError,
  RevokeNotAuthorizedError,
  PasskeyInvalidError,
} from '../../lib/errors.js';
import { parseEnv, type AppConfig } from '../../config/env.js';

export interface SecretCreatedResult {
  created: boolean;
  expiresAt: Date;
  passkey: string;
}

export interface SecretStatusResult {
  available: boolean;
  expiresAt: Date;
  passkeyRequired: true;
}

export interface SecretConsumedResult {
  ciphertext: string;
  iv: string;
  payloadVersion: number;
}

export class SecretsService {
  private readonly config: AppConfig;

  constructor(
    private readonly repository: SecretsRepository = new SecretsRepository(),
    config?: AppConfig
  ) {
    this.config = config ?? parseEnv(process.env);
  }

  /**
   * Encapsulates secret creation logic (FR-01, FR-01b, FR-04).
   * 1. Decodes and hashes token and revokeToken with SHA-256 (Invariant 1).
   * 2. Generates cryptographically secure 6-digit passkey with CSPRNG.
   * 3. Hashes passkey bound to tokenHash with HMAC-SHA256 and PASSKEY_PEPPER.
   * 4. Decodes ciphertext and IV from canonical base64url.
   * 5. Persists record in PostgreSQL with DB-evaluated expiresAt.
   * 6. Returns generated passkey once in response (never stored in plaintext).
   */
  async createSecret(
    db: NodePgDatabase<typeof schema>,
    input: CreateSecretInput
  ): Promise<SecretCreatedResult> {
    const tokenHash = hashTokenFromBase64Url(input.token, 'token');
    const revokeTokenHash = hashTokenFromBase64Url(input.revokeToken, 'revokeToken');
    const ciphertext = decodeBase64Url(input.ciphertext, undefined, 'ciphertext');
    const iv = decodeBase64Url(input.iv, 12, 'iv');

    // Generate random 6-digit numeric passkey using CSPRNG
    const passkey = generatePasskey();
    const passkeyHash = hashPasskey(passkey, tokenHash, this.config.PASSKEY_PEPPER);

    try {
      const created = await this.repository.create(db, {
        tokenHash,
        revokeTokenHash,
        passkeyHash,
        ciphertext,
        iv,
        expiresInSeconds: input.expiresInSeconds,
        payloadVersion: input.payloadVersion,
      });

      return {
        created: true,
        expiresAt: created.expiresAt,
        passkey,
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
   * Returns generic 404 SECRET_UNAVAILABLE if missing, expired, consumed, revoked, or locked.
   * Returns passkeyRequired: true on active secrets.
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

    // Invariant 4: Uniform masking for consumed, revoked, locked, or expired secrets
    if (record.consumedAt !== null || record.revokedAt !== null || record.lockedAt !== null) {
      throw new SecretUnavailableError();
    }

    if (record.expiresAt.getTime() <= Date.now()) {
      throw new SecretUnavailableError();
    }

    return {
      available: true,
      expiresAt: record.expiresAt,
      passkeyRequired: true,
    };
  }

  /**
   * Atomically verifies the 6-digit passkey and consumes secret in PostgreSQL (FR-06, Invariant 3).
   * - Success: Returns ciphertext and IV exactly once, zeroizing them in the database.
   * - Wrong passkey on active secret: Returns 403 PASSKEY_INVALID with remaining attempts.
   *   When attempts are exhausted, the secret is locked and destroyed.
   * - Unavailable (unknown, expired, consumed, revoked, locked): Uniform 404 SECRET_UNAVAILABLE.
   */
  async consumeSecret(
    db: NodePgDatabase<typeof schema>,
    token: string,
    passkey: string
  ): Promise<SecretConsumedResult> {
    const tokenHash = hashTokenFromBase64Url(token, 'token');
    const candidatePasskeyHash = hashPasskey(passkey, tokenHash, this.config.PASSKEY_PEPPER);

    const result = await this.repository.consumeWithPasskey(
      db,
      tokenHash,
      candidatePasskeyHash,
      this.config.PASSKEY_MAX_ATTEMPTS
    );

    if (result.status === 'UNAVAILABLE') {
      throw new SecretUnavailableError();
    }

    if (result.status === 'INVALID_PASSKEY') {
      throw new PasskeyInvalidError(result.attemptsRemaining);
    }

    return {
      ciphertext: result.ciphertext.toString('base64url'),
      iv: result.iv.toString('base64url'),
      payloadVersion: result.payloadVersion,
    };
  }

  /**
   * Revokes an active secret using the creator's revoke capability (FR-09, Phase 1 decision 3a & 3b).
   * Compares hashes using constant-time comparison (crypto.timingSafeEqual).
   * Follows non-oracle rules: returns 404 if secret is already unavailable (expired/consumed/revoked/locked/unknown).
   * Returns 403 if secret is available but revoke token is invalid.
   */
  async revokeSecret(
    db: NodePgDatabase<typeof schema>,
    token: string,
    rawRevokeToken: string
  ): Promise<void> {
    const tokenHash = hashTokenFromBase64Url(token, 'token');
    const expectedRevokeHash = hashTokenFromBase64Url(rawRevokeToken, 'revokeToken');

    const record = await this.repository.findForRevoke(db, tokenHash);

    // Phase 1 non-oracle rule: if secret is unavailable, return 404 regardless of revoke token
    if (
      !record ||
      record.consumedAt !== null ||
      record.revokedAt !== null ||
      record.lockedAt !== null
    ) {
      throw new SecretUnavailableError();
    }

    if (record.expiresAt.getTime() <= Date.now()) {
      throw new SecretUnavailableError();
    }

    // Constant-time hash verification against timing attacks (TH-09)
    if (!constantTimeEqual(record.revokeTokenHash, expectedRevokeHash)) {
      throw new RevokeNotAuthorizedError();
    }

    const revoked = await this.repository.revoke(db, record.id);
    if (!revoked) {
      throw new SecretUnavailableError();
    }
  }

  /**
   * Cleans up expired, consumed, revoked, and locked records exceeding the retention period.
   */
  async cleanupExpired(
    db: NodePgDatabase<typeof schema>,
    retentionHours: number,
    batchSize = 1000
  ): Promise<number> {
    return this.repository.cleanupExpiredAndConsumed(db, retentionHours, batchSize);
  }
}
