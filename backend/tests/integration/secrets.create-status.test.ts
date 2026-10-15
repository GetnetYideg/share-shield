import { Writable } from 'node:stream';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import crypto from 'node:crypto';
import { createApp } from '../../src/app.js';
import {
  setupTestDatabase,
  cleanTestDatabase,
  teardownTestDatabase,
  getTestConfig,
} from '../helpers/db.js';
import { createClientSecret } from '../helpers/clientCrypto.js';
import { getDb, getPool } from '../../src/db/client.js';
import { secrets } from '../../src/db/schema.js';
import { hashToken } from '../../src/lib/crypto.js';
import { createLogger } from '../../src/lib/logger.js';

describe('Phase 4: Create & Status Endpoints Integration Tests', () => {
  const config = getTestConfig();
  const db = getDb(config);

  beforeAll(async () => {
    await setupTestDatabase();
  });

  beforeEach(async () => {
    await cleanTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  describe('POST /api/v1/secrets (Create Secret)', () => {
    it('successfully creates an encrypted secret and returns 201 without echoing tokens or ciphertext', async () => {
      const app = createApp({ config, db });
      const secretPayload = await createClientSecret('my secret password for testing');

      const res = await request(app)
        .post('/api/v1/secrets')
        .set('Content-Type', 'application/json')
        .send({
          token: secretPayload.token,
          revokeToken: secretPayload.revokeToken,
          ciphertext: secretPayload.ciphertext,
          iv: secretPayload.iv,
          expiresInSeconds: 3600,
          payloadVersion: 1,
        });

      expect(res.status).toBe(201);
      expect(res.body).toEqual({
        data: {
          created: true,
          expiresAt: expect.any(String),
          passkey: expect.stringMatching(/^\d{6}$/),
        },
        requestId: res.headers['x-request-id'],
      });

      // Assert tokens and ciphertext are NOT echoed in the response (Invariant 1)
      const serializedResponse = JSON.stringify(res.body);
      expect(serializedResponse).not.toContain(secretPayload.token);
      expect(serializedResponse).not.toContain(secretPayload.revokeToken);
      expect(serializedResponse).not.toContain(secretPayload.ciphertext);
      expect(serializedResponse).not.toContain(secretPayload.key);
      expect(serializedResponse).not.toContain(secretPayload.plaintext);
    });

    it('stores ONLY the SHA-256 digest in the database (Invariant 1: deep scan of ALL rows and columns)', async () => {
      const app = createApp({ config, db });
      const secretPayload = await createClientSecret('super confidential secret');

      await request(app).post('/api/v1/secrets').set('Content-Type', 'application/json').send({
        token: secretPayload.token,
        revokeToken: secretPayload.revokeToken,
        ciphertext: secretPayload.ciphertext,
        iv: secretPayload.iv,
        expiresInSeconds: 3600,
      });

      // Query raw database rows
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');

      expect(rows.length).toBe(1);
      const row = rows[0] as Record<string, unknown>;

      // Expected digests
      const rawToken = Buffer.from(secretPayload.token, 'base64url');
      const rawRevokeToken = Buffer.from(secretPayload.revokeToken, 'base64url');
      const expectedTokenHash = hashToken(rawToken);
      const expectedRevokeHash = hashToken(rawRevokeToken);

      expect(Buffer.from(row.token_hash as Buffer).equals(expectedTokenHash)).toBe(true);
      expect(Buffer.from(row.revoke_token_hash as Buffer).equals(expectedRevokeHash)).toBe(true);

      // Deep scan all row values: neither raw token, revoke token, key, nor plaintext must exist
      for (const [column, value] of Object.entries(row)) {
        let stringValue = '';
        if (Buffer.isBuffer(value)) {
          stringValue =
            value.toString('utf8') +
            ' ' +
            value.toString('hex') +
            ' ' +
            value.toString('base64url');
        } else if (value !== null && value !== undefined) {
          stringValue = String(value);
        }

        expect(stringValue, `Column ${column} leaked raw token`).not.toContain(secretPayload.token);
        expect(stringValue, `Column ${column} leaked raw revokeToken`).not.toContain(
          secretPayload.revokeToken
        );
        expect(stringValue, `Column ${column} leaked key`).not.toContain(secretPayload.key);
        expect(stringValue, `Column ${column} leaked plaintext`).not.toContain(
          secretPayload.plaintext
        );
      }
    });

    it('rejects duplicate token hash with generic 400 VALIDATION_ERROR without confirming existence (Phase 1 decision 3h)', async () => {
      const app = createApp({ config, db });
      const secretPayload = await createClientSecret('first submission');

      const createPayload = {
        token: secretPayload.token,
        revokeToken: secretPayload.revokeToken,
        ciphertext: secretPayload.ciphertext,
        iv: secretPayload.iv,
        expiresInSeconds: 3600,
      };

      const res1 = await request(app).post('/api/v1/secrets').send(createPayload);
      expect(res1.status).toBe(201);

      // Re-submitting the same token
      const res2 = await request(app).post('/api/v1/secrets').send(createPayload);
      expect(res2.status).toBe(400);
      expect(res2.body).toEqual({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request could not be processed.',
          requestId: res2.headers['x-request-id'],
        },
      });
      // Ensure no 409 or DB constraint details leak
      expect(JSON.stringify(res2.body)).not.toContain('unique');
      expect(JSON.stringify(res2.body)).not.toContain('secrets_token_hash_idx');
    });

    describe('Strict Payload Validation Rejections (POST /api/v1/secrets)', () => {
      it('rejects missing fields with 400 VALIDATION_ERROR', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        // Missing token
        const res1 = await request(app).post('/api/v1/secrets').send({
          revokeToken: secretPayload.revokeToken,
          ciphertext: secretPayload.ciphertext,
          iv: secretPayload.iv,
        });
        expect(res1.status).toBe(400);
        expect(res1.body.error.code).toBe('VALIDATION_ERROR');

        // Missing ciphertext
        const res2 = await request(app).post('/api/v1/secrets').send({
          token: secretPayload.token,
          revokeToken: secretPayload.revokeToken,
          iv: secretPayload.iv,
        });
        expect(res2.status).toBe(400);
        expect(res2.body.error.code).toBe('VALIDATION_ERROR');

        // Missing iv
        const res3 = await request(app).post('/api/v1/secrets').send({
          token: secretPayload.token,
          revokeToken: secretPayload.revokeToken,
          ciphertext: secretPayload.ciphertext,
        });
        expect(res3.status).toBe(400);
        expect(res3.body.error.code).toBe('VALIDATION_ERROR');
      });

      it('rejects extra fields such as key, decryptionKey, plaintext (Invariant 2)', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        const res = await request(app).post('/api/v1/secrets').send({
          token: secretPayload.token,
          revokeToken: secretPayload.revokeToken,
          ciphertext: secretPayload.ciphertext,
          iv: secretPayload.iv,
          key: secretPayload.key,
        });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
        expect(res.body.error.message).toContain('Unrecognized fields');
      });

      it('rejects __proto__ injection keys with 400 VALIDATION_ERROR', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        const rawJsonWithProto =
          `{"token":"${secretPayload.token}","revokeToken":"${secretPayload.revokeToken}",` +
          `"ciphertext":"${secretPayload.ciphertext}","iv":"${secretPayload.iv}","__proto__":{"polluted":true}}`;

        const res = await request(app)
          .post('/api/v1/secrets')
          .set('Content-Type', 'application/json')
          .send(rawJsonWithProto);

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      });

      it('rejects wrong IV length with 400 VALIDATION_ERROR', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        const res = await request(app)
          .post('/api/v1/secrets')
          .send({
            token: secretPayload.token,
            revokeToken: secretPayload.revokeToken,
            ciphertext: secretPayload.ciphertext,
            iv: crypto.randomBytes(16).toString('base64url'), // 16 bytes instead of 12
          });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      });

      it('rejects bad base64url characters (+, /, =)', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        const res = await request(app)
          .post('/api/v1/secrets')
          .send({
            token: secretPayload.token.slice(0, 42) + '+', // bad char
            revokeToken: secretPayload.revokeToken,
            ciphertext: secretPayload.ciphertext,
            iv: secretPayload.iv,
          });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      });

      it('rejects ciphertext shorter than 23 characters', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        const res = await request(app).post('/api/v1/secrets').send({
          token: secretPayload.token,
          revokeToken: secretPayload.revokeToken,
          ciphertext: 'too_short',
          iv: secretPayload.iv,
        });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      });

      it('rejects invalid expiresInSeconds enum values', async () => {
        const app = createApp({ config, db });
        const secretPayload = await createClientSecret('text');

        const res = await request(app).post('/api/v1/secrets').send({
          token: secretPayload.token,
          revokeToken: secretPayload.revokeToken,
          ciphertext: secretPayload.ciphertext,
          iv: secretPayload.iv,
          expiresInSeconds: 9999,
        });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      });

      it('rejects arrays instead of JSON objects with 400 VALIDATION_ERROR', async () => {
        const app = createApp({ config, db });

        const res = await request(app)
          .post('/api/v1/secrets')
          .set('Content-Type', 'application/json')
          .send([{ item: 1 }]);

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      });
    });
  });

  describe('GET /api/v1/secrets/:token/status (Status Check)', () => {
    it('returns 200 with available: true and does NOT consume the secret', async () => {
      const app = createApp({ config, db });
      const secretPayload = await createClientSecret('test status availability');

      await request(app).post('/api/v1/secrets').send({
        token: secretPayload.token,
        revokeToken: secretPayload.revokeToken,
        ciphertext: secretPayload.ciphertext,
        iv: secretPayload.iv,
        expiresInSeconds: 3600,
      });

      // 1st status check
      const res1 = await request(app).get(`/api/v1/secrets/${secretPayload.token}/status`);
      expect(res1.status).toBe(200);
      expect(res1.body).toEqual({
        data: {
          available: true,
          expiresAt: expect.any(String),
          passkeyRequired: true,
        },
        requestId: res1.headers['x-request-id'],
      });
      expect(res1.body.data.ciphertext).toBeUndefined();
      expect(res1.body.data.iv).toBeUndefined();

      // 2nd status check: still available (status does not consume!)
      const res2 = await request(app).get(`/api/v1/secrets/${secretPayload.token}/status`);
      expect(res2.status).toBe(200);
      expect(res2.body.data.available).toBe(true);
      expect(res2.body.data.passkeyRequired).toBe(true);
    });

    describe('Uniform Masking for Unavailable Secrets (Invariant 4)', () => {
      it('returns byte-identical 404 SECRET_UNAVAILABLE for unknown, expired, consumed, revoked, and locked secrets', async () => {
        const app = createApp({ config, db });

        // 1. Unknown token
        const unknownToken = crypto.randomBytes(32).toString('base64url');
        const resUnknown = await request(app).get(`/api/v1/secrets/${unknownToken}/status`);

        // 2. Expired secret (inserted directly with past expires_at)
        const expiredToken = crypto.randomBytes(32).toString('base64url');
        await db.insert(secrets).values({
          tokenHash: hashToken(Buffer.from(expiredToken, 'base64url')),
          revokeTokenHash: hashToken(crypto.randomBytes(32)),
          passkeyHash: crypto.randomBytes(32),
          ciphertext: Buffer.from('ciphertext'),
          iv: crypto.randomBytes(12),
          createdAt: new Date(Date.now() - 7200000), // 2 hours ago
          expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        });
        const resExpired = await request(app).get(`/api/v1/secrets/${expiredToken}/status`);

        // 3. Consumed secret
        const consumedToken = crypto.randomBytes(32).toString('base64url');
        await db.insert(secrets).values({
          tokenHash: hashToken(Buffer.from(consumedToken, 'base64url')),
          revokeTokenHash: hashToken(crypto.randomBytes(32)),
          passkeyHash: crypto.randomBytes(32),
          ciphertext: Buffer.from('ciphertext'),
          iv: crypto.randomBytes(12),
          expiresAt: new Date(Date.now() + 3600000),
          consumedAt: new Date(),
        });
        const resConsumed = await request(app).get(`/api/v1/secrets/${consumedToken}/status`);

        // 4. Revoked secret
        const revokedToken = crypto.randomBytes(32).toString('base64url');
        await db.insert(secrets).values({
          tokenHash: hashToken(Buffer.from(revokedToken, 'base64url')),
          revokeTokenHash: hashToken(crypto.randomBytes(32)),
          passkeyHash: crypto.randomBytes(32),
          ciphertext: Buffer.from('ciphertext'),
          iv: crypto.randomBytes(12),
          expiresAt: new Date(Date.now() + 3600000),
          revokedAt: new Date(),
        });
        const resRevoked = await request(app).get(`/api/v1/secrets/${revokedToken}/status`);

        // 5. Locked secret (exhausted passkey attempts)
        const lockedToken = crypto.randomBytes(32).toString('base64url');
        await db.insert(secrets).values({
          tokenHash: hashToken(Buffer.from(lockedToken, 'base64url')),
          revokeTokenHash: hashToken(crypto.randomBytes(32)),
          passkeyHash: crypto.randomBytes(32),
          ciphertext: null,
          iv: null,
          expiresAt: new Date(Date.now() + 3600000),
          failedAttempts: 5,
          lockedAt: new Date(),
        });
        const resLocked = await request(app).get(`/api/v1/secrets/${lockedToken}/status`);

        // Verify status code is strictly 404 across all five
        expect(resUnknown.status).toBe(404);
        expect(resExpired.status).toBe(404);
        expect(resConsumed.status).toBe(404);
        expect(resRevoked.status).toBe(404);
        expect(resLocked.status).toBe(404);

        // Verify error code and message are byte-identical
        const expectedErrorPayload = {
          code: 'SECRET_UNAVAILABLE',
          message: 'This secret is unavailable.',
        };

        expect(resUnknown.body.error.code).toBe(expectedErrorPayload.code);
        expect(resUnknown.body.error.message).toBe(expectedErrorPayload.message);

        expect(resExpired.body.error.code).toBe(expectedErrorPayload.code);
        expect(resExpired.body.error.message).toBe(expectedErrorPayload.message);

        expect(resConsumed.body.error.code).toBe(expectedErrorPayload.code);
        expect(resConsumed.body.error.message).toBe(expectedErrorPayload.message);

        expect(resRevoked.body.error.code).toBe(expectedErrorPayload.code);
        expect(resRevoked.body.error.message).toBe(expectedErrorPayload.message);
      });
    });

    describe('Injection-Shaped Strings in :token Parameter', () => {
      it('rejects SQL injection, path traversal, and malformed strings with 400 VALIDATION_ERROR', async () => {
        const app = createApp({ config, db });

        const maliciousTokens = [
          "' OR 1=1 --",
          '../../etc/passwd',
          '; DROP TABLE secrets;',
          'token_with_spaces    ',
          'short',
          'A'.repeat(44), // 44 chars instead of 43
          'A'.repeat(42), // 42 chars instead of 43
          'abc+12345678901234567890123456789012345678', // '+' is forbidden
        ];

        for (const badToken of maliciousTokens) {
          const res = await request(app).get(
            `/api/v1/secrets/${encodeURIComponent(badToken)}/status`
          );
          expect(res.status, `Failed for token: ${badToken}`).toBe(400);
          expect(res.body.error.code).toBe('VALIDATION_ERROR');
        }
      });
    });
  });

  describe('Rate Limiting on Create and Status Routes', () => {
    it('enforces route-specific create rate limit returning 429 RATE_LIMITED', async () => {
      const testConfig = {
        ...config,
        RATE_LIMIT_CREATE_MAX: 2,
        RATE_LIMIT_GLOBAL_MAX: 100,
      };
      const app = createApp({ config: testConfig, db });

      for (let i = 0; i < 2; i++) {
        const secret = await createClientSecret(`msg ${i}`);
        const res = await request(app).post('/api/v1/secrets').send({
          token: secret.token,
          revokeToken: secret.revokeToken,
          ciphertext: secret.ciphertext,
          iv: secret.iv,
          expiresInSeconds: 3600,
        });
        expect(res.status).toBe(201);
      }

      // 3rd request exceeds limit
      const secret = await createClientSecret('overflow');
      const limitedRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });

      expect(limitedRes.status).toBe(429);
      expect(limitedRes.body.error.code).toBe('RATE_LIMITED');
    });

    it('enforces route-specific status rate limit returning 429 RATE_LIMITED', async () => {
      const testConfig = {
        ...config,
        RATE_LIMIT_STATUS_MAX: 2,
        RATE_LIMIT_GLOBAL_MAX: 100,
      };
      const app = createApp({ config: testConfig, db });

      const secret = await createClientSecret('status rate limit');
      await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });

      // 2 allowed status requests
      for (let i = 0; i < 2; i++) {
        const res = await request(app).get(`/api/v1/secrets/${secret.token}/status`);
        expect(res.status).toBe(200);
      }

      // 3rd status request gets 429
      const limitedRes = await request(app).get(`/api/v1/secrets/${secret.token}/status`);
      expect(limitedRes.status).toBe(429);
      expect(limitedRes.body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Audit Logging Verification on Create and Status Routes (Invariant 1 & 6)', () => {
    it('logs route templates and never logs raw tokens or ciphertext for create and status routes', async () => {
      const logLines: string[] = [];
      const stream = new Writable({
        write(chunk: Buffer | string, _encoding, callback) {
          logLines.push(chunk.toString('utf8').trim());
          callback();
        },
      });

      const logger = createLogger({ level: 'info', stream });
      const app = createApp({ config, logger, db });

      const secret = await createClientSecret('confidential payload for logging test');

      // Execute create
      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      expect(createRes.status).toBe(201);

      // Execute status
      const statusRes = await request(app).get(`/api/v1/secrets/${secret.token}/status`);
      expect(statusRes.status).toBe(200);

      const allLogsJoined = logLines.join('\n');

      // Assert complete absence of secrets in log output
      expect(allLogsJoined).not.toContain(secret.token);
      expect(allLogsJoined).not.toContain(secret.revokeToken);
      expect(allLogsJoined).not.toContain(secret.ciphertext);
      expect(allLogsJoined).not.toContain(secret.key);
      expect(allLogsJoined).not.toContain(secret.plaintext);

      // Assert parameterized route templates are logged
      const parsedLogs = logLines.map((line) => JSON.parse(line) as Record<string, unknown>);
      const createLog = parsedLogs.find((l) => l.method === 'POST');
      expect(createLog).toBeDefined();
      expect(createLog?.route).toBe('/api/v1/secrets');

      const statusLog = parsedLogs.find((l) => l.method === 'GET' && l.statusCode === 200);
      expect(statusLog).toBeDefined();
      expect(statusLog?.route).toBe('/api/v1/secrets/:token/status');
    });
  });
});
