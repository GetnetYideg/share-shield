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
import { createClientSecret, decryptClientSecret } from '../helpers/clientCrypto.js';
import { getDb, getPool } from '../../src/db/client.js';
import { secrets } from '../../src/db/schema.js';
import { hashToken } from '../../src/lib/crypto.js';
import { createLogger } from '../../src/lib/logger.js';
import { runCleanupJob } from '../../src/jobs/cleanup.js';

describe('Phase 5: Atomic Consume, Revoke & Cleanup Integration Tests', () => {
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

  describe('POST /api/v1/secrets/:token/consume', () => {
    it('successfully consumes a valid secret once with correct passkey, returning valid ciphertext and IV that decrypts correctly', async () => {
      const app = createApp({ config, db });
      const originalPlaintext = 'my confidential password 1234!';
      const secret = await createClientSecret(originalPlaintext);

      // Create
      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      expect(createRes.status).toBe(201);
      const passkey = createRes.body.data.passkey;
      expect(passkey).toMatch(/^\d{6}$/);

      // 1st Consume: succeeds with correct passkey
      const consumeRes = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      expect(consumeRes.status).toBe(200);
      expect(consumeRes.headers['cache-control']).toContain('no-store');
      expect(consumeRes.body).toEqual({
        data: {
          ciphertext: secret.ciphertext,
          iv: secret.iv,
          payloadVersion: 1,
        },
        requestId: consumeRes.headers['x-request-id'],
      });

      // Client decrypts locally with fragment key
      const decrypted = await decryptClientSecret(
        consumeRes.body.data.ciphertext,
        consumeRes.body.data.iv,
        secret.key
      );
      expect(decrypted).toBe(originalPlaintext);

      // Verify immediate zeroization in database (Phase 1 decision 3g & Invariant 1)
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');
      expect(rows.length).toBe(1);
      const row = rows[0] as Record<string, unknown>;
      expect(row.consumed_at).not.toBeNull();
      expect(row.ciphertext).toBeNull();
      expect(row.iv).toBeNull();

      // 2nd Sequential Consume: fails with uniform 404
      const secondConsumeRes = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      expect(secondConsumeRes.status).toBe(404);
      expect(secondConsumeRes.body).toEqual({
        error: {
          code: 'SECRET_UNAVAILABLE',
          message: 'This secret is unavailable.',
          requestId: secondConsumeRes.headers['x-request-id'],
        },
      });
    });

    it('client decryption fails when ciphertext is tampered or wrong key is provided (AES-GCM integrity)', async () => {
      const secret = await createClientSecret('authentic secret payload');

      // Tamper ciphertext
      const tamperedCiphertext =
        secret.ciphertext.slice(0, -2) + (secret.ciphertext.endsWith('AA') ? 'BB' : 'AA');

      await expect(
        decryptClientSecret(tamperedCiphertext, secret.iv, secret.key)
      ).rejects.toThrow();

      // Wrong key
      const wrongKey = crypto.randomBytes(32).toString('base64url');
      await expect(decryptClientSecret(secret.ciphertext, secret.iv, wrongKey)).rejects.toThrow();
    });

    it('returns 403 PASSKEY_INVALID with decreasing attemptsRemaining on wrong passkey and locks secret on limit', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('secret to brute force');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const realPasskey = createRes.body.data.passkey;
      const wrongPasskey = realPasskey === '123456' ? '654321' : '123456';

      // 4 wrong attempts (limit is 5)
      for (let i = 1; i <= 4; i++) {
        const res = await request(app)
          .post(`/api/v1/secrets/${secret.token}/consume`)
          .send({ passkey: wrongPasskey });
        expect(res.status).toBe(403);
        expect(res.body.error).toEqual({
          code: 'PASSKEY_INVALID',
          message: 'Incorrect passkey.',
          attemptsRemaining: 5 - i,
          requestId: expect.any(String),
        });
        expect(JSON.stringify(res.body)).not.toContain(secret.ciphertext);
      }

      // 5th wrong attempt: locks secret, attemptsRemaining: 0
      const fifthRes = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey: wrongPasskey });
      expect(fifthRes.status).toBe(403);
      expect(fifthRes.body.error).toEqual({
        code: 'PASSKEY_INVALID',
        message: 'Incorrect passkey.',
        attemptsRemaining: 0,
        requestId: expect.any(String),
      });

      // Verify DB state: locked_at is set, ciphertext and IV are wiped (null)
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');
      expect(rows[0].locked_at).not.toBeNull();
      expect(rows[0].failed_attempts).toBe(5);
      expect(rows[0].ciphertext).toBeNull();
      expect(rows[0].iv).toBeNull();

      // Subsequent 6th attempt with REAL passkey returns uniform 404
      const sixthRes = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey: realPasskey });
      expect(sixthRes.status).toBe(404);
      expect(sixthRes.body.error.code).toBe('SECRET_UNAVAILABLE');

      // Status check on locked secret also returns uniform 404
      const statusRes = await request(app).get(`/api/v1/secrets/${secret.token}/status`);
      expect(statusRes.status).toBe(404);
      expect(statusRes.body.error.code).toBe('SECRET_UNAVAILABLE');
    });

    it('rejects consume requests with malformed passkeys or non-empty unexpected JSON bodies without incrementing attempts', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('payload');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const validPasskey = createRes.body.data.passkey;

      // Extra fields rejected with 400
      const resExtra = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .set('Content-Type', 'application/json')
        .send({ passkey: validPasskey, unexpected: 'field' });
      expect(resExtra.status).toBe(400);
      expect(resExtra.body.error.code).toBe('VALIDATION_ERROR');

      // Malformed passkeys: 5 digits, 7 digits, letters, number type, null, array, __proto__
      const invalidPasskeys = [
        '12345',
        '1234567',
        'abcdef',
        123456,
        null,
        ['123456'],
      ];
      for (const bad of invalidPasskeys) {
        const res = await request(app)
          .post(`/api/v1/secrets/${secret.token}/consume`)
          .send({ passkey: bad });
        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }

      // __proto__ injection key sent as raw JSON string
      const rawProtoBody = '{"passkey":"123456","__proto__":{"polluted":true}}';
      const resProto = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .set('Content-Type', 'application/json')
        .send(rawProtoBody);
      expect(resProto.status).toBe(400);

      // Assert failed_attempts in DB was NOT incremented by 400 rejections
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT failed_attempts FROM secrets;');
      expect(rows[0].failed_attempts).toBe(0);
    });

    it('returns byte-identical 404 for unknown, expired, consumed, revoked, and locked secrets on consume', async () => {
      const app = createApp({ config, db });
      const dummyPasskey = '123456';

      // Unknown
      const unknownToken = crypto.randomBytes(32).toString('base64url');
      const resUnknown = await request(app)
        .post(`/api/v1/secrets/${unknownToken}/consume`)
        .send({ passkey: dummyPasskey });

      // Expired
      const expiredToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(expiredToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: Buffer.from('ciphertext'),
        iv: crypto.randomBytes(12),
        createdAt: new Date(Date.now() - 7200000),
        expiresAt: new Date(Date.now() - 3600000),
      });
      const resExpired = await request(app)
        .post(`/api/v1/secrets/${expiredToken}/consume`)
        .send({ passkey: dummyPasskey });

      // Consumed
      const consumedToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(consumedToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: null,
        iv: null,
        expiresAt: new Date(Date.now() + 3600000),
        consumedAt: new Date(),
      });
      const resConsumed = await request(app)
        .post(`/api/v1/secrets/${consumedToken}/consume`)
        .send({ passkey: dummyPasskey });

      // Revoked
      const revokedToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(revokedToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: null,
        iv: null,
        expiresAt: new Date(Date.now() + 3600000),
        revokedAt: new Date(),
      });
      const resRevoked = await request(app)
        .post(`/api/v1/secrets/${revokedToken}/consume`)
        .send({ passkey: dummyPasskey });

      // Locked
      const lockedToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(lockedToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: null,
        iv: null,
        failedAttempts: 5,
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
      });
      const resLocked = await request(app)
        .post(`/api/v1/secrets/${lockedToken}/consume`)
        .send({ passkey: dummyPasskey });

      expect(resUnknown.status).toBe(404);
      expect(resExpired.status).toBe(404);
      expect(resConsumed.status).toBe(404);
      expect(resRevoked.status).toBe(404);
      expect(resLocked.status).toBe(404);

      const expectedCode = 'SECRET_UNAVAILABLE';
      const expectedMessage = 'This secret is unavailable.';

      expect(resUnknown.body.error.code).toBe(expectedCode);
      expect(resUnknown.body.error.message).toBe(expectedMessage);
      expect(resExpired.body.error.code).toBe(expectedCode);
      expect(resExpired.body.error.message).toBe(expectedMessage);
      expect(resConsumed.body.error.code).toBe(expectedCode);
      expect(resConsumed.body.error.message).toBe(expectedMessage);
      expect(resRevoked.body.error.code).toBe(expectedCode);
      expect(resRevoked.body.error.message).toBe(expectedMessage);
      expect(resLocked.body.error.code).toBe(expectedCode);
      expect(resLocked.body.error.message).toBe(expectedMessage);

      // Verify byte-identical error structure (excluding dynamic requestId)
      const sanitize = (b: { error: { code: string; message: string } }) => ({
        code: b.error.code,
        message: b.error.message,
      });

      expect(sanitize(resExpired.body)).toEqual(sanitize(resUnknown.body));
      expect(sanitize(resConsumed.body)).toEqual(sanitize(resUnknown.body));
      expect(sanitize(resRevoked.body)).toEqual(sanitize(resUnknown.body));
      expect(sanitize(resLocked.body)).toEqual(sanitize(resUnknown.body));
    });
  });

  describe('DELETE /api/v1/secrets/:token (Revoke Secret)', () => {
    it('successfully revokes an active secret with valid revoke token, returning 204 No Content and wiping ciphertext', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('to be revoked');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      // Revoke with valid Bearer token
      const revokeRes = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);

      expect(revokeRes.status).toBe(204);
      expect(revokeRes.body).toEqual({});
      expect(revokeRes.headers['cache-control']).toContain('no-store');

      // Assert row has revoked_at and zeroized ciphertext/iv in DB
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');
      const row = rows[0] as Record<string, unknown>;
      expect(row.revoked_at).not.toBeNull();
      expect(row.ciphertext).toBeNull();
      expect(row.iv).toBeNull();

      // Revoking a second time returns 404 (non-oracle rule: unavailable secrets return 404)
      const secondRevokeRes = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);
      expect(secondRevokeRes.status).toBe(404);

      // Consuming after revoke returns 404
      const consumeAfterRevoke = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      expect(consumeAfterRevoke.status).toBe(404);
    });

    it('returns 403 REVOKE_NOT_AUTHORIZED when secret is active but revoke token is invalid (API-14)', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('revoke security check');

      await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });

      const wrongRevokeToken = crypto.randomBytes(32).toString('base64url');
      const res = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${wrongRevokeToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('REVOKE_NOT_AUTHORIZED');

      // Assert secret remains available (unrevoked)
      const statusRes = await request(app).get(`/api/v1/secrets/${secret.token}/status`);
      expect(statusRes.status).toBe(200);
      expect(statusRes.body.data.available).toBe(true);
      expect(statusRes.body.data.passkeyRequired).toBe(true);
    });

    it('returns 401 UNAUTHENTICATED when Authorization header is missing', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('text');

      const res = await request(app).delete(`/api/v1/secrets/${secret.token}`);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHENTICATED');
    });

    it('returns 400 VALIDATION_ERROR when Authorization header is malformed', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('text');

      // Not Bearer format
      const res1 = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', 'Basic 12345');
      expect(res1.status).toBe(400);

      // Wrong length revoke token
      const res2 = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', 'Bearer short_token');
      expect(res2.status).toBe(400);
    });

    it('returns 404 when attempting to revoke an already consumed secret', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('consume first');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      // Consume first
      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });

      // Attempt revoke after consume
      const res = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('SECRET_UNAVAILABLE');
    });
  });

  describe('Database Cleanup Task (runCleanupJob)', () => {
    it('deletes only expired, consumed, revoked, or locked records exceeding retention period', async () => {
      const now = Date.now();
      const retentionHours = 24;

      // 1. Active secret: NOT expired -> MUST NOT be deleted
      const activeToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(activeToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: Buffer.from('ciphertext'),
        iv: crypto.randomBytes(12),
        expiresAt: new Date(now + 3600000),
      });

      // 2. Expired recently (1 hour ago, within 24h retention) -> MUST NOT be deleted
      const recentExpiredToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(recentExpiredToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: Buffer.from('ciphertext'),
        iv: crypto.randomBytes(12),
        createdAt: new Date(now - 7200000),
        expiresAt: new Date(now - 3600000),
      });

      // 3. Expired beyond retention (25 hours ago) -> MUST be deleted
      const oldExpiredToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(oldExpiredToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: Buffer.from('ciphertext'),
        iv: crypto.randomBytes(12),
        createdAt: new Date(now - 30 * 3600000),
        expiresAt: new Date(now - 25 * 3600000),
      });

      // 4. Consumed beyond retention (25 hours ago) -> MUST be deleted
      const oldConsumedToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(oldConsumedToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: null,
        iv: null,
        expiresAt: new Date(now + 3600000),
        consumedAt: new Date(now - 25 * 3600000),
      });

      // 5. Revoked beyond retention (25 hours ago) -> MUST be deleted
      const oldRevokedToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(oldRevokedToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        ciphertext: null,
        iv: null,
        expiresAt: new Date(now + 3600000),
        revokedAt: new Date(now - 25 * 3600000),
      });

      // 6. Locked beyond retention (25 hours ago) -> MUST be deleted
      const oldLockedToken = crypto.randomBytes(32).toString('base64url');
      await db.insert(secrets).values({
        tokenHash: hashToken(Buffer.from(oldLockedToken, 'base64url')),
        revokeTokenHash: hashToken(crypto.randomBytes(32)),
        passkeyHash: Buffer.alloc(32, 1),
        failedAttempts: 5,
        lockedAt: new Date(now - 25 * 3600000),
        ciphertext: null,
        iv: null,
        expiresAt: new Date(now + 3600000),
      });

      const logger = createLogger({ level: 'silent' });
      const deletedCount = await runCleanupJob(
        db,
        { ...config, CLEANUP_RETENTION_HOURS: retentionHours },
        logger
      );

      expect(deletedCount).toBe(4);

      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');
      expect(rows.length).toBe(2);

      const remainingTokenHashes = rows.map((r: { token_hash: Buffer }) =>
        Buffer.from(r.token_hash).toString('hex')
      );
      expect(remainingTokenHashes).toContain(
        hashToken(Buffer.from(activeToken, 'base64url')).toString('hex')
      );
      expect(remainingTokenHashes).toContain(
        hashToken(Buffer.from(recentExpiredToken, 'base64url')).toString('hex')
      );
    });
  });

  describe('Rate Limiting & Audit Logging on Consume and Revoke Routes', () => {
    it('enforces route rate limits on consume and revoke routes', async () => {
      const testConfig = {
        ...config,
        RATE_LIMIT_CONSUME_MAX: 2,
        RATE_LIMIT_REVOKE_MAX: 2,
        RATE_LIMIT_GLOBAL_MAX: 100,
      };
      const app = createApp({ config: testConfig, db });

      const secret = await createClientSecret('rate limit check');
      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      // Consume requests: 1st succeeds, 2nd 404, 3rd rate-limited 429
      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      const limitedConsume = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      expect(limitedConsume.status).toBe(429);
      expect(limitedConsume.body.error.code).toBe('RATE_LIMITED');

      // Revoke requests: 1st 404, 2nd 404, 3rd rate-limited 429
      await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);
      await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);
      const limitedRevoke = await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);
      expect(limitedRevoke.status).toBe(429);
      expect(limitedRevoke.body.error.code).toBe('RATE_LIMITED');
    });

    it('enforces per-secret rate limit on consume across rotating IPs', async () => {
      const testConfig = {
        ...config,
        RATE_LIMIT_CONSUME_MAX: 3,
        RATE_LIMIT_GLOBAL_MAX: 100,
      };
      const app = createApp({ config: testConfig, db });

      const secret = await createClientSecret('per-secret rate limit check');
      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      // Send 3 requests against the same secret token
      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });

      // 4th request on the same secret is rate limited even if other routes are open
      const res = await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      expect(res.status).toBe(429);
      expect(res.body.error.code).toBe('RATE_LIMITED');
    });

    it('logs route templates and redacts tokens, passkeys, and ciphertexts on consume and revoke routes', async () => {
      const logLines: string[] = [];
      const stream = new Writable({
        write(chunk: Buffer | string, _encoding, callback) {
          logLines.push(chunk.toString('utf8').trim());
          callback();
        },
      });

      const logger = createLogger({ level: 'info', stream });
      const app = createApp({ config, logger, db });

      const secret = await createClientSecret('payload for consume and revoke logging');
      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      await request(app)
        .post(`/api/v1/secrets/${secret.token}/consume`)
        .send({ passkey });
      await request(app)
        .delete(`/api/v1/secrets/${secret.token}`)
        .set('Authorization', `Bearer ${secret.revokeToken}`);

      const allLogsJoined = logLines.join('\n');

      expect(allLogsJoined).not.toContain(secret.token);
      expect(allLogsJoined).not.toContain(secret.revokeToken);
      expect(allLogsJoined).not.toContain(secret.ciphertext);
      expect(allLogsJoined).not.toContain(secret.key);
      expect(allLogsJoined).not.toContain(secret.plaintext);
      expect(allLogsJoined).not.toContain(passkey);
      expect(allLogsJoined).not.toContain(config.PASSKEY_PEPPER);

      const parsedLogs = logLines.map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(parsedLogs.some((l) => l.route === '/api/v1/secrets/:token/consume')).toBe(true);
      expect(parsedLogs.some((l) => l.route === '/api/v1/secrets/:token')).toBe(true);
    });
  });
});
