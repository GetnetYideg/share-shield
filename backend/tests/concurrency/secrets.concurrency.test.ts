import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import {
  setupTestDatabase,
  cleanTestDatabase,
  teardownTestDatabase,
  getTestConfig,
} from '../helpers/db.js';
import { createClientSecret, decryptClientSecret } from '../helpers/clientCrypto.js';
import { getDb, getPool } from '../../src/db/client.js';
import { createLogger } from '../../src/lib/logger.js';
import { runCleanupJob } from '../../src/jobs/cleanup.js';

describe('Phase 5: High-Concurrency & Race Condition Tests (Real PostgreSQL)', () => {
  // Use high rate limits for concurrency race testing
  const config = {
    ...getTestConfig(),
    RATE_LIMIT_GLOBAL_MAX: 10000,
    RATE_LIMIT_CONSUME_MAX: 10000,
    RATE_LIMIT_REVOKE_MAX: 10000,
    RATE_LIMIT_CREATE_MAX: 10000,
  };
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

  describe('Concurrent Consume Races (50 Parallel Requests)', () => {
    // Run the concurrency stress test across 3 separate iterations to prove no race window
    it.each([1, 2, 3])(
      'iteration %i: exactly ONE consume request returns 200 and all others return 404',
      async (_iteration) => {
        const app = createApp({ config, db });
        const plaintext = `highly confidential message #${_iteration}`;
        const secret = await createClientSecret(plaintext);

        // Create the secret
        const createRes = await request(app).post('/api/v1/secrets').send({
          token: secret.token,
          revokeToken: secret.revokeToken,
          ciphertext: secret.ciphertext,
          iv: secret.iv,
          expiresInSeconds: 3600,
        });
        expect(createRes.status).toBe(201);
        const passkey = createRes.body.data.passkey;

        // Fire 50 simultaneous parallel consume requests with valid passkey
        const concurrencyCount = 50;
        const requests = Array.from({ length: concurrencyCount }, () =>
          request(app)
            .post(`/api/v1/secrets/${secret.token}/consume`)
            .send({ passkey })
        );

        const responses = await Promise.all(requests);

        const successResponses = responses.filter((r) => r.status === 200);
        const unavailableResponses = responses.filter((r) => r.status === 404);

        // Invariant 3 & NFR-04: At-most-once consumption guarantee
        expect(successResponses.length).toBe(1);
        expect(unavailableResponses.length).toBe(concurrencyCount - 1);

        // Verify the winning response received valid payload and decrypted correctly
        const winner = successResponses[0]!;
        expect(winner.body.data.ciphertext).toBe(secret.ciphertext);
        expect(winner.body.data.iv).toBe(secret.iv);

        const decrypted = await decryptClientSecret(
          winner.body.data.ciphertext,
          winner.body.data.iv,
          secret.key
        );
        expect(decrypted).toBe(plaintext);

        // Verify all losing responses received uniform 404
        for (const loser of unavailableResponses) {
          expect(loser.body.error.code).toBe('SECRET_UNAVAILABLE');
          expect(loser.body.error.message).toBe('This secret is unavailable.');
        }

        // Verify database state: row has consumed_at and zeroized ciphertext/iv
        const pool = getPool(config);
        const { rows } = await pool.query('SELECT * FROM secrets;');
        expect(rows.length).toBe(1);
        const row = rows[0] as Record<string, unknown>;
        expect(row.consumed_at).not.toBeNull();
        expect(row.ciphertext).toBeNull();
        expect(row.iv).toBeNull();
      }
    );
  });

  describe('Concurrent Wrong Passkey Races (50 Parallel Requests)', () => {
    it('50 parallel wrong guesses produce exactly N PASSKEY_INVALID responses and the rest uniform 404', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('secret to lock via concurrency');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      expect(createRes.status).toBe(201);
      const realPasskey = createRes.body.data.passkey;
      const wrongPasskey = realPasskey === '123456' ? '654321' : '123456';

      // Fire 50 simultaneous parallel requests with the wrong passkey
      const concurrencyCount = 50;
      const requests = Array.from({ length: concurrencyCount }, () =>
        request(app)
          .post(`/api/v1/secrets/${secret.token}/consume`)
          .send({ passkey: wrongPasskey })
      );

      const responses = await Promise.all(requests);

      const invalidResponses = responses.filter((r) => r.status === 403);
      const unavailableResponses = responses.filter((r) => r.status === 404);

      // Default max attempts is 5: exactly 5 wrong guesses must register
      expect(invalidResponses.length).toBe(config.PASSKEY_MAX_ATTEMPTS);
      expect(unavailableResponses.length).toBe(concurrencyCount - config.PASSKEY_MAX_ATTEMPTS);

      // Exactly one response (the 5th attempt) must have attemptsRemaining: 0
      const lockingResponse = invalidResponses.filter(
        (r) => r.body.error.attemptsRemaining === 0
      );
      expect(lockingResponse.length).toBe(1);

      // Database state verification: row is locked, failed_attempts is 5, ciphertext wiped
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');
      expect(rows.length).toBe(1);
      const row = rows[0] as Record<string, unknown>;
      expect(row.locked_at).not.toBeNull();
      expect(row.failed_attempts).toBe(config.PASSKEY_MAX_ATTEMPTS);
      expect(row.ciphertext).toBeNull();
      expect(row.iv).toBeNull();
    });
  });

  describe('Concurrent Correct vs Wrong Passkey Races (50 Parallel Requests)', () => {
    it('racing correct and wrong guesses never yields more than one 200 or more than N counted attempts', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('mixed race secret');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      expect(createRes.status).toBe(201);
      const realPasskey = createRes.body.data.passkey;
      const wrongPasskey = realPasskey === '123456' ? '654321' : '123456';

      // 25 correct + 25 wrong parallel requests
      const correctRequests = Array.from({ length: 25 }, () =>
        request(app)
          .post(`/api/v1/secrets/${secret.token}/consume`)
          .send({ passkey: realPasskey })
      );
      const wrongRequests = Array.from({ length: 25 }, () =>
        request(app)
          .post(`/api/v1/secrets/${secret.token}/consume`)
          .send({ passkey: wrongPasskey })
      );

      // Interleave
      const mixedRequests: Promise<request.Response>[] = [];
      while (correctRequests.length > 0 || wrongRequests.length > 0) {
        const c = correctRequests.shift();
        if (c) mixedRequests.push(c);
        const w = wrongRequests.shift();
        if (w) mixedRequests.push(w);
      }

      const responses = await Promise.all(mixedRequests);

      const successResponses = responses.filter((r) => r.status === 200);
      const invalidResponses = responses.filter((r) => r.status === 403);
      const unavailableResponses = responses.filter((r) => r.status === 404);

      // Invariants:
      // 1. At most one 200
      expect(successResponses.length).toBeLessThanOrEqual(1);
      // 2. At most PASSKEY_MAX_ATTEMPTS (5) 403s
      expect(invalidResponses.length).toBeLessThanOrEqual(config.PASSKEY_MAX_ATTEMPTS);
      // 3. All other requests are 404
      expect(
        successResponses.length + invalidResponses.length + unavailableResponses.length
      ).toBe(50);

      // Verify DB row integrity
      const pool = getPool(config);
      const { rows } = await pool.query('SELECT * FROM secrets;');
      expect(rows.length).toBe(1);
      const row = rows[0] as Record<string, unknown>;
      // Ciphertext must be wiped regardless of whether consume or lock won
      expect(row.ciphertext).toBeNull();
      expect(row.iv).toBeNull();
      expect(row.failed_attempts as number).toBeLessThanOrEqual(config.PASSKEY_MAX_ATTEMPTS);
    });
  });

  describe('Racing: Consume vs Revoke', () => {
    it('concurrently races consume against revoke: exactly ONE succeeds and the other fails', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('racing consume vs revoke');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      // Fire 10 simultaneous consume and 10 simultaneous revoke requests
      const consumeRequests = Array.from({ length: 10 }, () =>
        request(app)
          .post(`/api/v1/secrets/${secret.token}/consume`)
          .send({ passkey })
      );
      const revokeRequests = Array.from({ length: 10 }, () =>
        request(app)
          .delete(`/api/v1/secrets/${secret.token}`)
          .set('Authorization', `Bearer ${secret.revokeToken}`)
      );

      const allResponses = await Promise.all([...consumeRequests, ...revokeRequests]);

      const consumeSuccesses = allResponses.filter((r) => r.status === 200);
      const revokeSuccesses = allResponses.filter((r) => r.status === 204);

      // Either consume won OR revoke won; NEVER BOTH!
      const totalWinners = consumeSuccesses.length + revokeSuccesses.length;
      expect(totalWinners).toBe(1);

      if (consumeSuccesses.length === 1) {
        expect(revokeSuccesses.length).toBe(0);
      } else {
        expect(revokeSuccesses.length).toBe(1);
      }

      // All losing requests must be 404
      const losingResponses = allResponses.filter((r) => r.status === 404);
      expect(losingResponses.length).toBe(19);
    });
  });

  describe('Racing: Consume vs Cleanup', () => {
    it('concurrently races consume against cleanup without deadlocks', async () => {
      const app = createApp({ config, db });
      const secret = await createClientSecret('racing consume vs cleanup');

      const createRes = await request(app).post('/api/v1/secrets').send({
        token: secret.token,
        revokeToken: secret.revokeToken,
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        expiresInSeconds: 3600,
      });
      const passkey = createRes.body.data.passkey;

      const logger = createLogger({ level: 'silent' });

      // Fire simultaneous consume requests while running cleanup
      const consumePromise = Promise.all(
        Array.from({ length: 10 }, () =>
          request(app)
            .post(`/api/v1/secrets/${secret.token}/consume`)
            .send({ passkey })
        )
      );
      const cleanupPromise = runCleanupJob(db, { ...config, CLEANUP_RETENTION_HOURS: 0 }, logger);

      const [consumeResponses] = await Promise.all([consumePromise, cleanupPromise]);

      const successfulConsumes = consumeResponses.filter((r) => r.status === 200);
      // At most one consume succeeds
      expect(successfulConsumes.length).toBeLessThanOrEqual(1);

      for (const r of consumeResponses) {
        expect([200, 404]).toContain(r.status);
      }
    });
  });
});
