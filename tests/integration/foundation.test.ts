import { Writable } from 'node:stream';
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { z } from 'zod';
import { createApp } from '../../src/app.js';
import { parseEnv, type AppConfig } from '../../src/config/env.js';
import { createLogger } from '../../src/lib/logger.js';
import { validateRequest } from '../../src/middleware/validate.js';

function createTestConfig(overrides: Partial<Record<string, string>> = {}): AppConfig {
  return parseEnv({
    NODE_ENV: 'test',
    PORT: '3000',
    DATABASE_URL: 'postgresql://user:pass@localhost:5432/onevault_test',
    CORS_ALLOWED_ORIGINS: 'http://localhost:5173',
    TRUST_PROXY: 'false',
    IP_HASH_SALT: '0123456789abcdef0123456789abcdef',
    LOG_LEVEL: 'info',
    ...overrides,
  });
}

function createMemoryLogCollector(): {
  lines: string[];
  stream: Writable;
} {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      for (const line of text.split('\n')) {
        if (line.trim().length > 0) {
          lines.push(line.trim());
        }
      }
      callback();
    },
  });
  return { lines, stream };
}

function assertSecurityAndCacheHeaders(res: request.Response): void {
  expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(res.headers['referrer-policy']).toBe('no-referrer');
  expect(res.headers['x-content-type-options']).toBe('nosniff');
  expect(res.headers['x-frame-options']).toBe('DENY');
  expect(res.headers['permissions-policy']).toContain('camera=()');
  expect(res.headers['cache-control']).toBe(
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );
  expect(res.headers['pragma']).toBe('no-cache');
  expect(res.headers['expires']).toBe('0');
  expect(res.headers['surrogate-control']).toBe('no-store');
  expect(res.headers['x-powered-by']).toBeUndefined();
  expect(res.headers['x-request-id']).toMatch(/^req_[0-9a-f]{24}$/);
}

describe('Phase 2: Foundation & Security Baseline Integration Tests', () => {
  describe('GET /api/v1/health & Security Headers', () => {
    it('boots the application and responds 200 OK with minimal health payload and all security headers', async () => {
      const config = createTestConfig({ LOG_LEVEL: 'silent' });
      const app = createApp({ config });

      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      assertSecurityAndCacheHeaders(res);
      expect(res.body).toEqual({
        data: {
          status: 'ok',
        },
        requestId: res.headers['x-request-id'],
      });
      // Ensure no extra infrastructure details leak
      expect(Object.keys(res.body.data as Record<string, unknown>)).toEqual(['status']);
    });

    it('rejects unexpected query parameters on /api/v1/health with 400 VALIDATION_ERROR', async () => {
      const config = createTestConfig({ LOG_LEVEL: 'silent' });
      const app = createApp({ config });

      const res = await request(app).get('/api/v1/health?debug=true');

      expect(res.status).toBe(400);
      assertSecurityAndCacheHeaders(res);
      expect(res.body).toEqual({
        error: {
          code: 'VALIDATION_ERROR',
          message: expect.any(String),
          requestId: res.headers['x-request-id'],
        },
      });
    });

    it('enforces HTTPS and sets HSTS header in production mode', async () => {
      const prodConfig = createTestConfig({
        NODE_ENV: 'production',
        TRUST_PROXY: '1',
        LOG_LEVEL: 'silent',
      });
      const app = createApp({ config: prodConfig });

      // Plain HTTP request rejected in production
      const insecureRes = await request(app).get('/api/v1/health');
      expect(insecureRes.status).toBe(403);
      assertSecurityAndCacheHeaders(insecureRes);
      expect(insecureRes.body.error.code).toBe('HTTPS_REQUIRED');

      // HTTPS via trusted proxy succeeds and includes Strict-Transport-Security
      const secureRes = await request(app)
        .get('/api/v1/health')
        .set('X-Forwarded-Proto', 'https');
      expect(secureRes.status).toBe(200);
      assertSecurityAndCacheHeaders(secureRes);
      expect(secureRes.headers['strict-transport-security']).toContain('max-age=63072000');
    });
  });

  describe('Strict CORS Allow-List Enforcement', () => {
    it('allows configured Origin and sets Access-Control-Allow-Origin', async () => {
      const config = createTestConfig({
        CORS_ALLOWED_ORIGINS: 'http://localhost:5173',
        LOG_LEVEL: 'silent',
      });
      const app = createApp({ config });

      const res = await request(app)
        .get('/api/v1/health')
        .set('Origin', 'http://localhost:5173');

      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173');
    });

    it('rejects unknown Origin with 403 FORBIDDEN and omits Access-Control-Allow-Origin', async () => {
      const config = createTestConfig({
        CORS_ALLOWED_ORIGINS: 'http://localhost:5173',
        LOG_LEVEL: 'silent',
      });
      const app = createApp({ config });

      const res = await request(app)
        .get('/api/v1/health')
        .set('Origin', 'https://malicious.example.com');

      expect(res.status).toBe(403);
      assertSecurityAndCacheHeaders(res);
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      expect(res.body).toEqual({
        error: {
          code: 'FORBIDDEN',
          message: 'Origin is not allowed by CORS policy.',
          requestId: res.headers['x-request-id'],
        },
      });
    });
  });

  describe('JSON Body Parser, Size Limits & Content-Type Enforcement', () => {
    function createAppWithEchoRoute() {
      const config = createTestConfig({ LOG_LEVEL: 'silent', MAX_BODY_SIZE: '16kb' });
      const bodySchema = z
        .object({
          ciphertext: z.string().min(1),
        })
        .strict();

      return createApp({
        config,
        registerAdditionalRoutes: (app) => {
          app.post(
            '/api/v1/secrets',
            validateRequest({ body: bodySchema }),
            (req, res) => {
              res.status(201).json({ data: { created: true }, requestId: req.requestId });
            }
          );
        },
      });
    }

    it('returns 413 PAYLOAD_TOO_LARGE when JSON body exceeds 16kb', async () => {
      const app = createAppWithEchoRoute();
      const oversizedPayload = {
        ciphertext: 'A'.repeat(20 * 1024),
      };

      const res = await request(app)
        .post('/api/v1/secrets')
        .set('Content-Type', 'application/json')
        .send(oversizedPayload);

      expect(res.status).toBe(413);
      assertSecurityAndCacheHeaders(res);
      expect(res.body).toEqual({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'Request payload exceeds maximum allowed size.',
          requestId: res.headers['x-request-id'],
        },
      });
    });

    it('returns 400 VALIDATION_ERROR on malformed JSON without echoing the body', async () => {
      const app = createAppWithEchoRoute();
      const rawMalformedJson = '{"ciphertext": "SENSITIVE_UNCLOSED_STRING_12345';

      const res = await request(app)
        .post('/api/v1/secrets')
        .set('Content-Type', 'application/json')
        .send(rawMalformedJson);

      expect(res.status).toBe(400);
      assertSecurityAndCacheHeaders(res);
      expect(res.body).toEqual({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Malformed JSON in request body.',
          requestId: res.headers['x-request-id'],
        },
      });
      expect(JSON.stringify(res.body)).not.toContain('SENSITIVE_UNCLOSED_STRING_12345');
    });

    it('returns 415 UNSUPPORTED_MEDIA_TYPE when Content-Type is not application/json', async () => {
      const app = createAppWithEchoRoute();

      const res = await request(app)
        .post('/api/v1/secrets')
        .set('Content-Type', 'text/plain')
        .send('plain text body');

      expect(res.status).toBe(415);
      assertSecurityAndCacheHeaders(res);
      expect(res.body).toEqual({
        error: {
          code: 'UNSUPPORTED_MEDIA_TYPE',
          message: 'Request Content-Type must be application/json.',
          requestId: res.headers['x-request-id'],
        },
      });
    });

    it('rejects unknown fields in request body with 400 VALIDATION_ERROR (Invariant 2)', async () => {
      const app = createAppWithEchoRoute();

      const res = await request(app)
        .post('/api/v1/secrets')
        .set('Content-Type', 'application/json')
        .send({
          ciphertext: 'valid_ciphertext',
          decryptionKey: 'SECRET_KEY_THAT_MUST_BE_REJECTED',
        });

      expect(res.status).toBe(400);
      assertSecurityAndCacheHeaders(res);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(JSON.stringify(res.body)).not.toContain('SECRET_KEY_THAT_MUST_BE_REJECTED');
    });
  });

  describe('404 Handler & Error Format', () => {
    it('returns standard 404 error shape for unknown routes', async () => {
      const config = createTestConfig({ LOG_LEVEL: 'silent' });
      const app = createApp({ config });

      const res = await request(app).get('/api/v1/non-existent-endpoint');

      expect(res.status).toBe(404);
      assertSecurityAndCacheHeaders(res);
      expect(res.body).toEqual({
        error: {
          code: 'NOT_FOUND',
          message: 'The requested endpoint does not exist.',
          requestId: res.headers['x-request-id'],
        },
      });
    });
  });

  describe('Rate Limiting & X-Forwarded-For Spoofing Protection', () => {
    it('returns 429 RATE_LIMITED in standard format when rate limit is exceeded and resists spoofed X-Forwarded-For', async () => {
      const config = createTestConfig({
        LOG_LEVEL: 'silent',
        TRUST_PROXY: 'false',
        RATE_LIMIT_GLOBAL_MAX: '3',
        RATE_LIMIT_WINDOW_MS: '60000',
      });
      const app = createApp({ config });

      // 3 allowed requests
      for (let i = 1; i <= 3; i++) {
        const okRes = await request(app)
          .get('/api/v1/health')
          .set('X-Forwarded-For', `203.0.113.${i}`);
        expect(okRes.status).toBe(200);
      }

      // 4th request with a new spoofed X-Forwarded-For still gets rate-limited because TRUST_PROXY is false
      const limitedRes = await request(app)
        .get('/api/v1/health')
        .set('X-Forwarded-For', '198.51.100.99');

      expect(limitedRes.status).toBe(429);
      assertSecurityAndCacheHeaders(limitedRes);
      expect(limitedRes.headers['retry-after']).toBeDefined();
      expect(limitedRes.body).toEqual({
        error: {
          code: 'RATE_LIMITED',
          message: 'Rate limit exceeded. Please try again later.',
          requestId: limitedRes.headers['x-request-id'],
        },
      });
    });
  });

  describe('Audit-Safe Structured Logging & Redaction (Invariant 1 & 6)', () => {
    it('logs the route template and never logs raw tokens, keys, ciphertexts, bodies, headers, or query strings', async () => {
      const { lines, stream } = createMemoryLogCollector();
      const config = createTestConfig({ LOG_LEVEL: 'info' });
      const logger = createLogger({ level: 'info', stream });

      const app = createApp({
        config,
        logger,
        registerAdditionalRoutes: (expressApp) => {
          expressApp.post('/api/v1/secrets/:token/consume', (req, res) => {
            res.status(200).json({ data: { ok: true }, requestId: req.requestId });
          });
        },
      });

      const fakeUrlToken = 'FAKE_URL_SHARE_TOKEN_43_CHARS_ABCDEFGHIJKLM';
      const fakeBodyToken = 'FAKE_BODY_SHARE_TOKEN_SECRET_99999999999999';
      const fakeRevokeToken = 'FAKE_BEARER_REVOKE_TOKEN_SECRET_88888888888';
      const fakeEncryptionKey = 'FAKE_ENCRYPTION_KEY_FRAGMENT_77777777777777';
      const fakePlaintext = 'SUPER_SENSITIVE_PLAINTEXT_PASSWORD_66666666';
      const fakeCiphertext = 'FAKE_CIPHERTEXT_PAYLOAD_5555555555555555555';

      // 1. Hit matched parameterized route with sensitive data in path, query, header, and body
      const consumeRes = await request(app)
        .post(`/api/v1/secrets/${fakeUrlToken}/consume?key=${fakeEncryptionKey}`)
        .set('Authorization', `Bearer ${fakeRevokeToken}`)
        .set('Cookie', `session=${fakeEncryptionKey}`)
        .set('Content-Type', 'application/json')
        .send({
          token: fakeBodyToken,
          ciphertext: fakeCiphertext,
          plaintext: fakePlaintext,
          key: fakeEncryptionKey,
        });

      expect(consumeRes.status).toBe(200);

      // 2. Also hit an unmatched 404 route carrying a token in the URL path
      const unmatchedToken = 'UNMATCHED_RAW_PATH_TOKEN_SECRET_11111111111';
      const notFoundRes = await request(app).get(
        `/api/v1/secrets/${unmatchedToken}/unknown-subroute?secret=${fakePlaintext}`
      );
      expect(notFoundRes.status).toBe(404);

      expect(lines.length).toBeGreaterThanOrEqual(2);
      const allLogsJoined = lines.join('\n');

      // Assert NONE of the sensitive values appear anywhere in the logs
      expect(allLogsJoined).not.toContain(fakeUrlToken);
      expect(allLogsJoined).not.toContain(fakeBodyToken);
      expect(allLogsJoined).not.toContain(fakeRevokeToken);
      expect(allLogsJoined).not.toContain(fakeEncryptionKey);
      expect(allLogsJoined).not.toContain(fakePlaintext);
      expect(allLogsJoined).not.toContain(fakeCiphertext);
      expect(allLogsJoined).not.toContain(unmatchedToken);

      // Parse first log entry and verify required audit fields
      const firstLog = JSON.parse(lines[0]!) as Record<string, unknown>;
      expect(firstLog.requestId).toBe(consumeRes.headers['x-request-id']);
      expect(firstLog.method).toBe('POST');
      expect(firstLog.route).toBe('/api/v1/secrets/:token/consume');
      expect(firstLog.statusCode).toBe(200);
      expect(typeof firstLog.latencyMs).toBe('number');

      // Parse second log entry (404 unmatched route) and verify route is sanitized
      const secondLog = JSON.parse(lines[1]!) as Record<string, unknown>;
      expect(secondLog.requestId).toBe(notFoundRes.headers['x-request-id']);
      expect(secondLog.method).toBe('GET');
      expect(secondLog.route).toBe('UNMATCHED_ROUTE');
      expect(secondLog.statusCode).toBe(404);
      expect(secondLog.errorCode).toBe('NOT_FOUND');
    });
  });
});
