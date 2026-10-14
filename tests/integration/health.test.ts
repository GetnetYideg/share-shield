import { describe, it, expect } from 'vitest';
import request from 'supertest';
import type pg from 'pg';
import { createApp } from '../../src/app.js';
import { getTestConfig } from '../helpers/db.js';

describe('GET /api/v1/health with Database Liveness Probe', () => {
  const config = getTestConfig();

  it('returns 200 OK with status ok when database is responsive', async () => {
    const app = createApp({ config });

    const res = await request(app).get('/api/v1/health');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      data: {
        status: 'ok',
      },
      requestId: res.headers['x-request-id'],
    });
  });

  it('returns 503 Service Unavailable with status degraded when database fails, never leaking error details', async () => {
    const sensitiveDbError = 'FATAL: password authentication failed for user "secret_admin_user"';
    const failingMockPool = {
      query: async () => {
        throw new Error(sensitiveDbError);
      },
      on: () => {},
    } as unknown as pg.Pool;

    const app = createApp({
      config,
      pool: failingMockPool,
    });

    const res = await request(app).get('/api/v1/health');

    expect(res.status).toBe(503);
    expect(res.body).toEqual({
      data: {
        status: 'degraded',
      },
      requestId: res.headers['x-request-id'],
    });

    // CRITICAL: Ensure no sensitive database credentials or error strings leak
    const serializedResponse = JSON.stringify(res.body) + JSON.stringify(res.headers);
    expect(serializedResponse).not.toContain(sensitiveDbError);
    expect(serializedResponse).not.toContain('password');
    expect(serializedResponse).not.toContain('secret_admin_user');
  });
});
