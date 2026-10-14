import type { Request, Response } from 'express';
import type pg from 'pg';
import { getPool } from '../../db/client.js';

/**
 * Health check controller with database liveness probe (FR-12, Phase 3 requirement 9).
 * Pings PostgreSQL via 'SELECT 1'.
 * Returns status: 'ok' (200) or 'degraded' (503).
 * Never exposes database URLs, hostnames, passwords, stack traces, or internal error messages.
 */
export function createHealthController(pool?: pg.Pool) {
  return async (req: Request, res: Response): Promise<void> => {
    const dbPool = pool ?? getPool();

    try {
      await dbPool.query('SELECT 1');
      res.status(200).json({
        data: {
          status: 'ok',
        },
        requestId: req.requestId,
      });
    } catch {
      // Never expose error details or connection strings to client (Api_Reference section 4)
      res.status(503).json({
        data: {
          status: 'degraded',
        },
        requestId: req.requestId,
      });
    }
  };
}
