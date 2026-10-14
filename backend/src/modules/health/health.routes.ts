import { Router } from 'express';
import { z } from 'zod';
import type pg from 'pg';
import { createHealthController } from './health.controller.js';
import { validateRequest } from '../../middleware/validate.js';

const emptyQuerySchema = z.object({}).strict();

export function createHealthRouter(pool?: pg.Pool): Router {
  const router = Router();
  const healthHandler = createHealthController(pool);

  router.get('/', validateRequest({ query: emptyQuerySchema }), healthHandler);

  return router;
}
