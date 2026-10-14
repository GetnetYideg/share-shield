import { Router } from 'express';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../db/schema.js';
import { createSecretsController } from './secrets.controller.js';
import { SecretsService } from './secrets.service.js';
import { validateRequest } from '../../middleware/validate.js';
import {
  createSecretBodySchema,
  tokenParamSchema,
  statusQuerySchema,
} from './secrets.schemas.js';
import type { RateLimiterRegistry } from '../../middleware/rate-limiter.js';

export interface SecretsRouterOptions {
  db?: NodePgDatabase<typeof schema>;
  rateLimiters: RateLimiterRegistry;
  service?: SecretsService;
}

export function createSecretsRouter(options: SecretsRouterOptions): Router {
  const router = Router();
  const controller = createSecretsController(options.db, options.service);

  // POST /api/v1/secrets: Create new encrypted secret record
  router.post(
    '/',
    options.rateLimiters.create,
    validateRequest({ body: createSecretBodySchema }),
    controller.createSecret
  );

  // GET /api/v1/secrets/:token/status: Read-only availability check
  router.get(
    '/:token/status',
    options.rateLimiters.status,
    validateRequest({ params: tokenParamSchema, query: statusQuerySchema }),
    controller.getSecretStatus
  );

  return router;
}
