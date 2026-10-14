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
  consumeBodySchema,
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

  // POST /api/v1/secrets/:token/consume: Atomic claim and retrieval of ciphertext
  router.post(
    '/:token/consume',
    options.rateLimiters.consume,
    validateRequest({ params: tokenParamSchema, body: consumeBodySchema }),
    controller.consumeSecret
  );

  // DELETE /api/v1/secrets/:token: Creator revocation using revoke capability
  router.delete(
    '/:token',
    options.rateLimiters.revoke,
    validateRequest({ params: tokenParamSchema, query: statusQuerySchema }),
    controller.revokeSecret
  );

  return router;
}
