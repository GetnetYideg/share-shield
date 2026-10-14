import express, { type Express } from 'express';
import type pg from 'pg';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import type { Logger } from 'pino';
import type { SendCommandFn } from 'rate-limit-redis';
import * as schema from './db/schema.js';
import { parseEnv, type AppConfig } from './config/env.js';
import { createLogger } from './lib/logger.js';
import { requestIdMiddleware } from './middleware/request-id.js';
import { createRequestLoggerMiddleware } from './middleware/request-logger.js';
import { createSecurityHeadersMiddleware } from './middleware/security-headers.js';
import { cacheControlMiddleware } from './middleware/cache-control.js';
import { createHttpsEnforcementMiddleware } from './middleware/https-enforce.js';
import { createCorsMiddleware } from './middleware/cors.js';
import { createRateLimiters, type RateLimiterRegistry } from './middleware/rate-limiter.js';
import { createBodyParserMiddleware } from './middleware/body-parser.js';
import { createHealthRouter } from './modules/health/health.routes.js';
import { createSecretsRouter } from './modules/secrets/secrets.routes.js';
import { notFoundHandler, errorHandler } from './middleware/error-handler.js';

export interface CreateAppOptions {
  config?: AppConfig;
  logger?: Logger;
  pool?: pg.Pool;
  db?: NodePgDatabase<typeof schema>;
  redisSendCommand?: SendCommandFn;
  registerAdditionalRoutes?: (app: Express, rateLimiters: RateLimiterRegistry) => void;
}

export function createApp(options: CreateAppOptions = {}): Express {
  const config = options.config ?? parseEnv(process.env);
  const logger = options.logger ?? createLogger({ level: config.LOG_LEVEL });
  const isProduction = config.NODE_ENV === 'production';

  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', config.TRUST_PROXY);

  // 1. Request correlation & audit logging
  app.use(requestIdMiddleware);
  app.use(createRequestLoggerMiddleware(logger));

  // 2. Security & anti-caching headers on all responses
  app.use(createSecurityHeadersMiddleware(isProduction));
  app.use(cacheControlMiddleware);

  // 3. Transport security & CORS enforcement
  app.use(createHttpsEnforcementMiddleware(isProduction));
  app.use(createCorsMiddleware(config.CORS_ALLOWED_ORIGINS));

  // 4. Rate limiting
  const rateLimiters = createRateLimiters({
    config,
    redisSendCommand: options.redisSendCommand,
  });
  app.use(rateLimiters.global);

  // 5. Strict JSON body parsing & Content-Type enforcement
  app.use(createBodyParserMiddleware(config.MAX_BODY_SIZE));

  // 6. Routes
  app.use('/api/v1/health', createHealthRouter(options.pool));
  app.use(
    '/api/v1/secrets',
    createSecretsRouter({
      db: options.db,
      rateLimiters,
    })
  );

  if (options.registerAdditionalRoutes) {
    options.registerAdditionalRoutes(app, rateLimiters);
  }

  // 7. 404 & centralized error handling
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
