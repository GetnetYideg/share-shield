import crypto from 'node:crypto';
import rateLimit, { type RateLimitRequestHandler, type Store } from 'express-rate-limit';
import { RedisStore, type SendCommandFn } from 'rate-limit-redis';
import type { Request, Response } from 'express';
import type { AppConfig } from '../config/env.js';

export type RateLimitClass = 'global' | 'create' | 'status' | 'consume' | 'revoke' | 'auth';

export type RateLimiterRegistry = Record<RateLimitClass, RateLimitRequestHandler>;

/**
 * Derives a privacy-preserving, spoof-resistant rate-limit key from Express's req.ip.
 * Express computes req.ip strictly according to the app's `trust proxy` setting,
 * ignoring spoofed X-Forwarded-For headers when trust proxy is false.
 * The IP is HMAC-SHA256 hashed with IP_HASH_SALT to satisfy NFR-10 (minimize IP retention).
 */
export function deriveRateLimitKey(
  req: Request,
  ipHashSalt: string,
  limitClass: RateLimitClass
): string {
  const clientIp = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
  return crypto
    .createHmac('sha256', ipHashSalt)
    .update(`${limitClass}:${clientIp}`)
    .digest('hex')
    .slice(0, 32);
}

export interface CreateRateLimiterOptions {
  config: AppConfig;
  redisSendCommand?: SendCommandFn;
}

export function createRateLimiterForClass(
  limitClass: RateLimitClass,
  maxRequests: number,
  options: CreateRateLimiterOptions
): RateLimitRequestHandler {
  const { config, redisSendCommand } = options;

  let store: Store | undefined;
  if (redisSendCommand) {
    store = new RedisStore({
      sendCommand: redisSendCommand,
      prefix: `rl:${limitClass}:`,
    });
  }

  return rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    limit: maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    store,
    validate: false,
    keyGenerator: (req: Request): string =>
      deriveRateLimitKey(req, config.IP_HASH_SALT, limitClass),
    handler: (req: Request, res: Response): void => {
      res.locals.errorCode = 'RATE_LIMITED';
      const retryAfterSeconds = Math.ceil(config.RATE_LIMIT_WINDOW_MS / 1000);
      if (!res.getHeader('Retry-After')) {
        res.setHeader('Retry-After', String(retryAfterSeconds));
      }
      res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: 'Rate limit exceeded. Please try again later.',
          requestId: req.requestId,
        },
      });
    },
  });
}

export function createRateLimiters(options: CreateRateLimiterOptions): RateLimiterRegistry {
  const { config } = options;
  return {
    global: createRateLimiterForClass('global', config.RATE_LIMIT_GLOBAL_MAX, options),
    create: createRateLimiterForClass('create', config.RATE_LIMIT_CREATE_MAX, options),
    status: createRateLimiterForClass('status', config.RATE_LIMIT_STATUS_MAX, options),
    consume: createRateLimiterForClass('consume', config.RATE_LIMIT_CONSUME_MAX, options),
    revoke: createRateLimiterForClass('revoke', config.RATE_LIMIT_REVOKE_MAX, options),
    auth: createRateLimiterForClass('auth', config.RATE_LIMIT_AUTH_MAX, options),
  };
}
