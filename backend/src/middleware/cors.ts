import cors from 'cors';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { ForbiddenError } from '../lib/errors.js';

/**
 * Strict CORS allow-list middleware.
 * Rejects requests carrying an unrecognized Origin header with 403 FORBIDDEN.
 * Never emits Access-Control-Allow-Origin: *
 */
export function createCorsMiddleware(allowedOrigins: ReadonlyArray<string>): RequestHandler {
  const allowedSet = new Set(allowedOrigins);

  const corsHandler = cors({
    origin: (origin, callback) => {
      if (!origin || allowedSet.has(origin)) {
        callback(null, origin ?? false);
        return;
      }
      callback(new ForbiddenError('Origin is not allowed by CORS policy.'));
    },
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Request-Id'],
    exposedHeaders: [
      'X-Request-Id',
      'Retry-After',
      'RateLimit-Limit',
      'RateLimit-Remaining',
      'RateLimit-Reset',
    ],
    credentials: false,
    maxAge: 600,
    optionsSuccessStatus: 204,
  });

  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedSet.has(origin)) {
      res.setHeader('Vary', 'Origin');
      next(new ForbiddenError('Origin is not allowed by CORS policy.'));
      return;
    }
    corsHandler(req, res, next);
  };
}
