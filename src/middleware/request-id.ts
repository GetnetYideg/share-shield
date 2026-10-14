import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { ErrorCode } from '../lib/errors.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      requestId: string;
    }
    interface Locals {
      errorCode?: ErrorCode;
    }
  }
}

/**
 * Generates an unforgeable server-side request ID for correlation across logs and responses.
 * Never trusts client-supplied request IDs to prevent log injection or correlation spoofing.
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const id = `req_${crypto.randomBytes(12).toString('hex')}`;
  req.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
}
