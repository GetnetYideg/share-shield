import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { HttpsRequiredError } from '../lib/errors.js';

/**
 * Enforces HTTPS in production environments.
 * Relies on Express's req.secure which respects the configured trust proxy setting.
 */
export function createHttpsEnforcementMiddleware(isProduction: boolean): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (isProduction && !req.secure) {
      next(new HttpsRequiredError('HTTPS is required in production.'));
      return;
    }
    next();
  };
}
