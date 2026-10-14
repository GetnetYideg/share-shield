import type { Request, Response, NextFunction } from 'express';

/**
 * Prevents browsers, proxies, and CDNs from caching any API response.
 */
export function cacheControlMiddleware(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
}
