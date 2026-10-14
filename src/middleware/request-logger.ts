import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { Logger } from 'pino';

const ROUTE_TEMPLATE_MATCHERS: ReadonlyArray<{ pattern: RegExp; template: string }> = [
  { pattern: /^\/api\/v1\/health\/?$/, template: '/api/v1/health' },
  { pattern: /^\/api\/v1\/secrets\/?$/, template: '/api/v1/secrets' },
  { pattern: /^\/api\/v1\/secrets\/[^/]+\/status\/?$/, template: '/api/v1/secrets/:token/status' },
  { pattern: /^\/api\/v1\/secrets\/[^/]+\/consume\/?$/, template: '/api/v1/secrets/:token/consume' },
  { pattern: /^\/api\/v1\/secrets\/[^/]+\/?$/, template: '/api/v1/secrets/:token' },
];

/**
 * Resolves the parameterized route template for a request.
 * Never returns raw URL paths, path parameters, or query strings (Invariant 1 & 6).
 */
export function resolveRouteTemplate(req: Request): string {
  const routeObj = req.route as { path?: unknown } | undefined;
  if (routeObj && typeof routeObj.path === 'string') {
    const base = req.baseUrl ?? '';
    const routePath = routeObj.path === '/' && base.length > 0 ? '' : routeObj.path;
    return `${base}${routePath}` || '/';
  }

  const rawPath = req.path ?? '';
  for (const matcher of ROUTE_TEMPLATE_MATCHERS) {
    if (matcher.pattern.test(rawPath)) {
      return matcher.template;
    }
  }

  return 'UNMATCHED_ROUTE';
}

/**
 * Audit-safe request logging middleware.
 * Logs strictly: requestId, method, route template, statusCode, latencyMs, and coarse errorCode.
 * Never logs request bodies, query strings, headers, cookies, raw paths, or IP addresses.
 */
export function createRequestLoggerMiddleware(logger: Logger): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const startHrTime = process.hrtime.bigint();

    res.on('finish', () => {
      const durationNs = process.hrtime.bigint() - startHrTime;
      const latencyMs = Number(durationNs) / 1_000_000;
      const route = resolveRouteTemplate(req);
      const statusCode = res.statusCode;
      const errorCode = res.locals.errorCode;

      const logPayload: Record<string, unknown> = {
        requestId: req.requestId,
        method: req.method,
        route,
        statusCode,
        latencyMs: Math.round(latencyMs * 100) / 100,
      };

      if (errorCode !== undefined) {
        logPayload.errorCode = errorCode;
      }

      if (statusCode >= 500) {
        logger.error(logPayload, 'request_completed');
      } else if (statusCode >= 400) {
        logger.warn(logPayload, 'request_completed');
      } else {
        logger.info(logPayload, 'request_completed');
      }
    });

    next();
  };
}
