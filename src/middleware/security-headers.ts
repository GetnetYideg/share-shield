import helmet from 'helmet';
import type { Request, Response, NextFunction, RequestHandler } from 'express';

export function createSecurityHeadersMiddleware(isProduction: boolean): RequestHandler[] {
  const helmetMiddleware = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
      },
    },
    referrerPolicy: {
      policy: 'no-referrer',
    },
    frameguard: {
      action: 'deny',
    },
    noSniff: true,
    hidePoweredBy: true,
    hsts: isProduction
      ? {
          maxAge: 63072000,
          includeSubDomains: true,
          preload: true,
        }
      : false,
    crossOriginResourcePolicy: {
      policy: 'same-site',
    },
  });

  const permissionsPolicyMiddleware = (_req: Request, res: Response, next: NextFunction): void => {
    res.setHeader(
      'Permissions-Policy',
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    );
    next();
  };

  return [helmetMiddleware, permissionsPolicyMiddleware];
}
