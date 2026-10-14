import express, {
  type Request,
  type Response,
  type NextFunction,
  type RequestHandler,
} from 'express';
import { UnsupportedMediaTypeError, ValidationError } from '../lib/errors.js';

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

export function createBodyParserMiddleware(maxBodySize: string): RequestHandler[] {
  const enforceJsonContentType = (req: Request, _res: Response, next: NextFunction): void => {
    if (!BODY_METHODS.has(req.method.toUpperCase())) {
      next();
      return;
    }

    const contentType = req.headers['content-type'];
    const contentLengthHeader = req.headers['content-length'];
    const transferEncoding = req.headers['transfer-encoding'];
    const hasBody =
      (contentLengthHeader !== undefined && Number.parseInt(contentLengthHeader, 10) > 0) ||
      transferEncoding !== undefined;

    if (contentType !== undefined) {
      if (req.is('application/json') === false || req.is('application/json') === null) {
        next(new UnsupportedMediaTypeError('Request Content-Type must be application/json.'));
        return;
      }
    } else if (hasBody) {
      next(new UnsupportedMediaTypeError('Request Content-Type must be application/json.'));
      return;
    }

    next();
  };

  const jsonParser = express.json({
    limit: maxBodySize,
    strict: true,
    type: 'application/json',
    verify: (_req, _res, buf): void => {
      const text = buf.toString('utf8');
      if (
        text.includes('"__proto__"') ||
        text.includes('"constructor"') ||
        text.includes('"prototype"')
      ) {
        throw new ValidationError('Forbidden property name in JSON payload.');
      }
    },
    reviver: (key: string, value: unknown): unknown => {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new ValidationError(`Forbidden key '${key}' detected in request body.`);
      }
      return value;
    },
  });

  const ensureObjectBody = (req: Request, _res: Response, next: NextFunction): void => {
    if (
      req.body !== undefined &&
      (typeof req.body !== 'object' || req.body === null || Array.isArray(req.body))
    ) {
      next(new ValidationError('Request body must be a JSON object.'));
      return;
    }
    next();
  };

  return [enforceJsonContentType, jsonParser, ensureObjectBody];
}
