import { z } from 'zod';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { ValidationError } from '../lib/errors.js';

export type StrictValidationTarget = z.ZodTypeAny;

export interface ValidationSchemas {
  body?: StrictValidationTarget;
  params?: StrictValidationTarget;
  query?: StrictValidationTarget;
}

function ensureStrict(schema: StrictValidationTarget): StrictValidationTarget {
  if (schema instanceof z.ZodObject) {
    return schema.strict();
  }
  return schema;
}

function formatSafeZodMessage(targetName: 'body' | 'params' | 'query', error: z.ZodError): string {
  const firstIssue = error.issues[0];
  if (!firstIssue) {
    return `Invalid request ${targetName}.`;
  }

  if (firstIssue.code === z.ZodIssueCode.unrecognized_keys) {
    return `Unrecognized fields are not permitted in request ${targetName}.`;
  }

  const fieldPath = firstIssue.path.length > 0 ? firstIssue.path.join('.') : targetName;
  return `Invalid value for ${fieldPath}: ${firstIssue.message}`;
}

/**
 * Zod request validation middleware enforcing strict mode (unknown fields rejected).
 * Never echoes raw input values in error messages (Invariant 1 & 2, TH-13).
 */
export function validateRequest(schemas: ValidationSchemas): RequestHandler {
  const bodySchema = schemas.body ? ensureStrict(schemas.body) : undefined;
  const paramsSchema = schemas.params ? ensureStrict(schemas.params) : undefined;
  const querySchema = schemas.query ? ensureStrict(schemas.query) : undefined;

  return (req: Request, _res: Response, next: NextFunction): void => {
    if (paramsSchema) {
      const parsedParams = paramsSchema.safeParse(req.params ?? {});
      if (!parsedParams.success) {
        next(new ValidationError(formatSafeZodMessage('params', parsedParams.error)));
        return;
      }
      req.params = parsedParams.data as Record<string, string>;
    }

    if (querySchema) {
      const parsedQuery = querySchema.safeParse(req.query ?? {});
      if (!parsedQuery.success) {
        next(new ValidationError(formatSafeZodMessage('query', parsedQuery.error)));
        return;
      }
      req.query = parsedQuery.data as Request['query'];
    }

    if (bodySchema) {
      const parsedBody = bodySchema.safeParse(req.body ?? {});
      if (!parsedBody.success) {
        next(new ValidationError(formatSafeZodMessage('body', parsedBody.error)));
        return;
      }
      req.body = parsedBody.data;
    }

    next();
  };
}
