import { ZodError } from 'zod';
import type { Request, Response, NextFunction } from 'express';
import { AppError, NotFoundError, PasskeyInvalidError, type ErrorCode } from '../lib/errors.js';

interface BodyParserError {
  type?: string;
  status?: number;
  statusCode?: number;
}

function isBodyParserError(err: unknown): err is BodyParserError {
  return typeof err === 'object' && err !== null && ('type' in err || 'status' in err);
}

/**
 * Catch-all 404 handler for unmatched routes.
 */
export function notFoundHandler(_req: Request, _res: Response, next: NextFunction): void {
  next(new NotFoundError());
}

/**
 * Centralized error-handling middleware.
 * Maps operational, validation, and body-parser errors to Api_Reference.md section 2.2 format.
 * Never exposes stack traces, internal details, or request bodies (Invariant 1, TH-13).
 */
export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof PasskeyInvalidError) {
    res.locals.errorCode = err.code;
    res.status(err.statusCode).json({
      error: {
        code: err.code,
        message: err.message,
        attemptsRemaining: err.attemptsRemaining,
        requestId: req.requestId ?? 'req_unknown',
      },
    });
    return;
  }

  let statusCode = 500;
  let code: ErrorCode = 'INTERNAL_ERROR';
  let message = 'An unexpected server error occurred.';

  if (err instanceof AppError) {
    statusCode = err.statusCode;
    code = err.code;
    message = err.isOperational ? err.message : 'An unexpected server error occurred.';
  } else if (err instanceof ZodError) {
    statusCode = 400;
    code = 'VALIDATION_ERROR';
    message = 'Request validation failed.';
  } else if (isBodyParserError(err)) {
    if (err.type === 'entity.too.large' || err.status === 413 || err.statusCode === 413) {
      statusCode = 413;
      code = 'PAYLOAD_TOO_LARGE';
      message = 'Request payload exceeds maximum allowed size.';
    } else if (
      err.type === 'entity.parse.failed' ||
      (err instanceof SyntaxError && (err.status === 400 || err.statusCode === 400))
    ) {
      statusCode = 400;
      code = 'VALIDATION_ERROR';
      message = 'Malformed JSON in request body.';
    } else if (
      err.type === 'charset.unsupported' ||
      err.type === 'encoding.unsupported' ||
      err.status === 415 ||
      err.statusCode === 415
    ) {
      statusCode = 415;
      code = 'UNSUPPORTED_MEDIA_TYPE';
      message = 'Request Content-Type or encoding is not supported.';
    }
  }

  res.locals.errorCode = code;

  res.status(statusCode).json({
    error: {
      code,
      message,
      requestId: req.requestId ?? 'req_unknown',
    },
  });
}
