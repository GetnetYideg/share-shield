export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'UNAUTHENTICATED'
  | 'REVOKE_NOT_AUTHORIZED'
  | 'SECRET_UNAVAILABLE'
  | 'NOT_FOUND'
  | 'PAYLOAD_TOO_LARGE'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'RATE_LIMITED'
  | 'FORBIDDEN'
  | 'HTTPS_REQUIRED'
  | 'INTERNAL_ERROR';

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: ErrorCode;
  public readonly isOperational: boolean;

  constructor(statusCode: number, code: ErrorCode, message: string, isOperational = true) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Request validation failed.') {
    super(400, 'VALIDATION_ERROR', message);
  }
}

export class UnauthenticatedError extends AppError {
  constructor(message = 'Authentication is required.') {
    super(401, 'UNAUTHENTICATED', message);
  }
}

export class RevokeNotAuthorizedError extends AppError {
  constructor(message = 'Revoke capability is invalid or absent.') {
    super(403, 'REVOKE_NOT_AUTHORIZED', message);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Access to this resource is forbidden.') {
    super(403, 'FORBIDDEN', message);
  }
}

export class HttpsRequiredError extends AppError {
  constructor(message = 'HTTPS is required.') {
    super(403, 'HTTPS_REQUIRED', message);
  }
}

export class SecretUnavailableError extends AppError {
  constructor() {
    // Invariant 4: Uniform message for invalid, expired, consumed, or revoked secrets
    super(404, 'SECRET_UNAVAILABLE', 'This secret is unavailable.');
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'The requested endpoint does not exist.') {
    super(404, 'NOT_FOUND', message);
  }
}

export class PayloadTooLargeError extends AppError {
  constructor(message = 'Request payload exceeds maximum allowed size.') {
    super(413, 'PAYLOAD_TOO_LARGE', message);
  }
}

export class UnsupportedMediaTypeError extends AppError {
  constructor(message = 'Request Content-Type must be application/json.') {
    super(415, 'UNSUPPORTED_MEDIA_TYPE', message);
  }
}

export class RateLimitedError extends AppError {
  constructor(message = 'Rate limit exceeded. Please try again later.') {
    super(429, 'RATE_LIMITED', message);
  }
}

export class InternalServerError extends AppError {
  constructor(message = 'An unexpected server error occurred.') {
    super(500, 'INTERNAL_ERROR', message, false);
  }
}
