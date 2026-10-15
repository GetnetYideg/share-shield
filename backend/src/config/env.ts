import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

export class ConfigValidationError extends Error {
  public readonly issues: ReadonlyArray<{ field: string; message: string }>;

  constructor(issues: ReadonlyArray<{ field: string; message: string }>) {
    const summary = issues.map((i) => `${i.field}: ${i.message}`).join('; ');
    super(`Environment configuration validation failed: ${summary}`);
    this.name = 'ConfigValidationError';
    this.issues = issues;
  }
}

const parseTrustProxy = (val: string, ctx: z.RefinementCtx): boolean | number | string => {
  const trimmed = val.trim();
  if (trimmed === '' || trimmed.toLowerCase() === 'false') {
    return false;
  }
  if (trimmed.toLowerCase() === 'true') {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message:
        'Unrestricted TRUST_PROXY="true" is forbidden to prevent X-Forwarded-For spoofing. Specify hop count (e.g. "1") or explicit subnet/CIDR.',
    });
    return z.NEVER;
  }
  if (/^\d+$/.test(trimmed)) {
    const hops = Number.parseInt(trimmed, 10);
    if (hops < 1 || hops > 10) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'TRUST_PROXY hop count must be between 1 and 10.',
      });
      return z.NEVER;
    }
    return hops;
  }
  return trimmed;
};

const parseCorsOrigins = (val: string, ctx: z.RefinementCtx): string[] => {
  const rawOrigins = val
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (rawOrigins.length === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'CORS_ALLOWED_ORIGINS must contain at least one valid origin.',
    });
    return z.NEVER;
  }

  const validated: string[] = [];
  for (const origin of rawOrigins) {
    if (origin === '*') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Wildcard "*" is forbidden in CORS_ALLOWED_ORIGINS.',
      });
      return z.NEVER;
    }
    try {
      const parsed = new URL(origin);
      if (
        (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
        parsed.origin === 'null' ||
        parsed.pathname !== '/' ||
        parsed.search !== '' ||
        parsed.hash !== '' ||
        origin.endsWith('/')
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'Each CORS origin must be an exact origin (scheme://host[:port]) without trailing slash or path.',
        });
        return z.NEVER;
      }
      validated.push(parsed.origin);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Invalid URL format in CORS_ALLOWED_ORIGINS.',
      });
      return z.NEVER;
    }
  }
  return validated;
};

const rawEnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce
    .number({ invalid_type_error: 'PORT must be a valid number' })
    .int('PORT must be an integer')
    .min(1, 'PORT must be >= 1')
    .max(65535, 'PORT must be <= 65535')
    .default(3000),
  DATABASE_URL: z
    .string({ required_error: 'DATABASE_URL is required' })
    .min(1, 'DATABASE_URL cannot be empty')
    .refine(
      (val) => {
        try {
          const parsed = new URL(val);
          return parsed.protocol === 'postgres:' || parsed.protocol === 'postgresql:';
        } catch {
          return false;
        }
      },
      { message: 'DATABASE_URL must be a valid postgres:// or postgresql:// URI' }
    ),
  CORS_ALLOWED_ORIGINS: z
    .string({ required_error: 'CORS_ALLOWED_ORIGINS is required' })
    .min(1, 'CORS_ALLOWED_ORIGINS is required')
    .transform(parseCorsOrigins),
  TRUST_PROXY: z.string().default('false').transform(parseTrustProxy),
  IP_HASH_SALT: z
    .string({ required_error: 'IP_HASH_SALT is required' })
    .min(16, 'IP_HASH_SALT must be at least 16 characters long'),
  PASSKEY_PEPPER: z
    .string({ required_error: 'PASSKEY_PEPPER is required' })
    .min(32, 'PASSKEY_PEPPER must be at least 32 characters long'),
  PASSKEY_MAX_ATTEMPTS: z.coerce
    .number()
    .int()
    .min(3, 'PASSKEY_MAX_ATTEMPTS must be at least 3')
    .max(10, 'PASSKEY_MAX_ATTEMPTS must be at most 10')
    .default(5),
  REDIS_URL: z
    .string()
    .optional()
    .transform((val) => (val === undefined || val.trim() === '' ? undefined : val.trim()))
    .refine(
      (val) => {
        if (val === undefined) return true;
        try {
          const parsed = new URL(val);
          return parsed.protocol === 'redis:' || parsed.protocol === 'rediss:';
        } catch {
          return false;
        }
      },
      { message: 'REDIS_URL must be a valid redis:// or rediss:// URI when provided' }
    ),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60000),
  RATE_LIMIT_GLOBAL_MAX: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_CREATE_MAX: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_STATUS_MAX: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_CONSUME_MAX: z.coerce.number().int().positive().default(15),
  RATE_LIMIT_REVOKE_MAX: z.coerce.number().int().positive().default(15),
  RATE_LIMIT_AUTH_MAX: z.coerce.number().int().positive().default(10),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  MAX_BODY_SIZE: z
    .string()
    .regex(/^\d+(b|kb|mb)$/i, 'MAX_BODY_SIZE must be a valid size (e.g. 16kb)')
    .default('16kb'),
  MAX_PLAINTEXT_BYTES: z.coerce.number().int().min(1).max(10240).default(10240),
  MIN_CIPHERTEXT_CHARS: z.coerce.number().int().min(23).default(23),
  MAX_CIPHERTEXT_CHARS: z.coerce.number().int().min(23).max(13675).default(13675),
  CLEANUP_INTERVAL_MS: z.coerce.number().int().positive().default(900000),
  CLEANUP_RETENTION_HOURS: z.coerce.number().int().min(0).default(24),
});

export type AppConfig = z.infer<typeof rawEnvSchema>;

/**
 * Validates an environment dictionary against the strict schema.
 * Never includes raw environment values in error messages.
 */
export function parseEnv(rawEnv: Record<string, string | undefined> = process.env): AppConfig {
  const result = rawEnvSchema.safeParse(rawEnv);

  if (!result.success) {
    const safeIssues = result.error.issues.map((issue) => ({
      field: issue.path.join('.') || 'env',
      message: issue.message,
    }));
    throw new ConfigValidationError(safeIssues);
  }

  return result.data;
}
