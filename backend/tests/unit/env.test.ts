import { describe, it, expect } from 'vitest';
import { parseEnv, ConfigValidationError } from '../../src/config/env.js';

const validBaseEnv: Record<string, string> = {
  NODE_ENV: 'test',
  PORT: '3000',
  DATABASE_URL: 'postgresql://user:pass@localhost:5432/onevault_test',
  CORS_ALLOWED_ORIGINS: 'http://localhost:5173,https://app.example.com',
  TRUST_PROXY: 'false',
  IP_HASH_SALT: '0123456789abcdef0123456789abcdef',
  PASSKEY_PEPPER: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
};

describe('Environment Configuration Validation (src/config/env.ts)', () => {
  it('parses a valid environment configuration and applies defaults', () => {
    const config = parseEnv(validBaseEnv);
    expect(config.NODE_ENV).toBe('test');
    expect(config.PORT).toBe(3000);
    expect(config.CORS_ALLOWED_ORIGINS).toEqual([
      'http://localhost:5173',
      'https://app.example.com',
    ]);
    expect(config.TRUST_PROXY).toBe(false);
    expect(config.PASSKEY_PEPPER).toBe(validBaseEnv.PASSKEY_PEPPER);
    expect(config.PASSKEY_MAX_ATTEMPTS).toBe(5);
    expect(config.MAX_BODY_SIZE).toBe('16kb');
    expect(config.MAX_PLAINTEXT_BYTES).toBe(10240);
    expect(config.MIN_CIPHERTEXT_CHARS).toBe(23);
    expect(config.MAX_CIPHERTEXT_CHARS).toBe(13675);
    expect(config.REDIS_URL).toBeUndefined();
  });

  it('fails fast when required variables are missing', () => {
    expect(() => parseEnv({})).toThrow(ConfigValidationError);
  });

  it('never leaks raw secret values in ConfigValidationError messages', () => {
    const leakedDbPassword = 'SUPER_SECRET_DB_PASSWORD_DO_NOT_LOG_987654';
    const leakedSalt = 'SHORT_SALT_123';
    const badEnv: Record<string, string> = {
      ...validBaseEnv,
      DATABASE_URL: `mysql://admin:${leakedDbPassword}@localhost:3306/db`,
      IP_HASH_SALT: leakedSalt,
    };

    try {
      parseEnv(badEnv);
      expect.fail('Expected parseEnv to throw ConfigValidationError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigValidationError);
      const serialized = JSON.stringify(err) + (err as Error).message;
      expect(serialized).not.toContain(leakedDbPassword);
      expect(serialized).not.toContain(leakedSalt);
    }
  });

  it('rejects wildcard "*" in CORS_ALLOWED_ORIGINS', () => {
    expect(() =>
      parseEnv({
        ...validBaseEnv,
        CORS_ALLOWED_ORIGINS: '*',
      })
    ).toThrow(/Wildcard "\*" is forbidden/);
  });

  it('rejects origins containing paths or trailing slashes in CORS_ALLOWED_ORIGINS', () => {
    expect(() =>
      parseEnv({
        ...validBaseEnv,
        CORS_ALLOWED_ORIGINS: 'https://app.example.com/path',
      })
    ).toThrow(ConfigValidationError);
  });

  it('rejects unrestricted TRUST_PROXY="true" to prevent X-Forwarded-For spoofing', () => {
    expect(() =>
      parseEnv({
        ...validBaseEnv,
        TRUST_PROXY: 'true',
      })
    ).toThrow(/Unrestricted TRUST_PROXY="true" is forbidden/);
  });

  it('parses numeric hop count in TRUST_PROXY', () => {
    const config = parseEnv({
      ...validBaseEnv,
      TRUST_PROXY: '1',
    });
    expect(config.TRUST_PROXY).toBe(1);
  });

  it('rejects missing or short PASSKEY_PEPPER', () => {
    expect(() =>
      parseEnv({
        ...validBaseEnv,
        PASSKEY_PEPPER: 'too_short',
      })
    ).toThrow(/PASSKEY_PEPPER must be at least 32 characters/);
  });

  it('parses custom valid PASSKEY_MAX_ATTEMPTS (3 to 10)', () => {
    const config = parseEnv({
      ...validBaseEnv,
      PASSKEY_MAX_ATTEMPTS: '7',
    });
    expect(config.PASSKEY_MAX_ATTEMPTS).toBe(7);
  });

  it('rejects PASSKEY_MAX_ATTEMPTS outside of 3-10 range', () => {
    expect(() =>
      parseEnv({
        ...validBaseEnv,
        PASSKEY_MAX_ATTEMPTS: '2',
      })
    ).toThrow(/PASSKEY_MAX_ATTEMPTS must be at least 3/);

    expect(() =>
      parseEnv({
        ...validBaseEnv,
        PASSKEY_MAX_ATTEMPTS: '11',
      })
    ).toThrow(/PASSKEY_MAX_ATTEMPTS must be at most 10/);
  });
});
