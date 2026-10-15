import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { getDb, getPool, closePool } from '../../src/db/client.js';
import { parseEnv, type AppConfig } from '../../src/config/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function assertTestDatabase(databaseUrl: string, nodeEnv?: string): void {
  if (nodeEnv !== 'test') {
    throw new Error(
      `Safety guard violation: NODE_ENV must be 'test' when running tests. Received: '${nodeEnv}'`
    );
  }

  try {
    const parsed = new URL(databaseUrl);
    const dbName = parsed.pathname.replace(/^\//, '');
    if (!dbName.toLowerCase().includes('test')) {
      throw new Error(
        `Safety guard violation: Refusing to run tests against non-test database: '${dbName}'`
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('Safety guard violation')) {
      throw err;
    }
    throw new Error(`Invalid test DATABASE_URL: ${databaseUrl}`);
  }
}

export function getTestConfig(): AppConfig {
  const envConfig = parseEnv({
    NODE_ENV: 'test',
    PORT: '3000',
    DATABASE_URL:
      process.env.TEST_DATABASE_URL ??
      process.env.DATABASE_URL?.replace(/onevault_dev$/, 'onevault_test') ??
      'postgresql://postgres@localhost:5432/onevault_test',
    CORS_ALLOWED_ORIGINS: 'http://localhost:5173',
    TRUST_PROXY: 'false',
    IP_HASH_SALT: '0123456789abcdef0123456789abcdef',
    PASSKEY_PEPPER: 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
    LOG_LEVEL: 'silent',
  });

  assertTestDatabase(envConfig.DATABASE_URL, envConfig.NODE_ENV);
  return envConfig;
}

export async function setupTestDatabase(): Promise<void> {
  const config = getTestConfig();
  const db = getDb(config);

  const migrationsFolder = path.resolve(__dirname, '../../drizzle/migrations');
  await migrate(db, { migrationsFolder });

  await cleanTestDatabase();
}

export async function cleanTestDatabase(): Promise<void> {
  const config = getTestConfig();
  const pool = getPool(config);
  await pool.query('TRUNCATE TABLE secrets CASCADE;');
}

export async function teardownTestDatabase(): Promise<void> {
  await closePool();
}
