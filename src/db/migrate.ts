import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { getDb, closePool } from './client.js';
import { parseEnv } from '../config/env.js';
import { createLogger } from '../lib/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function runMigrations(): Promise<void> {
  const config = parseEnv(process.env);
  const logger = createLogger({ level: config.LOG_LEVEL });

  logger.info('Starting database migrations...');
  const db = getDb(config);

  const migrationsFolder = path.resolve(__dirname, '../../drizzle/migrations');
  await migrate(db, { migrationsFolder });

  logger.info('Database migrations applied successfully.');
}

async function main(): Promise<void> {
  try {
    await runMigrations();
    await closePool();
    process.exit(0);
  } catch (err) {
    const fallbackLogger = createLogger({ level: 'error' });
    fallbackLogger.fatal({ err }, 'Failed to apply database migrations.');
    await closePool();
    process.exit(1);
  }
}

// Only execute directly when invoked via CLI (not when imported in tests)
if (process.argv[1] === __filename) {
  void main();
}
