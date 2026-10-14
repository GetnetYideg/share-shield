import pg from 'pg';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from './schema.js';
import { parseEnv, type AppConfig } from '../config/env.js';
import { createLogger } from '../lib/logger.js';

const { Pool } = pg;

let poolInstance: pg.Pool | null = null;
let dbInstance: NodePgDatabase<typeof schema> | null = null;

export function createPool(config: AppConfig): pg.Pool {
  const isProduction = config.NODE_ENV === 'production';
  const logger = createLogger({ level: config.LOG_LEVEL });

  const pool = new Pool({
    connectionString: config.DATABASE_URL,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    ssl: isProduction ? { rejectUnauthorized: true } : false,
  });

  pool.on('error', (err) => {
    // Audit-safe error logging: never log DATABASE_URL or query strings
    logger.error({ errCode: (err as { code?: string }).code }, 'Unexpected PostgreSQL pool client error');
  });

  return pool;
}

export function getPool(config?: AppConfig): pg.Pool {
  if (!poolInstance) {
    const resolvedConfig = config ?? parseEnv(process.env);
    poolInstance = createPool(resolvedConfig);
  }
  return poolInstance;
}

export function getDb(config?: AppConfig): NodePgDatabase<typeof schema> {
  if (!dbInstance) {
    const pool = getPool(config);
    // Invariant 6 & TH-12: Disable Drizzle query logging to prevent leaking query parameters
    dbInstance = drizzle(pool, { schema, logger: false });
  }
  return dbInstance;
}

export async function closePool(): Promise<void> {
  if (poolInstance) {
    await poolInstance.end();
    poolInstance = null;
    dbInstance = null;
  }
}
