import { fileURLToPath } from 'node:url';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import type { Logger } from 'pino';
import * as schema from '../db/schema.js';
import { getDb, closePool } from '../db/client.js';
import { parseEnv, type AppConfig } from '../config/env.js';
import { createLogger } from '../lib/logger.js';
import { SecretsService } from '../modules/secrets/secrets.service.js';

const __filename = fileURLToPath(import.meta.url);

/**
 * Runs the database cleanup task in safe batches of 1,000 using FOR UPDATE SKIP LOCKED.
 * Deletes records that have been expired, consumed, or revoked beyond the retention threshold.
 * Logs strictly counts, never row contents or tokens (Invariant 1 & 6).
 */
export async function runCleanupJob(
  db: NodePgDatabase<typeof schema>,
  config: AppConfig,
  logger: Logger
): Promise<number> {
  const service = new SecretsService();
  const retentionHours = config.CLEANUP_RETENTION_HOURS;
  let totalDeleted = 0;
  const batchSize = 1000;

  try {
    // Loop until all eligible records in the window are pruned
    while (true) {
      const deletedInBatch = await service.cleanupExpired(db, retentionHours, batchSize);
      totalDeleted += deletedInBatch;

      if (deletedInBatch < batchSize) {
        break;
      }
    }

    logger.info(
      { deletedCount: totalDeleted, retentionHours },
      'Cleanup job executed successfully'
    );
    return totalDeleted;
  } catch (err) {
    logger.error(
      { errCode: (err as { code?: string }).code },
      'Failed to execute database cleanup job'
    );
    throw err;
  }
}

/**
 * Starts an in-process periodic cleanup timer gated by configuration.
 */
export function startCleanupScheduler(
  db: NodePgDatabase<typeof schema>,
  config: AppConfig,
  logger: Logger
): NodeJS.Timeout | null {
  if (config.CLEANUP_INTERVAL_MS <= 0) {
    return null;
  }

  logger.info(
    { intervalMs: config.CLEANUP_INTERVAL_MS, retentionHours: config.CLEANUP_RETENTION_HOURS },
    'Starting background cleanup scheduler'
  );

  const timer = setInterval(() => {
    runCleanupJob(db, config, logger).catch(() => {
      // Background worker catches errors to avoid unhandled rejections
    });
  }, config.CLEANUP_INTERVAL_MS);

  // Prevent background interval from preventing process exit
  timer.unref();

  return timer;
}

async function cliMain(): Promise<void> {
  const config = parseEnv(process.env);
  const logger = createLogger({ level: config.LOG_LEVEL });
  const db = getDb(config);

  try {
    await runCleanupJob(db, config, logger);
    await closePool();
    process.exit(0);
  } catch {
    await closePool();
    process.exit(1);
  }
}

if (process.argv[1] === __filename) {
  void cliMain();
}
