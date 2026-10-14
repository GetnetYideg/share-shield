import { createClient } from 'redis';
import { parseEnv, ConfigValidationError } from './config/env.js';
import { createLogger } from './lib/logger.js';
import { createApp } from './app.js';
import type { SendCommandFn } from 'rate-limit-redis';

async function bootstrap(): Promise<void> {
  let config;
  try {
    config = parseEnv(process.env);
  } catch (err) {
    const fallbackLogger = createLogger({ level: 'error' });
    if (err instanceof ConfigValidationError) {
      fallbackLogger.fatal({ issues: err.issues }, err.message);
    } else {
      fallbackLogger.fatal('Failed to validate environment configuration.');
    }
    process.exit(1);
  }

  const logger = createLogger({ level: config.LOG_LEVEL });

  let redisSendCommand: SendCommandFn | undefined;
  let redisClient: ReturnType<typeof createClient> | undefined;

  if (config.REDIS_URL) {
    redisClient = createClient({ url: config.REDIS_URL });
    redisClient.on('error', () => {
      logger.error('Redis client encountered a connection error.');
    });
    await redisClient.connect();
    redisSendCommand = (...args: string[]) => redisClient!.sendCommand(args);
    logger.info('Connected to Redis for distributed rate limiting.');
  }

  const app = createApp({
    config,
    logger,
    redisSendCommand,
  });

  const server = app.listen(config.PORT, () => {
    logger.info(
      { port: config.PORT, env: config.NODE_ENV },
      'OneVault API server started'
    );
  });

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'Received shutdown signal, closing server gracefully...');
    server.close(async () => {
      if (redisClient?.isOpen) {
        await redisClient.quit();
      }
      logger.info('Graceful shutdown complete.');
      process.exit(0);
    });
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void bootstrap();
