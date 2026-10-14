import type { Request, Response, NextFunction } from 'express';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../db/schema.js';
import { getDb } from '../../db/client.js';
import { SecretsService } from './secrets.service.js';
import type { CreateSecretInput } from './secrets.schemas.js';

export function createSecretsController(
  db?: NodePgDatabase<typeof schema>,
  service: SecretsService = new SecretsService()
) {
  const getDatabase = (): NodePgDatabase<typeof schema> => db ?? getDb();

  return {
    async createSecret(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const input = req.body as CreateSecretInput;
        const result = await service.createSecret(getDatabase(), input);

        // Never echo tokens, keys, or ciphertext in response (Invariant 1 & Phase 1)
        res.status(201).json({
          data: {
            created: true,
            expiresAt: result.expiresAt.toISOString(),
          },
          requestId: req.requestId,
        });
      } catch (err) {
        next(err);
      }
    },

    async getSecretStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const token = req.params.token as string;
        const result = await service.getSecretStatus(getDatabase(), token);

        res.status(200).json({
          data: {
            available: true,
            expiresAt: result.expiresAt.toISOString(),
          },
          requestId: req.requestId,
        });
      } catch (err) {
        next(err);
      }
    },
  };
}
