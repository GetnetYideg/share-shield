import {
  pgTable,
  uuid,
  integer,
  timestamp,
  index,
  uniqueIndex,
  check,
  customType,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

/**
 * Custom BYTEA column type for raw cryptographic binary buffers.
 * Safely handles Buffer and hex representations from the node-postgres driver.
 */
export const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return 'bytea';
  },
  toDriver(val: Buffer): Buffer {
    return val;
  },
  fromDriver(val: unknown): Buffer {
    if (Buffer.isBuffer(val)) {
      return val;
    }
    if (typeof val === 'string') {
      if (val.startsWith('\\x')) {
        return Buffer.from(val.slice(2), 'hex');
      }
      return Buffer.from(val, 'hex');
    }
    return Buffer.from(val as Uint8Array);
  },
});

export const secrets = pgTable(
  'secrets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tokenHash: bytea('token_hash').notNull(),
    revokeTokenHash: bytea('revoke_token_hash').notNull(),
    passkeyHash: bytea('passkey_hash').notNull(),
    failedAttempts: integer('failed_attempts').notNull().default(0),
    lockedAt: timestamp('locked_at', { withTimezone: true, mode: 'date' }),
    ciphertext: bytea('ciphertext'),
    iv: bytea('iv'),
    payloadVersion: integer('payload_version').notNull().default(1),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow(),
    consumedAt: timestamp('consumed_at', { withTimezone: true, mode: 'date' }),
    revokedAt: timestamp('revoked_at', { withTimezone: true, mode: 'date' }),
    maxViews: integer('max_views').notNull().default(1),
  },
  (table) => [
    uniqueIndex('secrets_token_hash_idx').on(table.tokenHash),
    index('secrets_expires_at_idx').on(table.expiresAt),
    index('secrets_cleanup_idx').on(
      table.consumedAt,
      table.revokedAt,
      table.lockedAt,
      table.expiresAt
    ),
    check('check_max_views', sql`${table.maxViews} = 1`),
    check('check_payload_version', sql`${table.payloadVersion} = 1`),
    check('check_token_hash_length', sql`octet_length(${table.tokenHash}) = 32`),
    check('check_revoke_token_hash_length', sql`octet_length(${table.revokeTokenHash}) = 32`),
    check('check_passkey_hash_length', sql`octet_length(${table.passkeyHash}) = 32`),
    check('check_failed_attempts_non_negative', sql`${table.failedAttempts} >= 0`),
    check('check_iv_length', sql`${table.iv} IS NULL OR octet_length(${table.iv}) = 12`),
    check('check_expires_after_created', sql`${table.expiresAt} > ${table.createdAt}`),
  ]
);

export type Secret = typeof secrets.$inferSelect;
export type NewSecret = typeof secrets.$inferInsert;
