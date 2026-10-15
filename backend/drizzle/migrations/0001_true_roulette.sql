DROP INDEX "secrets_cleanup_idx";--> statement-breakpoint
ALTER TABLE "secrets" ADD COLUMN "passkey_hash" "bytea";--> statement-breakpoint
ALTER TABLE "secrets" ADD COLUMN "failed_attempts" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "secrets" ADD COLUMN "locked_at" timestamp with time zone;--> statement-breakpoint
UPDATE "secrets"
SET "locked_at" = COALESCE("locked_at", NOW()),
    "ciphertext" = NULL,
    "iv" = NULL,
    "passkey_hash" = decode(repeat('00', 32), 'hex')
WHERE "passkey_hash" IS NULL;--> statement-breakpoint
ALTER TABLE "secrets" ALTER COLUMN "passkey_hash" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "secrets_cleanup_idx" ON "secrets" USING btree ("consumed_at","revoked_at","locked_at","expires_at");--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "check_passkey_hash_length" CHECK (octet_length("secrets"."passkey_hash") = 32);--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "check_failed_attempts_non_negative" CHECK ("secrets"."failed_attempts" >= 0);