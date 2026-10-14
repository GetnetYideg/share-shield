CREATE TABLE "secrets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"revoke_token_hash" "bytea" NOT NULL,
	"ciphertext" "bytea",
	"iv" "bytea",
	"payload_version" integer DEFAULT 1 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"max_views" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "check_max_views" CHECK ("secrets"."max_views" = 1),
	CONSTRAINT "check_payload_version" CHECK ("secrets"."payload_version" = 1),
	CONSTRAINT "check_token_hash_length" CHECK (octet_length("secrets"."token_hash") = 32),
	CONSTRAINT "check_revoke_token_hash_length" CHECK (octet_length("secrets"."revoke_token_hash") = 32),
	CONSTRAINT "check_iv_length" CHECK ("secrets"."iv" IS NULL OR octet_length("secrets"."iv") = 12),
	CONSTRAINT "check_expires_after_created" CHECK ("secrets"."expires_at" > "secrets"."created_at")
);
--> statement-breakpoint
CREATE UNIQUE INDEX "secrets_token_hash_idx" ON "secrets" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "secrets_expires_at_idx" ON "secrets" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "secrets_cleanup_idx" ON "secrets" USING btree ("consumed_at","revoked_at","expires_at");