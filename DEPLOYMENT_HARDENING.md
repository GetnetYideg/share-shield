# OneVault (share-shield) Production Deployment & Hardening Guide

*Classification: Operations & Infrastructure Hardening Guide | Standards: OWASP ASVS Level 2, CIS Benchmarks*

This guide specifies mandatory infrastructure, database, networking, and operational controls required to run OneVault in production environments.

---

## 1. Network & TLS Hardening

### 1.1 Reverse Proxy & TLS Termination
- **TLS Configuration**: The API must run behind a production reverse proxy (e.g., NGINX, Cloudflare, AWS ALB, Envoy).
  - Terminate TLS with **TLS 1.3** preferred (minimum **TLS 1.2**).
  - Disable legacy ciphers (RC4, 3DES, CBC mode ciphers).
  - Enforce ECDHE key exchange for Perfect Forward Secrecy (PFS).
- **HTTP Strict Transport Security (HSTS)**:
  - Enabled automatically in production via Helmet:
    ```http
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    ```
- **HTTP to HTTPS Redirection**: The API includes automated HTTPS redirection in production (`src/middleware/https-enforce.ts`). The reverse proxy must also reject plain HTTP or redirect with a `301 Moved Permanently`.

### 1.2 Trust Proxy & IP Resolution (Threat TH-11)
- **NEVER** set `TRUST_PROXY=true` in production. Unrestricted trust allows attackers to spoof `X-Forwarded-For` headers and circumvent rate limiting.
- **Safe Configuration**:
  - If behind a single reverse proxy (e.g. AWS ALB): set `TRUST_PROXY=1`.
  - If behind Cloudflare or a specific internal subnet: set explicit CIDR ranges (e.g., `TRUST_PROXY=10.0.0.0/8,172.16.0.0/12`).

---

## 2. Distributed Rate Limiting via Redis

For high-availability multi-instance deployments:
- Configure `REDIS_URL=rediss://user:password@redis-cluster:6379` (use TLS connection `rediss://`).
- The rate limiter (`src/middleware/rate-limiter.ts`) automatically switches from the local in-memory store to `rate-limit-redis`.
- All client IPs are salted and hashed via HMAC-SHA256 (`IP_HASH_SALT`) prior to generating Redis keys, preventing IP address exposure in Redis memory dumps or command logs.

---

## 3. Database Least-Privilege & Hardening

### 3.1 Separate Migration & Runtime Roles
Do not connect the production API with an owner, admin, or superuser role.

1. **Owner Role (`onevault_owner`)**:
   - Used exclusively during deployment to execute `npm run db:migrate`.
   - Has DDL permissions (`CREATE TABLE`, `ALTER TABLE`, `CREATE INDEX`).
2. **Runtime Role (`onevault_runtime`)**:
   - Used by the API container (`dist/server.js`).
   - Granted strictly DML permissions on table `public.secrets`:
     ```sql
     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.secrets TO onevault_runtime;
     REVOKE ALL ON SCHEMA public FROM PUBLIC;
     REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM onevault_runtime;
     ```
   - Lacks any DDL or privilege grant permissions.

### 3.2 Connection Security
- Set `NODE_ENV=production`: enforces SSL certificate verification (`ssl: { rejectUnauthorized: true }`).
- Pool statement timeouts: default configured to `5000 ms` to prevent long-running lock stalls or DoS.

---

## 4. Backup & Retention Policy (NFR-12)

Because OneVault is designed for ephemeral, one-time secret exchange, database backup and logging policies must prevent long-term data accumulation:

1. **Background Cleanup Schedule**:
   - Production instances should run the cleanup job periodically:
     ```text
     CLEANUP_INTERVAL_MS=900000     # 15 minutes
     CLEANUP_RETENTION_HOURS=24     # Hard-delete rows 24 hours after expiry/consumption
     ```
   - Alternatively, execute the standalone CLI command as a Kubernetes CronJob:
     ```bash
     npm run cleanup
     ```
2. **PostgreSQL WAL (Write-Ahead Logging)**:
   - Configure WAL archiving with an expiration window consistent with operational requirements (recommended: $\le$ 7 days).
3. **Database Snapshot Backups**:
   - Automated physical backups (e.g., AWS RDS automated backups) should have retention set to a maximum of **7 days**.
   - Disclose backup retention windows to end users in the privacy policy, as deleted database rows may persist inside immutable backup archives until snapshot expiration.

---

## 5. Audit Logging & SIEM Monitoring

### 5.1 Log Ingestion
- Standard output emits newline-delimited JSON logs (Pino).
- Stream logs to a centralized collector (e.g. Datadog, AWS CloudWatch, ElasticSearch, Grafana Loki).
- Verify that log ingestion pipelines enforce the retention policy (recommended: 30–90 days for audit metadata).

### 5.2 Security Alerting Triggers
Configure alerts for the following log patterns:
- **Rate Limit Triggering**: `statusCode: 429` spikes indicating brute-force or DoS attempts.
- **Revocation Failures**: `errorCode: "REVOKE_NOT_AUTHORIZED"` spikes indicating capability guessing.
- **Database Degradation**: `statusCode: 503` on `/api/v1/health` or PostgreSQL pool error events.

---

## 6. Continuous Integration & Vulnerability Scanning

Maintain supply-chain security throughout the software lifecycle:
1. **Dependency Audit**: Run `npm audit --omit=dev` in CI pipelines to catch production vulnerabilities.
2. **Static Analysis & Secret Scanning**:
   - Run ESLint with security plugins: `npm run lint`.
   - Enable GitHub Secret Scanning and Dependabot alerts.
3. **Container Image Scanning**:
   - Scan container images using Trivy or Docker Scout:
     ```bash
     trivy image onevault:latest
     ```
   - Verify the base image (`node:22-alpine`) is rebuilt regularly against the latest security patches.
