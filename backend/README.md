# OneVault (`share-shield`) Backend API

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22%20LTS-green.svg)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17+-blue.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-MIT-gray.svg)](LICENSE)

**OneVault** is a hardened, zero-knowledge, one-time secret sharing vault REST API. It allows creators to store encrypted payloads that recipients can retrieve and decrypt in the browser exactly once.

---

## 🔒 Non-Negotiable Security Invariants

1. **Zero-Knowledge Storage**: The server never accepts, expects, or stores secret plaintexts or decryption keys. The database stores only SHA-256 digests of tokens and encrypted ciphertext.
2. **Never Log Sensitive Material**: Raw tokens, revoke tokens, encryption keys, plaintexts, and ciphertexts are never logged, never included in error messages, and never returned in error responses.
3. **Atomic One-Time Consumption**: Consumption is a single conditional atomic statement in PostgreSQL (`FOR UPDATE` row lock + conditional state check + wipe to `NULL`). Concurrent requests can never both retrieve the secret.
4. **Uniform Unavailable Response**: Invalid, expired, consumed, revoked, and nonexistent tokens produce an identical HTTP 404 response body and status, completely preventing existence and state oracles.
5. **Authoritative Clock**: Expiry is evaluated strictly using server/database time (`NOW()`), never client-supplied timestamps.
6. **Audit-Safe Structured Logging**: Logs record strictly: request ID, method, parameterized route template (e.g. `/api/v1/secrets/:token/consume`), status code, latency, and coarse error codes. Request bodies, query strings, headers, and IP addresses are omitted or hashed.
7. **Parameterized Queries Only**: All queries use Drizzle ORM parameterized statements. Dynamic SQL string concatenation is strictly forbidden.

---

## 🛠 Tech Stack

- **Runtime**: Node.js 22 LTS (ES Modules)
- **Framework**: Express 4 with TypeScript strict mode (`noUncheckedIndexedAccess`)
- **Database & ORM**: PostgreSQL via `pg` Pool + Drizzle ORM & Drizzle Kit migrations
- **Validation**: Zod (strict object parsing rejecting unknown properties)
- **Security & Headers**: Helmet, CORS allowlist, Cache-Control (`no-store`), express-rate-limit (+ Redis store)
- **Testing**: Vitest + Supertest (unit, integration, and high-concurrency race suites)
- **Logging**: Pino structured JSON logger with field-level redaction

---

## 🚀 Getting Started

### Prerequisites
- Node.js >= 20.0.0 (Node 22 LTS recommended)
- PostgreSQL >= 15 (running locally or via Docker)
- Optional: Redis >= 7 (for multi-instance rate limiting)

### 1. Installation
```bash
git clone git@github.com:GetnetYideg/share-shield.git
cd share-shield
npm ci
```

### 2. Environment Configuration
Copy `.env.example` to `.env` and configure your environment:
```bash
cp .env.example .env
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NODE_ENV` | Environment (`development`, `test`, `production`) | `development` |
| `PORT` | HTTP port | `3000` |
| `DATABASE_URL` | PostgreSQL connection string | *Required* |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed frontend origins | `http://localhost:5173` |
| `TRUST_PROXY` | Proxy hop count or CIDR (`false`, `1`, `loopback`) | `false` |
| `IP_HASH_SALT` | Secret salt for HMAC-SHA256 IP hashing (min 16 chars) | *Required* |
| `REDIS_URL` | Optional Redis URL for distributed rate limiting | *Optional* |
| `LOG_LEVEL` | Pino logging level (`info`, `debug`, `warn`, `error`) | `info` |
| `MAX_BODY_SIZE` | Express JSON body parser limit | `16kb` |
| `CLEANUP_INTERVAL_MS` | In-process cleanup interval in ms | `900000` (15m) |
| `CLEANUP_RETENTION_HOURS` | Retention window before permanent deletion | `24` |

### 3. Database Migrations
Apply versioned DDL migrations:
```bash
npm run db:migrate
```

### 4. Running the Application
```bash
# Development mode with hot reload
npm run dev

# Compile TypeScript
npm run build

# Start production server
npm start
```

---

## 🧪 Testing

The test suite validates cryptographic primitives, Zod schemas, HTTP integration endpoints, database lifecycle, and high-concurrency race conditions:

```bash
# Run all tests
npm test

# Run tests with code coverage report
npm run test:coverage

# Run linter
npm run lint

# Check code formatting
npm run format:check
```

### Concurrency Guarantees
The test `tests/concurrency/secrets.concurrency.test.ts` fires **30 simultaneous parallel requests** across 5 repeated runs against PostgreSQL to mathematically verify that exactly one request succeeds and all others receive HTTP 404 `SECRET_UNAVAILABLE`.

---

## 🧹 Scheduled & CLI Cleanup

Expired, consumed, and revoked secrets can be purged after the configured retention period (`CLEANUP_RETENTION_HOURS`):

```bash
# Execute standalone cleanup job via CLI
npm run cleanup
```

In production, cleanup also runs automatically in the background via the in-process scheduler (`CLEANUP_INTERVAL_MS`).

---

## 🐳 Docker & Docker Compose

### Run complete local stack (API + PostgreSQL + Redis + Migrations)
```bash
docker compose up --build
```

The Docker Compose configuration:
1. Boots PostgreSQL and Redis containers with health checks.
2. Runs the `migrator` container to apply DDL schema migrations.
3. Starts the production `api` container running as a non-root user (`node`).

---

## 📚 Documentation Index

- [**API Reference (`API.md`)**](API.md): Complete REST endpoint documentation with curl examples.
- [**Client Crypto Contract (`docs/CLIENT_CRYPTO_CONTRACT.md`)**](docs/CLIENT_CRYPTO_CONTRACT.md): Browser WebCrypto specs, IV rules, and fragment scrubbing.
- [**Security Policy & Threat Model (`SECURITY.md`)**](SECURITY.md): Threat mitigations, OWASP Top 10 mappings, and system limitations.
- [**Production Deployment Hardening (`DEPLOYMENT_HARDENING.md`)**](DEPLOYMENT_HARDENING.md): Reverse proxy, TLS, database least-privilege, and retention.
- [**Phase 1 Analysis & Decisions (`docs/PHASE1_ANALYSIS.md`)**](docs/PHASE1_ANALYSIS.md): Architectural decisions and gap resolutions.

---

## 📄 License
MIT
