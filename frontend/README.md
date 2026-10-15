# ShareShield Frontend

High-security, zero-knowledge web application for one-time secret exchange. Built with React 19, TypeScript, Vite, and Tailwind CSS.

## Getting Started

### 1. Environment Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Environment variables:
- `VITE_API_URL`: Base URL for the ShareShield backend API.
  - **Local Development (Default)**: `/api/v1` (Requests are automatically proxied to `http://localhost:3000` via Vite's dev server proxy in `vite.config.ts`).
  - **Direct Backend**: `http://localhost:3000/api/v1` (Ensure `CORS_ALLOWED_ORIGINS` in backend `.env` includes `http://localhost:5173`).
  - **Production**: `/api/v1` (when served behind a reverse proxy) or `https://api.yourdomain.com/api/v1`.

### 2. Install Dependencies

```bash
npm install
```

### 3. Run Development Server

```bash
npm run dev
```

The application will start at `http://localhost:5173`.

### 4. Run Tests & Build

```bash
# Run unit & component test suite
npm test

# Build for production (TypeScript check + Vite bundle)
npm run build
```

## Security Invariants

1. **Client-Side Encryption**: Secrets are encrypted in the browser using WebCrypto (AES-256-GCM) with a unique 12-byte IV per encryption before transmission.
2. **Zero-Knowledge Decryption Key**: The 256-bit encryption key is stored in the URL fragment (`#key`). URL fragments are never sent to the server in HTTP requests.
3. **Mandatory 6-Digit Passkey**: Secrets require a 6-digit numeric passkey for retrieval. Passkeys are displayed once to the creator and must be sent out-of-band to the recipient.
4. **Status-Before-Consume Rule**: Opening a share link queries `GET /api/v1/secrets/:token/status` without consuming. The secret is only claimed when the recipient explicitly enters the 6-digit passkey and clicks "Reveal Secret".
5. **Memory Hygiene**: Decryption keys, passkeys, and plaintexts are kept strictly in memory state and are never written to `localStorage`, `sessionStorage`, cookies, analytics, or application logs.
