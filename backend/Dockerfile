# ==============================================================================
# OneVault (share-shield) Production Multi-Stage Dockerfile
# ==============================================================================

# Stage 1: Build & Prune
FROM node:22-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies for compilation)
RUN npm ci

# Copy TypeScript configs, source code, and migration assets
COPY tsconfig.json tsconfig.build.json ./
COPY src/ ./src/
COPY drizzle/ ./drizzle/

# Compile TypeScript to JavaScript in dist/
RUN npm run build

# Prune development dependencies for minimal production footprint
RUN npm prune --omit=dev

# Stage 2: Minimal Production Runtime
FROM node:22-alpine AS runner

# Hardened production environment defaults
ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

# Run as non-root user 'node' provided by official Node.js Alpine image
USER node

# Copy production runtime dependencies and build artifacts with non-root ownership
COPY --chown=node:node --from=builder /app/package.json ./package.json
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist
COPY --chown=node:node --from=builder /app/drizzle ./drizzle

# Healthcheck targeting unauthenticated health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const http = require('node:http'); \
    const req = http.request({ host: '127.0.0.1', port: process.env.PORT || 3000, path: '/api/v1/health', timeout: 4000 }, (res) => { \
      process.exit(res.statusCode === 200 ? 0 : 1); \
    }); \
    req.on('error', () => process.exit(1)); \
    req.end();"

EXPOSE 3000

# Start production server using compiled JavaScript
CMD ["node", "dist/server.js"]
