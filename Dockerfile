# ============================================================
# Hollis Identity Service — Multi-stage Docker build
# Stage 1: deps   — install production dependencies
# Stage 2: build  — compile TypeScript
# Stage 3: runner — lean production image
# ============================================================

# ---- Stage 1: deps ----
FROM node:20-alpine AS deps
WORKDIR /workspace/hollis-identity
COPY package.json package-lock.json* ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --omit=dev

# ---- Stage 2: build ----
FROM node:20-alpine AS build
WORKDIR /workspace/hollis-identity
COPY package.json package-lock.json* ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY tsconfig.json ./
COPY src/ ./src/
COPY prisma/ ./prisma/
RUN npm run prisma:generate
RUN npm run build

# ---- Stage 3: runner ----
FROM node:20-alpine AS runner
WORKDIR /workspace/hollis-identity
ENV NODE_ENV=production

COPY --from=deps /workspace/hollis-identity/node_modules ./node_modules
COPY --from=build /workspace/hollis-identity/dist ./dist
COPY --from=build /workspace/hollis-identity/prisma ./prisma
COPY package.json ./

EXPOSE 4001

CMD ["node", "dist/index.js"]
