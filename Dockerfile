# ============================================================
# Hollis Identity Service — Multi-stage Docker build
# Stage 0: hollis-shared — clone + build the sibling shared monorepo
# Stage 1: deps          — install production dependencies
# Stage 2: build         — compile TypeScript
# Stage 3: runner        — lean production image
#
# Shared deps (@hollis/contracts) use file: refs against
# ../hollis-shared. See:
# https://github.com/idlandes04/hollis-shared/blob/main/docs/2026-05-13-shared-deps-distribution.md
# ============================================================

# ---- Stage 0: hollis-shared ----
FROM node:20-alpine AS hollis-shared
RUN apk add --no-cache git
WORKDIR /workspace
ARG HOLLIS_SHARED_REF=main
RUN git clone --depth 1 --branch ${HOLLIS_SHARED_REF} \
      https://github.com/idlandes04/hollis-shared.git hollis-shared
WORKDIR /workspace/hollis-shared
RUN npm ci && npm run build

# ---- Stage 1: deps ----
FROM node:20-alpine AS deps
WORKDIR /workspace/hollis-identity
# Place hollis-shared at the sibling path file:../hollis-shared refs expect
COPY --from=hollis-shared /workspace/hollis-shared /workspace/hollis-shared
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# ---- Stage 2: build ----
FROM node:20-alpine AS build
WORKDIR /workspace/hollis-identity
COPY --from=hollis-shared /workspace/hollis-shared /workspace/hollis-shared
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
COPY prisma/ ./prisma/
RUN npm run prisma:generate
RUN npm run build

# ---- Stage 3: runner ----
FROM node:20-alpine AS runner
WORKDIR /workspace/hollis-identity
ENV NODE_ENV=production

# Ship hollis-shared on disk; node_modules contains file: symlinks
# that resolve to /workspace/hollis-shared/packages/* at runtime
COPY --from=hollis-shared /workspace/hollis-shared /workspace/hollis-shared
COPY --from=deps /workspace/hollis-identity/node_modules ./node_modules
COPY --from=build /workspace/hollis-identity/dist ./dist
COPY --from=build /workspace/hollis-identity/prisma ./prisma
COPY package.json ./

EXPOSE 3001

CMD ["node", "dist/index.js"]
