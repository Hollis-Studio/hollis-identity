# Hollis Identity Service

Standalone authentication and identity service for the Hollis suite. Handles user registration, login, MFA, password reset, OAuth account linking, JWT issuance, and token revocation for all Hollis apps (Health, Workouts, and future apps).

**Stack:** Express 5 + Prisma 7 + PostgreSQL + Node 20 + ECS Fargate

---

## Purpose

The Identity Service is the single source of truth for user identities across the Hollis suite. Consumer apps (hollis-health-app, hollis-workouts) delegate all auth to this service and verify tokens using `@hollis-studio/auth-client`.

Key responsibilities:
- Issue access tokens (JWT, short-lived) and refresh tokens (family-rotation)
- Enforce MFA (TOTP + WebAuthn)
- Manage password reset flows
- Manage OAuth account links (Apple, Google)
- Token denylist / revocation

---

## Current build status

**W6d complete — `npm run typecheck` is green (zero errors).**

**Shared package state (2026-05-18):** this repo consumes `@hollis-studio/contracts@0.2.0-alpha.7` from GitHub Packages. The previous sibling `file:../hollis-shared` install path has been removed from manifests, Docker, and lockfiles.

- W6b: Repo scaffolding
- W6c: Verbatim copy of auth services and lib files from hollis-health-app
- **W6d (done):** Refactored all lifted files — removed Health coupling, created stubs for missing libs, `typecheck` exits 0
- W6f (pending): Wire auth routes (authService functions → Express handlers)
- W6g (pending): Health app cutover to Identity Service tokens
- W6h (pending): Production deploy, webhook events, consumer app integration

### What was changed in W6d

- `src/lib/env.ts`: Stripped to Identity Service vars only (removed Stripe, Sentry, SNS, S3, GrowthBook, AI, HIPAA-audit, PHI, feature flags, data-migration aliases)
- `src/lib/prisma.ts`: Removed tenant isolation extension (`createTenantIsolationExtension`), switched to plain `PrismaClient`
- `src/services/authService.ts`: Removed barcode format check, org status gate, `pushService` call; `organizationId` is now optional; added `aud`/`iss` JWT claims from env
- `src/services/oauthVerificationService.ts`: Removed Health-specific fields (`tier`, `prefilledTier`, `isRegistered`, barcode registration flow)
- `src/lib/accountLockout.ts`: Removed `ioredis` dependency (Identity Service uses in-memory lockout only)
- `src/middleware/errorHandler.ts`: Removed Sentry and `SessionError` references
- New stubs created: `lib/tenantContext.ts`, `lib/cookieConfig.ts`, `lib/AppError.ts`, `lib/metrics.ts`, `lib/formatErrorDigest.ts`, `lib/rateLimitStore.ts`, `lib/mfaAttemptTracker.ts`, `lib/encryption.ts`, `lib/buildPgPool.ts`, `constants/errorMessages.ts`, `utils/response.ts`, `types/express.d.ts`, `validation/common.ts`, `services/sessionService.ts`
- `@hollis-studio/auth-client` removed from `package.json` (not used — Identity Service issues tokens, doesn't verify them)
- `@prisma/adapter-pg` + `pg` installed; Prisma client generated

---

## Environment variables

Copy `.env.example` to `.env` and fill in values before running locally.

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | Secret for signing JWTs |
| `JWT_ISSUER` | Issuer claim placed in every JWT |
| `JWT_AUDIENCES` | Comma-separated valid audiences |
| `BCRYPT_PEPPER` | Server-side pepper for bcrypt hashes |
| `PORT` | HTTP port (default 3001) |
| `LOG_LEVEL` | Pino log level |

---

## Shared dependencies

Uses `@hollis-studio/contracts` from GitHub Packages. Local development and container builds need npm auth for the `@hollis-studio` scope:

```ini
@hollis-studio:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

Container builds install directly from GitHub Packages through a BuildKit npmrc secret; they no longer clone or copy `hollis-shared`.

## Local development

```bash
npm install
npm run prisma:generate
npm run prisma:migrate
npm run dev
```
