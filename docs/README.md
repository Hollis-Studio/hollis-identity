# Hollis Identity Service — Technical Reference

Standalone authentication and identity service for the Hollis suite. Handles user registration, login, MFA, password reset, OAuth account linking, JWT issuance, and token revocation for all Hollis apps.

**Stack:** Express 5 · Prisma 7 (adapter-pg) · PostgreSQL 16 · Node 20 · ECS Fargate · TypeScript (ESM)

**Package:** `@hollis-studio/identity@0.1.0-alpha.2`  
**Shared contracts:** `@hollis-studio/contracts@0.2.0-alpha.19` from GitHub Packages

---

## Deployment status (2026-05-19)

Local hardening is complete — `typecheck`, `build`, `test`, and Terraform validation are green. The service is not yet deployed; no production cutover has happened. Health still owns production auth.

Remaining before cutover:

- Apply reviewed Terraform to a staging/prod environment
- Run `prisma migrate deploy` against the Identity RDS database (initial migration at `prisma/migrations/20260519000000_initial/`)
- Push container image to ECR; verify ECS health checks
- Configure Route53/ACM for `identity.hollis.health`
- Verify SES sender/domain and password-reset delivery
- Expand route tests from smoke/boundary to a full DB-backed auth matrix
- Harden `@hollis-studio/auth-client` for JWKS fetch/cache and revocation decisions
- Implement Health `USE_IDENTITY_SERVICE` delegation, soak, and rollback path

---

## Boot order

```
1. Sentry init (captures startup errors before anything else runs)
2. validateEnvOnStartup() — Zod schema + production-mode hard checks
3. Express app created — middleware stack wired (see below)
4. server.listen(PORT)
5. SIGTERM / SIGINT graceful shutdown handler registered
```

Production-mode hard failures at startup: `JWT_ALGORITHM` must be `RS256`, `JWT_PRIVATE_KEY` and `JWT_KEY_ID` are required, `EMAIL_PROVIDER=ses` requires `AWS_REGION`, `RESET_PASSWORD_URL`, and `VERIFY_EMAIL_URL`.

Graceful shutdown drains in-flight requests (15-second timeout), then disconnects the Prisma pool.

---

## Middleware stack

Applied in order by `createApp()` in `src/index.ts`:

| Middleware | Purpose |
|---|---|
| `requestContext` | Attaches per-request UUID (`X-Request-Id`) and child Pino logger |
| `cors` | Allows origins from `CORS_ORIGINS` (empty = block all in prod, allow all in dev) |
| `express.json` | Body parsing; 1 MB limit |
| `loginRateLimiter` | 5 req/min per IP on `POST /v1/auth/login` and `POST /v1/auth/register` |
| `loginEmailRateLimiter` | 10 req/15 min per email address on `POST /v1/auth/login` |
| `authSessionRateLimiter` | 15 req/min per IP on all `GET|POST /v1/auth/*` |
| `authenticateToken` | Bearer JWT verification + denylist check (used on protected routes only) |
| `errorHandler` | Central error handler — handles `AppError`, Prisma errors, payload-too-large, JSON parse errors |

Rate limiters use `MemoryStore` (single-instance). In dev/test, limits are multiplied by 10 to avoid interference. E2E security tests can force real limits via `E2E_SECURITY_TEST=true`. `REDIS_URL` enables Redis-backed rate limiting automatically (via `rateLimitStore.ts` abstraction).

---

## Route map

All auth routes are mounted at `/v1/auth`. The MFA router is mounted at `/v1/auth/mfa` before the auth router to prevent prefix collision.

### Public routes (no access token required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | DB-aware health check; pings DB with `SELECT 1` |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | RS256 public key set (empty in HS256/local mode) |
| `POST` | `/verify` | Root token verification endpoint (matches `@hollis-studio/auth-client` remote verify shape) |
| `POST` | `/v1/auth/login` | Email+password login; returns token envelope or MFA-pending session |
| `POST` | `/v1/auth/register` | New user registration; issues tokens immediately |
| `POST` | `/v1/auth/logout` | Revokes refresh token |
| `POST` | `/v1/auth/refresh` | Refresh token rotation; accepts optional `previousAccessToken` for MFA carry-forward |
| `GET` | `/v1/auth/verify` | Token verification via `Authorization: Bearer` header |
| `POST` | `/v1/auth/verify` | Token verification via JSON body `{ token, audience? }` |
| `POST` | `/v1/auth/oauth` | Apple/Google OAuth sign-in (id_token verification) |
| `POST` | `/v1/auth/forgot-password` | Initiates password reset; always returns 200 (anti-enumeration) |
| `POST` | `/v1/auth/reset-password` | Consumes reset token; rehashes password; revokes all sessions |
| `GET` | `/v1/auth/verify-email/confirm?token=` | Consumes email verification token |
| `POST` | `/v1/auth/mfa/login/verify` | Consumes MFA-pending session token; returns full session tokens |

### Protected routes (require `Authorization: Bearer <access_token>`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/auth/me` | Authenticated user profile |
| `POST` | `/v1/auth/change-password` | Authenticated password change; revokes other sessions |
| `POST` | `/v1/auth/biometric-token` | Issues long-TTL refresh token for mobile biometric login |
| `POST` | `/v1/auth/verify-email/send` | Sends or resends verification email |
| `GET` | `/v1/auth/mfa/status` | MFA status for authenticated user |
| `GET` | `/v1/auth/mfa/credentials` | List verified MFA credentials |
| `DELETE` | `/v1/auth/mfa/credentials/:credentialId` | Remove a credential |
| `POST` | `/v1/auth/mfa/totp/setup` | Initiate TOTP enrollment |
| `POST` | `/v1/auth/mfa/totp/verify` | Confirm TOTP enrollment with live code |
| `POST` | `/v1/auth/mfa/session-reverify` | Re-verify MFA when 8-hour session window expires |
| `POST` | `/v1/auth/mfa/step-up` | Issue 15-minute step-up token for sensitive action |
| `POST` | `/v1/auth/mfa/backup-codes` | Regenerate backup codes (requires current TOTP code) |

WebAuthn routes (`/v1/auth/mfa/webauthn/*`) are not yet implemented — tracked as `TODO(W6h)`.

---

## JWT and token model

### Token types

| Type | `type` claim | TTL | Stored in DB |
|---|---|---|---|
| Access | `access` | 15 minutes | No (stateless) |
| Refresh | `refresh` | 7 days | Yes (hash) |
| MFA-pending | `mfa_pending` | 15 minutes | Yes (`PendingMfaSession`) |

### Access token claims

`sub`, `userId`, `role`, `organizationId`, `type`, `jti`, `aud`, `iss`, `iat`, `exp`, `claims.hollisHealth.{role,organizationId}`, optionally `mfaVerifiedAt`, `mfaEnabled`.

The `claims.hollisHealth` namespace preserves backward compatibility during Health cutover.

### Signing algorithms

- **Production:** RS256. Requires `JWT_PRIVATE_KEY` (PEM) and `JWT_KEY_ID`. Public key served at `/.well-known/jwks.json`.
- **Local/test:** HS256. Only `JWT_SECRET` required. `/.well-known/jwks.json` returns `{ keys: [] }`.

Centralized in `src/lib/jwtKeys.ts` (`signJwt`, `verifyJwt`, `getPublicJwks`).

### Refresh token rotation

On refresh (`POST /v1/auth/refresh`):

1. Verify JWT signature and `type=refresh`.
2. Look up hash in `RefreshToken` table.
3. **Reuse detection:** if `usedAt` is already set, revoke the entire token family and throw `TOKEN_REUSE_DETECTED`.
4. Consume old token (set `usedAt`), create new token in the same family with `generation + 1` — done atomically at `SERIALIZABLE` isolation.
5. MFA carry-forward: if `previousAccessToken` is supplied and `mfaVerifiedAt` is within the 8-hour session window, the claim propagates to the new access token.

### Token revocation / denylist

`src/services/tokenDenylistService.ts` provides two revocation modes:

- **JTI revocation** (`denyAccessToken`) — targets a single token.
- **User-level bulk revocation** (`denyAllUserAccessTokens`) — invalidates all tokens issued at or before a watermark timestamp.

**Backend selection:** `DatabaseTokenDenylistStore` (PostgreSQL) in production; `InMemoryTokenDenylistStore` in dev/test. The DB store uses `AccessTokenDenylistEntry` and `UserTokenDenylistEntry` tables so revocation decisions are shared across all ECS tasks and survive deploys.

Denylist checking is controlled by `ACCESS_TOKEN_DENYLIST_ENABLED` (default `true`). Disabling it falls back to the 15-minute TTL as the security boundary.

---

## Database schema

All models live in the `public` schema. Key tables:

| Table | Purpose |
|---|---|
| `User` | Core identity: email, passwordHash, role (ADMIN/CLINICIAN/TRAINER/CLIENT), isActive, emailVerified, optional organizationId |
| `RefreshToken` | Family-rotation refresh tokens: tokenHash (SHA-256), familyId, generation, usedAt, replacedByTokenHash, revokedAt |
| `MfaCredential` | TOTP and WebAuthn credentials; totpSecret encrypted at rest |
| `MfaEvent` | Audit trail for all MFA actions |
| `PendingMfaSession` | Single-use MFA-pending session tokens (15-minute TTL) |
| `StepUpToken` | Single-use step-up tokens for sensitive actions (15-minute TTL) |
| `AccessTokenDenylistEntry` | Per-JTI revocation; expires with the token |
| `UserTokenDenylistEntry` | Per-user watermark revocation |
| `AccountLockoutEntry` | Progressive lockout state (wired to storage; login enforcement pending) |
| `PasswordResetToken` | Single-use tokens for password reset flow (tokenHash only) |
| `EmailVerificationToken` | Single-use tokens for email verification (tokenHash only) |
| `OAuthAccount` | Links Apple/Google provider sub to a Hollis user |
| `AuthAuditLog` | Audit trail for login, register, logout, refresh, password reset, email verification events |

`User.id` is format-agnostic — Health users may retain `HH-XXXXXX` barcodes; Workouts/new users get UUIDs. `organizationId` is nullable.

Initial migration: `prisma/migrations/20260519000000_initial/migration.sql`

---

## Key service modules

| File | Responsibility |
|---|---|
| `src/services/authService.ts` | Login, register, refresh, logout, token generation, MFA carry-forward |
| `src/services/mfaService.ts` | TOTP setup/verify, backup codes, step-up, credential management |
| `src/services/tokenDenylistService.ts` | Access token revocation (DB + in-memory backends) |
| `src/services/passwordResetService.ts` | Forgot-password / reset-password / change-password flows |
| `src/services/emailVerificationService.ts` | Email verification token lifecycle |
| `src/services/emailService.ts` | Email dispatch — console (dev) or SES (prod via `EMAIL_PROVIDER=ses`) |
| `src/services/oauthVerificationService.ts` | Apple and Google id_token verification |
| `src/services/pendingMfaSessionService.ts` | MFA-pending session create/consume (single-use) |
| `src/services/authAuditService.ts` | Writes `AuthAuditLog` rows |
| `src/lib/jwtKeys.ts` | RS256/HS256 sign, verify, JWKS export |
| `src/lib/env.ts` | Zod environment validation with production-mode hard checks |
| `src/lib/accountLockout.ts` | Progressive per-account lockout (5/10/15/20+ attempts → 15m/30m/1h/2h) — storage wired, login enforcement pending |
| `src/lib/buildPgPool.ts` | `pg.Pool` factory with TLS and production connection pool config |
| `src/lib/encryption.ts` | AES encryption for TOTP secrets at rest |

---

## Error handling

Central error handler (`src/middleware/errorHandler.ts`) catches:

- `AppError` — structured error with `statusCode` and `code`; logged at warn (4xx) or error (5xx)
- `Prisma.PrismaClientKnownRequestError` — Prisma error code logged without PHI
- JSON `SyntaxError` — `400 INVALID_JSON`
- `entity.too.large` — `413 PAYLOAD_TOO_LARGE`
- All others — `500 INTERNAL_ERROR`

In development, error messages are included in the response. In production, only the generic message is returned. All responses include `requestId` for log correlation.

Sentry integration captures startup errors and unhandled rejections. `sendDefaultPii: false` and a `beforeSend` hook strip request body, cookies, query params, and auth headers.

---

## MFA flows

### Login with MFA

1. `POST /v1/auth/login` — password verified, MFA enrollment detected.
2. Response: `{ mfaRequired: true, sessionToken, availableMethods, expiresIn: 900 }`.
3. `POST /v1/auth/mfa/login/verify` — consumer submits `{ sessionToken, code, credentialId }`.
4. Session token is consumed (single-use), TOTP code verified, full token pair issued.

### MFA session window

`mfaVerifiedAt` (epoch ms) is embedded in the access token. The 8-hour window (`MFA_SESSION_WINDOW_MS` from contracts) allows MFA status to carry forward across token refreshes without re-challenging the user. Carry-forward requires the caller to supply `previousAccessToken` on `POST /v1/auth/refresh`.

### Step-up

`POST /v1/auth/mfa/step-up` verifies a live TOTP code and returns a 15-minute `stepUpToken` scoped to the requested `action`. Step-up tokens are persisted to `StepUpToken` (PostgreSQL) for cross-instance validity.

---

## Account lockout

`src/lib/accountLockout.ts` implements per-account progressive friction keyed by email hash:

| Failed attempts | Lockout duration |
|---|---|
| 5 | 15 minutes |
| 10 | 30 minutes |
| 15 | 1 hour |
| 20+ | 2 hours (cap) |

Storage is PostgreSQL-backed in production (`AccountLockoutEntry`); in-memory in dev/test. **Login enforcement is not yet wired into the login route** — tracked as a remaining deployment task.

---

## Security properties

- **Cookie-agnostic:** Identity never sets or clears cookies. Consumers own cookie posture; mobile clients store JSON token responses.
- **Anti-enumeration:** `POST /v1/auth/forgot-password` always returns `200 { ok: true }`. Failed login and registration errors use generic messages. Timing-safe password comparison prevents user existence oracle.
- **Password hashing:** bcrypt with configurable cost factor (`BCRYPT_COST_FACTOR`, default 13, range 10–16) plus optional server-side pepper (`PASSWORD_PEPPER`). On-login rehash upgrades cost factor automatically.
- **TOTP secret encryption:** MFA TOTP secrets are encrypted at rest using `ENCRYPTION_KEY`.
- **Refresh token reuse detection:** Any reuse of an already-consumed token triggers family-wide revocation.
- **Postgres TLS:** Production verifies certificates by default (`sslmode=require`). Supply `DATABASE_SSL_CA` when the runtime trust store needs an explicit RDS CA bundle.
- **WAF:** AWS WAF rate-based rule (default 1000 req/5 min per IP) applied to the ALB via Terraform.

---

## Environment variables

Copy `.env.example` to `.env`. The app does not preload `.env`; export it before running:

```bash
set -a && source .env && set +a
```

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `DATABASE_SSL_CA` | No | PEM CA bundle for production RDS TLS |
| `JWT_SECRET` | Yes | HS256 signing secret (≥ 8 chars dev; ≥ 32 chars prod with entropy) |
| `JWT_ALGORITHM` | No | `RS256` in production; `HS256` only for local/test (default `HS256`) |
| `JWT_PRIVATE_KEY` | Prod | PEM RSA private key for RS256 |
| `JWT_PUBLIC_KEY` | No | PEM public key; derived from private key if omitted |
| `JWT_KEY_ID` | Prod | Key ID published in JWKS |
| `JWT_ISSUER` | No | `iss` claim placed in every JWT |
| `JWT_AUDIENCES` | No | Comma-separated valid audiences (default: all contracts audiences) |
| `ENCRYPTION_KEY` | Yes | 32+ char key for MFA TOTP secret encryption |
| `PASSWORD_PEPPER` | No | 32+ char server-side pepper for password hashes |
| `PORT` | No | HTTP port (default `4001`) |
| `LOG_LEVEL` | No | Pino level: `debug`\|`info`\|`warn`\|`error` (default `info`) |
| `CORS_ORIGINS` | No | Comma-separated allowed browser origins |
| `EMAIL_PROVIDER` | No | `console` (dev) or `ses` (prod, default `console`) |
| `EMAIL_FROM` | No | Verified sender address (default `noreply@hollis.health`) |
| `RESET_PASSWORD_URL` | Prod/SES | Frontend reset-password page URL (not the Identity API URL) |
| `VERIFY_EMAIL_URL` | Prod/SES | Frontend suite email verification page URL |
| `AWS_REGION` | Prod/SES | AWS region for SES |
| `REDIS_URL` | No | Enables Redis-backed rate limiting |
| `ACCESS_TOKEN_DENYLIST_ENABLED` | No | Set to `false` to skip denylist checks (default `true`) |
| `SENTRY_DSN` | No | Sentry project DSN (warn emitted in prod if absent) |
| `BCRYPT_COST_FACTOR` | No | bcrypt work factor 10–16 (default `13`) |

---

## Local development

```bash
# 1. Install dependencies (needs npm auth for @hollis-studio scope — see .env.npm.local)
npm install

# 2. Generate Prisma client
npm run prisma:generate

# 3. Create/migrate local database
npm run prisma:migrate

# 4. Start in watch mode (tsx)
npm run dev
```

## Verification

```bash
npm run typecheck   # tsc --noEmit
npm run build       # tsc → dist/
npm test            # Node built-in test runner via tsx
```

## Container build

```bash
# BuildKit + npmrc secret for GitHub Packages
DOCKER_BUILDKIT=1 docker build \
  --secret id=npmrc,src=.env.npm.local \
  -t hollis-identity:local .
```
