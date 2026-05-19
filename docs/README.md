# Hollis Identity Docs

Current state as of 2026-05-19:

- Standalone Express + Prisma identity service typechecks, builds, and has
  smoke/route-boundary tests.
- Shared contracts are consumed from GitHub Packages as `@hollis-studio/contracts@0.2.0-alpha.7`.
- Docker installs packages from GitHub Packages through an npmrc secret; no sibling `hollis-shared` checkout is required.
- Health auth code has been extracted and adapted rather than rewritten.
- Identity is cookie-agnostic: it returns JSON token envelopes only and exposes
  root `POST /verify` for the current `@hollis-studio/auth-client` remote verification path.
- Startup now mounts CORS, request IDs/log context, auth rate limiters, central
  error handling, and fail-fast environment validation.
- Production Postgres TLS now verifies certificates by default; configure `DATABASE_SSL_CA`
  when the runtime trust store needs an explicit RDS CA bundle.
- Production access/refresh/MFA-pending token signing uses RS256 and
  `/.well-known/jwks.json` publishes the public JWK for consumer-side
  verification.
- Production token revocation state is PostgreSQL-backed so ECS tasks share
  invalidation decisions across deploys and horizontal scale. Account lockout
  storage also has a PostgreSQL implementation, but login enforcement is still
  pending.
- Password reset email delivery is wired through SES when `EMAIL_PROVIDER=ses`.
- Terraform IaC now lives in `infrastructure/` and targets AWS account
  `344345273019` by default through provider account allowlisting. It validates
  and plans locally, but has not been applied.
- Health integration is not cut over yet. Health still owns production auth until the identity-service migration phases are completed.

Remaining deployment work: apply reviewed Terraform, create and review the initial
Prisma migration, run `prisma migrate deploy`, push the image to ECR, configure
DNS/ACM/SES, expand the DB-backed auth matrix, harden
`@hollis-studio/auth-client`, then implement Health delegation and soak.

Operational setup remains in the root [`README.md`](../README.md) until the service gets a fuller runbook set.
