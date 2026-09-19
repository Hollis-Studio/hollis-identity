# Hollis Identity

Read `../AGENTS.md` for coordination and shared-checkout rules.

TypeScript ESM + Express 5: `src/index.ts` assembles the app; `src/routes/`
owns HTTP contracts; `src/services/` owns auth; `src/lib/` owns infrastructure;
`prisma/schema.prisma` and migrations own persistence.

Preserve issuer/audience/JWKS, sessions, MFA/reset/rate-limit and anti-enumeration
behavior. Never log credentials, tokens or reset links. Shared contracts and
actual app adoption must be checked before changing auth interfaces.

Use `npm run typecheck`, `npm run build`, `npm test` for relevant changes.
`prisma:generate` generates the client; `prisma:migrate` is local-only;
production-like migrations use `prisma:migrate:deploy` with task authorization.
Do not expose or edit real `.env` files. Docker uses the BuildKit npmrc secret
specified in `README.md`. Publishing, deployment and infrastructure/migration
changes require authorization; local tests do not establish live rollout.
