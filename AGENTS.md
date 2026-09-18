# Hollis Identity Service

Read the workspace-level `../AGENTS.md` first. It defines the shared governance and coordination protocol; do not duplicate it here. When that protocol calls for coordination, use `../agent-coordination/board.py` (or `hollis-board` when installed), register/touch activity, and claim exact files before editing.

This is a TypeScript ESM Express 5 service. `src/index.ts` builds the app; `src/routes/` owns HTTP contracts; `src/services/` owns auth flows; `src/lib/` provides security and infrastructure concerns; `prisma/schema.prisma` and migrations define persistence. Treat token formats, password/MFA flows, rate limits, audit events, and public error messages as compatibility and security boundaries. Preserve anti-enumeration behavior and never log credentials, tokens, reset links, or secret values.

Use the package scripts as the source of truth:

```sh
npm run typecheck
npm run build
npm test
```

Generate the Prisma client with `npm run prisma:generate`. `npm run prisma:migrate` is only for a local development database; production-like environments use `npm run prisma:migrate:deploy`. Do not load, print, commit, or modify real `.env` files. Docker builds require the existing BuildKit npmrc secret described in `README.md`.

Keep changes focused and preserve other worktree changes. Update documentation when a source-verified behavior or script changes, but treat deployment, provider, DNS, and delivery status as external state that needs fresh evidence. Do not commit, push, apply infrastructure, run migrations outside a local database, or send external messages unless the task authorizes it.
