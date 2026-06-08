# Task Completion

- Run `npm run typecheck` for TypeScript changes.
- Run `npm test` when behavior or auth routing changes; tests are Node test-runner tests under `src/__tests__`.
- Run `npm run build` before deploy-oriented changes.
- If Prisma schema changes, run `npm run prisma:generate` and add/check a migration.