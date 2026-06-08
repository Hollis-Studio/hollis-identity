# Core

- Hollis Identity Service: standalone Express + Prisma + Postgres auth service.
- Runtime code in `src/`; auth routes in `src/routes/auth.ts`, token/session business logic in `src/services/authService.ts`, request auth middleware in `src/middleware/auth.ts`.
- Prisma schema in `prisma/schema.prisma`; no workspace layout.
- See `mem:tech_stack` for tools, `mem:conventions` for code patterns, `mem:suggested_commands` for commands, and `mem:task_completion` for completion checks.