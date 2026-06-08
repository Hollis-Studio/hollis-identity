# Conventions

- Source files use ESM imports, explicit `.js` extensions are common for relative runtime imports.
- Auth/service errors use local `AuthError`/structured codes and route handlers map them to response envelopes.
- Token and auth security behavior is centralized in `src/services/authService.ts`; route handlers should delegate there.
- Env is accessed through `getEnv()` / `env` helpers, not raw `process.env` in business logic.
- Prisma writes that are system-level auth operations may be wrapped in `runAsSystemOperation`.