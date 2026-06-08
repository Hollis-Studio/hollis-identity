# Tech Stack

- TypeScript ESM (`type: module`) on Node.
- Express 5 API, Prisma 7 with Postgres, `@prisma/client` and `@prisma/adapter-pg`.
- JWTs via `jsonwebtoken`; password hashing via `bcryptjs` plus local passwordHashing helpers.
- Tests use Node's built-in test runner with `tsx` import, not Jest.
- Package manager is npm with `package-lock.json`.