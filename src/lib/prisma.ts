/**
 * @ai-context Prisma client singleton | shared DB connection for Identity Service
 *
 * Prisma 7 requires an explicit driver adapter for database connections.
 * Connection pool is configured via the pg Pool options below.
 *
 * Identity Service has no multi-tenancy at the Prisma layer — all auth models
 * (User, RefreshToken, MfaCredential, etc.) are owned by Identity Service directly.
 */
import { PrismaPg } from "@prisma/adapter-pg";
import { buildPgPool } from "./buildPgPool";
import { Prisma, PrismaClient } from "../../prisma/generated/prisma/client.js";
import { logger } from "./logger";

// Re-export only the Prisma types actually used across the codebase.
export type {
  User,
  // Enum types
  OAuthProviderType,
  UserRole,
} from "../../prisma/generated/prisma/client.js";

/**
 * Type-safe DbNull for JSON field assignments.
 */
export const PRISMA_DB_NULL = Prisma.DbNull as unknown as Prisma.InputJsonValue;
export { Prisma, PrismaClient };

// env-ok: bootstrap-order guard — prisma client is instantiated at module load, before
// validateEnvOnStartup() runs in index.ts.
const isProduction = process.env.NODE_ENV === "production";
const dbUrl = process.env.DATABASE_URL ?? "";

if (isProduction && !dbUrl.includes("connection_limit")) {
  logger.warn(
    { component: "prisma" },
    "DATABASE_URL missing connection_limit parameter. Consider adding ?connection_limit=20&pool_timeout=10 for production workloads.",
  );
}

const logDbQueries = process.env.LOG_DB_QUERIES === "true";

const pool = buildPgPool({ databaseUrl: dbUrl, nodeEnv: process.env.NODE_ENV ?? "" });
const adapter = new PrismaPg(pool);

const basePrisma = new PrismaClient({
  adapter,
  log: [
    { emit: "event", level: "query" },
    { emit: "event", level: "error" },
    { emit: "event", level: "warn" },
  ],
});

basePrisma.$on("query", (e) => {
  if (logDbQueries) {
    logger.debug(
      { component: "prisma", durationMs: e.duration },
      `Query: ${e.query}`,
    );
  }
});

basePrisma.$on("warn", (err) => {
  logger.warn({ err, component: "prisma" }, "Prisma query event");
});

basePrisma.$on("error", (err) => {
  logger.error({ err, component: "prisma" }, "Prisma error event");
});

export const prisma = basePrisma as unknown as PrismaClient;
export const prismaUnsafe = basePrisma;

export type ExtendedPrismaClient = PrismaClient;
export type ExtendedTransactionClient = Prisma.TransactionClient;
export type PrismaClientLike = {
  user: PrismaClient["user"];
  [K: string]: unknown;
};

// Graceful shutdown
process.on("beforeExit", () => {
  basePrisma.$disconnect().catch((err: unknown) => {
    logger.warn({ err }, "Failed to disconnect Prisma on beforeExit");
  });
});
