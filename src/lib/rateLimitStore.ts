/**
 * @ai-context Shared Postgres rate-limit store for multi-task Identity deployments.
 *
 * Production ECS tasks must observe one service-wide counter. Development and
 * tests keep using express-rate-limit's MemoryStore for speed and isolation.
 */

import type {
  IncrementResponse,
  Options as RateLimitOptions,
  Store,
} from "express-rate-limit";

import { prismaUnsafe } from "./prisma";

export interface RateLimitStoreHealth {
  status: "healthy" | "degraded" | "unavailable";
  type: "postgres";
}

const stores = new Set<PostgresRateLimitStore>();
let tableReady: Promise<void> | null = null;

async function ensureRateLimitTable(): Promise<void> {
  tableReady ??= prismaUnsafe
    .$executeRawUnsafe(
      `
    CREATE TABLE IF NOT EXISTS "RateLimitCounter" (
      "key" TEXT PRIMARY KEY,
      "totalHits" INTEGER NOT NULL,
      "resetTime" TIMESTAMPTZ NOT NULL
    )
  `,
    )
    .then(() => undefined)
    .catch((error: unknown) => {
      tableReady = null;
      throw error;
    });
  return tableReady;
}

export class PostgresRateLimitStore implements Store {
  readonly localKeys = false;
  readonly prefix: string;
  private windowMs = 60_000;

  constructor(prefix: string) {
    this.prefix = `${prefix}:`;
    stores.add(this);
  }

  init(options: RateLimitOptions): void {
    this.windowMs = options.windowMs;
    void ensureRateLimitTable();
  }

  async increment(key: string): Promise<IncrementResponse> {
    await ensureRateLimitTable();
    const namespacedKey = `${this.prefix}${key}`;
    await prismaUnsafe.$executeRaw`
      DELETE FROM "RateLimitCounter" WHERE "resetTime" <= NOW()
    `;
    const rows = await prismaUnsafe.$queryRaw<
      Array<{ totalHits: number; resetTime: Date }>
    >`
      INSERT INTO "RateLimitCounter" ("key", "totalHits", "resetTime")
      VALUES (${namespacedKey}, 1, NOW() + ${this.windowMs} * INTERVAL '1 millisecond')
      ON CONFLICT ("key") DO UPDATE SET
        "totalHits" = CASE
          WHEN "RateLimitCounter"."resetTime" <= NOW() THEN 1
          ELSE "RateLimitCounter"."totalHits" + 1
        END,
        "resetTime" = CASE
          WHEN "RateLimitCounter"."resetTime" <= NOW()
            THEN NOW() + ${this.windowMs} * INTERVAL '1 millisecond'
          ELSE "RateLimitCounter"."resetTime"
        END
      RETURNING "totalHits", "resetTime"
    `;
    const row = rows[0];
    if (!row) throw new Error("Postgres rate-limit increment returned no row");
    return row;
  }

  async decrement(key: string): Promise<void> {
    await ensureRateLimitTable();
    await prismaUnsafe.$executeRaw`
      UPDATE "RateLimitCounter"
      SET "totalHits" = GREATEST("totalHits" - 1, 0)
      WHERE "key" = ${`${this.prefix}${key}`}
    `;
  }

  async resetKey(key: string): Promise<void> {
    await ensureRateLimitTable();
    await prismaUnsafe.$executeRaw`
      DELETE FROM "RateLimitCounter" WHERE "key" = ${`${this.prefix}${key}`}
    `;
  }

  async resetAll(): Promise<void> {
    await ensureRateLimitTable();
    await prismaUnsafe.$executeRaw`
      DELETE FROM "RateLimitCounter" WHERE "key" LIKE ${`${this.prefix}%`}
    `;
  }
}

export async function getRateLimitStoresHealth(): Promise<RateLimitStoreHealth> {
  try {
    await ensureRateLimitTable();
    await prismaUnsafe.$queryRaw`SELECT 1 FROM "RateLimitCounter" LIMIT 1`;
    return { status: "healthy", type: "postgres" };
  } catch {
    return { status: "unavailable", type: "postgres" };
  }
}

export async function resetAllRateLimitStores(): Promise<void> {
  await Promise.all([...stores].map((store) => store.resetAll()));
}

export async function closeAllRateLimitStores(): Promise<void> {
  stores.clear();
}

export function clearStoreInstances(): void {
  stores.clear();
}
