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

import { env } from "./env";
import { logger as baseLogger } from "./logger";
import { prismaUnsafe } from "./prisma";

const logger = baseLogger.child({ module: "rateLimitStore" });

export interface RateLimitStoreHealth {
  status: "healthy" | "degraded" | "unavailable";
  type: "postgres";
}

const stores = new Set<PostgresRateLimitStore>();

/** How often expired counter rows are swept. Matches the shortest window (1 min). */
const SWEEP_INTERVAL_MS = 60_000;

let sweepTimer: NodeJS.Timeout | null = null;

type RateLimitDatabase = Pick<typeof prismaUnsafe, "$executeRaw" | "$queryRaw">;

export class PostgresRateLimitStore implements Store {
  readonly localKeys = false;
  readonly prefix: string;
  private windowMs = 60_000;

  constructor(
    prefix: string,
    private readonly database: RateLimitDatabase = prismaUnsafe,
  ) {
    this.prefix = `${prefix}:`;
    stores.add(this);
  }

  init(options: RateLimitOptions): void {
    this.windowMs = options.windowMs;
  }

  async increment(key: string): Promise<IncrementResponse> {
    // No expired-row DELETE here on purpose. This ran a full-table scan-and-delete
    // on EVERY rate-limited request, which is both the hottest path in the service
    // and a write against a table every other request is upserting into. It was
    // never needed for correctness: the ON CONFLICT branch below already restarts
    // the window when "resetTime" has passed, so an expired row is ignored rather
    // than trusted. Reaping it is pure garbage collection and now runs on the
    // periodic sweep (startRateLimitCounterSweep).
    const namespacedKey = `${this.prefix}${key}`;
    const rows = await this.database.$queryRaw<
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
    await this.database.$executeRaw`
      UPDATE "RateLimitCounter"
      SET "totalHits" = GREATEST("totalHits" - 1, 0)
      WHERE "key" = ${`${this.prefix}${key}`}
    `;
  }

  async resetKey(key: string): Promise<void> {
    await this.database.$executeRaw`
      DELETE FROM "RateLimitCounter" WHERE "key" = ${`${this.prefix}${key}`}
    `;
  }

  async resetAll(): Promise<void> {
    await this.database.$executeRaw`
      DELETE FROM "RateLimitCounter" WHERE "key" LIKE ${`${this.prefix}%`}
    `;
  }
}

/**
 * Delete counter rows whose window has already closed.
 *
 * Exported so the sweep can be tested and invoked directly; production calls it
 * from the periodic timer below.
 *
 * @returns number of rows deleted
 */
export async function sweepExpiredRateLimitCounters(
  database: RateLimitDatabase = prismaUnsafe,
): Promise<number> {
  return database.$executeRaw`
    DELETE FROM "RateLimitCounter" WHERE "resetTime" <= NOW()
  `;
}

/**
 * Start the periodic expired-counter sweep.
 *
 * Only the production Postgres store has rows to reap — dev/test use
 * express-rate-limit's MemoryStore — so this is a no-op elsewhere rather than a
 * minute-by-minute query against a table that may not be migrated locally.
 *
 * Idempotent; the timer is unref'd so it never holds the process open.
 */
export function startRateLimitCounterSweep(): void {
  if (sweepTimer) return;
  if (env.NODE_ENV !== "production") return;

  sweepTimer = setInterval(() => {
    void sweepExpiredRateLimitCounters()
      .then((deleted) => {
        if (deleted > 0) {
          logger.debug({ deleted }, "Swept expired rate-limit counters");
        }
      })
      .catch((err: unknown) => {
        // A failed sweep only means stale rows linger — counters stay correct.
        logger.error({ err }, "rateLimitStore: expired-counter sweep failed");
      });
  }, SWEEP_INTERVAL_MS);

  sweepTimer.unref();
}

/** Stop the periodic sweep (graceful shutdown / tests). */
export function stopRateLimitCounterSweep(): void {
  if (sweepTimer) {
    clearInterval(sweepTimer);
    sweepTimer = null;
  }
}

export async function getRateLimitStoresHealth(): Promise<RateLimitStoreHealth> {
  try {
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
  stopRateLimitCounterSweep();
  stores.clear();
}

export function clearStoreInstances(): void {
  stores.clear();
}
