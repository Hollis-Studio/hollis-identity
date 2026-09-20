import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { Options as RateLimitOptions } from "express-rate-limit";

import {
  PostgresRateLimitStore,
  sweepExpiredRateLimitCounters,
} from "../lib/rateLimitStore";

interface Counter {
  totalHits: number;
  resetTime: Date;
}

function createSharedDatabase(): {
  counters: Map<string, Counter>;
  database: {
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => Promise<number>;
    $queryRaw: <T>(strings: TemplateStringsArray, ...values: unknown[]) => Promise<T>;
  };
} {
  const counters = new Map<string, Counter>();
  return {
    counters,
    database: {
      async $executeRaw(strings, ..._values): Promise<number> {
        const sql = strings.join("?");
        // increment() must not issue ANY statement other than the upsert: the
        // expired-row DELETE it used to run on every request now belongs to the
        // periodic sweep (sweepExpiredRateLimitCounters).
        throw new Error(`Unexpected execute SQL in test: ${sql}`);
      },
      async $queryRaw<T>(strings, ...values): Promise<T> {
        const sql = strings.join("?");
        assert.match(sql, /ON CONFLICT \("key"\) DO UPDATE/);
        const key = String(values[0]);
        const windowMs = Number(values[1]);
        const existing = counters.get(key);
        const row = existing
          ? { ...existing, totalHits: existing.totalHits + 1 }
          : { totalHits: 1, resetTime: new Date(Date.now() + windowMs) };
        counters.set(key, row);
        return [row] as T;
      },
    },
  };
}

function initialize(store: PostgresRateLimitStore, windowMs = 15 * 60_000): void {
  store.init({ windowMs } as RateLimitOptions);
}

describe("PostgresRateLimitStore", () => {
  it("shares one atomic namespaced counter across store instances", async () => {
    const { counters, database } = createSharedDatabase();
    const firstTask = new PostgresRateLimitStore("login-email", database as never);
    const secondTask = new PostgresRateLimitStore("login-email", database as never);
    initialize(firstTask);
    initialize(secondTask);

    assert.equal((await firstTask.increment("demo@woapp.com")).totalHits, 1);
    assert.equal((await secondTask.increment("demo@woapp.com")).totalHits, 2);
    assert.equal(counters.get("login-email:demo@woapp.com")?.totalHits, 2);
  });

  it("does not sweep expired rows on the increment hot path", async () => {
    // The shared fake throws on any $executeRaw; a DELETE-per-request would
    // therefore fail this increment.
    const { database } = createSharedDatabase();
    const store = new PostgresRateLimitStore("login", database as never);
    initialize(store);

    assert.equal((await store.increment("1.2.3.4")).totalHits, 1);
  });

  it("propagates database failures so express-rate-limit fails closed", async () => {
    const database = {
      $executeRaw: async (): Promise<number> => {
        throw new Error("execute should not run");
      },
      $queryRaw: async <T>(): Promise<T> => {
        throw new Error("postgres unavailable");
      },
    };
    const store = new PostgresRateLimitStore("login-email", database as never);
    initialize(store);

    await assert.rejects(store.increment("demo@woapp.com"), /postgres unavailable/);
  });
});

describe("sweepExpiredRateLimitCounters", () => {
  it("deletes only rows whose window has closed", async () => {
    let executed = "";
    const database = {
      $executeRaw: async (strings: TemplateStringsArray): Promise<number> => {
        executed = strings.join("?");
        return 4;
      },
      $queryRaw: async <T>(): Promise<T> => {
        throw new Error("query should not run");
      },
    };

    const deleted = await sweepExpiredRateLimitCounters(database as never);

    assert.equal(deleted, 4);
    assert.match(executed, /DELETE FROM "RateLimitCounter"/);
    assert.match(executed, /"resetTime" <= NOW\(\)/);
  });
});
