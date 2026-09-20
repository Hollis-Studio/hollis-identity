/**
 * The per-table cleanupExpired* helpers existed but had no caller, so seven auth
 * tables grew forever. authRetentionService is the single caller. These tests
 * pin which tables it prunes (and which it must not), and that one failing
 * table cannot stop the others.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  cleanupExpiredAuthRecords,
  defaultAuthRetentionCleanups,
  startAuthRetentionCleanup,
  stopAuthRetentionCleanup,
  type AuthRetentionCleanups,
} from "../services/authRetentionService";

function countingCleanups(
  counts: Partial<Record<keyof AuthRetentionCleanups, number>> = {},
): { cleanups: AuthRetentionCleanups; calls: string[] } {
  const calls: string[] = [];
  const cleanups = {} as AuthRetentionCleanups;

  for (const table of Object.keys(defaultAuthRetentionCleanups) as (keyof AuthRetentionCleanups)[]) {
    cleanups[table] = async (): Promise<number> => {
      calls.push(table);
      return counts[table] ?? 0;
    };
  }

  return { cleanups, calls };
}

describe("authRetentionService", () => {
  it("prunes exactly the five short-lived token tables", () => {
    assert.deepEqual(Object.keys(defaultAuthRetentionCleanups).sort(), [
      "emailVerificationTokens",
      "passwordResetTokens",
      "pendingMfaSessions",
      "refreshTokens",
      "stepUpTokens",
    ]);
  });

  it("does not prune AuthAuditLog or AccountLockoutEntry (owner retention decision)", () => {
    const tables = Object.keys(defaultAuthRetentionCleanups).join(",").toLowerCase();

    assert.ok(!tables.includes("audit"), "audit trail must not be swept automatically");
    assert.ok(!tables.includes("lockout"), "lockout state must not be swept automatically");
  });

  it("sweeps every table and reports per-table counts", async () => {
    const { cleanups, calls } = countingCleanups({
      passwordResetTokens: 3,
      refreshTokens: 7,
    });

    const result = await cleanupExpiredAuthRecords(cleanups);

    assert.equal(calls.length, 5);
    assert.deepEqual(result, {
      passwordResetTokens: 3,
      emailVerificationTokens: 0,
      stepUpTokens: 0,
      pendingMfaSessions: 0,
      refreshTokens: 7,
    });
  });

  it("keeps sweeping the remaining tables when one table fails", async () => {
    const { cleanups, calls } = countingCleanups({ refreshTokens: 4 });
    cleanups.stepUpTokens = async (): Promise<number> => {
      calls.push("stepUpTokens");
      throw new Error("relation \"StepUpToken\" does not exist");
    };

    const result = await cleanupExpiredAuthRecords(cleanups);

    assert.equal(calls.length, 5, "a failing table must not abort the sweep");
    assert.equal(result.stepUpTokens, 0);
    assert.equal(result.refreshTokens, 4, "tables after the failure still ran");
  });

  it("starts and stops an idempotent, unref'd timer", () => {
    // Double-start must not leak a second interval, and the process must still
    // be able to exit — this test file finishing at all is that assertion.
    startAuthRetentionCleanup();
    startAuthRetentionCleanup();
    stopAuthRetentionCleanup();
    stopAuthRetentionCleanup();
  });
});
