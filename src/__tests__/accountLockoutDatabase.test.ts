import assert from "node:assert/strict";
import { test } from "node:test";
import { DatabaseAccountLockoutStore, type LockoutConfig } from "../lib/accountLockout";
import { prisma } from "../lib/prisma";

const config: LockoutConfig = {
  initialThreshold: 5, initialLockoutSeconds: 900, maxLockoutSeconds: 7200,
  failureWindowSeconds: 60, maxUniqueIpsBeforeFlag: 3,
};

test("successful logins and resets tolerate absent failure rows without a throwing mutation", async (t) => {
  const delegate = prisma.accountLockoutEntry;
  const originals = { updateMany: delegate.updateMany, deleteMany: delegate.deleteMany,
    update: delegate.update, delete: delegate.delete };
  t.after(() => Object.assign(delegate, originals));
  delegate.update = (() => { throw new Error("Absent-row update emits P2025"); }) as typeof delegate.update;
  delegate.delete = (() => { throw new Error("Absent-row delete emits P2025"); }) as typeof delegate.delete;
  const updates: unknown[] = [];
  const deletes: unknown[] = [];
  delegate.updateMany = (async (args: unknown) => { updates.push(args); return { count: 0 }; }) as typeof delegate.updateMany;
  delegate.deleteMany = (async (args: unknown) => { deletes.push(args); return { count: 0 }; }) as typeof delegate.deleteMany;
  const store = new DatabaseAccountLockoutStore();
  await store.recordSuccess("no-failure-row");
  await store.clearLockout("no-failure-row");
  assert.deepEqual(updates, [{ where: { accountKey: "no-failure-row" }, data: { failedAttempts: [], lockoutEndsAt: null } }]);
  assert.deepEqual(deletes, [{ where: { accountKey: "no-failure-row" } }]);
});

test("lockout cleanup cannot overwrite a newer failure or fail after concurrent deletion", async (t) => {
  const delegate = prisma.accountLockoutEntry;
  const originals = { findUnique: delegate.findUnique, updateMany: delegate.updateMany };
  t.after(() => Object.assign(delegate, originals));
  const lastUpdated = new Date(Date.now() - 120_000);
  delegate.findUnique = (async () => ({ accountKey: "concurrent-account", failedAttempts: [lastUpdated],
    uniqueIpHashes: [], lockoutEndsAt: null, lastUpdated, createdAt: lastUpdated })) as typeof delegate.findUnique;
  const updates: unknown[] = [];
  delegate.updateMany = (async (args: unknown) => { updates.push(args); return { count: 0 }; }) as typeof delegate.updateMany;
  const status = await new DatabaseAccountLockoutStore().getStatus("concurrent-account", config);
  assert.equal(status.failedAttempts, 0);
  assert.equal(status.isLocked, false);
  assert.deepEqual(updates, [{ where: { accountKey: "concurrent-account", lastUpdated }, data: { failedAttempts: [] } }]);
});

test("real persistence failures during successful login and reset remain observable", async (t) => {
  const delegate = prisma.accountLockoutEntry;
  const originals = { updateMany: delegate.updateMany, deleteMany: delegate.deleteMany };
  t.after(() => Object.assign(delegate, originals));
  const outage = new Error("Database unavailable");
  delegate.updateMany = (async () => { throw outage; }) as typeof delegate.updateMany;
  delegate.deleteMany = (async () => { throw outage; }) as typeof delegate.deleteMany;
  const store = new DatabaseAccountLockoutStore();
  await assert.rejects(store.recordSuccess("account"), (error: unknown) => error === outage);
  await assert.rejects(store.clearLockout("account"), (error: unknown) => error === outage);
});
