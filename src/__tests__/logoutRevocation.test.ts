import assert from "node:assert/strict";
import { test } from "node:test";

import { signJwt } from "../lib/jwtKeys";
import { prisma } from "../lib/prisma";
import { logout } from "../services/authService";
import { getStore } from "../services/tokenDenylistService";

const USER_ID = "HH-LOGOUT1";

function refreshTokenFor(userId: string): string {
  return signJwt({ userId, sub: userId, type: "refresh" }, { expiresIn: "365d" });
}

function accessTokenFor(userId: string): string {
  return signJwt(
    { userId, sub: userId, type: "access", jti: `jti-${userId}` },
    { expiresIn: "90d" },
  );
}

/** Prisma's "record not found" — the row is already gone, so nothing is left to revoke. */
function recordNotFound(): Error & { code: string } {
  return Object.assign(new Error("Record to update not found."), { code: "P2025" });
}

test("logout reports failure when refresh-token revocation could not be written", async (t) => {
  const outage = new Error("Simulated database unavailable");
  const originalUpdate = prisma.refreshToken.update;
  prisma.refreshToken.update = (async () => {
    throw outage;
  }) as typeof originalUpdate;
  t.after(() => {
    prisma.refreshToken.update = originalUpdate;
  });

  // Claiming success here tells the caller the session is dead while the refresh
  // token stays usable for its full 365-day life.
  await assert.rejects(logout(refreshTokenFor(USER_ID)), (error: unknown) => error === outage);
});

test("logout reports failure when the access token could not be denied", async (t) => {
  const outage = new Error("Simulated denylist unavailable");
  const store = getStore();
  const originalDeny = store.denyToken.bind(store);
  store.denyToken = async () => {
    throw outage;
  };
  t.after(() => {
    store.denyToken = originalDeny;
  });

  await assert.rejects(
    logout(undefined, accessTokenFor(USER_ID)),
    (error: unknown) => error === outage,
  );
});

test("logout still succeeds when there is nothing left to revoke", async (t) => {
  const originalUpdate = prisma.refreshToken.update;
  prisma.refreshToken.update = (async () => {
    throw recordNotFound();
  }) as typeof originalUpdate;
  t.after(() => {
    prisma.refreshToken.update = originalUpdate;
  });

  assert.deepEqual(await logout(refreshTokenFor(USER_ID)), { success: true });
});

test("logout stays silent about tokens it cannot verify", async () => {
  // Anti-enumeration: an unauthenticated endpoint must not tell a caller whether
  // a submitted string was a real server-issued token.
  assert.deepEqual(await logout("not-a-jwt"), { success: true });
  assert.deepEqual(await logout(undefined, "not-a-jwt"), { success: true });
});

test("logout revokes and denies when both stores are healthy", async (t) => {
  const updates: unknown[] = [];
  const originalUpdate = prisma.refreshToken.update;
  prisma.refreshToken.update = (async (args: unknown) => {
    updates.push(args);
    return {};
  }) as typeof originalUpdate;
  t.after(() => {
    prisma.refreshToken.update = originalUpdate;
  });

  const store = getStore();
  await store.clear();
  assert.deepEqual(
    await logout(refreshTokenFor(USER_ID), accessTokenFor(USER_ID)),
    { success: true },
  );
  assert.equal(updates.length, 1);
  assert.equal(await store.isTokenDenied(`jti-${USER_ID}`), true);
});
