import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ACCESS_TOKEN_EXPIRY_MS } from "../services/authService";
import {
  InMemoryTokenDenylistStore,
  userDenylistEntryExpiresAt,
} from "../services/tokenDenylistService";

/** App Store reviewer account — a real Identity userId shape, not a placeholder. */
const REVIEWER_USER_ID = "HH-REV001";
const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * MINUTE_MS;
const REVOKED_AT_MS = Date.parse("2026-09-16T12:00:00.000Z");

describe("userDenylistEntryExpiresAt", () => {
  it("outlives every access token the watermark revokes", () => {
    const revokedAt = new Date(REVOKED_AT_MS);

    // A token issued in the same instant as the revocation stays signature-valid
    // for a full ACCESS_TOKEN_EXPIRY_MS, so the watermark must survive at least
    // that long. The old 15-minute entry TTL did not.
    assert.ok(
      userDenylistEntryExpiresAt(revokedAt).getTime() >=
        revokedAt.getTime() + ACCESS_TOKEN_EXPIRY_MS,
      "watermark must outlive the access token lifetime",
    );
  });
});

describe("InMemoryTokenDenylistStore user-level revocation", () => {
  it("keeps denying tokens long after the old 15-minute TTL would have lapsed", async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: REVOKED_AT_MS });
    const store = new InMemoryTokenDenylistStore();

    await store.denyAllUserTokens(
      REVIEWER_USER_ID,
      new Date(REVOKED_AT_MS),
      "password_reset",
    );

    // Minute 16: the reaped-too-early window. A stolen 90-day access token used
    // to be accepted again from here on.
    t.mock.timers.tick(16 * MINUTE_MS);
    assert.equal(await store.cleanup(), 0);
    assert.equal(await store.getUserDeniedAfter(REVIEWER_USER_ID), REVOKED_AT_MS);

    // Day 89: still inside the access token lifetime.
    t.mock.timers.tick(89 * DAY_MS - 16 * MINUTE_MS);
    assert.equal(await store.getUserDeniedAfter(REVIEWER_USER_ID), REVOKED_AT_MS);
    assert.equal((await store.count()).users, 1);
  });

  it("drops the watermark only once the tokens it covers have expired", async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: REVOKED_AT_MS });
    const store = new InMemoryTokenDenylistStore();

    await store.denyAllUserTokens(
      REVIEWER_USER_ID,
      new Date(REVOKED_AT_MS),
      "password_change",
    );

    // Past the access token lifetime plus the clock-skew margin: nothing the
    // watermark covered can still verify, so the entry is free to go.
    t.mock.timers.tick(ACCESS_TOKEN_EXPIRY_MS + DAY_MS);
    assert.equal(await store.cleanup(), 1);
    assert.equal(await store.getUserDeniedAfter(REVIEWER_USER_ID), null);
    assert.equal((await store.count()).users, 0);
  });
});
