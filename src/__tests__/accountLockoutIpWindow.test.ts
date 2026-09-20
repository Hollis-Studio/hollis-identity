/**
 * `uniqueIpCount` drives the "many IPs targeting single account" warning. It
 * used to accumulate every IP ever seen — never pruned by the failure window and
 * deliberately kept across successful logins — so a person who had signed in
 * from enough networks would eventually trip a permanent "distributed attack"
 * warning on any mistyped password. These tests pin the windowed behavior for
 * both stores: the memory store directly, and the Postgres store through the
 * `String[]` stamping helpers it shares.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  activeIpHashes,
  MemoryAccountLockoutStore,
  stampIpHash,
  type LockoutConfig,
} from "../lib/accountLockout";

/** 120 ms failure window so the test can outlive it without faking the clock. */
const SHORT_WINDOW: LockoutConfig = {
  initialThreshold: 5,
  initialLockoutSeconds: 900,
  maxLockoutSeconds: 7200,
  failureWindowSeconds: 0.12,
  maxUniqueIpsBeforeFlag: 3,
};

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

describe("account lockout IP reputation window (memory store)", () => {
  it("drops IPs whose last failure fell out of the failure window", async () => {
    const store = new MemoryAccountLockoutStore();
    const account = "account-key-a";

    for (const ip of ["198.51.100.1", "198.51.100.2", "198.51.100.3"]) {
      const status = await store.recordFailure(account, ip, SHORT_WINDOW);
      assert.ok(status.uniqueIpCount <= 3);
    }

    const beforeExpiry = await store.getStatus(account, SHORT_WINDOW);
    assert.equal(beforeExpiry.uniqueIpCount, 3);

    await sleep(200);

    const afterExpiry = await store.getStatus(account, SHORT_WINDOW);
    assert.equal(afterExpiry.failedAttempts, 0);
    assert.equal(
      afterExpiry.uniqueIpCount,
      0,
      "IPs outside the window must not count toward the distributed-attack signal",
    );

    // A single new failure long after the burst reports one IP, not four.
    const fresh = await store.recordFailure(account, "198.51.100.9", SHORT_WINDOW);
    assert.equal(fresh.uniqueIpCount, 1);
    assert.equal(fresh.failedAttempts, 1);

    await store.close();
  });

  it("still counts distinct IPs inside the window", async () => {
    const store = new MemoryAccountLockoutStore();
    const account = "account-key-b";

    const ips = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.1"];
    let status = await store.recordFailure(account, ips[0], SHORT_WINDOW);
    for (const ip of ips.slice(1)) {
      status = await store.recordFailure(account, ip, SHORT_WINDOW);
    }

    assert.equal(status.uniqueIpCount, 3, "repeat IPs are deduplicated, not double-counted");
    assert.ok(status.uniqueIpCount >= SHORT_WINDOW.maxUniqueIpsBeforeFlag);

    await store.close();
  });

  it("a successful login no longer freezes a stale IP count", async () => {
    const store = new MemoryAccountLockoutStore();
    const account = "account-key-c";

    for (const ip of ["192.0.2.1", "192.0.2.2", "192.0.2.3"]) {
      await store.recordFailure(account, ip, SHORT_WINDOW);
    }
    await store.recordSuccess(account);

    await sleep(200);

    const status = await store.getStatus(account, SHORT_WINDOW);
    assert.equal(status.uniqueIpCount, 0);

    await store.close();
  });
});

describe("account lockout IP stamping (Postgres String[] encoding)", () => {
  const now = 1_800_000_000_000;
  const windowStart = now - 60_000;

  it("keeps only stamps inside the window", () => {
    const active = activeIpHashes(
      [
        stampIpHash("aaaa1111", now - 1_000),
        stampIpHash("bbbb2222", now - 59_000),
        stampIpHash("cccc3333", now - 120_000),
      ],
      windowStart,
    );

    assert.deepEqual([...active.keys()].sort(), ["aaaa1111", "bbbb2222"]);
  });

  it("collapses repeated stamps of one IP to its latest sighting", () => {
    const active = activeIpHashes(
      [stampIpHash("aaaa1111", now - 50_000), stampIpHash("aaaa1111", now - 2_000)],
      windowStart,
    );

    assert.equal(active.size, 1);
    assert.equal(active.get("aaaa1111"), now - 2_000);
  });

  it("drops legacy unstamped rows instead of counting them forever", () => {
    // Rows written before stamping carry no timestamp, so they cannot be
    // attributed to any window. They must not inflate the count.
    const active = activeIpHashes(
      ["aaaa1111", "bbbb2222", stampIpHash("cccc3333", now - 1_000)],
      windowStart,
    );

    assert.deepEqual([...active.keys()], ["cccc3333"]);
  });

  it("round-trips through the stored string form", () => {
    const stamped = stampIpHash("deadbeefdeadbeef", now);

    assert.equal(stamped, `deadbeefdeadbeef@${now}`);
    assert.deepEqual([...activeIpHashes([stamped], windowStart).keys()], [
      "deadbeefdeadbeef",
    ]);
  });
});
