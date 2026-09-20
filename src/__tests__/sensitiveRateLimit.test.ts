/**
 * sensitiveRateLimiter was defined but never mounted, so the password-reset
 * flow had no hourly ceiling at all. These tests pin the mount points and the
 * budget: a legitimate reset must complete, and the flow must still be capped.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

import express from "express";

// Must be set before ../middleware/rateLimit is imported: otherwise the limiter
// skips itself in NODE_ENV=test and every assertion below passes vacuously.
process.env.E2E_SECURITY_TEST = "true";

const {
  SENSITIVE_RATE_LIMIT_MAX,
  SENSITIVE_RATE_LIMIT_WINDOW_MS,
  sensitiveRateLimiter,
  resetRateLimitStore,
} = await import("../middleware/rateLimit");

describe("sensitive (password-reset) rate limit", () => {
  let server: ReturnType<express.Express["listen"]>;
  let baseUrl = "";

  before(async () => {
    await resetRateLimitStore();

    // Mirrors the mount order in src/index.ts: both password-reset paths share
    // this one limiter, ahead of the per-minute auth-session limiter.
    const app = express();
    app.use(express.json());
    app.use("/v1/auth/forgot-password", sensitiveRateLimiter);
    app.use("/v1/auth/reset-password", sensitiveRateLimiter);
    app.post("/v1/auth/forgot-password", (_req, res) => res.json({ ok: true }));
    app.post("/v1/auth/reset-password", (_req, res) => res.json({ ok: true }));

    server = app.listen(0);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    assert(address && typeof address !== "string");
    baseUrl = `http://127.0.0.1:${address.port}`; // url-ok: loopback test server
  });

  after(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    await resetRateLimitStore();
  });

  const post = (path: string): Promise<Response> =>
    fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "demo@woapp.com", token: "t", newPassword: "p" }),
    });

  it("is a 5-per-hour budget shared by forgot-password and reset-password", async () => {
    assert.equal(SENSITIVE_RATE_LIMIT_MAX, 5);
    assert.equal(SENSITIVE_RATE_LIMIT_WINDOW_MS, 60 * 60 * 1000);

    // A legitimate reset: one forgot-password, then a reset submission. Neither
    // may be throttled, and three attempts must remain for retries after a
    // rejected new password.
    const forgot = await post("/v1/auth/forgot-password");
    assert.equal(forgot.status, 200);

    const reset = await post("/v1/auth/reset-password");
    assert.equal(reset.status, 200);
    assert.equal(reset.headers.get("ratelimit-remaining"), "3");

    // Remaining budget is consumed across BOTH paths — one shared counter.
    for (let attempt = 3; attempt <= SENSITIVE_RATE_LIMIT_MAX; attempt += 1) {
      const retry = await post("/v1/auth/reset-password");
      assert.equal(retry.status, 200, `attempt ${attempt} should pass`);
    }

    const blockedReset = await post("/v1/auth/reset-password");
    assert.equal(blockedReset.status, 429);
    assert.equal(blockedReset.headers.get("retry-after"), "3600");

    const blockedForgot = await post("/v1/auth/forgot-password");
    assert.equal(blockedForgot.status, 429);
  });
});
