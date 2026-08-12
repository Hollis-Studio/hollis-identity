import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

import express from "express";

process.env.E2E_SECURITY_TEST = "true";

const {
  LOGIN_EMAIL_RATE_LIMIT_MAX,
  LOGIN_EMAIL_RATE_LIMIT_WINDOW_MS,
  loginEmailRateLimiter,
  resetRateLimitStore,
} = await import("../middleware/rateLimit");

describe("login email rate limit", () => {
  let server: ReturnType<express.Express["listen"]>;
  let baseUrl = "";

  before(async () => {
    await resetRateLimitStore();
    const app = express();
    app.use(express.json());
    app.use("/v1/auth/login", loginEmailRateLimiter);
    app.post("/v1/auth/login", (_req, res) => res.status(204).end());
    server = app.listen(0);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    assert(address && typeof address !== "string");
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    await resetRateLimitStore();
  });

  it("enforces 50 normalized-email requests per 15 minutes on the login path", async () => {
    assert.equal(LOGIN_EMAIL_RATE_LIMIT_MAX, 50);
    assert.equal(LOGIN_EMAIL_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000);

    for (let attempt = 1; attempt <= 50; attempt += 1) {
      const email = attempt % 2 === 0 ? " demo@woapp.com " : "DEMO@WOAPP.COM";
      const response = await fetch(`${baseUrl}/v1/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      });
      assert.equal(response.status, 204, `attempt ${attempt} should pass`);
    }

    const blocked = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "demo@woapp.com" }),
    });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get("retry-after"), "900");
  });
});
