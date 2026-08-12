import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  LOGIN_EMAIL_RATE_LIMIT_MAX,
  LOGIN_EMAIL_RATE_LIMIT_WINDOW_MS,
} from "../middleware/rateLimit";

describe("login email rate-limit configuration", () => {
  it("allows 50 attempts per email in a 15-minute production window", () => {
    assert.equal(LOGIN_EMAIL_RATE_LIMIT_MAX, 50);
    assert.equal(LOGIN_EMAIL_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000);
  });
});
