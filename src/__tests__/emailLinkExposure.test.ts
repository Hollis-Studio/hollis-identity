/**
 * Password-reset and email-verification links are single-use account-takeover
 * credentials. Two guards keep them out of logs:
 *
 * 1. pino redacts `resetUrl` / `verifyUrl` (lib/logger.ts), so no caller can
 *    reintroduce the leak the console email provider used to have.
 * 2. Production refuses to boot with EMAIL_PROVIDER=console (lib/env.ts), so the
 *    console path — which prints the link — cannot run in production at all.
 */

import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { Writable } from "node:stream";

import pino from "pino";

import { REDACTED_LOG_PATHS } from "../lib/logger";
import { resetEnvValidation, validateEnvOnStartup } from "../lib/env";

// A strong, non-forbidden secret: production validation rejects anything
// containing "test", "secret", "password", etc.
const PROD_SECRET = "Zq7!vB2xLp9#Kd4mNr6&Ts1uWy3eHg5jAb";

describe("reset/verify link redaction", () => {
  function captureLog(payload: Record<string, unknown>): Record<string, unknown> {
    let line = "";
    const sink = new Writable({
      write(chunk, _encoding, callback) {
        line += String(chunk);
        callback();
      },
    });

    // Same redaction configuration as the real root logger, driven by the same
    // exported path list — not a copy of it.
    const testLogger = pino(
      { level: "info", redact: { paths: [...REDACTED_LOG_PATHS], remove: true } },
      sink,
    );
    testLogger.info(payload, "console delivery");

    return JSON.parse(line) as Record<string, unknown>;
  }

  it("removes resetUrl and verifyUrl at the top level", () => {
    const record = captureLog({
      resetUrl: "https://hollis.health/reset-password?token=SECRET",
      verifyUrl: "https://hollis.health/verify-email?token=SECRET",
      expiresAt: "2026-10-17T00:00:00.000Z",
    });

    assert.equal(record.resetUrl, undefined);
    assert.equal(record.verifyUrl, undefined);
    // Non-sensitive context still survives, or the log line would be useless.
    assert.equal(record.expiresAt, "2026-10-17T00:00:00.000Z");
    assert.ok(!JSON.stringify(record).includes("SECRET"));
  });

  it("removes nested resetUrl and verifyUrl", () => {
    const record = captureLog({
      email: { resetUrl: "https://hollis.health/reset-password?token=SECRET" },
      delivery: { verifyUrl: "https://hollis.health/verify-email?token=SECRET" },
    });

    assert.ok(!JSON.stringify(record).includes("SECRET"));
  });

  it("declares every link path in the redaction contract", () => {
    for (const path of ["resetUrl", "verifyUrl", "*.resetUrl", "*.verifyUrl"]) {
      assert.ok(
        REDACTED_LOG_PATHS.includes(path),
        `${path} must stay in REDACTED_LOG_PATHS`,
      );
    }
  });
});

describe("EMAIL_PROVIDER=console in production", () => {
  const original = { ...process.env };

  afterEach(() => {
    process.env = { ...original };
    resetEnvValidation();
  });

  function setProductionEnv(emailProvider: string): void {
    resetEnvValidation();
    process.env.NODE_ENV = "production";
    process.env.JWT_ALGORITHM = "HS256";
    process.env.JWT_SECRET = PROD_SECRET;
    process.env.ENCRYPTION_KEY = PROD_SECRET;
    process.env.DATABASE_URL = "postgresql://identity:pw@db.internal:5432/identity";
    process.env.EMAIL_PROVIDER = emailProvider;
    process.env.AWS_REGION = "us-east-1";
    process.env.RESET_PASSWORD_URL = "https://hollis.health/reset-password";
    process.env.VERIFY_EMAIL_URL = "https://hollis.health/verify-email";
  }

  it("refuses to start", () => {
    setProductionEnv("console");

    assert.throws(
      () => validateEnvOnStartup(),
      /EMAIL_PROVIDER=console is not allowed in production/,
    );
  });

  it("starts with EMAIL_PROVIDER=ses", () => {
    setProductionEnv("ses");

    // Negative control: the failure above must come from the console provider,
    // not from some other missing production variable in this fixture.
    assert.doesNotThrow(() => validateEnvOnStartup());
  });

  it("still allows console delivery outside production", () => {
    setProductionEnv("console");
    process.env.NODE_ENV = "development";
    resetEnvValidation();

    assert.doesNotThrow(() => validateEnvOnStartup());
  });
});
