import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";
import { buildVerifyUrl } from "../services/emailService";
import { resetEnvValidation, validateEnvOnStartup } from "../lib/env";

const BASE_ENV: Record<string, string> = {
  NODE_ENV: "test",
  PORT: "1",
  JWT_ALGORITHM: "HS256",
  JWT_SECRET: "test-secret-for-identity-service",
  JWT_ISSUER: "https://identity.test",
  JWT_AUDIENCES: "hollis-health,hollis-workouts",
  DATABASE_URL: "postgresql://user:pass@localhost:5432/hollis_identity_test",
  ENCRYPTION_KEY: "test-encryption-key-for-identity-service",
  PASSWORD_PEPPER: "test-pepper-that-is-long-enough-for-tests",
  VERIFY_EMAIL_URL: "https://www.hollis.health/verify?type=email",
  RESET_PASSWORD_URL: "https://hollis.health/reset-password",
};

function configureEnv(overrides: Record<string, string | undefined> = {}): void {
  Object.assign(process.env, BASE_ENV, overrides);
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete process.env[key];
    }
  }
  resetEnvValidation();
  validateEnvOnStartup();
}

describe("email verification URL construction", () => {
  beforeEach(() => {
    configureEnv();
  });

  afterEach(() => {
    resetEnvValidation();
  });

  it("preserves the configured suite verify path and query params", () => {
    const url = new URL(buildVerifyUrl("token-123"));

    assert.equal(url.origin, "https://www.hollis.health");
    assert.equal(url.pathname, "/verify");
    assert.equal(url.searchParams.get("type"), "email");
    assert.equal(url.searchParams.get("token"), "token-123");
    assert.equal(url.searchParams.has("app"), false);
  });

  it("appends source app metadata when provided", () => {
    const url = new URL(buildVerifyUrl("token-456", "workouts"));

    assert.equal(url.pathname, "/verify");
    assert.equal(url.searchParams.get("type"), "email");
    assert.equal(url.searchParams.get("token"), "token-456");
    assert.equal(url.searchParams.get("app"), "workouts");
  });

  it("preserves future suite app identifiers as source metadata", () => {
    const url = new URL(buildVerifyUrl("token-suite", "nutrition"));

    assert.equal(url.pathname, "/verify");
    assert.equal(url.searchParams.get("type"), "email");
    assert.equal(url.searchParams.get("token"), "token-suite");
    assert.equal(url.searchParams.get("app"), "nutrition");
  });

  it("falls back to reset password URL when verify URL is unset", () => {
    configureEnv({ VERIFY_EMAIL_URL: undefined });

    const url = new URL(buildVerifyUrl("token-789", "health"));

    assert.equal(url.origin, "https://hollis.health");
    assert.equal(url.pathname, "/reset-password");
    assert.equal(url.searchParams.get("token"), "token-789");
    assert.equal(url.searchParams.get("app"), "health");
  });
});
