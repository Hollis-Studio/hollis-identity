import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { AddressInfo } from "node:net";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { AccessTokenClaimsSchema, AUDIENCES } from "@hollis-studio/contracts";
import {
  ACCESS_TOKEN_EXPIRY,
  ACCESS_TOKEN_EXPIRY_MS,
  AUTH_TOKEN_TYPE,
  generateAccessTokenWithJti,
  REFRESH_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY_MS,
} from "../services/authService";
import {
  recordLoginFailure,
  resetAccountLockoutStore,
  clearAccountLockoutStoreInstance,
  DEFAULT_LOCKOUT_CONFIG,
} from "../lib/accountLockout";
import { resetEnvValidation, validateEnvOnStartup } from "../lib/env";
import type { Server } from "node:http";

const TEST_JWT_SECRET = "test-secret-for-identity-service";

function configureEnv(overrides: NodeJS.ProcessEnv = {}): void {
  process.env.NODE_ENV = "test";
  process.env.PORT = "1";
  process.env.JWT_ALGORITHM = "HS256";
  process.env.JWT_SECRET = TEST_JWT_SECRET;
  delete process.env.JWT_PRIVATE_KEY;
  delete process.env.JWT_PUBLIC_KEY;
  delete process.env.JWT_KEY_ID;
  process.env.JWT_ISSUER = "https://identity.test";
  process.env.JWT_AUDIENCES = "hollis-health,hollis-workouts";
  process.env.DATABASE_URL =
    "postgresql://user:pass@localhost:5432/hollis_identity_test";
  process.env.ENCRYPTION_KEY = "test-encryption-key-for-identity-service";
  process.env.PASSWORD_PEPPER = "test-pepper-that-is-long-enough-for-tests";
  Object.assign(process.env, overrides);
  resetEnvValidation();
  validateEnvOnStartup();
}

function generateTestRsaKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("Identity extraction invariants", () => {
  before(() => {
    configureEnv();
  });

  it("uses consumer-app token lifetimes", () => {
    assert.equal(ACCESS_TOKEN_EXPIRY, "90d");
    assert.equal(ACCESS_TOKEN_EXPIRY_MS, 90 * 24 * 60 * 60 * 1000);
    assert.equal(REFRESH_TOKEN_EXPIRY, "365d");
    assert.equal(REFRESH_TOKEN_EXPIRY_MS, 365 * 24 * 60 * 60 * 1000);
  });

  it("emits shared-schema-compatible access token claims", () => {
    const { token } = generateAccessTokenWithJti(
      "HH-TEST01",
      "CLIENT",
      "org_123",
      { tokenType: AUTH_TOKEN_TYPE.ACCESS },
    );

    const payload = jwt.verify(token, TEST_JWT_SECRET, {
      audience: "hollis-health",
    });

    const parsed = AccessTokenClaimsSchema.safeParse(payload);
    assert.equal(parsed.success, true);
    if (!parsed.success) return;

    assert.equal(parsed.data.userId, "HH-TEST01");
    assert.deepEqual(parsed.data.aud, [...AUDIENCES]);
    assert.equal(
      (parsed.data.claims?.["hollisHealth"] as Record<string, unknown>)
        .organizationId,
      "org_123",
    );
  });

  it("rejects tokens for the wrong audience during verification", () => {
    const { token } = generateAccessTokenWithJti("HH-TEST01", "CLIENT", null, {
      tokenType: AUTH_TOKEN_TYPE.ACCESS,
    });

    assert.throws(
      () => jwt.verify(token, TEST_JWT_SECRET, { audience: "not-hollis" }),
      /audience invalid/i,
    );
  });

  it("publishes RS256 public keys through JWKS", async () => {
    const { privateKey, publicKey } = generateTestRsaKeyPair();
    configureEnv({
      JWT_ALGORITHM: "RS256",
      JWT_PRIVATE_KEY: privateKey,
      JWT_PUBLIC_KEY: publicKey,
      JWT_KEY_ID: "identity-test-key",
    });

    const { createApp } = await import("../index");
    const localServer = createApp().listen(0);
    try {
      const address = localServer.address() as AddressInfo;
      const response = await fetch(
        `http://127.0.0.1:${address.port}/.well-known/jwks.json`,
      );
      assert.equal(response.status, 200);

      const body = (await response.json()) as {
        keys?: Array<{ kid?: string; alg?: string; n?: string; e?: string }>;
      };
      assert.equal(body.keys?.[0]?.kid, "identity-test-key");
      assert.equal(body.keys?.[0]?.alg, "RS256");
      assert.equal(typeof body.keys?.[0]?.n, "string");
      assert.equal(typeof body.keys?.[0]?.e, "string");
    } finally {
      localServer.close();
      configureEnv();
    }
  });
});

describe("Identity HTTP auth boundary", () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    configureEnv();
    const { createApp } = await import("../index");
    server = createApp().listen(0);
    const address = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(() => {
    server.close();
  });

  it("POST /verify returns auth-client-compatible claims without setting cookies", async () => {
    const { token } = generateAccessTokenWithJti("HH-TEST02", "CLIENT", null, {
      tokenType: AUTH_TOKEN_TYPE.ACCESS,
    });

    const response = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, audience: "hollis-workouts" }),
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers.has("set-cookie"), false);

    const body = (await response.json()) as { claims?: { userId?: string } };
    assert.equal(body.claims?.userId, "HH-TEST02");
  });

  it("rejects invalid verify requests without cookies", async () => {
    const response = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: "not-a-token",
        audience: "hollis-workouts",
      }),
    });

    assert.equal(response.status, 401);
    assert.equal(response.headers.has("set-cookie"), false);
  });

  it("covers unauthenticated auth route contract failures", async () => {
    const cases = [
      { path: "/v1/auth/login", body: {}, status: 400 },
      {
        path: "/v1/auth/register",
        body: { email: "bad", password: "short" },
        status: 400,
      },
      {
        path: "/v1/auth/register",
        body: {
          email: "user@example.com",
          password: "correct-password",
          sourceApp: "",
        },
        status: 400,
      },
      { path: "/v1/auth/refresh", body: {}, status: 401 },
      { path: "/v1/auth/logout", body: {}, status: 200 },
      {
        path: "/v1/auth/forgot-password",
        body: { email: "not-email" },
        status: 200,
      },
      {
        path: "/v1/auth/reset-password",
        body: { token: "short", newPassword: "weak" },
        status: 400,
      },
      { path: "/v1/auth/change-password", body: {}, status: 401 },
    ];

    for (const testCase of cases) {
      const response = await fetch(`${baseUrl}${testCase.path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testCase.body),
      });
      assert.equal(response.status, testCase.status, testCase.path);
      assert.equal(response.headers.has("set-cookie"), false, testCase.path);
    }
  });

  it("rejects /me without a bearer token", async () => {
    const response = await fetch(`${baseUrl}/v1/auth/me`);
    assert.equal(response.status, 401);
    assert.equal(response.headers.has("set-cookie"), false);
  });

  it("requires a bearer token for account deletion", async () => {
    const response = await fetch(`${baseUrl}/v1/auth/account`, { method: "DELETE" });
    assert.equal(response.status, 401);
    assert.equal(response.headers.has("set-cookie"), false);
  });

  it("requires a bearer token for the onboarding reset", async () => {
    const response = await fetch(`${baseUrl}/v1/auth/onboarding/reset`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(response.status, 401);
    assert.equal(response.headers.has("set-cookie"), false);
  });
});

// ============================================================================
// Account lockout wiring
// ============================================================================

describe("Account lockout — login route enforcement", () => {
  let server: Server;
  let baseUrl: string;
  const lockedEmail = "lockout-test@example.com";

  before(async () => {
    configureEnv();
    // Ensure in-memory store starts clean for this suite.
    clearAccountLockoutStoreInstance();

    // Seed enough failures to trigger the first lockout threshold (default: 5).
    for (let i = 0; i < DEFAULT_LOCKOUT_CONFIG.initialThreshold; i++) {
      await recordLoginFailure(lockedEmail, "127.0.0.1");
    }

    const { createApp } = await import("../index");
    server = createApp().listen(0);
    const address = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    server.close();
    await resetAccountLockoutStore();
    clearAccountLockoutStoreInstance();
  });

  it("returns 429 with RATE_LIMIT_EXCEEDED code when account is locked", async () => {
    const response = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: lockedEmail, password: "any-password" }),
    });

    assert.equal(response.status, 429, "locked account must return 429");
    assert.equal(response.headers.has("set-cookie"), false);

    const body = (await response.json()) as {
      success?: boolean;
      code?: string;
      retryAfterSeconds?: number;
    };
    assert.equal(body.success, false);
    assert.equal(body.code, "RATE_LIMIT_EXCEEDED");
    assert.equal(typeof body.retryAfterSeconds, "number");
    assert.ok(
      (body.retryAfterSeconds ?? 0) > 0,
      "retryAfterSeconds must be positive when locked",
    );
  });

  it("does NOT return 429 for a non-locked account (lockout gate passes through)", async () => {
    // Different email — no prior failures so the lockout check succeeds.
    // In this test environment there is no real Postgres, so the login will
    // fail with a 500 after passing the lockout gate (Prisma cannot connect).
    // We only assert that the lockout gate did NOT fire (no 429), which is
    // what we need to verify here.
    const response = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "not-locked@example.com",
        password: "wrong",
      }),
    });

    assert.notEqual(response.status, 429, "non-locked account must not be 429");
  });
});
