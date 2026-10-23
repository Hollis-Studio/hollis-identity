import assert from "node:assert/strict";
import { after, afterEach, before, it, mock } from "node:test";
import express from "express";
import { prisma } from "../lib/prisma";
import { validateEnvOnStartup } from "../lib/env";
import { authRouter } from "../routes/auth";
import {
  OAUTH_ERROR_CODE,
  OAuthError,
  verifyOAuthCredentials,
  verifyOAuthReauthenticationProof,
} from "../services/oauthVerificationService";
import { clearDenylist, getStore } from "../services/tokenDenylistService";

const INSTALL_A = "a".repeat(64);
const INSTALL_B = "b".repeat(64);
const originalTransaction = prisma.$transaction;
const originalRefresh = prisma.refreshToken.create;
const originalOAuthAccount = prisma.oAuthAccount.findUnique;
const originalFetch = globalThis.fetch;

before(() => {
  process.env.GOOGLE_CLIENT_ID = "install-reuse-client";
  validateEnvOnStartup();
  prisma.$transaction = (async (callback: (tx: unknown) => unknown) => callback({
    oAuthAccount: { findUnique: async () => ({ user: {
      id: "install-user", role: "CLIENT", organizationId: null, email: "member@example.invalid",
      isActive: true, emailVerified: new Date(), _count: { mfaCredentials: 0 },
    } }) },
  })) as unknown as typeof prisma.$transaction;
  prisma.refreshToken.create = (async () => ({})) as unknown as typeof prisma.refreshToken.create;
});

afterEach(async () => {
  mock.restoreAll();
  await clearDenylist();
});

after(() => {
  prisma.$transaction = originalTransaction;
  prisma.refreshToken.create = originalRefresh;
  prisma.oAuthAccount.findUnique = originalOAuthAccount;
});

function mockGoogle(claims: { sub?: string; expOffset?: number } = {}): void {
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    if (String(input).startsWith("http://127.0.0.1:")) return originalFetch(input, init);
    const now = Math.floor(Date.now() / 1000);
    return new Response(JSON.stringify({
      iss: "https://accounts.google.com", aud: "install-reuse-client",
      exp: now + (claims.expOffset ?? 300), iat: now, sub: claims.sub ?? "google-subject",
      email: "member@example.invalid", email_verified: "true",
    }));
  });
}

function signIn(idToken: string, clientInstallId?: string) {
  return verifyOAuthCredentials({
    provider: "google", idToken, nonce: "", state: "", ...(clientInstallId ? { clientInstallId } : {}),
  });
}

function rejectsWith(code: string) {
  return (error: unknown) => error instanceof OAuthError && error.code === code;
}

it("accepts the first use and a re-presentation from the same install", async () => {
  mockGoogle();
  await assert.doesNotReject(signIn("cached-play-services-token", INSTALL_A));
  await assert.doesNotReject(signIn("cached-play-services-token", INSTALL_A));
});

it("rejects a re-presentation from a different install as TOKEN_REUSED", async () => {
  mockGoogle();
  await signIn("token-other-install", INSTALL_A);
  await assert.rejects(signIn("token-other-install", INSTALL_B), rejectsWith(OAUTH_ERROR_CODE.TOKEN_REUSED));
});

it("rejects a re-presentation without an install id as TOKEN_REUSED", async () => {
  mockGoogle();
  await signIn("token-missing-install", INSTALL_A);
  await assert.rejects(signIn("token-missing-install"), rejectsWith(OAUTH_ERROR_CODE.TOKEN_REUSED));
});

it("keeps strict single use when the first use carried no install id", async () => {
  mockGoogle();
  await signIn("token-legacy-client");
  await assert.rejects(signIn("token-legacy-client"), rejectsWith(OAUTH_ERROR_CODE.TOKEN_REUSED));
  await assert.rejects(signIn("token-legacy-client", INSTALL_A), rejectsWith(OAUTH_ERROR_CODE.TOKEN_REUSED));
});

it("rejects a re-presented token that has since expired", async () => {
  mockGoogle();
  await signIn("token-expiring", INSTALL_A);
  mock.restoreAll();
  mockGoogle({ expOffset: -1 });
  await assert.rejects(signIn("token-expiring", INSTALL_A), rejectsWith(OAUTH_ERROR_CODE.TOKEN_EXPIRED));
});

it("rejects a re-presentation that verifies to a different subject", async () => {
  mockGoogle({ sub: "first-subject" });
  await signIn("token-subject", INSTALL_A);
  mock.restoreAll();
  mockGoogle({ sub: "second-subject" });
  await assert.rejects(signIn("token-subject", INSTALL_A), rejectsWith(OAUTH_ERROR_CODE.TOKEN_REUSED));
});

it("fails closed when the first replay claim fails", async () => {
  mockGoogle();
  mock.method(getStore(), "claimOAuthToken", async () => { throw new Error("Synthetic store outage"); });
  await assert.rejects(signIn("token-store-down", INSTALL_A), rejectsWith(OAUTH_ERROR_CODE.VERIFICATION_FAILED));
});

it("fails closed when an existing install replay claim fails", async () => {
  mockGoogle();
  await signIn("token-binding-down", INSTALL_A);
  mock.method(getStore(), "claimOAuthToken", async () => { throw new Error("Synthetic transaction outage"); });
  await assert.rejects(signIn("token-binding-down", INSTALL_A), rejectsWith(OAUTH_ERROR_CODE.VERIFICATION_FAILED));
});

it("accepts a deletion reauthentication with the token this install just signed in with", async () => {
  mockGoogle();
  prisma.oAuthAccount.findUnique = (async () => ({ userId: "install-user" })) as unknown as typeof prisma.oAuthAccount.findUnique;
  await signIn("token-then-reauth", INSTALL_A);
  await assert.doesNotReject(verifyOAuthReauthenticationProof("install-user", {
    provider: "google", idToken: "token-then-reauth", clientInstallId: INSTALL_A,
  }));
  await assert.rejects(verifyOAuthReauthenticationProof("install-user", {
    provider: "google", idToken: "token-then-reauth",
  }), rejectsWith(OAUTH_ERROR_CODE.TOKEN_REUSED));
});

it("answers reuse with 409 OAUTH_TOKEN_REUSED, logs the code, and validates the install id", async (t) => {
  const warnings: Record<string, unknown>[] = [];
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info: () => undefined, error: () => undefined,
      warn: (fields: Record<string, unknown>) => warnings.push(fields) } as unknown as NonNullable<typeof req.log>;
    next();
  });
  app.use("/auth", authRouter);
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  assert(address && typeof address !== "string");
  const post = (body: Record<string, unknown>) => fetch(`http://127.0.0.1:${address.port}/auth/oauth`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  mockGoogle();

  assert.equal((await post({ provider: "google", idToken: "route-token", clientInstallId: INSTALL_A })).status, 200);
  assert.equal((await post({ provider: "google", idToken: "route-token", clientInstallId: INSTALL_A })).status, 200);
  const reused = await post({ provider: "google", idToken: "route-token", clientInstallId: INSTALL_B });
  assert.equal(reused.status, 409);
  const body = await reused.json() as { code?: string; error?: string };
  assert.equal(body.code, "OAUTH_TOKEN_REUSED");
  assert.match(body.error ?? "", /already used/);
  assert.deepEqual(warnings.at(-1), { provider: "google", oauthErrorCode: "OAUTH_TOKEN_REUSED" });

  assert.equal((await post({ provider: "google", idToken: "route-token-2", clientInstallId: "short" })).status, 400);
});
