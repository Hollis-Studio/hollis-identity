import assert from "node:assert/strict";
import { after, before, it, mock } from "node:test";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";
import { validateEnvOnStartup } from "../lib/env";
import { verifyOAuthCredentials } from "../services/oauthVerificationService";

before(() => {
  process.env.GOOGLE_CLIENT_ID = "synthetic-client";
  validateEnvOnStartup();
});
const originalTransaction = prisma.$transaction;
const originalCredentials = prisma.mfaCredential.findMany;
const originalPending = prisma.pendingMfaSession.create;
const originalRefresh = prisma.refreshToken.create;
after(() => {
  mock.restoreAll();
  prisma.$transaction = originalTransaction;
  prisma.mfaCredential.findMany = originalCredentials;
  prisma.pendingMfaSession.create = originalPending;
  prisma.refreshToken.create = originalRefresh;
});

it("returns a single-use MFA challenge without access or refresh tokens for an enrolled OAuth account", async () => {
  mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ iss: "https://accounts.google.com", aud: "synthetic-client", exp: Math.floor(Date.now()/1000)+300, sub: "synthetic-google-user", email: "member@example.invalid", email_verified: "true" })));
  prisma.$transaction = mock.fn(async (callback: (tx: unknown) => unknown) => callback({ oAuthAccount: { findUnique: async () => ({ user: { id: "synthetic-user", role: "CLIENT", organizationId: null, email: "member@example.invalid", isActive: true, emailVerified: new Date(), _count: { mfaCredentials: 1 } } }) } })) as unknown as typeof prisma.$transaction;
  prisma.mfaCredential.findMany = mock.fn(async () => [{ type: "TOTP" }]) as unknown as typeof prisma.mfaCredential.findMany;
  const pending = mock.fn(async () => ({}));
  prisma.pendingMfaSession.create = pending as unknown as typeof prisma.pendingMfaSession.create;
  const refresh = mock.fn(async () => ({}));
  prisma.refreshToken.create = refresh as unknown as typeof prisma.refreshToken.create;
  const session = await verifyOAuthCredentials({ provider: "google", idToken: "synthetic-provider-token", nonce: "", state: "" });
  assert.ok("mfaRequired" in session);
  assert.equal(session.mfaRequired, true);
  assert.deepEqual(session.availableMethods, ["TOTP"]);
  assert.equal("idToken" in session, false);
  assert.equal("refreshToken" in session, false);
  assert.equal((jwt.decode(session.sessionToken) as jwt.JwtPayload).type, "mfa_pending");
  assert.equal(pending.mock.callCount(), 1);
  assert.equal(refresh.mock.callCount(), 0);
});


it("preserves a complete OAuth session for accounts without MFA", async () => {
  prisma.$transaction = mock.fn(async (callback: (tx: unknown) => unknown) => callback({ oAuthAccount: { findUnique: async () => ({ user: { id: "plain-user", role: "CLIENT", organizationId: null, email: "plain@example.invalid", isActive: true, emailVerified: new Date(), _count: { mfaCredentials: 0 } } }) } })) as unknown as typeof prisma.$transaction;
  const refresh = mock.fn(async () => ({}));
  prisma.refreshToken.create = refresh as unknown as typeof prisma.refreshToken.create;
  const session = await verifyOAuthCredentials({ provider: "google", idToken: "another-synthetic-provider-token", nonce: "", state: "" });
  assert.ok("idToken" in session);
  const claims = jwt.decode(session.idToken) as jwt.JwtPayload;
  assert.equal(claims.type, "access");
  assert.equal(claims.email, "plain@example.invalid");
  assert.equal(claims.email_verified, true);
  assert.equal("mfaRequired" in session, false);
  assert.equal(refresh.mock.callCount(), 1);
});
