import assert from "node:assert/strict";
import { test } from "node:test";
import { publicRegisterBodySchema } from "../validation/publicRegistration";
import { issueMfaEnrollmentAuthorization, verifyMfaEnrollmentAuthorization } from "../services/mfaManagementAuthorization";
import { InMemoryTokenDenylistStore } from "../services/tokenDenylistService";
import { resolveLegacyAccountDeleteSunset } from "../lib/env";
test("registration enforces the shared password minimum", () => {
  assert.equal(publicRegisterBodySchema.safeParse({ email: "fixture@example.invalid", password: "123456" }).success, false);
});
test("MFA enrollment authorization is bound to user and credential", () => {
  const token = issueMfaEnrollmentAuthorization("owner", "credential");
  assert.equal(verifyMfaEnrollmentAuthorization(token, "owner", "credential"), true);
  assert.equal(verifyMfaEnrollmentAuthorization(token, "other", "credential"), false);
  assert.equal(verifyMfaEnrollmentAuthorization(token, "owner", "other"), false);
  assert.equal(verifyMfaEnrollmentAuthorization("invalid", "owner", "credential"), false);
});
test("grantless deletion is closed unless explicitly configured", () => {
  assert.equal(resolveLegacyAccountDeleteSunset(undefined), null);
  assert.equal(resolveLegacyAccountDeleteSunset(""), null);
});
test("memory replay store atomically binds only the first install", async () => {
  const store = new InMemoryTokenDenylistStore();
  const expiry = new Date(Date.now() + 60000);
  assert.deepEqual(await Promise.all([store.claimOAuthToken("replay", "one", expiry), store.claimOAuthToken("replay", "two", expiry)]), [true, false]);
  assert.equal(await store.claimOAuthToken("replay", "one", expiry), true);
  assert.equal(await store.claimOAuthToken("replay", null, expiry), false);
});

import { buildPgPool } from "../lib/buildPgPool";
import { authorizeMfaEnrollment } from "../services/mfaManagementAuthorization";
import { prisma } from "../lib/prisma";
test("production database TLS cannot silently disable certificate validation", async () => {
  const saved = process.env.DATABASE_SSL_CA;
  try {
    delete process.env.DATABASE_SSL_CA;
    assert.throws(() => buildPgPool({ databaseUrl: "postgresql://test:test@localhost/test?sslmode=require", nodeEnv: "production" }), /DATABASE_SSL_CA is required/);
    process.env.DATABASE_SSL_CA = "test-ca";
    const pool = buildPgPool({ databaseUrl: "postgresql://test:test@localhost/test?sslmode=disable", nodeEnv: "production" });
    assert.deepEqual(pool.options.ssl, { ca: "test-ca", rejectUnauthorized: true });
    assert.equal(new URL(pool.options.connectionString!).searchParams.has("sslmode"), false);
    await pool.end();
  } finally { if (saved === undefined) delete process.env.DATABASE_SSL_CA; else process.env.DATABASE_SSL_CA = saved; }
});
test("MFA management refuses bearer-only enrollment for first and additional factors", async t => {
  const original = prisma.mfaCredential.count;
  t.after(() => { prisma.mfaCredential.count = original; });
  prisma.mfaCredential.count = (async () => 0) as typeof original;
  assert.equal(await authorizeMfaEnrollment("user", undefined, undefined, "127.0.0.1"), false);
  prisma.mfaCredential.count = (async () => 1) as typeof original;
  assert.equal(await authorizeMfaEnrollment("user", { method: "password", currentPassword: "fixture" }, undefined, "127.0.0.1"), false);
});

import { removeCredential } from "../services/mfaService";
test("bare-session cleanup cannot delete a credential verified after authorization reads", async t => {
  const credential = { id: "credential", userId: "user", isVerified: false, isDefault: false };
  const originals = { findUnique: prisma.mfaCredential.findUnique, count: prisma.mfaCredential.count, user: prisma.user.findUnique, transaction: prisma.$transaction };
  t.after(() => { prisma.mfaCredential.findUnique = originals.findUnique; prisma.mfaCredential.count = originals.count; prisma.user.findUnique = originals.user; prisma.$transaction = originals.transaction; });
  prisma.mfaCredential.findUnique = (async () => credential) as typeof originals.findUnique;
  prisma.mfaCredential.count = (async () => 1) as typeof originals.count;
  prisma.user.findUnique = (async () => ({ role: "CLIENT" })) as typeof originals.user;
  prisma.$transaction = (async (fn: (tx: unknown) => unknown) => {
    // The real database would recheck the conditional write after the concurrent verification.
    credential.isVerified = true;
    return fn({ mfaCredential: { deleteMany: async ({ where }: { where: { isVerified?: boolean } }) => {
      assert.equal(where.isVerified, false);
      return { count: 0 };
    } } });
  }) as typeof originals.transaction;
  await assert.rejects(removeCredential("user", "credential"), /Fresh MFA verification is required/);
});
