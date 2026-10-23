/** Real PostgreSQL race regressions. Explicit opt-in, local isolated test database only. */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test, after } from "node:test";
import { prisma } from "../lib/prisma";
import { resetPassword } from "../services/passwordResetService";
import { verifyMfaLogin } from "../services/mfaService";
import { DatabaseTokenDenylistStore } from "../services/tokenDenylistService";
const enabled = process.env.IDENTITY_SECURITY_DATABASE_TESTS === "1";
if (enabled) {
  const url = new URL(process.env.DATABASE_URL ?? "");
  if (process.env.NODE_ENV !== "test" || !["localhost", "127.0.0.1"].includes(url.hostname) || !["/test", "/identity_security"].includes(url.pathname)) {
    throw new Error("Security database tests require NODE_ENV=test and an isolated local test/identity_security database");
  }
}
const id = crypto.randomUUID();
after(async () => {
  if (enabled) {
    await prisma.mfaEvent.deleteMany({ where: { userId: id } });
    await prisma.user.deleteMany({ where: { id } });
    await prisma.userTokenDenylistEntry.deleteMany({ where: { userId: id } });
    await prisma.accessTokenDenylistEntry.deleteMany({ where: { jti: { startsWith: `security-test:${id}:` } } });
  }
  await prisma.$disconnect();
});
test("PostgreSQL: one reset token authorizes exactly one concurrent password change", { skip: !enabled }, async () => {
  await prisma.user.create({ data: { id, email: `${id}@example.invalid`, passwordHash: "fixture", role: "CLIENT" } });
  const token = crypto.randomBytes(32).toString("base64url");
  await prisma.passwordResetToken.create({ data: { userId: id, tokenHash: crypto.createHash("sha256").update(token).digest("hex"), expiresAt: new Date(Date.now() + 60000) } });
  const results = await Promise.allSettled(Array.from({ length: 8 }, (_, i) => resetPassword(token, `RaceFixture${i}!strong-password`)));
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(await prisma.passwordResetToken.count({ where: { userId: id, usedAt: { not: null } } }), 1);
});
test("PostgreSQL: one backup code authorizes exactly one concurrent MFA verification", { skip: !enabled }, async () => {
  const code = crypto.randomBytes(10).toString("hex").toUpperCase();
  const credential = await prisma.mfaCredential.create({ data: { userId: id, type: "TOTP", name: "Security test", isVerified: true, isDefault: true, webauthnTransports: [], backupCodesRemaining: 1, backupCodesHash: JSON.stringify([crypto.createHash("sha256").update(code).digest("hex")]) } });
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => verifyMfaLogin(id, code, credential.id, true)));
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal((await prisma.mfaCredential.findUniqueOrThrow({ where: { id: credential.id } })).backupCodesRemaining, 0);
});
test("PostgreSQL: concurrent first OAuth use binds exactly one install", { skip: !enabled }, async () => {
  const store = new DatabaseTokenDenylistStore();
  const key = `security-test:${id}:replay`, expiry = new Date(Date.now() + 60000);
  const bindings = Array.from({ length: 8 }, (_, i) => `security-test:${id}:install:${i}`);
  const results = await Promise.all(bindings.map(binding => store.claimOAuthToken(key, binding, expiry)));
  assert.equal(results.filter(Boolean).length, 1);
  const winner = bindings[results.findIndex(Boolean)]!;
  assert.equal(await store.claimOAuthToken(key, winner, expiry), true);
  assert.equal(await store.claimOAuthToken(key, `security-test:${id}:other`, expiry), false);
  assert.equal(await store.claimOAuthToken(key, null, expiry), false);
});

test("PostgreSQL: an older revocation cannot lower an existing watermark", { skip: !enabled }, async () => {
  const store = new DatabaseTokenDenylistStore();
  const newer = new Date(), older = new Date(newer.getTime() - 60000);
  await store.denyAllUserTokens(id, newer, "password_reset");
  await store.denyAllUserTokens(id, older, "logout");
  assert.equal(await store.getUserDeniedAfter(id), newer.getTime());
});
