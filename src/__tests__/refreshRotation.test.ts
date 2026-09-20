import assert from "node:assert/strict";
import { test } from "node:test";
import crypto from "crypto";
import type { JwtPayload } from "jsonwebtoken";
import { signJwt, verifyJwt } from "../lib/jwtKeys";
import { prisma } from "../lib/prisma";
import { REFRESH_RETRY_GRACE_MS, rotateRefreshToken } from "../services/refreshRotation";

const hash = (s: string): string => crypto.createHash("sha256").update(s).digest("hex");
type Row = { tokenHash: string; userId: string; familyId: string; generation: number; expiresAt: Date; usedAt: Date | null; revokedAt: Date | null; replacedByTokenHash: string | null; deviceId: null; userAgent: null };

async function fixture(t: Parameters<Parameters<typeof test>[1]>[0]) {
  const token = signJwt({ userId: "HH-REV001", sub: "HH-REV001", role: "CLIENT", type: "refresh", jti: crypto.randomUUID() }, { expiresIn: "365d" });
  const claims = verifyJwt<JwtPayload & { userId: string }>(token);
  const rows = new Map<string, Row>([[hash(token), { tokenHash: hash(token), userId: "HH-REV001", familyId: "family-one", generation: 0, expiresAt: new Date(claims.exp! * 1000), usedAt: null, revokedAt: null, replacedByTokenHash: null, deviceId: null, userAgent: null }]]);
  const revocations: unknown[] = [];
  let failCreate = false;
  const tx = {
    $executeRaw: async (sql: TemplateStringsArray, ...values: unknown[]) => {
      if (sql.join("").includes('INSERT INTO "UserTokenDenylistEntry"')) revocations.push(values);
      return 1;
    },
    refreshToken: {
      findUnique: async ({ where }: { where: { tokenHash: string } }) => rows.get(where.tokenHash) ?? null,
      update: async ({ where, data }: { where: { tokenHash: string }; data: Partial<Row> }) => { const row = { ...rows.get(where.tokenHash)!, ...data }; rows.set(where.tokenHash, row); return row; },
      create: async ({ data }: { data: Row }) => { if (failCreate) throw new Error("insert failed"); const row = { usedAt: null, revokedAt: null, replacedByTokenHash: null, ...data }; rows.set(row.tokenHash, row); return row; },
      updateMany: async ({ where, data }: { where: { familyId: string }; data: Partial<Row> }) => { for (const [key, row] of rows) if (row.familyId === where.familyId) rows.set(key, { ...row, ...data }); return { count: rows.size }; },
    },
    userTokenDenylistEntry: { upsert: async (args: unknown) => { revocations.push(args); }, updateMany: async () => ({ count: 1 }) },
  };
  const originalFind = prisma.refreshToken.findUnique;
  const originalTx = prisma.$transaction;
  prisma.refreshToken.findUnique = tx.refreshToken.findUnique as typeof originalFind;
  let pending: Promise<unknown> = Promise.resolve();
  prisma.$transaction = ((fn: (client: typeof tx) => Promise<unknown>) => {
    // Model PostgreSQL's transaction serialization and rollback. Every caller
    // still reads predecessor state before taking the family lock.
    const run = pending.then(async () => {
      const snapshot = new Map([...rows].map(([key, row]) => [key, { ...row }]));
      try { return await fn(tx); } catch (error) { rows.clear(); for (const [key, row] of snapshot) rows.set(key, row); throw error; }
    });
    pending = run.catch(() => undefined);
    return run;
  }) as typeof originalTx;
  t.after(() => { prisma.refreshToken.findUnique = originalFind; prisma.$transaction = originalTx; });
  return { token, claims, rows, revocations, failInsert: () => { failCreate = true; } };
}

test("concurrent refreshes return one signed successor and leave one active generation", async (t) => {
  const f = await fixture(t);
  const replacements = await Promise.all(Array.from({ length: 8 }, () => rotateRefreshToken(f.token, f.claims)));
  assert.equal(new Set(replacements).size, 1);
  assert.notEqual(replacements[0], f.token);
  assert.equal(f.rows.size, 2);
  assert.equal([...f.rows.values()].filter((r) => r.usedAt === null).length, 1);
  const replacementClaims = verifyJwt<JwtPayload>(replacements[0]!);
  assert.equal(replacementClaims.exp, f.claims.exp);
  assert.notEqual(replacementClaims.jti, f.claims.jti);
});

test("lost response can reconstruct the identical successor solely from persisted predecessor state", async (t) => {
  const f = await fixture(t);
  const first = await rotateRefreshToken(f.token, f.claims);
  const retry = await rotateRefreshToken(f.token, { ...f.claims });
  assert.equal(retry, first);
  assert.equal(f.rows.get(hash(first))?.generation, 1);
});

test("replay after grace commits family revocation and denies existing access tokens", async (t) => {
  const f = await fixture(t);
  const first = await rotateRefreshToken(f.token, f.claims);
  f.rows.get(hash(f.token))!.usedAt = new Date(Date.now() - REFRESH_RETRY_GRACE_MS - 1);
  await assert.rejects(rotateRefreshToken(f.token, f.claims), { code: "TOKEN_REUSE_DETECTED" });
  assert.ok(f.rows.get(hash(first))!.revokedAt);
  assert.equal(f.revocations.length, 1);
  await assert.rejects(rotateRefreshToken(first, verifyJwt<JwtPayload & { userId: string }>(first)), { code: "TOKEN_REVOKED" });
});

test("successor insert failure rolls back predecessor consumption", async (t) => {
  const f = await fixture(t); f.failInsert();
  await assert.rejects(rotateRefreshToken(f.token, f.claims), /insert failed/);
  assert.equal(f.rows.get(hash(f.token))!.usedAt, null);
  assert.equal(f.rows.size, 1);
});

test("revoked successor is never recovered through the retry grace window", async (t) => {
  const f = await fixture(t);
  const first = await rotateRefreshToken(f.token, f.claims);
  f.rows.get(hash(first))!.revokedAt = new Date();
  await assert.rejects(rotateRefreshToken(f.token, f.claims), { code: "TOKEN_REUSE_DETECTED" });
});

test("stored hash mismatch fails transiently without revoking the family", async (t) => {
  const f = await fixture(t);
  await rotateRefreshToken(f.token, f.claims);
  f.rows.get(hash(f.token))!.replacedByTokenHash = "unexpected-key-rollover";
  await assert.rejects(rotateRefreshToken(f.token, f.claims), /signing key unavailable/);
  assert.equal(f.revocations.length, 0);
});

test("retry grace covers the consumer timeout and expires at the bounded deadline", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const f = await fixture(t);
  const replacement = await rotateRefreshToken(f.token, f.claims);
  t.mock.timers.tick(30_001);
  assert.equal(await rotateRefreshToken(f.token, f.claims), replacement);
  t.mock.timers.tick(REFRESH_RETRY_GRACE_MS - 30_001);
  assert.equal(await rotateRefreshToken(f.token, f.claims), replacement);
  t.mock.timers.tick(1);
  await assert.rejects(rotateRefreshToken(f.token, f.claims), { code: "TOKEN_REUSE_DETECTED" });
  assert.ok(f.rows.get(hash(replacement))!.revokedAt);
});
