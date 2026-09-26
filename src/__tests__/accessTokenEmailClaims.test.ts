/**
 * Access tokens carry `email` and `email_verified` (Hollis-Workouts#130). Consumers take
 * the account email from the verified claim, so every issue path must read the user's
 * current email state; refresh must not carry it over from the previous token.
 */
import assert from "node:assert/strict";
import { after, before, beforeEach, it, mock } from "node:test";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { AUDIENCES } from "@hollis-studio/contracts";
import { signJwt } from "../lib/jwtKeys";
import { validateEnvOnStartup } from "../lib/env";
import { hashPassword } from "../lib/passwordHashing";
import { prisma } from "../lib/prisma";
import {
  generateAccessTokenWithJti,
  login,
  refresh,
  issueAuthenticatedSession,
} from "../services/authService";

const USER_ID = "claims-user";
const PASSWORD = "sufficient-secret";

interface UserState {
  email: string;
  emailVerified: Date | null;
}

let user: UserState;
let passwordHash: string;

const originals = {
  userFindUnique: prisma.user.findUnique,
  userUpdate: prisma.user.update,
  refreshFindUnique: prisma.refreshToken.findUnique,
  refreshCreate: prisma.refreshToken.create,
  transaction: prisma.$transaction,
};

function decode(token: string): jwt.JwtPayload {
  return jwt.decode(token) as jwt.JwtPayload;
}

before(async () => {
  validateEnvOnStartup();
  passwordHash = await hashPassword(PASSWORD);
});

beforeEach(() => {
  user = { email: "member@example.invalid", emailVerified: new Date("2026-01-01T00:00:00Z") };
  prisma.user.findUnique = mock.fn(async () => ({
    id: USER_ID,
    email: user.email,
    emailVerified: user.emailVerified,
    passwordHash,
    displayName: null,
    role: "CLIENT",
    organizationId: null,
    isActive: true,
    _count: { mfaCredentials: 0 },
  })) as unknown as typeof prisma.user.findUnique;
  prisma.user.update = mock.fn(async () => ({})) as unknown as typeof prisma.user.update;
  prisma.refreshToken.create = mock.fn(async () => ({})) as unknown as typeof prisma.refreshToken.create;
});

after(() => {
  prisma.user.findUnique = originals.userFindUnique;
  prisma.user.update = originals.userUpdate;
  prisma.refreshToken.findUnique = originals.refreshFindUnique;
  prisma.refreshToken.create = originals.refreshCreate;
  prisma.$transaction = originals.transaction;
});

/** A stored, unused refresh token for USER_ID, with an in-memory rotation transaction. */
function mockStoredRefreshToken(): string {
  const token = signJwt(
    { sub: USER_ID, userId: USER_ID, role: "CLIENT", type: "refresh", jti: crypto.randomUUID(), aud: [...AUDIENCES] },
    { expiresIn: "365d" },
  );
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const row = {
    tokenHash,
    userId: USER_ID,
    familyId: "family",
    generation: 0,
    expiresAt: new Date(Date.now() + 86_400_000),
    usedAt: null,
    revokedAt: null,
    revokedReason: null,
    replacedByTokenHash: null,
    deviceId: null,
    userAgent: null,
  };
  const findUnique = async ({ where }: { where: { tokenHash: string } }) =>
    where.tokenHash === tokenHash ? row : null;
  prisma.refreshToken.findUnique = findUnique as unknown as typeof prisma.refreshToken.findUnique;
  prisma.$transaction = (async (fn: (tx: unknown) => Promise<unknown>) =>
    fn({
      $executeRaw: async () => 1,
      refreshToken: {
        findUnique,
        update: async () => row,
        create: async () => ({}),
        updateMany: async () => ({ count: 0 }),
      },
    })) as unknown as typeof prisma.$transaction;
  return token;
}

it("login signs the account's email and verification into the access token", async () => {
  const session = await login(user.email, PASSWORD, "203.0.113.1");
  const claims = decode(session.idToken);
  assert.equal(claims.type, "access");
  assert.equal(claims.email, "member@example.invalid");
  assert.equal(claims.email_verified, true);
});

it("email_verified is false for an unverified account", async () => {
  user.emailVerified = null;
  const session = await login(user.email, PASSWORD, "203.0.113.1");
  const claims = decode(session.idToken);
  assert.equal(claims.email, "member@example.invalid");
  assert.equal(claims.email_verified, false);
});

it("registration's first session is signed as unverified", async () => {
  const session = await issueAuthenticatedSession(
    {
      profile: {
        uid: USER_ID,
        email: "new@example.invalid",
        displayName: "new",
        role: "CLIENT",
        organizationId: null,
        isAnonymous: false,
        emailVerified: false,
      },
      provider: "password",
      onboardingCompleted: false,
      mfaEnabled: false,
    },
    "register",
  );
  const claims = decode(session.idToken);
  assert.equal(claims.email, "new@example.invalid");
  assert.equal(claims.email_verified, false);
});

it("refresh signs the account's current email state", async () => {
  const session = await refresh(mockStoredRefreshToken());
  const claims = decode(session.idToken);
  assert.equal(claims.type, "access");
  assert.equal(claims.email, "member@example.invalid");
  assert.equal(claims.email_verified, true);
});

it("refresh reflects an email change made after the previous token was issued", async () => {
  const previous = decode(
    generateAccessTokenWithJti(USER_ID, "CLIENT", null, {
      account: { email: user.email, emailVerified: true },
    }).token,
  );
  assert.equal(previous.email, "member@example.invalid");

  user = { email: "changed@example.invalid", emailVerified: null };
  const session = await refresh(mockStoredRefreshToken());
  const claims = decode(session.idToken);
  assert.equal(claims.email, "changed@example.invalid");
  assert.equal(claims.email_verified, false);
});

it("omits the email claims rather than signing an address consumers would reject", () => {
  const claims = decode(
    generateAccessTokenWithJti(USER_ID, "CLIENT", null, {
      account: { email: "not-an-email", emailVerified: true },
    }).token,
  );
  assert.equal("email" in claims, false);
  assert.equal("email_verified" in claims, false);
});

it("mfa_pending tokens carry no email claims", () => {
  const claims = decode(
    generateAccessTokenWithJti(USER_ID, "CLIENT", null, { tokenType: "mfa_pending" }).token,
  );
  assert.equal(claims.type, "mfa_pending");
  assert.equal("email" in claims, false);
});
