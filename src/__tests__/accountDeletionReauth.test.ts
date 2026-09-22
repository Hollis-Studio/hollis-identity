import assert from "node:assert/strict";
import { after, before, it, mock } from "node:test";
import { prisma } from "../lib/prisma";
import {
  LEGACY_ACCOUNT_DELETE_SUNSET,
  resolveLegacyAccountDeleteSunset,
  validateEnvOnStartup,
} from "../lib/env";
import { signJwt } from "../lib/jwtKeys";
import {
  ACCOUNT_DELETION_GRANT_PURPOSE,
  ACCOUNT_DELETION_GRANT_TYPE,
  resolveAccountDeletionAuthorization,
} from "../services/accountDeletionAuthorization";
import { verifyOAuthReauthenticationProof } from "../services/oauthVerificationService";

const originalFindUnique = prisma.oAuthAccount.findUnique;

before(() => {
  process.env.GOOGLE_CLIENT_ID = "deletion-reauth-client";
  validateEnvOnStartup();
});

after(() => {
  mock.restoreAll();
  prisma.oAuthAccount.findUnique = originalFindUnique;
});

function mockGoogleToken(subject: string, authenticatedAt = Math.floor(Date.now() / 1000)): void {
  mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({
    iss: "https://accounts.google.com",
    aud: "deletion-reauth-client",
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: authenticatedAt,
    sub: subject,
    email: "member@example.invalid",
    email_verified: "true",
  })));
}

it("accepts a fresh provider proof linked to the authenticated account", async () => {
  mockGoogleToken("provider-owner");
  prisma.oAuthAccount.findUnique = mock.fn(async () => ({ userId: "identity-owner" })) as typeof prisma.oAuthAccount.findUnique;
  await assert.doesNotReject(verifyOAuthReauthenticationProof("identity-owner", {
    provider: "google", idToken: "fresh-owner-proof",
  }));
});

it("rejects a provider proof whose authentication is stale", async () => {
  mockGoogleToken("provider-stale", Math.floor(Date.now() / 1000) - 601);
  prisma.oAuthAccount.findUnique = mock.fn(async () => ({ userId: "identity-owner" })) as typeof prisma.oAuthAccount.findUnique;
  await assert.rejects(verifyOAuthReauthenticationProof("identity-owner", {
    provider: "google", idToken: "stale-provider-proof",
  }), /not recent/);
});

it("rejects a provider proof with a future authentication time", async () => {
  mockGoogleToken("provider-future", Math.floor(Date.now() / 1000) + 61);
  prisma.oAuthAccount.findUnique = mock.fn(async () => ({ userId: "identity-owner" })) as typeof prisma.oAuthAccount.findUnique;
  await assert.rejects(verifyOAuthReauthenticationProof("identity-owner", {
    provider: "google", idToken: "future-provider-proof",
  }), /not recent/);
});

it("rejects a provider proof linked to a different account", async () => {
  mockGoogleToken("provider-other");
  prisma.oAuthAccount.findUnique = mock.fn(async () => ({ userId: "different-owner" })) as typeof prisma.oAuthAccount.findUnique;
  await assert.rejects(verifyOAuthReauthenticationProof("identity-owner", {
    provider: "google", idToken: "fresh-mismatched-proof", nonce: "1234567890abcdef",
  }));
});

it("rejects replay of an already-consumed provider proof", async () => {
  mockGoogleToken("provider-replay");
  prisma.oAuthAccount.findUnique = mock.fn(async () => ({ userId: "identity-owner" })) as typeof prisma.oAuthAccount.findUnique;
  const proof = { provider: "google" as const, idToken: "single-use-provider-proof", nonce: "1234567890abcdef" };
  await verifyOAuthReauthenticationProof("identity-owner", proof);
  await assert.rejects(verifyOAuthReauthenticationProof("identity-owner", proof));
});

// ── DELETE /auth/account: grant vs. legacy compatibility window ────────────

const BEFORE_SUNSET = new Date(LEGACY_ACCOUNT_DELETE_SUNSET.getTime() - 1);
const AT_SUNSET = new Date(LEGACY_ACCOUNT_DELETE_SUNSET.getTime());

function deletionGrant(sub: string, overrides: Record<string, unknown> = {}): string {
  return signJwt(
    { sub, type: ACCOUNT_DELETION_GRANT_TYPE, purpose: ACCOUNT_DELETION_GRANT_PURPOSE, ...overrides },
    { expiresIn: "10m" },
  );
}

it("accepts a grant-less (legacy) delete before the sunset", () => {
  for (const body of [undefined, null, {}, { unrelated: true }, { authorization: undefined }]) {
    assert.deepEqual(
      resolveAccountDeletionAuthorization(body, "identity-owner", {
        now: BEFORE_SUNSET, legacySunset: LEGACY_ACCOUNT_DELETE_SUNSET,
      }),
      { ok: true, mode: "legacy" },
    );
  }
});

it("rejects a grant-less delete at/after the sunset or when the window is off", () => {
  for (const options of [
    { now: AT_SUNSET, legacySunset: LEGACY_ACCOUNT_DELETE_SUNSET },
    { now: new Date("2027-06-01T00:00:00Z"), legacySunset: LEGACY_ACCOUNT_DELETE_SUNSET },
    { now: BEFORE_SUNSET, legacySunset: null },
  ]) {
    const result = resolveAccountDeletionAuthorization(undefined, "identity-owner", options);
    assert.equal(result.ok, false);
  }
});

it("rejects a present-but-invalid grant even inside the legacy window", () => {
  const options = { now: BEFORE_SUNSET, legacySunset: LEGACY_ACCOUNT_DELETE_SUNSET };
  const invalid: unknown[] = [
    { authorization: "" },
    { authorization: null },
    { authorization: 12345 },
    { authorization: "not-a-jwt-but-long-enough-to-pass-length" },
    { authorization: deletionGrant("someone-else") },
    { authorization: deletionGrant("identity-owner", { type: "access" }) },
    { authorization: deletionGrant("identity-owner", { purpose: "other" }) },
    { authorization: signJwt({ sub: "identity-owner", type: ACCOUNT_DELETION_GRANT_TYPE, purpose: ACCOUNT_DELETION_GRANT_PURPOSE }, { expiresIn: -10 }) },
  ];
  for (const body of invalid) {
    assert.equal(resolveAccountDeletionAuthorization(body, "identity-owner", options).ok, false);
  }
});

it("accepts a valid grant before and after the sunset", () => {
  for (const now of [BEFORE_SUNSET, AT_SUNSET]) {
    assert.deepEqual(
      resolveAccountDeletionAuthorization({ authorization: deletionGrant("identity-owner") }, "identity-owner", {
        now, legacySunset: LEGACY_ACCOUNT_DELETE_SUNSET,
      }),
      { ok: true, mode: "grant" },
    );
  }
});

it("resolves the legacy sunset override from IDENTITY_LEGACY_ACCOUNT_DELETE_UNTIL", () => {
  assert.equal(resolveLegacyAccountDeleteSunset(undefined), LEGACY_ACCOUNT_DELETE_SUNSET);
  assert.equal(resolveLegacyAccountDeleteSunset("  "), LEGACY_ACCOUNT_DELETE_SUNSET);
  assert.equal(resolveLegacyAccountDeleteSunset("off"), null);
  assert.equal(resolveLegacyAccountDeleteSunset("OFF"), null);
  assert.equal(resolveLegacyAccountDeleteSunset("garbage"), null);
  assert.equal(resolveLegacyAccountDeleteSunset("2027-03-01")?.toISOString(), "2027-03-01T00:00:00.000Z");
  const past = resolveLegacyAccountDeleteSunset("2020-01-01T00:00:00Z");
  assert.equal(
    resolveAccountDeletionAuthorization(undefined, "identity-owner", { now: new Date(), legacySunset: past }).ok,
    false,
  );
});
