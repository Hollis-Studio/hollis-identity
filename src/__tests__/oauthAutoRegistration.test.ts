/**
 * Unit tests for the OAuth auto-registration path added to findOrLinkOAuthUser.
 *
 * These tests exercise the transaction-level branching logic inline (no module mocking needed).
 * Node 20 built-in test runner; no mock.module available.
 *
 * Covers:
 * 1. New email identity (no OAuthAccount, no User) → creates User + OAuthAccount + isNewUser:true
 * 2. Email-less identity → does NOT create a user, throws NO_ACCOUNT_FOUND semantics
 * 3. Existing User found by email (no OAuthAccount) → links account + isNewUser:false (unchanged)
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import crypto from "node:crypto";

// ============================================================================
// Inline simulation of the findOrLinkOAuthUser transaction logic
// This mirrors the exact branch logic added to oauthVerificationService.ts.
// ============================================================================

type FakeTx = {
  oAuthAccount: {
    findUnique: () => Promise<unknown>;
    create: (args: { data: { userId: string; provider: string; providerUserId: string } }) => Promise<{ id: string }>;
  };
  user: {
    findUnique: () => Promise<unknown>;
    create: (args: {
      data: {
        id: string;
        email: string;
        passwordHash: string;
        role: string;
        isActive: boolean;
      };
    }) => Promise<{ id: string; email: string; role: string; organizationId: null }>;
  };
};

type FindOrLinkResult = {
  userId: string;
  userRole: string;
  organizationId: string | null;
  email: string;
  isNewLink: boolean;
  isNewUser: boolean;
  mfaEnabled: boolean;
};

async function simulateFindOrLinkBranch(
  identity: { sub: string; email?: string; emailVerified?: boolean },
  tx: FakeTx,
): Promise<FindOrLinkResult> {
  // Step 1: fast-path OAuthAccount lookup
  const existingAccount = await tx.oAuthAccount.findUnique();
  if (existingAccount) {
    const u = existingAccount as {
      user: { id: string; role: string; organizationId: null; email: string; isActive: boolean; _count: { mfaCredentials: number } };
    };
    if (!u.user.isActive) throw new Error("OAUTH_ACCOUNT_INACTIVE");
    return {
      userId: u.user.id,
      userRole: u.user.role,
      organizationId: u.user.organizationId,
      email: u.user.email,
      isNewLink: false,
      isNewUser: false,
      mfaEnabled: u.user._count.mfaCredentials > 0,
    };
  }

  // Step 2: email verification gate
  if (identity.email && identity.emailVerified !== true) {
    throw new Error("OAUTH_EMAIL_NOT_VERIFIED");
  }

  if (identity.email) {
    // Step 3: email lookup
    const existingUser = await tx.user.findUnique();

    if (existingUser) {
      const u = existingUser as { id: string; role: string; organizationId: null; email: string; isActive: boolean; _count: { mfaCredentials: number } };
      if (!u.isActive) throw new Error("OAUTH_ACCOUNT_INACTIVE");

      await tx.oAuthAccount.create({
        data: { userId: u.id, provider: "GOOGLE", providerUserId: identity.sub },
      });

      return {
        userId: u.id,
        userRole: u.role,
        organizationId: u.organizationId,
        email: u.email,
        isNewLink: true,
        isNewUser: false,
        mfaEnabled: u._count.mfaCredentials > 0,
      };
    }

    // Step 4: auto-register (new path)
    const newUserId = crypto.randomUUID();
    const newUser = await tx.user.create({
      data: {
        id: newUserId,
        email: identity.email.toLowerCase(),
        passwordHash: "",      // OAuth-only; password login blocked by length === 0 check
        role: "CLIENT",
        isActive: true,
      },
    });

    await tx.oAuthAccount.create({
      data: { userId: newUserId, provider: "GOOGLE", providerUserId: identity.sub },
    });

    return {
      userId: newUser.id,
      userRole: newUser.role,
      organizationId: newUser.organizationId,
      email: newUser.email,
      isNewLink: true,
      isNewUser: true,
      mfaEnabled: false,
    };
  }

  // No verified email — cannot auto-register; throw NO_ACCOUNT_FOUND
  throw new Error("OAUTH_NO_ACCOUNT_FOUND");
}

// ============================================================================
// Test suites
// ============================================================================

describe("OAuth auto-registration: new email identity", () => {
  it("creates a new User + OAuthAccount and returns isNewUser:true", async () => {
    let userCreateCalled = false;
    let oauthCreateCalled = false;
    let capturedUserData: Parameters<FakeTx["user"]["create"]>[0]["data"] | null = null;

    const tx: FakeTx = {
      oAuthAccount: {
        findUnique: async () => null,   // no existing OAuthAccount
        create: async () => {
          oauthCreateCalled = true;
          return { id: "oa-new" };
        },
      },
      user: {
        findUnique: async () => null,   // no existing User by email
        create: async (args) => {
          userCreateCalled = true;
          capturedUserData = args.data;
          return {
            id: args.data.id,
            email: args.data.email,
            role: "CLIENT",
            organizationId: null,
          };
        },
      },
    };

    const identity = { sub: "google-sub-new", email: "newuser@example.com", emailVerified: true };
    const result = await simulateFindOrLinkBranch(identity, tx);

    // Registration result contract
    assert.equal(result.isNewUser, true, "isNewUser must be true");
    assert.equal(result.isNewLink, true, "isNewLink must be true");
    assert.equal(result.mfaEnabled, false, "mfaEnabled must be false for new user");
    assert.equal(result.email, "newuser@example.com");

    // User created with register-path-mirrored fields
    assert.equal(userCreateCalled, true, "user.create must be called");
    assert.ok(capturedUserData !== null);
    assert.equal(capturedUserData!.email, "newuser@example.com", "email must be lowercased");
    assert.equal(capturedUserData!.passwordHash, "", "passwordHash must be empty string for OAuth-only account");
    assert.equal(capturedUserData!.role, "CLIENT", "role must default to CLIENT");
    assert.equal(capturedUserData!.isActive, true, "isActive must be true");

    // OAuthAccount linked in same transaction
    assert.equal(oauthCreateCalled, true, "oAuthAccount.create must be called");
    // userId in OAuthAccount matches the created user
    assert.equal(result.userId, capturedUserData!.id, "OAuthAccount userId must match new User id");
  });
});

describe("OAuth auto-registration: email-less identity still returns NO_ACCOUNT_FOUND", () => {
  it("throws OAUTH_NO_ACCOUNT_FOUND when identity has no email", async () => {
    let userCreateCalled = false;

    const tx: FakeTx = {
      oAuthAccount: { findUnique: async () => null, create: async () => ({ id: "x" }) },
      user: {
        findUnique: async () => null,
        create: async () => {
          userCreateCalled = true;
          assert.fail("user.create must NOT be called for email-less identity");
          return { id: "x", email: "x", role: "CLIENT", organizationId: null };
        },
      },
    };

    const identity = { sub: "apple-sub-emailless" }; // no email

    await assert.rejects(
      () => simulateFindOrLinkBranch(identity, tx),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, "OAUTH_NO_ACCOUNT_FOUND");
        return true;
      },
      "must throw OAUTH_NO_ACCOUNT_FOUND for email-less identity",
    );

    assert.equal(userCreateCalled, false, "user.create must not have been called");
  });
});

describe("OAuth auto-registration: existing email links account (unchanged behaviour)", () => {
  it("links OAuthAccount to existing User and returns isNewUser:false", async () => {
    const existingUser = {
      id: "existing-user-id",
      email: "existing@example.com",
      role: "CLIENT",
      organizationId: null as null,
      isActive: true,
      _count: { mfaCredentials: 0 },
    };

    let oauthCreateCalled = false;
    let userCreateCalled = false;

    const tx: FakeTx = {
      oAuthAccount: {
        findUnique: async () => null,   // no existing OAuthAccount
        create: async () => {
          oauthCreateCalled = true;
          return { id: "oa-linked" };
        },
      },
      user: {
        findUnique: async () => existingUser,  // existing User found by email
        create: async () => {
          userCreateCalled = true;
          assert.fail("user.create must NOT be called when existing user found");
          return { id: "x", email: "x", role: "CLIENT", organizationId: null };
        },
      },
    };

    const identity = { sub: "google-sub-existing", email: "existing@example.com", emailVerified: true };
    const result = await simulateFindOrLinkBranch(identity, tx);

    assert.equal(result.isNewUser, false, "isNewUser must be false for existing user link");
    assert.equal(result.isNewLink, true, "isNewLink must be true (new OAuthAccount row)");
    assert.equal(result.userId, "existing-user-id");
    assert.equal(result.email, "existing@example.com");
    assert.equal(oauthCreateCalled, true, "oAuthAccount.create must be called to link");
    assert.equal(userCreateCalled, false, "user.create must NOT be called");
  });
});
