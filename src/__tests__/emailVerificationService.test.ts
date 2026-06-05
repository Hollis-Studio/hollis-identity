import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  confirmEmailVerification,
  EmailVerificationError,
  getVerificationEmailCooldown,
  sendVerificationEmail,
} from "../services/emailVerificationService";

type UpdateCall = {
  where: unknown;
  data: { usedAt: Date };
};

function createDeps(overrides: {
  create?: (input: unknown) => Promise<{ id: string }>;
  updateMany?: (input: UpdateCall) => Promise<{ count: number }>;
  findFirst?: () => Promise<{ createdAt: Date } | null>;
  findUniqueToken?: () => Promise<{
    id: string;
    userId: string;
    expiresAt: Date;
    usedAt: Date | null;
  } | null>;
  findUniqueUser?: () => Promise<{ emailVerified: Date | null } | null>;
  sendEmail?: () => Promise<void>;
  transaction?: (callback: (tx: {
    emailVerificationToken: { updateMany: (input: UpdateCall) => Promise<{ count: number }> };
    user: { update: (input: unknown) => Promise<unknown> };
  }) => Promise<void>) => Promise<void>;
}) {
  const updateMany = overrides.updateMany ?? (async () => ({ count: 1 }));
  return {
    emailVerificationToken: {
      create: overrides.create ?? (async () => ({ id: "new-token-id" })),
      updateMany,
      findFirst: overrides.findFirst ?? (async () => null),
      findUnique: overrides.findUniqueToken ?? (async () => null),
    },
    user: {
      findUnique: overrides.findUniqueUser ?? (async () => null),
      update: async () => ({}),
    },
    transaction:
      overrides.transaction ??
      (async (callback) => {
        await callback({
          emailVerificationToken: { updateMany },
          user: { update: async () => ({}) },
        });
      }),
    sendEmail: overrides.sendEmail ?? (async () => undefined),
  };
}

describe("emailVerificationService", () => {
  it("burns only the newly-created token when email delivery fails", async () => {
    const updateCalls: UpdateCall[] = [];
    const deps = createDeps({
      updateMany: async (input) => {
        updateCalls.push(input);
        return { count: 1 };
      },
      sendEmail: async () => {
        throw new Error("SES unavailable");
      },
    });

    await assert.rejects(
      () => sendVerificationEmail("user-1", "user@example.com", "workouts", deps),
      /SES unavailable/,
    );

    assert.equal(updateCalls.length, 1);
    assert.deepEqual(updateCalls[0]?.where, { id: "new-token-id", usedAt: null });
    assert.ok(updateCalls[0]?.data.usedAt instanceof Date);
  });

  it("invalidates older unused tokens only after delivery succeeds", async () => {
    const updateCalls: UpdateCall[] = [];
    const deps = createDeps({
      updateMany: async (input) => {
        updateCalls.push(input);
        return { count: 2 };
      },
    });

    await sendVerificationEmail("user-1", "user@example.com", "workouts", deps);

    assert.equal(updateCalls.length, 1);
    const where = updateCalls[0]?.where as {
      userId: string;
      usedAt: null;
      createdAt: { lt: Date };
    };
    assert.equal(where.userId, "user-1");
    assert.equal(where.usedAt, null);
    assert.ok(where.createdAt.lt instanceof Date);
    assert.ok(updateCalls[0]?.data.usedAt instanceof Date);
  });

  it("returns resend cooldown while an unused token is still inside the cooldown window", async () => {
    const deps = createDeps({
      findFirst: async () => ({ createdAt: new Date(Date.now() - 10_000) }),
    });

    const cooldown = await getVerificationEmailCooldown("user-1", 60_000, deps);

    assert.ok(cooldown);
    assert.equal(cooldown.retryAfterSeconds <= 50, true);
    assert.equal(cooldown.retryAfterSeconds > 0, true);
  });

  it("treats an already-used token as success once the user is verified", async () => {
    const deps = createDeps({
      findUniqueToken: async () => ({
        id: "token-1",
        userId: "user-1",
        expiresAt: new Date(Date.now() + 60_000),
        usedAt: new Date(),
      }),
      findUniqueUser: async () => ({ emailVerified: new Date() }),
    });

    await assert.doesNotReject(() => confirmEmailVerification("already-used-token", deps));
  });

  it("rejects an already-used token when the user is still unverified", async () => {
    const deps = createDeps({
      findUniqueToken: async () => ({
        id: "token-1",
        userId: "user-1",
        expiresAt: new Date(Date.now() + 60_000),
        usedAt: new Date(),
      }),
      findUniqueUser: async () => ({ emailVerified: null }),
    });

    await assert.rejects(
      () => confirmEmailVerification("already-used-token", deps),
      (error: unknown) =>
        error instanceof EmailVerificationError && error.code === "TOKEN_USED",
    );
  });
});
