/**
 * @ai-context Email Verification Service | token generation, validation, and email dispatch
 *
 * Security properties match passwordResetService:
 * - 32-byte cryptographically random tokens stored only as SHA-256 hashes
 * - 24-hour TTL
 * - Single-use enforcement
 * - Delivery-safe resend semantics: old links stay valid if email delivery fails
 *
 * deps: prisma, crypto, emailService | consumers: routes/auth.ts (verify-email routes)
 */

import crypto from "crypto";
import { logger } from "../lib/logger";
import { prisma } from "../lib/prisma";
import { sendEmailVerificationEmail } from "./emailService";

import type { VerificationSourceApp } from "./emailService";

type EmailVerificationDeps = {
  emailVerificationToken: {
    create: typeof prisma.emailVerificationToken.create;
    updateMany: typeof prisma.emailVerificationToken.updateMany;
    findFirst: typeof prisma.emailVerificationToken.findFirst;
    findUnique: typeof prisma.emailVerificationToken.findUnique;
  };
  user: {
    findUnique: typeof prisma.user.findUnique;
    update: typeof prisma.user.update;
  };
  transaction: typeof prisma.$transaction;
  sendEmail: typeof sendEmailVerificationEmail;
};

const defaultDeps: EmailVerificationDeps = {
  emailVerificationToken: prisma.emailVerificationToken,
  user: prisma.user,
  transaction: prisma.$transaction.bind(prisma),
  sendEmail: sendEmailVerificationEmail,
};

// ============================================================================
// Configuration
// ============================================================================

/** Token expires after 24 hours */
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

// ============================================================================
// Types
// ============================================================================

export class EmailVerificationError extends Error {
  constructor(
    message: string,
    public code:
      | "INVALID_TOKEN"
      | "TOKEN_EXPIRED"
      | "TOKEN_USED"
      | "ALREADY_VERIFIED"
      | "USER_NOT_FOUND",
    public statusCode: number = 400,
  ) {
    super(message);
    this.name = "EmailVerificationError";
  }
}

// ============================================================================
// Internal helpers
// ============================================================================

function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// ============================================================================
// Service functions
// ============================================================================

/**
 * Create and send an email verification token for the given user.
 * Invalidates older unused tokens only after the new email has been accepted
 * by the delivery provider. If delivery fails, the newly-created token is
 * burned and prior valid links remain usable.
 *
 * @returns The plain token (for testing) — in production, it goes only to the email.
 */
export async function sendVerificationEmail(
  userId: string,
  email: string,
  sourceApp?: VerificationSourceApp,
  deps: EmailVerificationDeps = defaultDeps,
): Promise<{ plainToken: string; expiresAt: Date }> {
  const plainToken = generateSecureToken();
  const tokenHash = hashToken(plainToken);
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);
  const createdAt = new Date();

  const newToken = await deps.emailVerificationToken.create({
    data: { userId, tokenHash, expiresAt, createdAt },
    select: { id: true },
  });

  try {
    await deps.sendEmail({
      email,
      token: plainToken,
      expiresAt,
      sourceApp,
    });
  } catch (error) {
    await deps.emailVerificationToken.updateMany({
      where: { id: newToken.id, usedAt: null },
      data: { usedAt: new Date() },
    });
    throw error;
  }

  await deps.emailVerificationToken.updateMany({
    where: {
      userId,
      usedAt: null,
      createdAt: { lt: createdAt },
    },
    data: { usedAt: new Date() },
  });

  logger.info({ userId }, "[EMAIL-VERIFY] Verification email sent"); // phi-safe

  return { plainToken, expiresAt };
}

export async function getVerificationEmailCooldown(
  userId: string,
  cooldownMs: number,
  deps: EmailVerificationDeps = defaultDeps,
): Promise<{ retryAfterSeconds: number } | null> {
  const latest = await deps.emailVerificationToken.findFirst({
    where: { userId, usedAt: null },
    orderBy: { createdAt: "desc" },
    select: { createdAt: true },
  });

  if (!latest) {
    return null;
  }

  const elapsedMs = Date.now() - latest.createdAt.getTime();
  if (elapsedMs >= cooldownMs) {
    return null;
  }

  return {
    retryAfterSeconds: Math.max(1, Math.ceil((cooldownMs - elapsedMs) / 1000)),
  };
}

export async function isEmailVerified(
  userId: string,
  deps: EmailVerificationDeps = defaultDeps,
): Promise<boolean> {
  const user = await deps.user.findUnique({
    where: { id: userId },
    select: { emailVerified: true },
  });

  return user?.emailVerified != null;
}

export async function confirmEmailVerification(
  token: string,
  deps: EmailVerificationDeps = defaultDeps,
): Promise<void> {
  const tokenHash = hashToken(token);

  const stored = await deps.emailVerificationToken.findUnique({
    where: { tokenHash },
    select: { id: true, userId: true, expiresAt: true, usedAt: true },
  });

  if (!stored) {
    throw new EmailVerificationError(
      "Invalid or expired verification token",
      "INVALID_TOKEN",
    );
  }

  if (stored.usedAt) {
    if (await isEmailVerified(stored.userId, deps)) {
      return;
    }
    throw new EmailVerificationError(
      "Verification token has already been used",
      "TOKEN_USED",
    );
  }

  if (stored.expiresAt < new Date()) {
    if (await isEmailVerified(stored.userId, deps)) {
      return;
    }
    throw new EmailVerificationError(
      "Verification token has expired",
      "TOKEN_EXPIRED",
    );
  }

  // Atomic: claim the still-unused token + set emailVerified. The conditional
  // update preserves single-use semantics under concurrent confirmations.
  await deps.transaction(async (tx) => {
    const claimed = await tx.emailVerificationToken.updateMany({
      where: { id: stored.id, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (claimed.count !== 1) {
      if (await isEmailVerified(stored.userId, deps)) {
        return;
      }
      throw new EmailVerificationError(
        "Verification token has already been used",
        "TOKEN_USED",
      );
    }

    await tx.user.update({
      where: { id: stored.userId },
      data: { emailVerified: new Date() },
    });
  });

  logger.info({ userId: stored.userId }, "[EMAIL-VERIFY] Email verified"); // phi-safe
}
