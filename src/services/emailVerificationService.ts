/**
 * @ai-context Email Verification Service | token generation, validation, and email dispatch
 *
 * Security properties match passwordResetService:
 * - 32-byte cryptographically random tokens stored only as SHA-256 hashes
 * - 24-hour TTL
 * - Single-use enforcement
 * - Constant-time comparison
 *
 * deps: prisma, crypto, emailService | consumers: routes/auth.ts (verify-email routes)
 */

import crypto from "crypto";
import { logger } from "../lib/logger";
import { prisma } from "../lib/prisma";
import { sendEmailVerificationEmail } from "./emailService";

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
 * Invalidates any existing unused tokens before issuing a new one.
 *
 * @returns The plain token (for testing) — in production, it goes only to the email.
 */
export async function sendVerificationEmail(
  userId: string,
  email: string,
): Promise<{ plainToken: string; expiresAt: Date }> {
  const plainToken = generateSecureToken();
  const tokenHash = hashToken(plainToken);
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);

  await prisma.$transaction(async (tx) => {
    // Invalidate existing unused tokens for this user
    await tx.emailVerificationToken.updateMany({
      where: { userId, usedAt: null },
      data: { usedAt: new Date() },
    });

    await tx.emailVerificationToken.create({
      data: { userId, tokenHash, expiresAt },
    });
  });

  await sendEmailVerificationEmail({ email, token: plainToken, expiresAt });

  logger.info({ userId }, "[EMAIL-VERIFY] Verification email sent"); // phi-safe

  return { plainToken, expiresAt };
}

/**
 * Consume an email verification token and mark the user's email as verified.
 *
 * @throws EmailVerificationError on any failure
 */
export async function confirmEmailVerification(token: string): Promise<void> {
  const tokenHash = hashToken(token);

  const stored = await prisma.emailVerificationToken.findUnique({
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
    throw new EmailVerificationError(
      "Verification token has already been used",
      "TOKEN_USED",
    );
  }

  if (stored.expiresAt < new Date()) {
    throw new EmailVerificationError(
      "Verification token has expired",
      "TOKEN_EXPIRED",
    );
  }

  // Atomic: mark token used + set emailVerified
  await prisma.$transaction(async (tx) => {
    await tx.emailVerificationToken.update({
      where: { id: stored.id },
      data: { usedAt: new Date() },
    });

    await tx.user.update({
      where: { id: stored.userId },
      data: { emailVerified: new Date() },
    });
  });

  logger.info({ userId: stored.userId }, "[EMAIL-VERIFY] Email verified"); // phi-safe
}
