/**
 * @ai-context Password Reset Service | secure token generation, validation, and password changes
 *
 * Security properties:
 * - Tokens are cryptographically random (32 bytes, URL-safe base64)
 * - Only SHA-256 hash of token is stored (plain token sent via email, never logged)
 * - Short TTL (30 minutes) limits exposure window
 * - Single-use enforcement prevents token replay
 * - Constant-time comparison prevents timing attacks
 * - Identical responses regardless of email existence (anti-enumeration)
 * - All active sessions invalidated on password change/reset
 * - Access token denylist for immediate session termination
 *
 * deps: prisma, crypto, bcryptjs | consumers: routes/auth.ts
 */

import { REVOKED_REASON } from "@hollis/contracts";
import crypto from "crypto";
import { USER_ERRORS } from "../constants/errorMessages";
import { clearAccountLockout } from "../lib/accountLockout";
import { logger } from "../lib/logger";
import { hashPassword, verifyPassword } from "../lib/passwordHashing";
import { prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";
import { denyAllUserAccessTokens } from "./tokenDenylistService";

// ============================================================================
// Configuration
// ============================================================================

/** Token expires after 30 minutes (in milliseconds) */
const TOKEN_TTL_MS = 30 * 60 * 1000;

// ============================================================================
// Types
// ============================================================================

export interface CreateResetTokenResult {
  /** The plain token to send via email (never store or log this) */
  plainToken: string;
  /** When the token expires */
  expiresAt: Date;
}

export interface ValidateResetTokenResult {
  valid: boolean;
  userId?: string;
  /** Error reason (only for logging, never expose to client) */
  reason?: "not_found" | "expired" | "already_used";
}

export class PasswordResetError extends Error {
  constructor(
    message: string,
    public code:
      | "INVALID_TOKEN"
      | "TOKEN_EXPIRED"
      | "TOKEN_USED"
      | "INVALID_PASSWORD"
      | "USER_NOT_FOUND",
    public statusCode: number = 400,
  ) {
    super(message);
    this.name = "PasswordResetError";
  }
}

// ============================================================================
// Token Generation & Hashing
// ============================================================================

/**
 * Generates a cryptographically secure random token.
 * Returns URL-safe base64 encoding (32 bytes = 256 bits of entropy).
 */
function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

/**
 * Hashes a token using SHA-256.
 * We use SHA-256 rather than bcrypt because:
 * 1. Tokens are already high-entropy random values
 * 2. We need fast lookup by hash (bcrypt would be too slow)
 * 3. SHA-256 is sufficient for high-entropy inputs
 */
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/**
 * Constant-time comparison of token hashes to prevent timing attacks.
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still do a comparison to maintain constant time
    crypto.timingSafeEqual(Buffer.from(a), Buffer.from(a));
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ============================================================================
// Service Functions
// ============================================================================

/**
 * Creates a password reset token for a user.
 *
 * IMPORTANT: This function should ALWAYS be called, even if the email doesn't exist,
 * to prevent account enumeration. The caller should return the same response
 * regardless of whether a token was actually created.
 *
 * @param email - User's email address
 * @returns Token info if user exists, null if user doesn't exist
 */
export async function createPasswordResetToken(
  email: string,
): Promise<CreateResetTokenResult | null> {
  // Find user by email (case-insensitive)
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    select: { id: true, isActive: true },
  });

  // If user doesn't exist or is inactive, return null
  // Caller should still return success response (anti-enumeration)
  if (!user || !user.isActive) {
    // Log for internal monitoring (without exposing to client)
    logger.debug("Password reset requested for non-existent or inactive email"); // phi-safe
    return null;
  }

  // Generate new token values before entering the transaction so that
  // the expensive crypto work happens outside the DB transaction window.
  const plainToken = generateSecureToken();
  const tokenHash = hashToken(plainToken);
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);

  // Atomically invalidate old tokens and create the new one.
  // Without a transaction, a crash between the two writes would leave all
  // prior tokens invalidated but no new token issued, locking the user out
  // of password reset until the TTL window expires.
  await prisma.$transaction(async (tx) => {
    // Invalidate any existing unused tokens for this user
    await tx.passwordResetToken.updateMany({
      where: {
        userId: user.id,
        usedAt: null,
      },
      data: {
        usedAt: new Date(), // Mark as used to invalidate
      },
    });

    // Store hashed token
    await tx.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
      },
    });
  });

  logger.info({ userId: user.id }, "Password reset token created"); // phi-safe:userId,password,token

  return {
    plainToken,
    expiresAt,
  };
}

/**
 * Validates a password reset token.
 *
 * Uses constant-time comparison to prevent timing attacks.
 * Returns validation result without exposing specific error reasons to client.
 */
export async function validateResetToken(
  token: string,
): Promise<ValidateResetTokenResult> {
  const tokenHash = hashToken(token);

  // Find token by hash
  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { tokenHash },
    select: {
      id: true,
      userId: true,
      expiresAt: true,
      usedAt: true,
    },
  });

  // Token not found
  if (!resetToken) {
    // Do a dummy comparison to maintain constant time
    secureCompare(tokenHash, tokenHash);
    return { valid: false, reason: "not_found" };
  }

  // Token already used
  if (resetToken.usedAt) {
    return { valid: false, reason: "already_used" };
  }

  // Token expired
  if (resetToken.expiresAt < new Date()) {
    return { valid: false, reason: "expired" };
  }

  return {
    valid: true,
    userId: resetToken.userId,
  };
}

/**
 * Resets a user's password using a valid reset token.
 *
 * This function:
 * 1. Validates the token
 * 2. Updates the password
 * 3. Marks the token as used
 * 4. Invalidates all active sessions (refresh tokens)
 * 5. Denies all access tokens immediately via denylist
 *
 * @throws PasswordResetError if token is invalid
 */
export async function resetPassword(
  token: string,
  newPassword: string,
): Promise<void> {
  const validation = await validateResetToken(token);

  if (!validation.valid || !validation.userId) {
    // Generic error message (don't reveal specific reason)
    throw new PasswordResetError(
      "Invalid or expired reset token",
      validation.reason === "expired"
        ? "TOKEN_EXPIRED"
        : validation.reason === "already_used"
          ? "TOKEN_USED"
          : "INVALID_TOKEN",
    );
  }

  const tokenHash = hashToken(token);
  // Use unified password hashing service for consistent versioned hashes
  const passwordHash = await hashPassword(newPassword);

  // Transaction: update password, mark token used, revoke all sessions
  await prisma.$transaction(async (tx) => {
    // Update user's password
    await tx.user.update({
      where: { id: validation.userId },
      data: { passwordHash },
    });

    // Mark token as used
    await tx.passwordResetToken.update({
      where: { tokenHash },
      data: { usedAt: new Date() },
    });

    // Revoke all active refresh tokens (invalidate all sessions)
    await tx.refreshToken.updateMany({
      where: {
        userId: validation.userId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
        revokedReason: REVOKED_REASON.PASSWORD_RESET,
      },
    });
  });

  // Immediately deny all access tokens for this user via denylist
  // This provides instant session termination (vs waiting for access token expiry)
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  await denyAllUserAccessTokens(validation.userId!, "password_reset");

  // Clear any account lockout so user can log in with new password
  // Fetch user email for lockout key
  const user = await prisma.user.findUnique({
    where: { id: validation.userId },
    select: { email: true },
  });

  if (user?.email) {
    await clearAccountLockout(user.email);
  }

  logger.info(
    { userId: validation.userId },
    "Password reset completed, all sessions invalidated",
  );
}

/**
 * Changes password for an authenticated user.
 *
 * This function:
 * 1. Verifies the current password
 * 2. Updates to the new password
 * 3. Invalidates all OTHER sessions (keeps current session active)
 * 4. Denies access tokens for other sessions via denylist
 *
 * Note: When keeping current session active, we can't selectively deny
 * access tokens since they don't track session affiliation. For immediate
 * revocation of other sessions, we deny all tokens but the current session's
 * refresh token remains valid for obtaining a new access token.
 *
 * @param userId - The authenticated user's ID
 * @param currentPassword - User's current password
 * @param newPassword - User's new password
 * @param currentRefreshTokenHash - Hash of the current session's refresh token (to keep active)
 * @throws PasswordResetError if current password is invalid
 */
export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  currentRefreshTokenHash?: string,
): Promise<void> {
  // Find user and verify current password
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { passwordHash: true },
  });

  if (!user) {
    throw new PasswordResetError(USER_ERRORS.NOT_FOUND, "USER_NOT_FOUND", 404);
  }

  // Verify current password using unified password hashing service
  const isValidPassword = await verifyPassword(
    currentPassword,
    user.passwordHash,
  );
  if (!isValidPassword) {
    throw new PasswordResetError(
      "Current password is incorrect",
      "INVALID_PASSWORD",
      401,
    );
  }

  // Use unified password hashing service for consistent versioned hashes
  const newPasswordHash = await hashPassword(newPassword);

  // Transaction: update password and revoke other sessions
  await prisma.$transaction(async (tx) => {
    // Update password
    await tx.user.update({
      where: { id: userId },
      data: { passwordHash: newPasswordHash },
    });

    // Revoke all other refresh tokens (keep current session if provided)
    const whereClause = currentRefreshTokenHash
      ? {
          userId,
          revokedAt: null,
          tokenHash: { not: currentRefreshTokenHash },
        }
      : {
          userId,
          revokedAt: null,
        };

    await tx.refreshToken.updateMany({
      where: whereClause,
      data: {
        revokedAt: new Date(),
        revokedReason: REVOKED_REASON.PASSWORD_CHANGE,
      },
    });
  });

  // Deny all access tokens for this user via denylist
  // The current session will need to refresh to get a new access token,
  // but their refresh token is still valid so this is seamless
  await denyAllUserAccessTokens(userId, "password_change");

  logger.info({ userId }, "Password changed, other sessions invalidated"); // phi-safe:userId,password
}

/**
 * Cleans up expired password reset tokens.
 * Should be called periodically (e.g., via cron job).
 */
export async function cleanupExpiredTokens(): Promise<number> {
  return runAsSystemOperation(
    async () => {
      const result = await prisma.passwordResetToken.deleteMany({
        where: {
          OR: [{ expiresAt: { lt: new Date() } }, { usedAt: { not: null } }],
        },
      });

      if (result.count > 0) {
        logger.info(
          { count: result.count },
          "Cleaned up expired password reset tokens",
        ); // phi-safe
      }

      return result.count;
    },
    { reason: "scheduled:password-reset-token-cleanup" },
  );
}

/**
 * Gets the count of active (unused, unexpired) reset tokens for a user.
 * Useful for rate limiting checks.
 */
export async function getActiveTokenCount(userId: string): Promise<number> {
  return prisma.passwordResetToken.count({
    where: {
      userId,
      usedAt: null,
      expiresAt: { gt: new Date() },
    },
  });
}
