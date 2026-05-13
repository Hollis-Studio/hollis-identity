/**
 * @ai-context Pending MFA Session Service | Single-use session tokens for MFA login flow
 *
 * Tracks session tokens issued after password verification but before MFA completion.
 * Implements single-use enforcement to prevent replay attacks.
 *
 * SECURITY:
 * - Session tokens are stored hashed (never plaintext)
 * - Tokens are single-use (consumedAt marks usage)
 * - Tokens expire after 15 minutes
 * - Token reuse is logged as a security event
 *
 * deps: prisma, crypto | consumers: routes/auth.ts, routes/mfa.ts
 */

import crypto from "crypto";
import { logger } from "../lib/logger";
import { prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";

// ============================================================================
// CONSTANTS
// ============================================================================

/** Session token expiry in milliseconds (15 minutes) */
const SESSION_TOKEN_EXPIRY_MS = 15 * 60 * 1000;

// ============================================================================
// HELPERS
// ============================================================================

/**
 * Hash a token for storage (we never store plaintext)
 */
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// ============================================================================
// SERVICE FUNCTIONS
// ============================================================================

/**
 * Create a pending MFA session after password verification.
 * Called when a user with MFA enabled logs in and needs to complete MFA.
 *
 * @param jti - The JWT ID (jti) from the session token
 * @param token - The full session token (will be hashed before storage)
 * @param userId - The user ID this session belongs to
 */
export async function createPendingMfaSession(
  jti: string,
  token: string,
  userId: string,
): Promise<void> {
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TOKEN_EXPIRY_MS);

  await runAsSystemOperation(
    async () => {
      await prisma.pendingMfaSession.create({
        data: {
          tokenHash,
          jti,
          userId,
          expiresAt,
        },
      });
    },
    { reason: "auth:mfa-management" },
  );
}

/**
 * Validate and consume a pending MFA session.
 * Returns true if the session is valid and was successfully consumed.
 * Returns false if the session doesn't exist, is expired, or was already used.
 *
 * @param jti - The JWT ID from the session token
 * @param token - The full session token
 * @param userId - The user ID attempting to verify
 * @returns Object with valid status and reason if invalid
 */
export async function consumePendingMfaSession(
  jti: string,
  token: string,
  userId: string,
): Promise<{ valid: boolean; reason?: string }> {
  const tokenHash = hashToken(token);

  return runAsSystemOperation(
    async () => {
      // Find the session by JTI (faster than hash lookup)
      const session = await prisma.pendingMfaSession.findUnique({
        where: { jti },
      });

      if (!session) {
        logger.warn(
          { userId, jti },
          "[SECURITY] Pending MFA session not found",
        );
        return { valid: false, reason: "Session not found" };
      }

      // Verify the token hash matches
      if (session.tokenHash !== tokenHash) {
        logger.warn(
          { userId, jti },
          "[SECURITY] Pending MFA session token hash mismatch",
        );
        return { valid: false, reason: "Invalid token" };
      }

      // Verify the user matches
      if (session.userId !== userId) {
        logger.warn(
          { userId, sessionUserId: session.userId, jti },
          "[SECURITY] Pending MFA session user mismatch",
        );
        return { valid: false, reason: "User mismatch" };
      }

      // Check expiration
      if (session.expiresAt < new Date()) {
        logger.warn(
          { userIdSurrogate: userId, jti },
          "[SECURITY] Pending MFA session expired",
        );
        // Clean up expired session
        await prisma.pendingMfaSession.delete({ where: { id: session.id } });
        return { valid: false, reason: "Session expired" };
      }

      // Check if already consumed (single-use enforcement)
      if (session.consumedAt) {
        logger.error(
          { userId, jti, consumedAt: session.consumedAt },
          "[SECURITY] PENDING MFA SESSION REUSE DETECTED - possible token theft",
        );
        // Don't delete - keep for forensics
        return { valid: false, reason: "Session already used" };
      }

      // Mark as consumed (single-use) using compare-and-set guard
      const consumeResult = await prisma.pendingMfaSession.updateMany({
        where: {
          id: session.id,
          tokenHash,
          userId,
          consumedAt: null,
        },
        data: { consumedAt: new Date() },
      });

      if (consumeResult.count !== 1) {
        logger.error(
          { userId, jti },
          "[SECURITY] Pending MFA session consume race/reuse detected",
        );
        return { valid: false, reason: "Session already used" };
      }

      return { valid: true };
    },
    { reason: "auth:mfa-verify" },
  );
}

/**
 * Clean up expired pending MFA sessions.
 * Call this periodically (e.g., from a cron job) to prevent table bloat.
 *
 * @returns Number of sessions deleted
 */
export async function cleanupExpiredPendingMfaSessions(): Promise<number> {
  return runAsSystemOperation(
    async () => {
      const result = await prisma.pendingMfaSession.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            // Also clean up consumed sessions older than 1 hour
            {
              AND: [
                { consumedAt: { not: null } },
                { consumedAt: { lt: new Date(Date.now() - 60 * 60 * 1000) } },
              ],
            },
          ],
        },
      });
      return result.count;
    },
    { reason: "auth:mfa-session-cleanup" },
  );
}
