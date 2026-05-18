/**
 * @ai-context MFA Middleware | Multi-Factor Authentication middleware for Express
 *
 * Provides:
 * - MFA verification check on login (for users who opted in)
 * - Step-up authentication for sensitive actions
 * - Advisory MFA recommendation headers for PHI routes
 *
 * SECURITY:
 * - MFA is recommended (not enforced) for ADMIN and CLINICIAN roles
 * - Step-up auth required for high-risk actions
 * - Step-up tokens are stored in database for horizontal scaling
 * - All MFA events are logged for audit
 *
 * deps: express, mfaService, @contracts, prisma | consumers: routes/*
 */
import type { StepUpAuthAction } from "@hollis-studio/contracts";
import {
    MFA_SESSION_WINDOW_MS,
    STEP_UP_AUTH_ACTIONS,
    STEP_UP_AUTH_WINDOW_MS,
} from "@hollis-studio/contracts";
import crypto from "crypto";
import type { NextFunction, Request, Response } from "express";
import { AppError } from "../lib/AppError";
import { logger } from "../lib/logger";
import { prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";
import { hasMfaEnabled } from "../services/mfaService";
import { sendError, sendForbidden, sendUnauthorized } from "../utils/response";

// ============================================================================
// STEP-UP TOKEN MANAGEMENT
// ============================================================================

/**
 * Hash a step-up token for storage (we never store plaintext)
 */
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/**
 * Create a step-up token for a specific action.
 * Token is stored hashed in the database for persistence across instances.
 */
export async function createStepUpToken(
  userId: string,
  action: StepUpAuthAction,
): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + STEP_UP_AUTH_WINDOW_MS);

  await runAsSystemOperation(
    async () => {
      await prisma.stepUpToken.create({
        data: {
          tokenHash,
          userId,
          action,
          expiresAt,
        },
      });
    },
    { reason: "auth:mfa-verify" },
  );

  return token;
}

/**
 * Validate and consume a step-up token.
 * Returns true if token is valid, false otherwise.
 * Token is marked as used (single-use enforcement).
 */
export async function validateStepUpToken(
  token: string,
  userId: string,
  action: StepUpAuthAction,
): Promise<boolean> {
  const tokenHash = hashToken(token);

  return runAsSystemOperation(
    async () => {
      const storedToken = await prisma.stepUpToken.findUnique({
        where: { tokenHash },
      });

      if (!storedToken) {
        return false;
      }

      // Check expiration
      if (storedToken.expiresAt < new Date()) {
        // Clean up expired token
        await prisma.stepUpToken.delete({ where: { id: storedToken.id } });
        return false;
      }

      // Check user and action match
      if (storedToken.userId !== userId || storedToken.action !== action) {
        return false;
      }

      // Check if already used (single-use enforcement)
      if (storedToken.usedAt) {
        logger.warn(
          { userId, action, tokenId: storedToken.id },
          "[SECURITY] Attempted reuse of step-up token",
        );
        return false;
      }

      // Mark as used (consume the token) with atomic compare-and-set guard
      const consumeResult = await prisma.stepUpToken.updateMany({
        where: {
          id: storedToken.id,
          userId,
          action,
          usedAt: null,
        },
        data: { usedAt: new Date() },
      });

      if (consumeResult.count !== 1) {
        logger.warn(
          { userId, action, tokenId: storedToken.id },
          "[SECURITY] Step-up token consume race/reuse detected",
        );
        return false;
      }

      return true;
    },
    { reason: "auth:mfa-verify" },
  );
}

/**
 * Clean up expired step-up tokens.
 * Call this periodically (e.g., from a cron job) to prevent table bloat.
 */
export async function cleanupExpiredStepUpTokens(): Promise<number> {
  return runAsSystemOperation(
    async () => {
      const result = await prisma.stepUpToken.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            // Also clean up used tokens older than 1 hour
            {
              AND: [
                { usedAt: { not: null } },
                { usedAt: { lt: new Date(Date.now() - 60 * 60 * 1000) } },
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

// ============================================================================
// MFA REQUIREMENT MIDDLEWARE
// ============================================================================

/**
 * Middleware factory that enforces MFA verification for users who have opted in.
 *
 * Behavior:
 * - User has NO verified MfaCredential (mfaEnabled=false in JWT) → pass through.
 *   MFA is optional; non-enrolled users are never blocked.
 * - User HAS a verified MfaCredential (mfaEnabled=true in JWT):
 *   - mfaVerifiedAt present and fresh (within MFA_SESSION_WINDOW_MS) → pass through.
 *   - mfaVerifiedAt absent or expired → 401 Unauthorized.
 *
 * mfaEnabled is embedded in the JWT at mint time (login / refresh) so this
 * middleware never needs a DB lookup.
 *
 * @example
 * router.use(authenticateToken, requireMfaEnabled(), sensitiveRouter);
 */
export const requireMfaEnabled = () => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    if (!req.user) {
      sendUnauthorized(res, "Authentication required");
      return;
    }

    const { mfaEnabled, mfaVerifiedAt } = req.user;

    // User has not enrolled in MFA — pass through unconditionally.
    if (!mfaEnabled) {
      next();
      return;
    }

    // User is enrolled — enforce that they have verified MFA in this session.
    if (!mfaVerifiedAt) {
      logger.warn(
        {
          userIdSurrogate: req.user.userId.slice(0, 8),
          path: req.path,
        },
        "[MFA] Access denied — user has MFA enabled but no mfaVerifiedAt in token",
      );
      sendError(res, "MFA verification required", 401, undefined, "MFA_REQUIRED");
      return;
    }

    const mfaAge = Date.now() - mfaVerifiedAt;
    if (mfaAge > MFA_SESSION_WINDOW_MS) {
      logger.warn(
        {
          userIdSurrogate: req.user.userId.slice(0, 8),
          mfaAgeMs: mfaAge,
          path: req.path,
        },
        "[MFA] Access denied — MFA verification has expired",
      );
      sendError(res, "MFA session expired. Please re-verify.", 401, undefined, "MFA_SESSION_EXPIRED");
      return;
    }

    next();
  };
};

/**
 * Direct middleware form of requireMfaEnabled() for routes that use it inline.
 *
 * @example
 * app.use('/phi', authenticateToken, requireMFA, phiRouter);
 */
export const requireMFA = requireMfaEnabled();

// ============================================================================
// STEP-UP AUTH MIDDLEWARE
// ============================================================================

/**
 * Middleware factory for step-up authentication on sensitive actions.
 *
 * Checks for a valid step-up token in the request header. If not present
 * or invalid, returns 403 with instructions to perform step-up auth.
 *
 * @param action - The sensitive action requiring step-up auth
 *
 * @example
 * // Protect a sensitive route
 * router.post('/users/:id/delete',
 *   authenticateToken,
 *   requireStepUpAuth('DELETE_ACCOUNT'),
 *   deleteUserHandler
 * );
 */
export const requireStepUpAuth = (action: StepUpAuthAction) => {
  // Validate action at middleware creation time
  if (!STEP_UP_AUTH_ACTIONS.includes(action)) {
    throw AppError.badRequest(`Invalid step-up auth action: ${action}`);
  }

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    if (!req.user) {
      sendUnauthorized(res, "Authentication required");
      return;
    }

    // Check for step-up token in header
    const stepUpToken = req.headers["x-step-up-token"] as string | undefined;

    if (!stepUpToken) {
      sendForbidden(
        res,
        "This action requires additional authentication. Please verify your identity.",
        "STEP_UP_REQUIRED",
      );
      return;
    }

    // Validate the step-up token (async - checks database)
    const isValid = await validateStepUpToken(
      stepUpToken,
      req.user.userId,
      action,
    );

    if (!isValid) {
      logger.warn(
        {
          userIdSurrogate: req.user.userId.slice(0, 8),
          action,
          path: req.path,
        },
        "[MFA] Invalid or expired step-up token",
      );
      sendForbidden(
        res,
        "Your verification has expired. Please verify your identity again.",
        "STEP_UP_INVALID",
      );
      return;
    }

    logger.info(
      {
        userIdSurrogate: req.user.userId.slice(0, 8),
        action,
        path: req.path,
      },
      "[MFA] Step-up authentication verified",
    );

    next();
  };
};

/**
 * Middleware for checking MFA during login flow.
 *
 * This is used after password verification to check if the user has
 * opted into MFA and needs to provide a code before getting full access tokens.
 *
 * Only triggers for users who have voluntarily enabled MFA.
 */
export const checkMfaOnLogin = () => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    // This middleware expects the user info to be attached by the login handler
    const loginUser = (
      req as Request & {
        loginUser?: { userId: string; role: string; mfaEnabled?: boolean };
      }
    ).loginUser;

    if (!loginUser) {
      // No login user means this middleware shouldn't be here
      next();
      return;
    }

    // Check if user has MFA enabled (opted in voluntarily)
    // MFA is no longer role-required but still verified for users who enabled it
    const mfaEnabled =
      loginUser.mfaEnabled ?? (await hasMfaEnabled(loginUser.userId));

    if (!mfaEnabled) {
      // MFA not set up — proceed without requiring it
      next();
      return;
    }

    // MFA is enabled - require verification
    (
      req as Request & { mfaVerificationRequired: boolean }
    ).mfaVerificationRequired = true;
    next();
  };
};
