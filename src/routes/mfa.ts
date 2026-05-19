/**
 * @ai-context MFA Routes | Multi-Factor Authentication API endpoints
 *
 * Ported from hollis-health-app server/src/routes/mfa.ts (W6f-mfa).
 * Health's WebAuthn routes did NOT exist — see TODO(W6h) below.
 *
 * Routes (all mounted at /v1/auth/mfa in index.ts):
 *   GET  /status                - MFA status for authenticated user
 *   GET  /credentials           - List user's MFA credentials
 *   DELETE /credentials/:credentialId - Remove a credential
 *   POST /totp/setup            - Initiate TOTP enrollment
 *   POST /totp/verify           - Confirm TOTP enrollment
 *   POST /login/verify          - Verify MFA code from mfa_pending session; return full session tokens
 *   POST /session-reverify      - Re-verify MFA when 8h session window expires
 *   POST /step-up               - Step-up auth for sensitive actions
 *   POST /backup-codes          - Regenerate backup codes (requires current TOTP code)
 *
 * TODO(W6h): WebAuthn routes (register/start, register/finish, auth/start, auth/finish)
 *   were not present in Health's codebase at the time of this port. When implemented,
 *   challenge storage should be migrated from the in-memory Map placeholder below to a
 *   dedicated Prisma model (e.g. WebAuthnChallenge) to support multi-instance deployments.
 *
 * deps: express, zod, @hollis-studio/contracts, mfaService, pendingMfaSessionService, authService
 * consumers: index.ts (app.use("/v1/auth/mfa", mfaRouter))
 */

import {
  AUDIENCES,
  backupCodesRequestSchema,
  mfaLoginVerifyRequestSchema,
  mfaSessionReverifyRequestSchema,
  stepUpAuthRequestSchema,
  totpSetupRequestSchema,
  totpVerifyRequestSchema,
  type BackupCodesRequestContract,
  type MfaLoginVerifyRequestContract,
  type MfaSessionReverifyRequestContract,
  type StepUpAuthRequestContract,
  type TotpSetupRequestContract,
  type TotpVerifyRequestContract,
} from "@hollis-studio/contracts";
import { Request, Response, Router } from "express";
import { z } from "zod";
import { verifyJwt } from "../lib/jwtKeys.js";
import { logger } from "../lib/logger.js";
import { prisma } from "../lib/prisma.js";
import { runAsSystemOperation } from "../lib/tenantContext.js";
import { authenticateToken } from "../middleware/auth.js";
import { createStepUpToken } from "../middleware/mfa.js";
import {
  AUTH_TOKEN_TYPE,
  generateMfaVerifiedToken,
} from "../services/authService.js";
import * as mfaService from "../services/mfaService.js";
import { consumePendingMfaSession } from "../services/pendingMfaSessionService.js";
import {
  sendBadRequest,
  sendError,
  sendNotFound,
  sendSuccess,
} from "../utils/response.js";

export const mfaRouter = Router();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Extract request metadata for audit logging.
 */
function getRequestMeta(req: Request): {
  ipAddress?: string;
  userAgent?: string;
} {
  const rawIp = req.ip ?? (req.headers["x-forwarded-for"] as string) ?? "";
  return {
    ipAddress: rawIp.split(",")[0]?.trim() || undefined,
    userAgent: req.headers["user-agent"],
  };
}

/**
 * Inline Zod body parser — replaces Health's `validateBody` middleware.
 * Returns the parsed value on success, or sends a 400 and returns null.
 */
function parseBody<T>(
  schema: z.ZodType<T>,
  body: unknown,
  res: Response,
): T | null {
  const result = schema.safeParse(body);
  if (!result.success) {
    const issues = result.error.issues;
    sendBadRequest(res, issues[0]?.message ?? "Invalid request body");
    return null;
  }
  return result.data;
}

/**
 * Inline Zod params parser — replaces Health's `validateParams` middleware.
 */
function parseParams<T>(
  schema: z.ZodType<T>,
  params: unknown,
  res: Response,
): T | null {
  const result = schema.safeParse(params);
  if (!result.success) {
    sendBadRequest(res, "Invalid path parameter");
    return null;
  }
  return result.data;
}

// Param schema for :credentialId
const credentialIdParamsSchema = z.object({
  credentialId: z.string().uuid("Invalid credential ID format"),
});

// ============================================================================
// MFA STATUS AND CREDENTIALS
// ============================================================================

/**
 * GET /v1/auth/mfa/status
 * Returns { isEnabled, isRequired, isRecommended, credentials, hasBackupCodes, lastVerifiedAt }
 */
mfaRouter.get(
  "/status",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const status = await mfaService.getMfaStatus(req.user.userId);
      return sendSuccess(res, status);
    } catch (err) {
      logger.error({ err }, "[MFA] Failed to get MFA status");
      return sendError(
        res,
        "Failed to get MFA status",
        500,
        undefined,
        "MFA_STATUS_ERROR",
      );
    }
  },
);

/**
 * GET /v1/auth/mfa/credentials
 * Lists all verified MFA credentials for the authenticated user.
 */
mfaRouter.get(
  "/credentials",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const status = await mfaService.getMfaStatus(req.user.userId);
      return sendSuccess(res, { credentials: status.credentials });
    } catch (err) {
      logger.error({ err }, "[MFA] Failed to list credentials");
      return sendError(
        res,
        "Failed to list credentials",
        500,
        undefined,
        "MFA_CREDENTIAL_LIST_ERROR",
      );
    }
  },
);

/**
 * DELETE /v1/auth/mfa/credentials/:credentialId
 * Removes a specific MFA credential owned by the authenticated user.
 */
mfaRouter.delete(
  "/credentials/:credentialId",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const params = parseParams(credentialIdParamsSchema, req.params, res);
      if (!params) return;

      await mfaService.removeCredential(
        req.user.userId,
        params.credentialId,
        getRequestMeta(req),
      );

      // 204 No Content — Identity response.ts does not export sendNoContent yet.
      // Using inline res.status(204).end() per the 2-file hard constraint.
      res.status(204).end();
      return;
    } catch (err) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as { code?: string }).code === "MFA_REQUIRED"
      ) {
        logger.warn({ err }, "[MFA] MFA required to remove credential");
        return sendError(
          res,
          "MFA verification is required for this action",
          400,
          undefined,
          "MFA_REQUIRED",
        );
      }
      if (
        err instanceof Error &&
        "code" in err &&
        (err as { code?: string }).code === "CREDENTIAL_NOT_FOUND"
      ) {
        return sendError(
          res,
          "Credential not found",
          404,
          undefined,
          "CREDENTIAL_NOT_FOUND",
        );
      }
      logger.error({ err }, "[MFA] Failed to remove credential");
      return sendError(
        res,
        "Failed to remove credential",
        500,
        undefined,
        "MFA_CREDENTIAL_REMOVE_ERROR",
      );
    }
  },
);

// ============================================================================
// TOTP SETUP
// ============================================================================

/**
 * POST /v1/auth/mfa/totp/setup
 * Initiates TOTP enrollment. Returns { credentialId, secret, qrCodeUri, backupCodes }.
 */
mfaRouter.post(
  "/totp/setup",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const body = parseBody(totpSetupRequestSchema, req.body, res);
      if (!body) return;

      const { deviceName } = body as TotpSetupRequestContract;
      const result = await mfaService.initiateTotpSetup(
        req.user.userId,
        deviceName ?? "Authenticator App",
      );

      return sendSuccess(res, result);
    } catch (err) {
      logger.error({ err }, "[MFA] Failed to initiate TOTP setup");
      return sendError(
        res,
        "Failed to initiate TOTP setup",
        500,
        undefined,
        "MFA_TOTP_SETUP_ERROR",
      );
    }
  },
);

/**
 * POST /v1/auth/mfa/totp/verify
 * Confirms TOTP enrollment by verifying a live code. Returns the verified credential.
 */
mfaRouter.post(
  "/totp/verify",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const body = parseBody(totpVerifyRequestSchema, req.body, res);
      if (!body) return;

      const { credentialId, code } = body as TotpVerifyRequestContract;
      const result = await mfaService.verifyTotpSetup(
        req.user.userId,
        credentialId,
        code,
      );

      return sendSuccess(res, result);
    } catch (err) {
      if (err instanceof Error && "code" in err) {
        const code = (err as { code?: string }).code;
        if (code === "INVALID_CODE" || code === "INVALID_SETUP") {
          return sendError(res, "Invalid code or setup", 400, undefined, code);
        }
      }
      logger.error({ err }, "[MFA] Failed to verify TOTP setup");
      return sendError(
        res,
        "Failed to verify TOTP setup",
        500,
        undefined,
        "MFA_TOTP_VERIFY_ERROR",
      );
    }
  },
);

// ============================================================================
// MFA LOGIN VERIFICATION
// ============================================================================

/**
 * POST /v1/auth/mfa/login/verify
 * auth-public: accepts a single-use mfa_pending session token (issued by /login when MFA is
 * enabled). Verifies the TOTP/backup code, consumes the pending session, and issues a full
 * authenticated session pair (access + refresh tokens).
 */
mfaRouter.post("/login/verify", async (req: Request, res: Response) => {
  try {
    const body = parseBody(mfaLoginVerifyRequestSchema, req.body, res);
    if (!body) return;

    const { code, credentialId, isBackupCode, sessionToken } =
      body as MfaLoginVerifyRequestContract;

    // --- Validate and decode the mfa_pending session token ---
    let userIdToVerify: string;
    let userRole: string;
    let userOrgId: string | null;
    let jti: string;

    try {
      const decoded = verifyJwt<{
        userId?: string;
        role?: string;
        organizationId?: string | null;
        jti?: string;
        type?: string;
      }>(sessionToken, { audience: [...AUDIENCES] });

      if (
        decoded.type !== AUTH_TOKEN_TYPE.MFA_PENDING ||
        !decoded.userId ||
        !decoded.role ||
        !decoded.jti
      ) {
        logger.warn(
          {
            userId: decoded.userId,
            jti: decoded.jti,
            tokenType: decoded.type,
          },
          "[SECURITY] Invalid token payload for MFA login verification",
        );
        return sendError(
          res,
          "Invalid or expired session token",
          401,
          undefined,
          "INVALID_SESSION_TOKEN",
        );
      }

      userIdToVerify = decoded.userId;
      userRole = decoded.role;
      userOrgId = decoded.organizationId ?? null;
      jti = decoded.jti;
    } catch (err) {
      // phi-safe:token — error object only, no actual token value logged
      logger.warn({ err }, "[MFA] Invalid session token");
      return sendError(
        res,
        "Invalid or expired session token",
        401,
        undefined,
        "INVALID_SESSION_TOKEN",
      );
    }

    // --- Consume the pending MFA session (single-use enforcement) ---
    const sessionResult = await consumePendingMfaSession(
      jti,
      sessionToken,
      userIdToVerify,
    );

    if (!sessionResult.valid) {
      logger.warn(
        { userId: userIdToVerify, jti, reason: sessionResult.reason },
        "[SECURITY] Pending MFA session validation failed",
      );
      return sendError(
        res,
        sessionResult.reason === "Session already used"
          ? "Session token has already been used. Please login again."
          : "Invalid or expired session token",
        401,
        undefined,
        "INVALID_SESSION_TOKEN",
      );
    }

    // --- Verify the MFA code ---
    const result = await mfaService.verifyMfaLogin(
      userIdToVerify,
      code,
      credentialId,
      isBackupCode,
      getRequestMeta(req),
    );

    if (!result.success) {
      return sendBadRequest(res, "MFA verification failed");
    }

    // --- Generate full session tokens with mfaVerifiedAt ---
    const tokenResponse = await generateMfaVerifiedToken(
      userIdToVerify,
      userRole,
      userOrgId,
    );

    // --- Fetch user profile for response ---
    const user = await runAsSystemOperation(
      async () =>
        prisma.user.findUnique({
          where: { id: userIdToVerify },
          select: { id: true, email: true, role: true },
        }),
      { reason: "auth:mfa-verify" },
    );

    if (!user) {
      // phi-safe:userId — surrogate key, not PHI
      logger.error(
        { userId: userIdToVerify },
        "[MFA] User not found after MFA verification",
      );
      return sendNotFound(res, "User");
    }

    return sendSuccess(res, {
      idToken: tokenResponse.idToken,
      refreshToken: tokenResponse.refreshToken,
      expiresIn: tokenResponse.expiresIn,
      expiresAt: tokenResponse.expiresAt,
      user: {
        uid: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    if (err instanceof Error && "code" in err) {
      const mfaErr = err as {
        code?: string;
        attemptsRemaining?: number;
        retryAfterSeconds?: number;
      };
      const code = mfaErr.code;

      if (
        code === "INVALID_CODE" ||
        code === "INVALID_BACKUP_CODE" ||
        code === "MFA_LOCKED"
      ) {
        let details: string | undefined;
        if (
          typeof mfaErr.attemptsRemaining === "number" ||
          typeof mfaErr.retryAfterSeconds === "number"
        ) {
          const parts: string[] = [];
          if (typeof mfaErr.attemptsRemaining === "number") {
            parts.push(`Attempts remaining: ${mfaErr.attemptsRemaining}`);
          }
          if (typeof mfaErr.retryAfterSeconds === "number") {
            parts.push(`Retry after: ${mfaErr.retryAfterSeconds}s`);
          }
          details = parts.join(", ");
        }
        return sendError(res, "MFA verification failed", 400, details, code);
      }
    }
    logger.error({ err }, "[MFA] Failed to verify MFA login");
    return sendError(
      res,
      "Failed to verify MFA",
      500,
      undefined,
      "MFA_VERIFY_ERROR",
    );
  }
});

// ============================================================================
// MFA SESSION RE-VERIFICATION
// ============================================================================

/**
 * POST /v1/auth/mfa/session-reverify
 * Re-verifies MFA for an already-authenticated user whose 8-hour MFA session window expired.
 * Uses the user's existing access token (requireAuth) rather than a mfa_pending token.
 * Returns fresh auth tokens with an updated mfaVerifiedAt timestamp.
 */
mfaRouter.post(
  "/session-reverify",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const body = parseBody(mfaSessionReverifyRequestSchema, req.body, res);
      if (!body) return;

      const { code, credentialId, isBackupCode } =
        body as MfaSessionReverifyRequestContract;

      const result = await mfaService.verifyMfaLogin(
        req.user.userId,
        code,
        credentialId,
        isBackupCode ?? false,
        getRequestMeta(req),
      );

      if (!result.success) {
        return sendBadRequest(res, "MFA verification failed");
      }

      const tokenResponse = await generateMfaVerifiedToken(
        req.user.userId,
        req.user.role,
        req.user.organizationId ?? null,
      );

      logger.info(
        { userId: req.user.userId },
        "[MFA] Session re-verified successfully",
      );

      return sendSuccess(res, {
        success: true,
        idToken: tokenResponse.idToken,
        refreshToken: tokenResponse.refreshToken,
        expiresIn: tokenResponse.expiresIn,
        expiresAt: tokenResponse.expiresAt,
      });
    } catch (err) {
      if (err instanceof Error && "code" in err) {
        const mfaErr = err as {
          code?: string;
          attemptsRemaining?: number;
          retryAfterSeconds?: number;
        };
        const code = mfaErr.code;

        if (code === "INVALID_CODE" || code === "MFA_LOCKED") {
          let details: string | undefined;
          if (
            typeof mfaErr.attemptsRemaining === "number" ||
            typeof mfaErr.retryAfterSeconds === "number"
          ) {
            const parts: string[] = [];
            if (typeof mfaErr.attemptsRemaining === "number") {
              parts.push(`Attempts remaining: ${mfaErr.attemptsRemaining}`);
            }
            if (typeof mfaErr.retryAfterSeconds === "number") {
              parts.push(`Retry after: ${mfaErr.retryAfterSeconds}s`);
            }
            details = parts.join(", ");
          }
          return sendError(res, "MFA verification failed", 400, details, code);
        }
      }
      logger.error({ err }, "[MFA] Failed to re-verify session");
      return sendError(
        res,
        "Failed to re-verify MFA session",
        500,
        undefined,
        "MFA_SESSION_REVERIFY_ERROR",
      );
    }
  },
);

// ============================================================================
// STEP-UP AUTHENTICATION
// ============================================================================

/**
 * POST /v1/auth/mfa/step-up
 * Verifies a current MFA code for the authenticated user and issues a short-lived
 * step-up token (15 min) scoped to the requested sensitive action.
 */
mfaRouter.post(
  "/step-up",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const body = parseBody(stepUpAuthRequestSchema, req.body, res);
      if (!body) return;

      const { action, code, credentialId } = body as StepUpAuthRequestContract;

      // Verify the MFA code
      await mfaService.verifyMfaLogin(
        req.user.userId,
        code,
        credentialId,
        false,
        getRequestMeta(req),
      );

      // Generate step-up token (stored in DB for cross-instance validity)
      const stepUpToken = await createStepUpToken(req.user.userId, action);
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      return sendSuccess(res, {
        success: true,
        stepUpToken,
        expiresAt,
      });
    } catch (err) {
      if (err instanceof Error && "code" in err) {
        const mfaErr = err as {
          code?: string;
          attemptsRemaining?: number;
          retryAfterSeconds?: number;
        };
        const code = mfaErr.code;

        if (code === "INVALID_CODE" || code === "MFA_LOCKED") {
          let details: string | undefined;
          if (
            typeof mfaErr.attemptsRemaining === "number" ||
            typeof mfaErr.retryAfterSeconds === "number"
          ) {
            const parts: string[] = [];
            if (typeof mfaErr.attemptsRemaining === "number") {
              parts.push(`Attempts remaining: ${mfaErr.attemptsRemaining}`);
            }
            if (typeof mfaErr.retryAfterSeconds === "number") {
              parts.push(`Retry after: ${mfaErr.retryAfterSeconds}s`);
            }
            details = parts.join(", ");
          }
          return sendError(res, "MFA verification failed", 400, details, code);
        }
      }
      logger.error({ err }, "[MFA] Failed to perform step-up auth");
      return sendError(
        res,
        "Failed to perform step-up authentication",
        500,
        undefined,
        "MFA_STEPUP_ERROR",
      );
    }
  },
);

// ============================================================================
// BACKUP CODES
// ============================================================================

/**
 * POST /v1/auth/mfa/backup-codes
 * Regenerates backup codes for a TOTP credential. Requires the current TOTP code
 * to prevent a stolen session from silently cycling backup codes.
 */
mfaRouter.post(
  "/backup-codes",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return sendBadRequest(res, "User not authenticated");
      }

      const body = parseBody(backupCodesRequestSchema, req.body, res);
      if (!body) return;

      const { credentialId, code } = body as BackupCodesRequestContract;

      const backupCodes = await mfaService.regenerateBackupCodes(
        req.user.userId,
        credentialId,
        code,
      );

      return sendSuccess(res, { backupCodes });
    } catch (err) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as { code?: string }).code === "CREDENTIAL_NOT_FOUND"
      ) {
        return sendError(
          res,
          "Credential not found",
          404,
          undefined,
          "CREDENTIAL_NOT_FOUND",
        );
      }
      logger.error({ err }, "[MFA] Failed to regenerate backup codes");
      return sendError(
        res,
        "Failed to regenerate backup codes",
        500,
        undefined,
        "MFA_BACKUP_CODES_ERROR",
      );
    }
  },
);

// ============================================================================
// WEBAUTHN — TODO(W6h)
// ============================================================================
//
// The four WebAuthn routes listed in the W6f-mfa spec did NOT exist in
// hollis-health-app at the time of this port:
//   POST /webauthn/register/start
//   POST /webauthn/register/finish
//   POST /webauthn/auth/start
//   POST /webauthn/auth/finish
//
// When implemented, challenge storage will require a Prisma model. Until then,
// an in-memory Map is acceptable for single-instance bootstrapping:
//
//   // TODO(W6h): Replace with Prisma WebAuthnChallenge model for multi-instance safety.
//   const webAuthnChallengeStore = new Map<string, { challenge: string; expiresAt: number }>();
//
// Implementation is blocked on selecting a WebAuthn library (e.g. @simplewebauthn/server)
// and adding WEBAUTHN credential type support to mfaService.
