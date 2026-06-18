/**
 * @ai-context Auth routes | login, register, refresh, logout, verify, jwks, oauth, password-reset, biometric
 *
 * Implements W6f-core (six core routes) + W6f-flows (five auth-flow routes):
 *   - W6f-core:  login, register, logout, refresh, verify, jwks
 *   - W6f-flows: oauth, forgot-password, reset-password, change-password, biometric-token
 *
 * Routes deliberately NOT included here (separate follow-up agents):
 *   - MFA challenge/verify  — W6f-mfa
 *
 * deps: express, zod, jsonwebtoken, authService, prisma
 * consumers: index.ts (mounted at /v1/auth), @hollis-studio/auth-client (/verify)
 */

import { AUDIENCES, type Audience, type MfaLoginPendingResponse } from "@hollis-studio/contracts";
import { passwordSchema } from "@hollis-studio/contracts/password";
import { Router, type Request, type Response } from "express";
import crypto from "crypto";
import { z } from "zod";
import { getPublicJwks, verifyJwt } from "../lib/jwtKeys";
import { logger } from "../lib/logger";
import { hashPassword } from "../lib/passwordHashing";
import { prisma, type UserRole } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";
import { authenticateToken } from "../middleware/auth";
import * as authService from "../services/authService";
import { AuthError } from "../services/authService";
import { sendPasswordResetEmail } from "../services/emailService";
import {
  confirmEmailVerification,
  EmailVerificationError,
  getVerificationEmailCooldown,
  sendVerificationEmail,
} from "../services/emailVerificationService";
import { writeAuditLog, extractIp } from "../services/authAuditService";
import { checkAccountLockout } from "../lib/accountLockout";
import { getMfaStatus } from "../services/mfaService";
import {
  OAUTH_ERROR_CODE,
  OAuthError,
  verifyOAuthCredentials,
} from "../services/oauthVerificationService";
import * as passwordResetService from "../services/passwordResetService";
import { PasswordResetError } from "../services/passwordResetService";
import { createPendingMfaSession } from "../services/pendingMfaSessionService";
import { denyAllUserAccessTokens, isAccessTokenDenied } from "../services/tokenDenylistService";
import {
  sendBadRequest,
  sendConflict,
  sendCreated,
  sendError,
  sendSuccess,
  sendTooManyRequests,
  sendUnauthorized,
} from "../utils/response";

export const authRouter = Router();

// ============================================================================
// Validation schemas
// ============================================================================

const loginBodySchema = z.object({
  email: z.string().email("Valid email required"),
  password: z.string().min(1, "Password is required"),
});

const registerBodySchema = z.object({
  email: z.string().email("Valid email required"),
  password: z.string().min(6, "Password must be at least 6 characters").max(128, "Password must be at most 128 characters"),
  displayName: z.string().trim().min(1).max(128).optional(),
  role: z.enum(["ADMIN", "CLINICIAN", "TRAINER", "CLIENT"] as const).optional(),
  sourceApp: z.string().trim().min(1).max(64).optional(),
});

const verificationSourceBodySchema = z.object({
  sourceApp: z.string().trim().min(1).max(64).optional(),
});

const VERIFY_EMAIL_RESEND_COOLDOWN_MS = 60 * 1000;

const logoutBodySchema = z.object({
  refreshToken: z.string().optional(),
  accessToken: z.string().optional(),
});

const refreshBodySchema = z.object({
  refreshToken: z.string().optional(),
  previousAccessToken: z.string().optional(),
});

const verifyBodySchema = z.object({
  token: z.string().min(1),
  audience: z.enum(AUDIENCES).optional(),
});

// W6f-flows schemas

const oauthBodySchema = z.object({
  provider: z.enum(["apple", "google"] as const),
  idToken: z.string().min(1, "idToken is required"),
  nonce: z.string().optional(),
  csrfState: z.string().optional(),
  authorizationCode: z.string().optional(),
  fullName: z
    .object({
      givenName: z.string().nullable().optional(),
      familyName: z.string().nullable().optional(),
    })
    .optional(),
  accessToken: z.string().optional(),
});

const forgotPasswordBodySchema = z.object({
  email: z.string().email("Valid email required"),
});

const resetPasswordBodySchema = z.object({
  token: z.string().min(20, "Invalid reset token").max(512, "Invalid reset token"),
  newPassword: passwordSchema,
});

const changePasswordBodySchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: passwordSchema,
  currentRefreshToken: z.string().optional(),
});

// ============================================================================
// POST /login
// ============================================================================

authRouter.post("/login", async (req: Request, res: Response) => {
  // auth-public: unauthenticated login endpoint
  const parseResult = loginBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  const { email, password } = parseResult.data;
  const ipAddress = extractIp(req) ?? "unknown";

  try {
    const authenticatedUser = await authService.authenticatePasswordUser(email, password, ipAddress);

    // Check if user has MFA enrolled. If so, return a pending MFA session token
    // rather than a full access token. MFA verification is handled by W6f-mfa routes.
    const mfaStatus = await runAsSystemOperation(
      () => getMfaStatus(authenticatedUser.profile.uid),
      { reason: "auth:mfa-verify", userId: authenticatedUser.profile.uid },
    );

    if (mfaStatus.isEnabled) {
      // Generate MFA-pending session token with tracked JTI (single-use enforcement)
      const { token: sessionToken, jti } = authService.generateAccessTokenWithJti(
        authenticatedUser.profile.uid,
        authenticatedUser.profile.role,
        authenticatedUser.profile.organizationId,
        { tokenType: authService.AUTH_TOKEN_TYPE.MFA_PENDING },
      );

      await createPendingMfaSession(jti, sessionToken, authenticatedUser.profile.uid);

      const mfaResponse: MfaLoginPendingResponse = {
        mfaRequired: true,
        sessionToken,
        availableMethods: mfaStatus.credentials.map((c) => c.type),
        expiresIn: 15 * 60,
        user: {
          userId: authenticatedUser.profile.uid,
          fullName: authenticatedUser.profile.displayName,
          email: authenticatedUser.profile.email,
          role: authenticatedUser.profile.role as UserRole,
        },
      };

      writeAuditLog({
        actorId: authenticatedUser.profile.uid,
        eventType: "LOGIN_SUCCESS",
        success: true,
        ipAddress: extractIp(req),
        userAgent: req.headers["user-agent"],
        metadata: { mfaPending: true },
      });
      res.json({ success: true, data: mfaResponse });
      return;
    }

    const result = await authService.issueAuthenticatedSession(authenticatedUser, "login");

    writeAuditLog({
      actorId: authenticatedUser.profile.uid,
      eventType: "LOGIN_SUCCESS",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });

    res.json({
      success: true,
      data: {
        profile: result.profile,
        idToken: result.idToken,
        refreshToken: result.refreshToken,
        expiresAt: result.expiresAt,
        provider: result.provider,
      },
    });
  } catch (error) {
    req.log?.error({ err: error }, "Login error");

    writeAuditLog({
      eventType: "LOGIN_FAILED",
      success: false,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
      metadata: { reason: error instanceof AuthError ? error.code : "UNKNOWN" },
    });

    if (error instanceof AuthError) {
      if (error.code === "ACCOUNT_LOCKED") {
        // Account is temporarily locked due to too many failed attempts.
        // Re-check for retryAfterSeconds so we can surface it to the client.
        const lockoutStatus = await checkAccountLockout(email);
        sendTooManyRequests(
          res,
          "Account temporarily locked. Please try again later.",
          lockoutStatus.retryAfterSeconds > 0 ? lockoutStatus.retryAfterSeconds : undefined,
        );
      } else if (
        error.code === "ACCOUNT_INACTIVE" ||
        error.code === "INVALID_CREDENTIALS"
      ) {
        // Generic response prevents account enumeration
        sendUnauthorized(res, "Invalid credentials");
      } else {
        sendError(res, "Login failed", error.statusCode, undefined, "LOGIN_ERROR");
      }
      return;
    }

    sendError(res, "Login failed", 500, undefined, "LOGIN_ERROR");
  }
});

// ============================================================================
// POST /register  (greenfield — not ported from Health)
// ============================================================================

authRouter.post("/register", async (req: Request, res: Response) => {
  // auth-public: unauthenticated registration for Workouts / greenfield users.
  // Creates a User with email + passwordHash + role=CLIENT (default). No barcode,
  // no clinicalProfile, no organizationId required.
  const parseResult = registerBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  const { email, password, displayName, role = "CLIENT", sourceApp } = parseResult.data;

  try {
    // Check if email already registered (SECURITY: use generic error to prevent enumeration)
    const existingUser = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (existingUser) {
      // Anti-enumeration: don't reveal whether the email exists
      sendConflict(res, "Registration failed. Please try a different email address.");
      return;
    }

    const passwordHash = await hashPassword(password);
    // crypto.randomUUID() is Node 14.17+ built-in — no extra dependency needed
    const id = crypto.randomUUID();

    const newUser = await prisma.user.create({
      data: {
        id,
        email: email.toLowerCase(),
        passwordHash,
        displayName: displayName ?? null,
        role: role as UserRole,
        isActive: true,
      },
    });

    // Issue session immediately so caller gets tokens without a second round-trip
    const authenticatedUser: authService.AuthenticatedPasswordUser = {
      profile: {
        uid: newUser.id,
        email: newUser.email,
        displayName: newUser.displayName ?? newUser.email.split("@")[0],
        role: newUser.role,
        organizationId: newUser.organizationId,
        isAnonymous: false,
        emailVerified: false,
      },
      provider: "password",
      onboardingCompleted: false,
      mfaEnabled: false,
    };

    const result = await authService.issueAuthenticatedSession(authenticatedUser, "register");

    writeAuditLog({
      actorId: newUser.id,
      eventType: "REGISTER_SUCCESS",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });

    // Send verification email (non-blocking — registration succeeds regardless)
    sendVerificationEmail(newUser.id, newUser.email, sourceApp).catch((err: unknown) => {
      req.log?.warn({ err }, "Failed to send verification email after registration");
    });

    sendCreated(res, {
      profile: result.profile,
      idToken: result.idToken,
      refreshToken: result.refreshToken,
      expiresAt: result.expiresAt,
      provider: result.provider,
      emailVerified: false,
    });
  } catch (error) {
    req.log?.error({ err: error }, "Register error");
    writeAuditLog({
      eventType: "REGISTER_FAILED",
      success: false,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });
    sendError(res, "Registration failed", 500, undefined, "REGISTER_ERROR");
  }
});

// ============================================================================
// POST /logout
// ============================================================================

authRouter.post("/logout", async (req: Request, res: Response) => {
  // auth-public: logout revokes tokens, no access token required
  // Note: pushService.deleteDevicesForUser was removed in W6d — authService.logout
  // only revokes the refresh token in DB. No push service calls here.
  const parseResult = logoutBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  try {
    const { refreshToken, accessToken } = parseResult.data;

    await authService.logout(refreshToken, accessToken);

    writeAuditLog({
      actorId: req.user?.userId,
      eventType: "LOGOUT",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });

    res.json({ success: true, data: { ok: true } });
  } catch (error) {
    req.log?.error({ err: error }, "Logout error");
    // Logout should always succeed from the client's perspective
    sendError(res, "Logout failed", 500, undefined, "LOGOUT_ERROR");
  }
});

// ============================================================================
// POST /refresh
// ============================================================================

authRouter.post("/refresh", async (req: Request, res: Response) => {
  // auth-public: uses refresh token (not access token) to issue a new token pair
  const parseResult = refreshBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  try {
    const refreshToken = parseResult.data.refreshToken;

    if (!refreshToken) {
      sendUnauthorized(res, "No refresh token provided");
      return;
    }

    // MFA carry-forward: read mfaVerifiedAt from the previous access token so
    // clinical/admin users aren't forced to re-complete MFA when a long-lived
    // access token eventually refreshes while the 8h MFA session window is still valid.
    //
    // SECURITY: the previous access token is expired by definition (that's why we're
    // refreshing), so we verify its SIGNATURE while ignoring expiry. Using jwt.decode
    // (no signature check) would let any holder of a valid refresh token forge a
    // {mfaVerifiedAt: now} payload and bypass MFA entirely. We also capture the token's
    // owner so authService.refresh can reject a carry-forward value minted for a
    // different account.
    let previousMfaVerifiedAt: number | undefined;
    let previousAccessTokenUserId: string | undefined;
    if (parseResult.data.previousAccessToken) {
      try {
        const decoded = verifyJwt<{
          userId?: string;
          sub?: string;
          type?: string;
          mfaVerifiedAt?: number;
        }>(parseResult.data.previousAccessToken, { ignoreExpiration: true });
        if (decoded.type === authService.AUTH_TOKEN_TYPE.ACCESS && decoded.mfaVerifiedAt != null) {
          previousMfaVerifiedAt = decoded.mfaVerifiedAt;
          previousAccessTokenUserId = decoded.userId ?? decoded.sub;
        }
      } catch {
        // Invalid signature / not an access token — silently skip MFA carry-forward.
      }
    }

    const result = await authService.refresh(
      refreshToken,
      previousMfaVerifiedAt,
      previousAccessTokenUserId,
    );

    writeAuditLog({
      actorId: result.profile.uid,
      eventType: "TOKEN_REFRESH_SUCCESS",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });

    res.json({
      success: true,
      data: {
        profile: result.profile,
        idToken: result.idToken,
        refreshToken: result.refreshToken,
        expiresAt: result.expiresAt,
        provider: result.provider,
      },
    });
  } catch (error) {
    req.log?.error({ err: error }, "Refresh error");

    writeAuditLog({
      eventType: "TOKEN_REFRESH_FAILED",
      success: false,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
      metadata: { reason: error instanceof AuthError ? error.code : "UNKNOWN" },
    });

  if (error instanceof AuthError) {
      if (error.code === "TOKEN_REVOKED") {
        sendUnauthorized(res, "Session has been revoked - please log in again");
        return;
      }
      sendUnauthorized(res, "Invalid or expired refresh token");
      return;
    }

    sendUnauthorized(res, "Invalid or expired refresh token");
  }
});

// ============================================================================
// GET|POST /verify
// ============================================================================

function getVerifyAudience(rawAudience: string | undefined): Audience | undefined {
  if (!rawAudience) return undefined;
  return AUDIENCES.find((audience) => audience === rawAudience);
}

function verifyIdentityToken(token: string, audience?: Audience): Record<string, unknown> {
  const verifyOptions = audience ? { audience } : undefined;
  return verifyJwt<Record<string, unknown>>(token, verifyOptions);
}

/**
 * SECURITY: a valid signature + unexpired token is NOT sufficient — a token revoked
 * via logout / password reset / admin action must be rejected here too. Consumers
 * (e.g. the Workouts server's auth-client) rely on /verify for revocation when they
 * use the remote verification path. Fail CLOSED on denylist errors.
 */
async function isVerifiedTokenRevoked(claims: Record<string, unknown>): Promise<boolean> {
  const jti = typeof claims.jti === "string" ? claims.jti : undefined;
  const userId = typeof claims.userId === "string" ? claims.userId : undefined;
  const iat = typeof claims.iat === "number" ? claims.iat : undefined;
  if (!jti || !userId || iat == null) return false;
  try {
    return await isAccessTokenDenied(jti, userId, iat);
  } catch (error) {
    logger.error({ err: error, component: "auth/verify" }, "Denylist check failed on /verify — treating token as revoked");
    return true;
  }
}

export async function verifyTokenGetHandler(req: Request, res: Response): Promise<void> {
  // auth-public: verifies a Bearer token and returns AccessTokenClaims as JSON.
  // Used by @hollis-studio/auth-client's remote verify path when offline JWT verification
  // is not suitable (e.g., first request before JWKS is cached).
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    sendUnauthorized(res, "No token provided");
    return;
  }

  const token = authHeader.substring(7);

  try {
    const audience = getVerifyAudience(typeof req.query.audience === "string" ? req.query.audience : undefined);
    const decoded = verifyIdentityToken(token, audience);

    if (await isVerifiedTokenRevoked(decoded)) {
      sendUnauthorized(res, "Token has been revoked");
      return;
    }

    // Return the raw decoded claims — audience validation is the consumer's responsibility
    res.json({ success: true, data: decoded });
  } catch (error) {
    logger.debug({ err: error, component: "auth/verify" }, "Token verification failed");
    sendUnauthorized(res, "Invalid or expired token");
  }
}

export async function verifyTokenPostHandler(req: Request, res: Response): Promise<void> {
  const parseResult = verifyBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  try {
    const decoded = verifyIdentityToken(parseResult.data.token, parseResult.data.audience);

    if (await isVerifiedTokenRevoked(decoded)) {
      sendUnauthorized(res, "Token has been revoked");
      return;
    }

    res.json({ success: true, data: decoded, claims: decoded });
  } catch (error) {
    logger.debug({ err: error, component: "auth/verify" }, "Token verification failed");
    sendUnauthorized(res, "Invalid or expired token");
  }
}

authRouter.get("/verify", verifyTokenGetHandler);
authRouter.post("/verify", verifyTokenPostHandler);

// ============================================================================
// GET /me
// ============================================================================

authRouter.get("/me", authenticateToken, async (req: Request, res: Response) => {
  const userId = req.user?.userId;
  if (!userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        organizationId: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        emailVerified: true,
      },
    });

    if (!user || !user.isActive) {
      sendUnauthorized(res, "Account not active");
      return;
    }

    // Cross-device onboarding-reset epoch. Read defensively so a profile load can
    // never fail on it: if the UserOnboardingReset table is not yet migrated (or
    // any read error occurs) we degrade to null ("no reset pending"), which is the
    // pre-feature behavior. Clients compare this against their locally-consumed
    // epoch to decide whether to re-run onboarding once.
    const onboardingResetAt = await readOnboardingResetAt(userId);

    sendSuccess(res, {
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId,
      emailVerified: user.emailVerified != null,
      onboardingResetAt,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
    });
  } catch (error) {
    req.log?.error({ err: error }, "Failed to load identity profile");
    sendError(res, "Failed to load identity profile", 500, undefined, "PROFILE_LOAD_ERROR");
  }
});

/**
 * Reads the user's cross-device onboarding-reset epoch as an ISO string, or null
 * when no reset is pending. Wrapped so a missing/unmigrated table or any read
 * error degrades to null rather than failing the caller (deploy-safe: the new
 * server image can ship before the UserOnboardingReset migration is applied).
 */
async function readOnboardingResetAt(userId: string): Promise<string | null> {
  try {
    const row = await prisma.userOnboardingReset.findUnique({
      where: { userId },
      select: { resetAt: true },
    });
    return row ? row.resetAt.toISOString() : null;
  } catch (error) {
    logger.debug(
      { err: error, component: "auth/onboarding-reset" },
      "Onboarding-reset read failed (treating as no reset pending)",
    );
    return null;
  }
}

// ============================================================================
// POST /onboarding/reset  — cross-device "Reset Onboarding"
// Authenticated. Bumps the user's reset epoch to now so every other device
// (and a reinstalled one) re-runs onboarding once on its next /me restore.
// auth-protected: requires valid access token
// ============================================================================

authRouter.post("/onboarding/reset", authenticateToken, async (req: Request, res: Response) => {
  const userId = req.user?.userId;
  if (!userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  try {
    const resetAt = new Date();
    await prisma.userOnboardingReset.upsert({
      where: { userId },
      update: { resetAt },
      create: { userId, resetAt },
    });

    res.json({ success: true, data: { onboardingResetAt: resetAt.toISOString() } });
  } catch (error) {
    req.log?.error({ err: error }, "Failed to record onboarding reset");
    sendError(res, "Failed to record onboarding reset", 500, undefined, "ONBOARDING_RESET_ERROR");
  }
});

// ============================================================================
// DELETE /account  — GDPR account erasure
// Authenticated. Permanently deletes the Identity user record and all auth-layer
// data (refresh tokens, MFA credentials/events, OAuth links, reset/verification
// tokens). After this the email / social identity is free to register anew.
// Workouts-domain data is erased separately by the Workouts server (the client
// calls DELETE /v1/users/me before this). Idempotent: a second call for an
// already-deleted account still returns success.
// auth-protected: requires valid access token
// ============================================================================

authRouter.delete("/account", authenticateToken, async (req: Request, res: Response) => {
  const userId = req.user?.userId;
  if (!userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  try {
    // Deny the user's outstanding access tokens immediately so a leaked token
    // cannot keep acting on behalf of the now-deleted account. Refresh tokens are
    // removed by the cascade below, so the session can no longer be renewed.
    await denyAllUserAccessTokens(userId, "account_deactivated").catch((error: unknown) => {
      req.log?.warn({ err: error }, "Failed to deny tokens during account deletion (proceeding)");
    });

    await runAsSystemOperation(
      async () => {
        // MfaEvent has onDelete: Restrict, so it must be removed before the user.
        // Every other relation is onDelete: Cascade (or SetNull for AuthAuditLog).
        await prisma.$transaction([
          prisma.mfaEvent.deleteMany({ where: { userId } }),
          prisma.user.delete({ where: { id: userId } }),
        ]);
      },
      { reason: "auth:delete-account", userId },
    );

    writeAuditLog({
      // actorId intentionally omitted: the user row is gone, and AuthAuditLog
      // sets actorId to null on delete anyway. The event is still recorded.
      eventType: "LOGOUT",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
      metadata: { action: "ACCOUNT_DELETED" },
    });

    logger.info({ component: "auth/delete-account" }, "Identity account deleted");
    res.json({ success: true, data: { ok: true } });
  } catch (error) {
    // Prisma P2025 = record not found: the account is already gone. Treat delete
    // as idempotent and report success so the client's local wipe still proceeds.
    const prismaError = error as { code?: string };
    if (prismaError.code === "P2025") {
      res.json({ success: true, data: { ok: true } });
      return;
    }
    req.log?.error({ err: error }, "Account deletion failed");
    sendError(res, "Account deletion failed", 500, undefined, "ACCOUNT_DELETE_ERROR");
  }
});

// ============================================================================
// POST /oauth  — W6f-flows
// Apple/Google OAuth sign-in. Verifies id_token, finds linked account, issues session.
// If no OAuthAccount link exists, returns 404 OAUTH_NO_LINKED_ACCOUNT so the consumer
// app can invoke its own registration flow.
// auth-public: pre-authentication; no access token exists yet
// ============================================================================

authRouter.post("/oauth", async (req: Request, res: Response) => {
  const parseResult = oauthBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  const { provider, idToken, nonce, csrfState, authorizationCode, fullName, accessToken } =
    parseResult.data;
  try {
    const session = await verifyOAuthCredentials({
      provider,
      idToken,
      nonce: nonce ?? "",
      state: csrfState ?? "",
      authorizationCode,
      fullName,
      accessToken,
    });

    res.json({ success: true, data: session, isNewUser: session.isNewUser });
  } catch (error) {
    req.log?.error({ err: error, provider }, "OAuth sign-in error");

    if (error instanceof OAuthError) {
      switch (error.code) {
        case OAUTH_ERROR_CODE.PROVIDER_NOT_CONFIGURED:
          sendError(res, "OAuth sign-in is not configured on this server", 503, undefined, "OAUTH_NOT_CONFIGURED");
          return;

        case OAUTH_ERROR_CODE.NONCE_MISMATCH:
        case OAUTH_ERROR_CODE.VERIFICATION_FAILED:
        case OAUTH_ERROR_CODE.INVALID_ISSUER:
        case OAUTH_ERROR_CODE.AUDIENCE_MISMATCH:
        case OAUTH_ERROR_CODE.TOKEN_EXPIRED:
        case OAUTH_ERROR_CODE.TOKEN_DECODE_FAILED:
        case OAUTH_ERROR_CODE.EMAIL_NOT_VERIFIED:
          req.log?.warn({ provider, code: error.code }, "OAuth id_token verification rejected");
          sendBadRequest(res, "Invalid or expired authentication credential");
          return;

        case OAUTH_ERROR_CODE.ACCOUNT_INACTIVE:
          sendUnauthorized(res, "Account is inactive");
          return;

        case OAUTH_ERROR_CODE.ACCOUNT_LINK_UNVERIFIED:
          sendConflict(res, error.message);
          return;

        case OAUTH_ERROR_CODE.NO_ACCOUNT_FOUND:
          // Identity Service does NOT auto-register on OAuth — consumer app must invoke
          // its own registration flow when it receives this error code.
          sendError(
            res,
            "No account linked to this social sign-in. Please register or sign in with email and password first.",
            404,
            undefined,
            "OAUTH_NO_LINKED_ACCOUNT",
          );
          return;

        default:
          sendError(res, "OAuth sign-in failed", 500, undefined, "OAUTH_ERROR");
          return;
      }
    }

    sendError(res, "OAuth sign-in failed", 500, undefined, "OAUTH_ERROR");
  }
});

// ============================================================================
// POST /forgot-password  — W6f-flows
// Initiates password reset. Anti-enumeration: always returns 200 { ok: true }.
// Internally: looks up user, creates reset token, stubs email event.
// auth-public: unauthenticated; requestor does not have an access token
// ============================================================================

authRouter.post("/forgot-password", async (req: Request, res: Response) => {
  const parseResult = forgotPasswordBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    // Still return 200 to prevent enumeration — any 400 here leaks schema info.
    // Return early with ok:true to match anti-enumeration contract.
    res.json({ success: true, data: { ok: true } });
    return;
  }

  const { email } = parseResult.data;

  // SECURITY: Run as system operation — email lookup is cross-tenant (requestor is unauthenticated).
  await runAsSystemOperation(
    async () => {
      try {
        const result = await passwordResetService.createPasswordResetToken(email);

        if (result) {
          await sendPasswordResetEmail({
            email,
            token: result.plainToken,
            expiresAt: result.expiresAt,
          });
          writeAuditLog({
            eventType: "PASSWORD_RESET_REQUESTED",
            success: true,
            ipAddress: extractIp(req),
            userAgent: req.headers["user-agent"],
          });
        }
      } catch (error) {
        // Log internally but swallow — anti-enumeration requires consistent 200 response.
        req.log?.error({ err: error }, "Forgot password internal error (swallowed)");
      }
    },
    { reason: "auth:forgot-password" },
  );

  // Always return success regardless of whether the email exists (anti-enumeration).
  res.json({ success: true, data: { ok: true } });
});

// ============================================================================
// POST /reset-password  — W6f-flows
// Consumes a one-time reset token and sets a new password.
// Revokes all refresh tokens (forces re-login on all devices).
// auth-public: unauthenticated; requestor uses a reset token instead of a session
// ============================================================================

authRouter.post("/reset-password", async (req: Request, res: Response) => {
  const parseResult = resetPasswordBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  const { token, newPassword } = parseResult.data;

  // SECURITY: System operation — token lookup is cross-tenant; userId unknown until token resolves.
  await runAsSystemOperation(
    async () => {
      try {
        // resetPassword validates the token, rehashes the password, revokes all refresh tokens,
        // and denies all active access tokens via the denylist — see passwordResetService.
        await passwordResetService.resetPassword(token, newPassword);

        writeAuditLog({
          eventType: "PASSWORD_RESET_COMPLETED",
          success: true,
          ipAddress: extractIp(req),
          userAgent: req.headers["user-agent"],
        });

        res.json({ success: true, data: { ok: true } });
      } catch (error) {
        req.log?.error({ err: error }, "Reset password error");

        if (error instanceof PasswordResetError) {
          if (error.code === "TOKEN_EXPIRED") {
            sendBadRequest(res, "Reset token has expired. Please request a new password reset.");
          } else if (error.code === "TOKEN_USED") {
            sendBadRequest(res, "Reset token has already been used. Please request a new password reset.");
          } else {
            sendBadRequest(res, "Invalid or expired reset token");
          }
          return;
        }

        sendError(res, "Password reset failed", 500, undefined, "PASSWORD_RESET_ERROR");
      }
    },
    { reason: "auth:reset-password" },
  );
});

// ============================================================================
// POST /change-password  — W6f-flows
// Authenticated password change. Revokes OTHER sessions; keeps current session active.
// auth-protected: requires valid access token
// ============================================================================

authRouter.post("/change-password", authenticateToken, async (req: Request, res: Response) => {
  const parseResult = changePasswordBodySchema.safeParse(req.body);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  const { currentPassword, newPassword, currentRefreshToken } = parseResult.data;
  const userId = req.user?.userId;

  if (!userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  // SECURITY: System operation — session invalidation writes are cross-tenant.
  await runAsSystemOperation(
    async () => {
      try {
        // Derive current refresh token hash so changePassword can keep the current session.
        const currentRefreshTokenHash = currentRefreshToken
          ? crypto.createHash("sha256").update(currentRefreshToken).digest("hex")
          : undefined;

        // changePassword verifies currentPassword, rehashes newPassword, revokes other sessions,
        // and denies access tokens — see passwordResetService.changePassword.
        await passwordResetService.changePassword(
          userId,
          currentPassword,
          newPassword,
          currentRefreshTokenHash,
        );

        res.json({ success: true, data: { ok: true } });
      } catch (error) {
        req.log?.error({ err: error }, "Change password error");

        if (error instanceof PasswordResetError) {
          if (error.code === "INVALID_PASSWORD") {
            sendUnauthorized(res, "Current password is incorrect");
          } else if (error.code === "USER_NOT_FOUND") {
            sendUnauthorized(res, "User not found");
          } else {
            sendError(res, "Password change failed", 400, undefined, "PASSWORD_CHANGE_ERROR");
          }
          return;
        }

        sendError(res, "Password change failed", 500, undefined, "PASSWORD_CHANGE_ERROR");
      }
    },
    { reason: "auth:change-password", userId },
  );
});

// ============================================================================
// POST /biometric-token  — W6f-flows
// Authenticated. Issues a long-TTL refresh token for mobile SecureStore biometric login.
// auth-protected: requires valid access token
// ============================================================================

authRouter.post("/biometric-token", authenticateToken, async (req: Request, res: Response) => {
  const userId = req.user?.userId;

  if (!userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  try {
    // Re-fetch user for freshness (mirrors Health pattern).
    const user = await runAsSystemOperation(
      async () =>
        prisma.user.findUnique({
          where: { id: userId },
          select: { isActive: true, role: true, organizationId: true },
        }),
      { reason: "auth:biometric-token", userId },
    );

    if (!user || !user.isActive) {
      sendUnauthorized(res, "Account not active");
      return;
    }

    const { refreshToken } = await authService.generateBiometricRefreshToken(
      userId,
      user.role,
      user.organizationId,
    );

    // expiresAt mirrors REFRESH_TOKEN_EXPIRY_MS.
    const expiresAt = new Date(Date.now() + authService.REFRESH_TOKEN_EXPIRY_MS).toISOString();

    res.json({ success: true, data: { refreshToken, expiresAt } });
  } catch (error) {
    req.log?.error({ err: error }, "Failed to generate biometric token");
    sendError(res, "Failed to generate biometric token", 500, undefined, "BIOMETRIC_TOKEN_ERROR");
  }
});

// ============================================================================
// POST /verify-email/send  — W6f-verify
// Sends or resends a verification email for the authenticated user.
// auth-protected: requires valid access token
// ============================================================================

authRouter.post("/verify-email/send", authenticateToken, async (req: Request, res: Response) => {
  const parseResult = verificationSourceBodySchema.safeParse(req.body ?? {});
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Invalid request body");
    return;
  }

  const userId = req.user?.userId;
  if (!userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  try {
    const user = await runAsSystemOperation(
      () =>
        prisma.user.findUnique({
          where: { id: userId },
          select: { email: true, emailVerified: true, isActive: true },
        }),
      { reason: "auth:verify-email-send", userId },
    );

    if (!user || !user.isActive) {
      sendUnauthorized(res, "Account not active");
      return;
    }

    if (user.emailVerified) {
      res.json({ success: true, data: { ok: true, alreadyVerified: true } });
      return;
    }

    const cooldown = await getVerificationEmailCooldown(
      userId,
      VERIFY_EMAIL_RESEND_COOLDOWN_MS,
    );
    if (cooldown) {
      sendTooManyRequests(
        res,
        "Verification email recently sent. Please wait before requesting another link.",
        cooldown.retryAfterSeconds,
      );
      return;
    }

    await sendVerificationEmail(userId, user.email, parseResult.data.sourceApp);

    writeAuditLog({
      actorId: userId,
      eventType: "EMAIL_VERIFICATION_SENT",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });

    res.json({ success: true, data: { ok: true } });
  } catch (error) {
    req.log?.error({ err: error }, "Failed to send verification email");
    sendError(res, "Failed to send verification email", 500, undefined, "EMAIL_VERIFY_SEND_ERROR");
  }
});

// ============================================================================
// GET /verify-email/confirm?token=...  — W6f-verify
// Consumes a single-use verification token and marks emailVerified.
// auth-public: token carries its own authority; no session required
// ============================================================================

const confirmQuerySchema = z.object({
  token: z.string().min(1, "token query param is required"),
});

authRouter.get("/verify-email/confirm", async (req: Request, res: Response) => {
  const parseResult = confirmQuerySchema.safeParse(req.query);
  if (!parseResult.success) {
    sendBadRequest(res, parseResult.error.issues[0]?.message ?? "Missing token");
    return;
  }

  try {
    await runAsSystemOperation(
      () => confirmEmailVerification(parseResult.data.token),
      { reason: "auth:verify-email-confirm" },
    );

    writeAuditLog({
      eventType: "EMAIL_VERIFICATION_COMPLETED",
      success: true,
      ipAddress: extractIp(req),
      userAgent: req.headers["user-agent"],
    });

    res.json({ success: true, data: { ok: true } });
  } catch (error) {
    req.log?.error({ err: error }, "Email verification confirm error");

    if (error instanceof EmailVerificationError) {
      if (error.code === "TOKEN_EXPIRED") {
        sendBadRequest(res, "Verification link has expired. Please request a new one.");
        return;
      }
      if (error.code === "TOKEN_USED") {
        sendBadRequest(res, "Verification link has already been used.");
        return;
      }
      sendBadRequest(res, "Invalid or expired verification link.");
      return;
    }

    sendError(res, "Email verification failed", 500, undefined, "EMAIL_VERIFY_ERROR");
  }
});

// ============================================================================
// GET /.well-known/jwks.json
// NOTE: This route is registered at the app root level in index.ts, NOT under
// /v1/auth. It is defined here as an exported handler for clean wiring in index.ts.
// ============================================================================

export function jwksHandler(_req: Request, res: Response): void {
  try {
    res.json(getPublicJwks());
  } catch (error) {
    logger.error({ err: error, component: "auth/jwks" }, "JWKS export failed");
    sendError(res, "JWKS unavailable", 500, undefined, "JWKS_UNAVAILABLE");
  }
}
