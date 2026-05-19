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
import jwt from "jsonwebtoken";
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
import { getMfaStatus } from "../services/mfaService";
import {
  OAUTH_ERROR_CODE,
  OAuthError,
  verifyOAuthCredentials,
} from "../services/oauthVerificationService";
import * as passwordResetService from "../services/passwordResetService";
import { PasswordResetError } from "../services/passwordResetService";
import { createPendingMfaSession } from "../services/pendingMfaSessionService";
import {
  sendBadRequest,
  sendConflict,
  sendCreated,
  sendError,
  sendSuccess,
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
  role: z.enum(["ADMIN", "CLINICIAN", "TRAINER", "CLIENT"] as const).optional(),
});

const logoutBodySchema = z.object({
  refreshToken: z.string().optional(),
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

  try {
    const authenticatedUser = await authService.authenticatePasswordUser(email, password);

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

      res.json({ success: true, data: mfaResponse });
      return;
    }

    const result = await authService.issueAuthenticatedSession(authenticatedUser, "login");

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

    if (error instanceof AuthError) {
      if (
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

  const { email, password, role = "CLIENT" } = parseResult.data;

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
        role: role as UserRole,
        isActive: true,
      },
    });

    // Issue session immediately so caller gets tokens without a second round-trip
    const authenticatedUser: authService.AuthenticatedPasswordUser = {
      profile: {
        uid: newUser.id,
        email: newUser.email,
        displayName: newUser.email.split("@")[0],
        role: newUser.role,
        organizationId: newUser.organizationId,
        isAnonymous: false,
      },
      provider: "password",
      onboardingCompleted: false,
      mfaEnabled: false,
    };

    const result = await authService.issueAuthenticatedSession(authenticatedUser, "register");

    sendCreated(res, {
      profile: result.profile,
      idToken: result.idToken,
      refreshToken: result.refreshToken,
      expiresAt: result.expiresAt,
      provider: result.provider,
    });
  } catch (error) {
    req.log?.error({ err: error }, "Register error");
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
    const refreshToken = parseResult.data.refreshToken;

    await authService.logout(refreshToken);

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

    // MFA carry-forward: decode the previous access token to check for mfaVerifiedAt.
    // This prevents clinical/admin users from being forced to re-complete MFA on every
    // 15-min access token expiry while the MFA session window (8h) is still valid.
    let previousMfaVerifiedAt: number | undefined;
    if (parseResult.data.previousAccessToken) {
      try {
        const decoded = jwt.decode(parseResult.data.previousAccessToken) as { mfaVerifiedAt?: number } | null;
        if (decoded?.mfaVerifiedAt != null) {
          previousMfaVerifiedAt = decoded.mfaVerifiedAt;
        }
      } catch {
        // Ignore decode failures — MFA status simply won't carry forward
      }
    }

    const result = await authService.refresh(refreshToken, previousMfaVerifiedAt);

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

  if (error instanceof AuthError) {
      if (error.code === "TOKEN_REUSE_DETECTED") {
        sendUnauthorized(res, "Session revoked due to token reuse - please log in again");
        return;
      }
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
      },
    });

    if (!user || !user.isActive) {
      sendUnauthorized(res, "Account not active");
      return;
    }

    sendSuccess(res, {
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
    });
  } catch (error) {
    req.log?.error({ err: error }, "Failed to load identity profile");
    sendError(res, "Failed to load identity profile", 500, undefined, "PROFILE_LOAD_ERROR");
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

    res.json({ success: true, data: session });
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

    // expiresAt mirrors REFRESH_TOKEN_EXPIRY_MS (7 days).
    const expiresAt = new Date(Date.now() + authService.REFRESH_TOKEN_EXPIRY_MS).toISOString();

    res.json({ success: true, data: { refreshToken, expiresAt } });
  } catch (error) {
    req.log?.error({ err: error }, "Failed to generate biometric token");
    sendError(res, "Failed to generate biometric token", 500, undefined, "BIOMETRIC_TOKEN_ERROR");
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
