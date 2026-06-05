/**
 * @ai-context Auth service | business logic for authentication (login, logout, refresh)
 *
 * Identity Service auth service — stripped of Health-specific business logic:
 * - organizationId is optional (Workouts users have no org)
 * - No barcode/USER_ID_REGEX format check (Identity Service is format-agnostic)
 * - No organization status gate (ACTIVE/ARCHIVED/SUSPENDED — Health enforces this)
 * - No pushService.deleteDevicesForUser (Health-specific infrastructure)
 * - No runAsSystemOperation/tenantContext (Identity Service has no PHI multi-tenancy)
 *
 * All cryptographic token logic (refresh rotation, reuse detection, MFA carry-forward)
 * is preserved verbatim.
 *
 * deps: prisma, passwordHashing, jsonwebtoken, crypto | consumers: routes/auth.ts
 */
import {
  AUDIENCES,
  MFA_SESSION_WINDOW_MS,
  REVOKED_REASON,
  type Audience,
} from "@hollis-studio/contracts";
import crypto from "crypto";
import { USER_ERRORS } from "../constants/errorMessages";
import { getEnv } from "../lib/env";
import { signJwt, verifyJwt } from "../lib/jwtKeys";
import { logger } from "../lib/logger";
import {
  checkAccountLockout,
  recordLoginFailure,
  recordLoginSuccess,
} from "../lib/accountLockout";
import { rehashIfNeeded, verifyPassword } from "../lib/passwordHashing";
import { timingSafePasswordVerify } from "../lib/securityUtils";
import { Prisma, prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";
import { denyAccessToken } from "./tokenDenylistService";

// ============================================================================
// Config
// ============================================================================

export const ACCESS_TOKEN_EXPIRY = "15m";
export const REFRESH_TOKEN_EXPIRY = "60d";
export const REFRESH_TOKEN_EXPIRY_MS = 60 * 24 * 60 * 60 * 1000;
export const ACCESS_TOKEN_EXPIRY_MS = 15 * 60 * 1000;

/**
 * Rotation grace window. A refresh token is single-use: rotating it marks it
 * `usedAt` and mints a replacement. If the client never receives that
 * replacement — a dropped response, the app backgrounded/killed mid-flight, or
 * a client-side timeout-abort *after* the server already committed the rotation
 * — it will retry with the same (now-used) token. Re-presenting a used token
 * within this window is treated as that benign lost-response retry rather than
 * theft, *provided* its replacement was never delivered (still unused and
 * unrevoked). Outside the window, or when the replacement has already been
 * used, it is genuine reuse and the whole token family is revoked.
 *
 * Because the access token lives only 15 minutes, an active client rotates its
 * refresh token ~96×/day; on flaky mobile networks the lost-response race is
 * common, so without this grace window users are signed out seemingly at
 * random. 60s comfortably covers a client retry without meaningfully widening
 * the theft-detection window.
 */
export const REFRESH_REUSE_GRACE_MS = 60 * 1000;

/**
 * `revokedReason` for the undelivered replacement we retire when forgiving a
 * lost-response retry (see {@link REFRESH_REUSE_GRACE_MS}). Distinct from
 * TOKEN_REUSE_DETECTED so audit logs separate benign retries from real theft.
 * The column is free-form text; this is intentionally a local literal rather
 * than a wire-level REVOKED_REASON.
 */
const GRACE_SUPERSEDE_REASON = "SUPERSEDED_BY_GRACE_RETRY";

/**
 * JWT token purpose/type values used across auth flows.
 *
 * R7: AUTH_TOKEN_TYPE values match the shared @hollis-studio/contracts AUTH_TOKEN_TYPES
 * lowercase values. Local const kept to avoid a circular-import cycle with the
 * contracts bundle at this stage. TODO(W6f): migrate to contracts import.
 */
export const AUTH_TOKEN_TYPE = {
  ACCESS: "access",
  REFRESH: "refresh",
  MFA_PENDING: "mfa_pending",
} as const;
export type AuthTokenType = (typeof AUTH_TOKEN_TYPE)[keyof typeof AUTH_TOKEN_TYPE];

function getTokenAudiences(): [Audience, ...Audience[]] {
  const configured = getEnv().JWT_AUDIENCES?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
  const validAudiences = configured.filter((audience): audience is Audience =>
    AUDIENCES.includes(audience as Audience),
  );

  return validAudiences.length > 0
    ? validAudiences as [Audience, ...Audience[]]
    : [...AUDIENCES] as [Audience, ...Audience[]];
}

// ============================================================================
// Types
// ============================================================================

export interface AuthResponse {
  profile: {
    uid: string;
    email: string;
    displayName: string;
    role: string;
    organizationId: string | null;
    isAnonymous: boolean;
    emailVerified: boolean;
  };
  provider: string;
  idToken: string;
  refreshToken: string;
  expiresAt: string;
  /** Whether the user has completed onboarding. */
  onboardingCompleted: boolean;
}

export interface AuthenticatedPasswordUser {
  profile: AuthResponse["profile"];
  provider: string;
  onboardingCompleted: boolean;
  /** Whether the user has at least one verified MFA credential. */
  mfaEnabled: boolean;
}

export class AuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 401,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

interface AccessTokenOptions {
  mfaVerifiedAt?: number;
  mfaEnabled?: boolean;
  tokenType?: AuthTokenType;
}

/**
 * Generate an access token with optional MFA claims.
 */
export function generateAccessToken(
  userId: string,
  role: string,
  organizationId: string | null,
  options?: AccessTokenOptions,
): string {
  const { token } = generateAccessTokenWithJti(userId, role, organizationId, options);
  return token;
}

/**
 * Generate an access token and return both the token and its JTI for tracking.
 */
export function generateAccessTokenWithJti(
  userId: string,
  role: string,
  organizationId: string | null,
  options?: AccessTokenOptions,
): { token: string; jti: string } {
  const { mfaVerifiedAt, mfaEnabled, tokenType = AUTH_TOKEN_TYPE.ACCESS } = options ?? {};
  const accessJti = crypto.randomUUID();

  const payload: Record<string, unknown> = {
    sub: userId,
    userId,
    role,
    organizationId,
    type: tokenType,
    jti: accessJti,
    aud: getTokenAudiences(),
    claims: {
      hollisHealth: {
        role,
        organizationId,
      },
    },
  };

  const env = getEnv();
  if (env.JWT_ISSUER) {
    payload.iss = env.JWT_ISSUER;
  }

  if (mfaVerifiedAt !== undefined) {
    payload.mfaVerifiedAt = mfaVerifiedAt;
  }

  if (mfaEnabled !== undefined) {
    payload.mfaEnabled = mfaEnabled;
  }

  const token = signJwt(payload, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
  });
  return { token, jti: accessJti };
}

/**
 * Issue a new refresh token for a user and persist it to the database.
 */
export async function issueRefreshToken(
  userId: string,
  role: string,
  organizationId: string | null,
  collisionContext: string,
): Promise<string> {
  const refreshJti = crypto.randomUUID();

  const payload: Record<string, unknown> = {
    sub: userId,
    userId,
    role,
    organizationId,
    type: AUTH_TOKEN_TYPE.REFRESH,
    jti: refreshJti,
    aud: getTokenAudiences(),
  };
  const env = getEnv();
  if (env.JWT_ISSUER) {
    payload.iss = env.JWT_ISSUER;
  }

  const refreshToken = signJwt(payload, { expiresIn: REFRESH_TOKEN_EXPIRY });

  const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
  const familyId = crypto.randomUUID();
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS);

  try {
    await prisma.refreshToken.create({
      data: {
        userId,
        tokenHash,
        familyId,
        generation: 0,
        expiresAt: refreshExpiresAt,
      },
    });
  } catch (error: unknown) {
    const prismaError = error as { code?: string; meta?: { target?: string[] } };
    if (
      prismaError.code === "P2002" &&
      prismaError.meta?.target?.includes("tokenHash")
    ) {
      logger.error(
        { userId, component: "authService" },
        `[SECURITY] Refresh token hash collision detected during ${collisionContext}`,
      );
    }
    throw error;
  }

  return refreshToken;
}

/**
 * Generate an access token with MFA verification timestamp set to now.
 */
export async function generateMfaVerifiedToken(
  userId: string,
  role: string,
  organizationId: string | null,
): Promise<{
  idToken: string;
  refreshToken: string;
  expiresAt: string;
  expiresIn: number;
}> {
  const mfaVerifiedAt = Date.now();
  const idToken = generateAccessToken(userId, role, organizationId, { mfaVerifiedAt, mfaEnabled: true });

  const refreshToken = await runAsSystemOperation(
    () => issueRefreshToken(userId, role, organizationId, "MFA verification"),
    { reason: "auth:mfa-verify" },
  );

  const expiresAt = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_MS).toISOString();

  return {
    idToken,
    refreshToken,
    expiresAt,
    expiresIn: ACCESS_TOKEN_EXPIRY_MS / 1000,
  };
}

// ============================================================================
// Service Functions
// ============================================================================

/**
 * Generate a refresh token specifically for biometric login storage.
 */
export async function generateBiometricRefreshToken(
  userId: string,
  role: string,
  organizationId: string | null,
): Promise<{ refreshToken: string }> {
  return runAsSystemOperation(
    async () => {
      const refreshToken = await issueRefreshToken(
        userId,
        role,
        organizationId,
        "biometric token generation",
      );
      return { refreshToken };
    },
    { reason: "auth:biometric-token", userId },
  );
}

/**
 * Authenticate a user with email and password.
 */
export async function login(email: string, password: string, ipAddress: string): Promise<AuthResponse> {
  const authenticatedUser = await authenticatePasswordUser(email, password, ipAddress);
  return issueAuthenticatedSession(authenticatedUser, "login");
}

export async function issueAuthenticatedSession(
  authenticatedUser: AuthenticatedPasswordUser,
  collisionContext: string,
): Promise<AuthResponse> {
  const idToken = generateAccessToken(
    authenticatedUser.profile.uid,
    authenticatedUser.profile.role,
    authenticatedUser.profile.organizationId,
    { mfaEnabled: authenticatedUser.mfaEnabled },
  );

  const refreshToken = await runAsSystemOperation(
    () =>
      issueRefreshToken(
        authenticatedUser.profile.uid,
        authenticatedUser.profile.role,
        authenticatedUser.profile.organizationId,
        collisionContext,
      ),
    { reason: "auth:issue-session" },
  );

  const expiresAt = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_MS).toISOString();

  return {
    profile: authenticatedUser.profile,
    provider: authenticatedUser.provider,
    idToken,
    refreshToken,
    expiresAt,
    onboardingCompleted: authenticatedUser.onboardingCompleted,
  };
}

export async function authenticatePasswordUser(
  email: string,
  password: string,
  ipAddress: string,
): Promise<AuthenticatedPasswordUser> {
  return runAsSystemOperation(
    async () => {
      // SECURITY: Check account lockout BEFORE touching the DB user record or
      // doing any password work. This prevents brute-force attacks that rotate
      // IPs to bypass IP-level rate limiting.
      const lockoutStatus = await checkAccountLockout(email);
      if (lockoutStatus.isLocked) {
        throw new AuthError(
          "Account temporarily locked due to too many failed login attempts",
          "ACCOUNT_LOCKED",
          429,
        );
      }

      const user = await prisma.user.findUnique({
        where: { email },
        include: {
          _count: {
            select: {
              mfaCredentials: {
                where: { isVerified: true },
              },
            },
          },
        },
      });

      if (!user) {
        // SECURITY: Timing-oracle prevention.
        await timingSafePasswordVerify(password, null);
        // Record failure against the email even when no account exists to
        // make enumeration harder (same latency, same lockout counter growth).
        await recordLoginFailure(email, ipAddress);
        throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
      }

      if (!user.isActive) {
        await timingSafePasswordVerify(password, null);
        throw new AuthError("Account is inactive", "ACCOUNT_INACTIVE", 403);
      }

      // R3.3: USER_ID_REGEX barcode check REMOVED.
      // Identity Service is agnostic to userId format.
      // Health's HH-XXXXXX IDs and Workouts cuid() IDs both work.

      // R3.5: Organization status gate REMOVED.
      // Health enforces ACTIVE/ARCHIVED/SUSPENDED in its own auth-client middleware.

      if (
        user.passwordHash.length === 0 ||
        !(await verifyPassword(password, user.passwordHash))
      ) {
        await recordLoginFailure(email, ipAddress);
        throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
      }

      // Password verified — reset the failure counter.
      await recordLoginSuccess(email);

      const newHash = await rehashIfNeeded(password, user.passwordHash);
      if (newHash) {
        await prisma.user.update({
          where: { id: user.id },
          data: { passwordHash: newHash },
        });
        logger.info(
          { userId: user.id, component: "authService" },
          "[SECURITY] Password hash upgraded on login",
        );
      }

      const userMfaEnabled = user._count.mfaCredentials > 0;
      const displayName = user.displayName ?? user.email.split("@")[0];

      return {
        profile: {
          uid: user.id,
          email: user.email,
          displayName,
          role: user.role,
          organizationId: user.organizationId,
          isAnonymous: false,
          emailVerified: user.emailVerified != null,
        },
        provider: "password",
        onboardingCompleted: false, // TODO(W6f): add onboardingCompleted to User model when app-specific fields are added
        mfaEnabled: userMfaEnabled,
      };
    },
    { reason: "auth:login", userId: undefined },
  );
}

/**
 * Logout — revokes the refresh token and (if supplied) immediately denies the
 * session's access token so it stops working before its natural 15-min expiry.
 */
export async function logout(
  refreshToken?: string,
  accessToken?: string,
): Promise<{ success: boolean }> {
  return runAsSystemOperation(
    async () => {
      let sessionUserId: string | undefined;

      if (refreshToken) {
        try {
          // SECURITY: verify the refresh token's signature before revoking. The endpoint
          // is unauthenticated, so without this an attacker could attempt to revoke
          // arbitrary sessions by submitting forged/guessed token strings. Revocation
          // stays keyed by the token hash (caller must hold the real token); we only
          // additionally require it to be a server-issued refresh token.
          const decoded = verifyJwt<{ userId?: string; type?: string }>(refreshToken, {
            ignoreExpiration: true,
          });
          if (decoded.type === AUTH_TOKEN_TYPE.REFRESH) {
            sessionUserId = decoded.userId;
            const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
            await prisma.refreshToken.update({
              where: { tokenHash },
              data: {
                revokedAt: new Date(),
                revokedReason: REVOKED_REASON.LOGOUT,
              },
            });
          }
        } catch (error) {
          logger.warn(
            { err: error, component: "authService" },
            "Failed to revoke token on logout",
          );
        }
      }

      // SECURITY (revocation propagation): deny the session's access token by jti so it
      // is rejected immediately by every Identity route and by any consumer using the
      // denylist-aware verify path — instead of remaining valid until natural expiry.
      // Scoped to this token's jti so other devices/sessions stay signed in.
      if (accessToken) {
        try {
          const decoded = verifyJwt<{
            userId?: string;
            type?: string;
            jti?: string;
            exp?: number;
          }>(accessToken, { ignoreExpiration: true });
          if (
            decoded.type === AUTH_TOKEN_TYPE.ACCESS &&
            decoded.jti &&
            decoded.exp != null &&
            (sessionUserId == null || decoded.userId === sessionUserId)
          ) {
            await denyAccessToken(decoded.jti, new Date(decoded.exp * 1000), "logout");
          }
        } catch (error) {
          logger.warn(
            { err: error, component: "authService" },
            "Failed to deny access token on logout",
          );
        }
      }

      // TODO(W6h): emit user.logout webhook for consumer apps to do their own device/cache cleanup
      // pushService.deleteDevicesForUser removed — Health-specific infrastructure

      return { success: true };
    },
    { reason: "auth:logout", userId: undefined },
  );
}

/**
 * Refresh an authentication token with token rotation and reuse detection.
 *
 * SECURITY: Implements refresh token rotation with family-wide revocation.
 */
export async function refresh(
  refreshToken: string,
  previousMfaVerifiedAt?: number,
  previousAccessTokenUserId?: string,
): Promise<AuthResponse> {
  return runAsSystemOperation(
    async () => {
      try {
        const decoded = verifyJwt<{
          userId: string;
          role: string;
          type?: string;
          jti?: string;
        }>(refreshToken, { audience: getTokenAudiences() });

        if (decoded.type !== AUTH_TOKEN_TYPE.REFRESH) {
          logger.warn(
            { userId: decoded.userId, tokenType: decoded.type, component: "authService" },
            "[SECURITY] Non-refresh token used on refresh endpoint",
          );
          throw new AuthError("Invalid refresh token", "TOKEN_INVALID_TYPE");
        }

        const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
        const storedToken = await prisma.refreshToken.findUnique({ where: { tokenHash } });

        if (!storedToken) {
          logger.warn(
            { userId: decoded.userId, component: "authService" },
            "[SECURITY] Refresh token not found in database",
          );
          throw new AuthError("Invalid refresh token", "TOKEN_NOT_FOUND");
        }

        if (storedToken.revokedAt) {
          logger.warn(
            { userId: decoded.userId, reason: storedToken.revokedReason, component: "authService" },
            "[SECURITY] Refresh attempt with revoked token",
          );
          throw new AuthError("Refresh token has been revoked", "TOKEN_REVOKED");
        }

        if (storedToken.expiresAt < new Date()) {
          logger.warn(
            { userId: decoded.userId, component: "authService" },
            "[SECURITY] Refresh attempt with expired token",
          );
          throw new AuthError("Refresh token has expired", "TOKEN_EXPIRED");
        }

        // REUSE DETECTION (with a lost-response grace window — see REFRESH_REUSE_GRACE_MS)
        let graceSupersede: { id: string; generation: number } | null = null;
        if (storedToken.usedAt) {
          const usedAgeMs = Date.now() - storedToken.usedAt.getTime();
          const successor = storedToken.replacedByTokenHash
            ? await prisma.refreshToken.findUnique({
                where: { tokenHash: storedToken.replacedByTokenHash },
              })
            : null;
          // The replacement reaching the client is proven only once it is itself
          // used (or revoked). A still-pristine successor means the client never
          // got it — consistent with a dropped response, not theft.
          const successorDelivered =
            successor != null && (successor.usedAt != null || successor.revokedAt != null);
          const isLostResponseRetry =
            usedAgeMs <= REFRESH_REUSE_GRACE_MS && successor != null && !successorDelivered;

          if (!isLostResponseRetry) {
            logger.error(
              {
                userId: decoded.userId,
                familyId: storedToken.familyId,
                generation: storedToken.generation,
                component: "authService",
              },
              "[SECURITY] TOKEN REUSE DETECTED - Revoking entire token family (possible token theft)",
            );

            await prisma.refreshToken.updateMany({
              where: { familyId: storedToken.familyId, revokedAt: null },
              data: { revokedAt: new Date(), revokedReason: REVOKED_REASON.TOKEN_REUSE_DETECTED },
            });

            throw new AuthError(
              "Token reuse detected - session revoked for security",
              "TOKEN_REUSE_DETECTED",
            );
          }

          logger.warn(
            {
              userId: decoded.userId,
              familyId: storedToken.familyId,
              generation: storedToken.generation,
              usedAgeMs,
              component: "authService",
            },
            "[AUTH] Lost-response refresh retry within grace window — reissuing instead of revoking",
          );
          // Retire the undelivered replacement and re-rotate off this token so the
          // family stays a single linear chain (no fork). The transaction below
          // branches on this and re-verifies the successor is still undelivered.
          graceSupersede = { id: successor.id, generation: successor.generation };
        }

        const user = await prisma.user.findUnique({
          where: { id: decoded.userId },
          select: {
            id: true,
            isActive: true,
            organizationId: true,
            email: true,
            displayName: true,
            role: true,
            emailVerified: true,
            _count: {
              select: { mfaCredentials: { where: { isVerified: true } } },
            },
          },
        });
        if (!user) {
          throw new AuthError(USER_ERRORS.NOT_FOUND, "USER_NOT_FOUND");
        }

        // R3.3: USER_ID_REGEX check REMOVED — format-agnostic.
        // R3.5: Organization status gate REMOVED — Health enforces this.

        if (!user.isActive) {
          logger.warn(
            { userId: decoded.userId, component: "authService" },
            "[SECURITY] Token refresh rejected for deactivated user",
          );
          throw new AuthError("Account deactivated", "ACCOUNT_DEACTIVATED");
        }

        // MFA carry-forward. SECURITY: only honor a carried mfaVerifiedAt when the
        // previous access token (signature already verified by the route) belonged to
        // the SAME user as this refresh token. Without this binding, a holder of any
        // valid refresh token could pair it with a forged/borrowed token's mfaVerifiedAt
        // and bypass MFA.
        let carryMfaVerifiedAt: number | undefined;
        if (previousMfaVerifiedAt != null) {
          const ownerMatches = previousAccessTokenUserId === decoded.userId;
          const mfaAge = Date.now() - previousMfaVerifiedAt;
          if (!ownerMatches) {
            logger.warn(
              { userId: decoded.userId, component: "authService" },
              "[SECURITY] previousAccessToken owner mismatch on refresh — not carrying MFA forward",
            );
          } else if (mfaAge <= MFA_SESSION_WINDOW_MS) {
            carryMfaVerifiedAt = previousMfaVerifiedAt;
          } else {
            logger.info(
              { userId: decoded.userId, mfaAge, component: "authService" },
              "[MFA] MFA session expired during refresh, not carrying forward mfaVerifiedAt",
            );
          }
        }

        const refreshMfaEnabled = user._count.mfaCredentials > 0;
        const idToken = generateAccessToken(
          decoded.userId,
          decoded.role,
          user.organizationId,
          { mfaVerifiedAt: carryMfaVerifiedAt, mfaEnabled: refreshMfaEnabled },
        );

        // TOKEN ROTATION
        const newRefreshJti = crypto.randomUUID();
        const newRefreshPayload: Record<string, unknown> = {
          sub: decoded.userId,
          userId: decoded.userId,
          role: decoded.role,
          organizationId: user.organizationId,
          type: AUTH_TOKEN_TYPE.REFRESH,
          jti: newRefreshJti,
          aud: getTokenAudiences(),
        };
        const env = getEnv();
        if (env.JWT_ISSUER) {
          newRefreshPayload.iss = env.JWT_ISSUER;
        }
        const newRefreshToken = signJwt(newRefreshPayload, {
          expiresIn: REFRESH_TOKEN_EXPIRY,
        });

        const newTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
        const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS);
        // Grace reissues chain off the retired replacement so generation stays monotonic.
        const newGeneration = (graceSupersede?.generation ?? storedToken.generation) + 1;

        await prisma.$transaction(
          async (tx) => {
            if (graceSupersede) {
              // Lost-response retry: retire the undelivered replacement instead of
              // consuming `storedToken` (already used). Re-verify it is still
              // pristine inside the transaction — if it was used/revoked between
              // the pre-check and here, the replacement WAS delivered after all,
              // so this is genuine reuse: revoke the family.
              const supersede = await tx.refreshToken.updateMany({
                where: { id: graceSupersede.id, usedAt: null, revokedAt: null },
                data: { revokedAt: new Date(), revokedReason: GRACE_SUPERSEDE_REASON },
              });
              if (supersede.count !== 1) {
                await tx.refreshToken.updateMany({
                  where: { familyId: storedToken.familyId, revokedAt: null },
                  data: { revokedAt: new Date(), revokedReason: REVOKED_REASON.TOKEN_REUSE_DETECTED },
                });
                throw new AuthError(
                  "Token reuse detected - session revoked for security",
                  "TOKEN_REUSE_DETECTED",
                );
              }
              // Repoint the already-used token at the new replacement so a further
              // retry within the grace window resolves against this fresh successor.
              await tx.refreshToken.update({
                where: { id: storedToken.id },
                data: { replacedByTokenHash: newTokenHash },
              });
            } else {
              const consumeResult = await tx.refreshToken.updateMany({
                where: { id: storedToken.id, usedAt: null, revokedAt: null },
                data: { usedAt: new Date(), replacedByTokenHash: newTokenHash },
              });

              if (consumeResult.count !== 1) {
                const latest = await tx.refreshToken.findUnique({ where: { id: storedToken.id } });

                if (latest?.usedAt) {
                  await tx.refreshToken.updateMany({
                    where: { familyId: storedToken.familyId, revokedAt: null },
                    data: { revokedAt: new Date(), revokedReason: REVOKED_REASON.TOKEN_REUSE_DETECTED },
                  });
                  throw new AuthError(
                    "Token reuse detected - session revoked for security",
                    "TOKEN_REUSE_DETECTED",
                  );
                }

                if (latest?.revokedAt) {
                  throw new AuthError("Refresh token has been revoked", "TOKEN_REVOKED");
                }

                throw new AuthError("Invalid refresh token", "TOKEN_NOT_FOUND");
              }
            }

            await tx.refreshToken.create({
              data: {
                userId: user.id,
                tokenHash: newTokenHash,
                familyId: storedToken.familyId,
                generation: newGeneration,
                expiresAt: refreshExpiresAt,
              },
            });
          },
          { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
        );

        logger.info(
          {
            userId: user.id,
            familyId: storedToken.familyId,
            oldGeneration: storedToken.generation,
            newGeneration,
            graceReissue: graceSupersede != null,
            component: "authService",
          },
          "[AUTH] Refresh token rotated successfully",
        );

        const expiresAt = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_MS).toISOString();
        const displayName = user.displayName ?? user.email.split("@")[0];

        return {
          profile: {
            uid: user.id,
            email: user.email,
            displayName,
            role: user.role,
            organizationId: user.organizationId,
            isAnonymous: false,
            emailVerified: user.emailVerified != null,
          },
          provider: "password",
          idToken,
          refreshToken: newRefreshToken,
          expiresAt,
          onboardingCompleted: false, // TODO(W6f): add onboardingCompleted to User model
        };
      } catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("Invalid or expired refresh token", "TOKEN_EXPIRED");
      }
    },
    { reason: "auth:refresh", userId: undefined },
  );
}
