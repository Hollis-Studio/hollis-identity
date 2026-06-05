/**
 * @ai-context JWT auth middleware | verifies Authorization Bearer tokens and attaches user to request
 *
 * SECURITY: Tokens contain minimal claims (userId, role, jti) — no email/PHI.
 * organizationId is optional — Workouts users have no org.
 *
 * Identity Service is cookie-agnostic. Consumer apps own cookie posture and pass
 * Bearer tokens to Identity when calling authenticated Identity routes.
 */
import { AUDIENCES } from "@hollis-studio/contracts";
import { NextFunction, Request, Response } from "express";
import { type JwtPayload } from "jsonwebtoken";
import { USER_ERRORS } from "../constants/errorMessages";
import { env } from "../lib/env";
import { verifyJwt } from "../lib/jwtKeys";
import { logger } from "../lib/logger";
import { metrics } from "../lib/metrics";
import { prisma } from "../lib/prisma";
import { AUTH_TOKEN_TYPE } from "../services/authService";
import { isAccessTokenDenied } from "../services/tokenDenylistService";
import { sendForbidden, sendUnauthorized } from "../utils/response";

// Import the type augmentation
import "../types/express.d.ts";

function getAcceptedAudiences(): [string, ...string[]] {
  const configured = env.JWT_AUDIENCES?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
  return configured.length > 0
    ? configured as [string, ...string[]]
    : [...AUDIENCES] as [string, ...string[]];
}

/**
 * @deprecated Use Express.Request directly — user property is now globally augmented
 */
export type AuthRequest = Request;

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  return null;
}

export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = extractToken(req);

  if (!token) {
    sendUnauthorized(res, "No token provided");
    return;
  }

  void (async () => {
    try {
      const decoded = verifyJwt<JwtPayload | string>(token, { audience: getAcceptedAudiences() });
      if (!decoded || typeof decoded === "string") {
        sendUnauthorized(res, "Invalid or expired token");
        return;
      }

      const userPayload = decoded as JwtPayload & {
        userId: string;
        role?: string;
        type?: string;
        organizationId?: string | null;
        claims?: {
          hollisHealth?: {
            role?: string;
            organizationId?: string | null;
          };
        };
        jti?: string;
        iat?: number;
        mfaVerifiedAt?: number;
        mfaEnabled?: boolean;
      };

      const role = userPayload.role ?? userPayload.claims?.hollisHealth?.role;
      if (!role) {
        sendUnauthorized(res, "Invalid token claims");
        return;
      }

      if (userPayload.type !== AUTH_TOKEN_TYPE.ACCESS) {
        logger.warn(
          { userId: userPayload.userId, tokenType: userPayload.type, component: "auth" },
          "[SECURITY] Non-access token rejected on authenticated route",
        );
        sendUnauthorized(res, "Invalid token type");
        return;
      }

      if (userPayload.jti && userPayload.iat) {
        try {
          const isDenied = await isAccessTokenDenied(
            userPayload.jti,
            userPayload.userId,
            userPayload.iat,
          );
          if (isDenied) {
            logger.info(
              { userId: userPayload.userId, jti: userPayload.jti, component: "auth" },
              "[SECURITY] Access denied - token has been revoked",
            );
            sendUnauthorized(res, "Token has been revoked");
            return;
          }
        } catch (denylistError) {
          // SECURITY: fail CLOSED. If we cannot determine whether a token was revoked
          // (e.g. transient denylist DB outage), reject rather than admit a potentially
          // revoked token onto sensitive routes (/change-password, /me, MFA). The 15-min
          // access-token TTL keeps the degradation window for legitimate users small.
          logger.error(
            { err: denylistError, userId: userPayload.userId, component: "auth" },
            "[SECURITY] Token denylist check failed - denying request (fail-closed)",
          );
          metrics.increment("auth_denylist_check_failed", { userId: userPayload.userId });
          sendUnauthorized(res, "Authentication temporarily unavailable");
          return;
        }
      }

      req.user = {
        userId: userPayload.userId,
        role,
        organizationId:
          userPayload.organizationId ?? userPayload.claims?.hollisHealth?.organizationId ?? undefined,
        jti: userPayload.jti,
        mfaVerifiedAt: userPayload.mfaVerifiedAt,
        mfaEnabled: userPayload.mfaEnabled,
      };
      next();
    } catch {
      sendUnauthorized(res, "Invalid or expired token");
    }
  })();
};

/**
 * Middleware to verify user is still active in the database.
 */
export const requireActiveUser = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (!req.user?.userId) {
    sendUnauthorized(res, "Authentication required");
    return;
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: { isActive: true },
    });

    if (!user) {
      logger.warn(
        { userId: req.user.userId, component: "auth" },
        "[SECURITY] Active user check failed - user not found",
      );
      sendUnauthorized(res, USER_ERRORS.NOT_FOUND);
      return;
    }

    if (!user.isActive) {
      logger.warn(
        { userId: req.user.userId, path: req.path, component: "auth" },
        "[SECURITY] Access denied for deactivated user",
      );
      sendForbidden(res, "Account deactivated");
      return;
    }

    next();
  } catch (err) {
    logger.error({ err, component: "auth" }, "[SECURITY] Error checking user active status");
    sendUnauthorized(res, "Authentication error");
  }
};
