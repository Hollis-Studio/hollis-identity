/**
 * @ai-context JWT auth middleware | verifies cookies or Authorization header and attaches user to request
 *
 * SECURITY: Tokens contain minimal claims (userId, role, jti) — no email/PHI.
 * organizationId is optional — Workouts users have no org.
 *
 * Authentication priority:
 * 1. httpOnly cookie (web-admin) — preferred for web
 * 2. Authorization Bearer header (mobile apps) — fallback
 */
import { NextFunction, Request, Response } from "express";
import jwt, { type JwtPayload, type VerifyErrors } from "jsonwebtoken";
import { USER_ERRORS } from "../constants/errorMessages";
import { AUTH_COOKIES } from "../lib/cookieConfig";
import { env } from "../lib/env";
import { logger } from "../lib/logger";
import { metrics } from "../lib/metrics";
import { prisma } from "../lib/prisma";
import { AUTH_TOKEN_TYPE } from "../services/authService";
import { isAccessTokenDenied } from "../services/tokenDenylistService";
import { sendForbidden, sendUnauthorized } from "../utils/response";

// Import the type augmentation
import "../types/express.d.ts";

const getJwtSecret = () => env.JWT_SECRET;

/**
 * @deprecated Use Express.Request directly — user property is now globally augmented
 */
export type AuthRequest = Request;

function extractToken(req: Request): string | null {
  const cookieToken = req.cookies[AUTH_COOKIES.ACCESS_TOKEN];
  if (cookieToken) return cookieToken;

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

  jwt.verify(
    token,
    getJwtSecret(),
    async (
      err: VerifyErrors | null,
      decoded: JwtPayload | string | undefined,
    ) => {
      if (err || !decoded || typeof decoded === "string") {
        sendUnauthorized(res, "Invalid or expired token");
        return;
      }

      const userPayload = decoded as JwtPayload & {
        userId: string;
        role: string;
        type?: string;
        organizationId?: string;
        jti?: string;
        iat?: number;
        mfaVerifiedAt?: number;
        mfaEnabled?: boolean;
      };

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
          logger.error(
            { err: denylistError, userId: userPayload.userId, component: "auth" },
            "[SECURITY] Token denylist check failed - allowing request",
          );
          metrics.increment("auth_denylist_check_failed", { userId: userPayload.userId });
        }
      }

      req.user = {
        userId: userPayload.userId,
        role: userPayload.role,
        organizationId: userPayload.organizationId,
        jti: userPayload.jti,
        mfaVerifiedAt: userPayload.mfaVerifiedAt,
        mfaEnabled: userPayload.mfaEnabled,
      };
      next();
    },
  );
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
