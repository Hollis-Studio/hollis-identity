/**
 * @ai-context Auth Audit Service | persistent auth-layer audit trail
 *
 * Write-only service. Writes AuthAuditLog rows for login, register, logout,
 * token refresh, password reset, and email verification events.
 *
 * Failures are swallowed + logged — audit writes must never block auth flows.
 * Additive — does NOT replace MfaEvent writes.
 *
 * deps: prisma | consumers: routes/auth.ts, authService
 */

import type { Prisma } from "../../prisma/generated/prisma/client.js";
import { logger } from "../lib/logger";
import { prisma } from "../lib/prisma";

export type AuthAuditEventType =
  | "LOGIN_SUCCESS"
  | "LOGIN_FAILED"
  | "REGISTER_SUCCESS"
  | "REGISTER_FAILED"
  | "LOGOUT"
  | "TOKEN_REFRESH_SUCCESS"
  | "TOKEN_REFRESH_FAILED"
  | "PASSWORD_RESET_REQUESTED"
  | "PASSWORD_RESET_COMPLETED"
  | "EMAIL_VERIFICATION_SENT"
  | "EMAIL_VERIFICATION_COMPLETED";

export interface WriteAuditLogParams {
  actorId?: string;
  eventType: AuthAuditEventType;
  success: boolean;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Prisma.InputJsonValue;
}

/**
 * Fire-and-forget audit log writer.
 * Never throws — failures are logged but do not propagate.
 */
export function writeAuditLog(params: WriteAuditLogParams): void {
  prisma.authAuditLog
    .create({
      data: {
        actorId: params.actorId ?? null,
        eventType: params.eventType,
        success: params.success,
        ipAddress: params.ipAddress ?? null,
        userAgent: params.userAgent ?? null,
        metadata: params.metadata ?? undefined,
      },
    })
    .catch((err: unknown) => {
      logger.warn({ err, component: "authAudit" }, "Failed to write auth audit log");
    });
}

/**
 * Extract IP address from Express request (handles proxy headers).
 */
export function extractIp(req: { ip?: string; headers: Record<string, string | string[] | undefined> }): string | undefined {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0];
    return first?.trim();
  }
  return req.ip;
}
