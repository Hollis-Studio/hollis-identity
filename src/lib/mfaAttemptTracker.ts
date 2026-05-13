/**
 * @ai-context MFA Attempt Tracker | Tracks and limits MFA verification attempts
 */

import { MfaEventTypeSchema } from "@hollis/contracts";
import { logger } from "./logger";
import { prisma } from "./prisma";
import { runAsSystemOperation } from "./tenantContext";

// ============================================================================
// CONSTANTS
// ============================================================================

export const MFA_MAX_ATTEMPTS = 5;
export const MFA_LOCKOUT_DURATION_MS = 15 * 60 * 1000;
export const MFA_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

// ============================================================================
// TYPES
// ============================================================================

export interface MfaAttemptStatus {
  isLocked: boolean;
  failedAttempts: number;
  attemptsRemaining: number;
  retryAfterSeconds: number;
}

export interface MfaVerificationError extends Error {
  code: string;
  statusCode: number;
  attemptsRemaining?: number;
  retryAfterSeconds?: number;
}

// ============================================================================
// SERVICE FUNCTIONS
// ============================================================================

export async function getMfaAttemptStatus(userId: string): Promise<MfaAttemptStatus> {
  return runAsSystemOperation(
    async () => {
      const now = new Date();
      const windowStart = new Date(now.getTime() - MFA_ATTEMPT_WINDOW_MS);

      const failedAttempts = await prisma.mfaEvent.count({
        where: {
          userId,
          eventType: MfaEventTypeSchema.enum.VERIFICATION_FAILED,
          success: false,
          createdAt: { gte: windowStart },
        },
      });

      const lastLockoutEvent = await prisma.mfaEvent.findFirst({
        where: {
          userId,
          eventType: MfaEventTypeSchema.enum.STEP_UP_FAILED,
          context: { path: ["lockoutTriggered"], equals: true },
          createdAt: { gte: windowStart },
        },
        orderBy: { createdAt: "desc" },
      });

      let isLocked = false;
      let retryAfterSeconds = 0;

      if (lastLockoutEvent) {
        const lockoutEndsAt = new Date(
          lastLockoutEvent.createdAt.getTime() + MFA_LOCKOUT_DURATION_MS,
        );
        if (lockoutEndsAt > now) {
          isLocked = true;
          retryAfterSeconds = Math.ceil(
            (lockoutEndsAt.getTime() - now.getTime()) / 1000,
          );
        }
      } else if (failedAttempts >= MFA_MAX_ATTEMPTS) {
        isLocked = true;
        retryAfterSeconds = Math.ceil(MFA_LOCKOUT_DURATION_MS / 1000);
      }

      const attemptsRemaining = isLocked ? 0 : Math.max(0, MFA_MAX_ATTEMPTS - failedAttempts);

      return { isLocked, failedAttempts, attemptsRemaining, retryAfterSeconds };
    },
    { reason: "auth:mfa-management" },
  );
}

export async function recordMfaFailure(userId: string): Promise<MfaAttemptStatus> {
  const status = await getMfaAttemptStatus(userId);

  if (!status.isLocked && status.attemptsRemaining === 0) {
    await runAsSystemOperation(
      async () => {
        await prisma.mfaEvent.create({
          data: {
            userId,
            eventType: MfaEventTypeSchema.enum.STEP_UP_FAILED,
            success: false,
            errorMessage: "MFA verification locked out after too many failed attempts",
            context: {
              lockoutTriggered: true,
              failedAttempts: status.failedAttempts + 1,
            },
          },
        });
        logger.warn(
          { userId, failedAttempts: status.failedAttempts + 1 },
          "[SECURITY] MFA verification locked out due to failed attempts",
        );
      },
      { reason: "auth:mfa-management" },
    );

    return {
      isLocked: true,
      failedAttempts: status.failedAttempts + 1,
      attemptsRemaining: 0,
      retryAfterSeconds: Math.ceil(MFA_LOCKOUT_DURATION_MS / 1000),
    };
  }

  return {
    ...status,
    attemptsRemaining: Math.max(0, status.attemptsRemaining - 1),
  };
}

export async function clearMfaAttempts(userId: string): Promise<void> {
  logger.info({ userId }, "[MFA] MFA attempts reset after successful verification");
}

export function createMfaErrorWithAttempts(
  message: string,
  code: string,
  status: MfaAttemptStatus,
): MfaVerificationError {
  const error = new Error(message) as MfaVerificationError;
  error.code = code;
  error.statusCode = status.isLocked ? 429 : 400;
  error.attemptsRemaining = status.attemptsRemaining;
  if (status.isLocked) {
    error.retryAfterSeconds = status.retryAfterSeconds;
  }
  return error;
}
