/**
 * @ai-context Periodic retention cleanup for Identity's short-lived auth tables
 *
 * Identity has no cron, no scheduled ECS task and no Lambda in front of it, so
 * the per-table `cleanupExpired*` helpers that already existed
 * (passwordResetService, middleware/mfa, pendingMfaSessionService) had zero
 * callers and every one of these tables grew forever. This module is the single
 * caller: one unref'd in-process timer, started in index.ts and stopped in
 * gracefulShutdown, following the same pattern as the token-denylist cleanup
 * timer in tokenDenylistService.
 *
 * ## What is pruned
 *
 * | Table                  | Rule                                             |
 * | ---------------------- | ------------------------------------------------ |
 * | PasswordResetToken     | expired or already used (30-minute TTL)          |
 * | EmailVerificationToken | expired/used more than USED_TOKEN_GRACE_MS ago   |
 * | StepUpToken            | expired, or used more than an hour ago           |
 * | PendingMfaSession      | expired, or consumed more than an hour ago       |
 * | RefreshToken           | expired, or revoked/rotated away more than REVOKED_GRACE_MS ago |
 *
 * ## What is deliberately NOT pruned
 *
 * - **AuthAuditLog** — the auth-event audit trail. Deleting it is a retention
 *   decision for the owner (HIPAA-adjacent evidence of who signed in, reset a
 *   password or was locked out), not something a cleanup timer should decide.
 * - **AccountLockoutEntry** — lockout + IP-reputation state. Same reason: the
 *   window pruning inside lib/accountLockout.ts keeps each row small, and how
 *   long an account's reputation history is kept is an owner decision.
 *
 * Both tables therefore still grow. They grow slowly (one row per auth event /
 * one row per attacked account) and neither is on a hot read path, but if either
 * needs a retention policy it should be an explicit, reviewed one.
 *
 * deps: prisma, logger, tenantContext | consumers: index.ts
 */

import { env } from "../lib/env";
import { logger as baseLogger } from "../lib/logger";
import { prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";
import { cleanupExpiredStepUpTokens } from "../middleware/mfa";
import { cleanupExpiredTokens as cleanupExpiredPasswordResetTokens } from "./passwordResetService";
import { cleanupExpiredPendingMfaSessions } from "./pendingMfaSessionService";

const logger = baseLogger.child({ module: "authRetentionService" });

// ============================================================================
// Configuration
// ============================================================================

/**
 * How often the sweep runs. Hourly, not per-minute: nothing here is
 * correctness-critical (every consumer of these tables already re-checks
 * `expiresAt` / `usedAt` / `revokedAt` itself before trusting a row), so this is
 * purely about keeping the tables bounded.
 */
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Grace period before a spent email-verification token is dropped. Long enough
 * that "did my verification link ever get issued?" support questions can still
 * be answered from the row itself, short enough to bound the table.
 */
const USED_TOKEN_GRACE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Grace period before a spent (revoked or rotated-away) refresh-token row is
 * dropped. Deliberately much longer than the 30-second rotation retry grace
 * (REFRESH_RETRY_GRACE_MS in refreshRotation).
 *
 * Fail-closed either way: a presented token whose row is gone is rejected as
 * TOKEN_NOT_FOUND exactly as a revoked row is rejected as TOKEN_REVOKED. What
 * the grace buys is the *informative* handling while it lasts — the
 * "[AUTH] Refresh attempt with revoked token" warning with its revokedReason,
 * and refreshRotation's replay detection, which revokes the whole token family
 * when a consumed token is presented again. After 30 days a replayed ancestor is
 * still refused, just without the family revocation, which is why this margin is
 * generous rather than tight.
 */
const REVOKED_GRACE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

let cleanupTimer: NodeJS.Timeout | null = null;

// ============================================================================
// Per-table cleanups owned by this module
// ============================================================================

/** Delete spent email-verification tokens past the grace period. */
async function cleanupExpiredEmailVerificationTokens(): Promise<number> {
  return runAsSystemOperation(
    async () => {
      const cutoff = new Date(Date.now() - USED_TOKEN_GRACE_MS);
      const result = await prisma.emailVerificationToken.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: cutoff } },
            { AND: [{ usedAt: { not: null } }, { usedAt: { lt: cutoff } }] },
          ],
        },
      });
      return result.count;
    },
    { reason: "scheduled:email-verification-token-cleanup" },
  );
}

/**
 * Delete refresh-token rows that can no longer authorize anything: expired past
 * the grace period, revoked longer ago than REVOKED_GRACE_MS, or consumed by
 * rotation longer ago than REVOKED_GRACE_MS.
 *
 * `usedAt` matters because refresh tokens now rotate (refreshRotation): every
 * refresh leaves a consumed predecessor row behind, and with a 365-day token
 * lifetime those would otherwise sit in the table for a year per refresh per
 * device. A consumed row is unusable the moment the 30-second retry grace
 * passes — the successor is the only live credential — so ageing it out is safe.
 */
async function cleanupExpiredRefreshTokens(): Promise<number> {
  return runAsSystemOperation(
    async () => {
      const now = Date.now();
      const expiredCutoff = new Date(now - USED_TOKEN_GRACE_MS);
      const spentCutoff = new Date(now - REVOKED_GRACE_MS);
      const result = await prisma.refreshToken.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: expiredCutoff } },
            { AND: [{ revokedAt: { not: null } }, { revokedAt: { lt: spentCutoff } }] },
            { AND: [{ usedAt: { not: null } }, { usedAt: { lt: spentCutoff } }] },
          ],
        },
      });
      return result.count;
    },
    { reason: "scheduled:refresh-token-cleanup" },
  );
}

// ============================================================================
// Sweep
// ============================================================================

/** One cleanup per pruned table, keyed by the name reported in the log line. */
export type AuthRetentionCleanups = Record<
  | "passwordResetTokens"
  | "emailVerificationTokens"
  | "stepUpTokens"
  | "pendingMfaSessions"
  | "refreshTokens",
  () => Promise<number>
>;

export type AuthRetentionCleanupResult = Record<keyof AuthRetentionCleanups, number>;

/**
 * The tables this service prunes, and nothing else. AuthAuditLog and
 * AccountLockoutEntry are absent on purpose — see the module header.
 */
export const defaultAuthRetentionCleanups: AuthRetentionCleanups = {
  passwordResetTokens: cleanupExpiredPasswordResetTokens,
  emailVerificationTokens: cleanupExpiredEmailVerificationTokens,
  stepUpTokens: cleanupExpiredStepUpTokens,
  pendingMfaSessions: cleanupExpiredPendingMfaSessions,
  refreshTokens: cleanupExpiredRefreshTokens,
};

/**
 * Run every retention cleanup once.
 *
 * Each table is swept independently and a failure on one is logged and skipped
 * rather than aborting the rest — one bad table must not stop the others from
 * ever being pruned. Safe to run concurrently from several ECS tasks: every
 * statement is an idempotent `deleteMany` over an already-expired predicate.
 *
 * @param cleanups - injection point for tests; defaults to the real tables
 */
export async function cleanupExpiredAuthRecords(
  cleanups: AuthRetentionCleanups = defaultAuthRetentionCleanups,
): Promise<AuthRetentionCleanupResult> {
  const result = {} as AuthRetentionCleanupResult;

  for (const table of Object.keys(cleanups) as (keyof AuthRetentionCleanups)[]) {
    try {
      result[table] = await cleanups[table]();
    } catch (err) {
      result[table] = 0;
      logger.error({ err, table }, "authRetentionService: cleanup failed for table");
    }
  }

  return result;
}

/**
 * Start the periodic retention sweep.
 *
 * Idempotent; the interval is unref'd so it never holds the process open (which
 * also keeps it harmless under the test runner).
 */
export function startAuthRetentionCleanup(): void {
  if (cleanupTimer) return;

  cleanupTimer = setInterval(() => {
    void cleanupExpiredAuthRecords()
      .then((deleted) => {
        const total = Object.values(deleted).reduce((sum, count) => sum + count, 0);
        if (total > 0 && env.NODE_ENV !== "test") {
          logger.info({ ...deleted, total }, "Pruned expired auth records");
        }
      })
      .catch((err: unknown) => {
        // cleanupExpiredAuthRecords already swallows per-table errors; this only
        // fires on something unexpected around them.
        logger.error({ err }, "authRetentionService: unexpected error in cleanup interval");
      });
  }, CLEANUP_INTERVAL_MS);

  cleanupTimer.unref();
}

/** Stop the periodic retention sweep (graceful shutdown / tests). */
export function stopAuthRetentionCleanup(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}
