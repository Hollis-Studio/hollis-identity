/**
 * @ai-context Token Denylist Service | Immediate token revocation via cache-backed denylist
 *
 * Provides immediate kill-switch behavior for access tokens. While refresh tokens
 * are tracked in the database (see authService.ts), access tokens are stateless JWTs
 * that would otherwise be valid until expiry (15 min). This denylist enables:
 *
 * 1. Immediate session termination on logout (optional - configurable)
 * 2. Immediate revocation on security events (password change, suspicious activity)
 * 3. Admin force-logout capability
 *
 * ## Design Decisions
 *
 * - **In-memory cache primary**: Per SECURITY_ASSUMPTIONS.md, Redis is out of scope.
 *   In-memory cache provides sub-millisecond checks, acceptable for single-instance.
 * - **Short TTL entries**: Entries expire when the access token would expire anyway
 *   (ACCESS_TOKEN_TTL_MS), preventing unbounded memory growth.
 * - **Graceful degradation**: If checking the denylist adds latency, it can be disabled
 *   via ACCESS_TOKEN_DENYLIST_ENABLED=false. Short access token TTL still provides
 *   reasonable security (15 min exposure window).
 * - **JTI-based**: Each access token gets a unique JTI for granular revocation.
 * - **User-based batch revocation**: Can deny all tokens for a user (indexed by userId).
 *
 * ## Storage Backend
 *
 * Currently in-memory only. For multi-instance deployments, either:
 * 1. Accept per-instance denylists (eventual consistency within 15 min)
 * 2. Add PostgreSQL-backed store similar to sseTokenService
 * 3. Add Redis when it becomes available
 *
 * AUDIT-02 #6 & #37 (accepted): In-memory denylist fails open on restart and is
 * not shared across instances. Acceptable at <20 clients on single instance —
 * 15-min access token TTL limits exposure. Revisit at multi-instance scale.
 *
 * @see authService.ts - Refresh token revocation (DB-backed)
 * @see sseTokenService.ts - Similar pattern for SSE token single-use tracking
 */

// DEFERRED(audit-#15): [Scaling] In-memory token denylist is lost on process restart. Any tokens revoked
// before the restart (logout, password change) will be accepted again until they naturally expire (15 min).
// Severity: High | Rationale: Single-instance deployment with 10-20 users. 15-min access token TTL limits
//   exposure window. A restart clearing the denylist is an acceptable trade-off at this scale.
// Revisit: Before horizontal scaling or if deployment requires zero-downtime rolling restarts.

import { env } from "../lib/env";
import { logger as baseLogger } from "../lib/logger";

const logger = baseLogger.child({ module: "tokenDenylistService" });

// ============================================================================
// Configuration
// ============================================================================

/**
 * Access token TTL in milliseconds (must match authService.ts).
 * Denylist entries expire after this duration since they're no longer useful.
 */
const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Whether to enable denylist checks on access tokens.
 * When disabled, relies on short TTL + refresh token revocation for security.
 * Default: true (enable for immediate revocation capability)
 */
export const ACCESS_TOKEN_DENYLIST_ENABLED = env.ACCESS_TOKEN_DENYLIST_ENABLED;

/**
 * Cleanup interval in milliseconds.
 * Expired entries are cleaned up periodically to prevent memory growth.
 */
const CLEANUP_INTERVAL_MS = 60_000; // 1 minute

// ============================================================================
// Types
// ============================================================================

/**
 * Revocation reasons for audit trail.
 */
export type RevocationReason =
  | "logout" // User-initiated logout
  | "password_change" // Password was changed
  | "password_reset" // Password was reset via email
  | "account_deactivated" // Account was deactivated
  | "security_incident" // Suspicious activity detected
  | "admin_action" // Admin forced logout
  | "token_reuse"; // Refresh token reuse detected

/**
 * Entry in the denylist cache.
 */
interface DenylistEntry {
  /** When the token would naturally expire (used for cleanup) */
  expiresAt: number;
  /** Why the token was revoked */
  reason: RevocationReason;
  /** When the revocation occurred */
  revokedAt: number;
}

/**
 * Storage interface for token denylist.
 * Allows for future Redis/PostgreSQL implementations.
 */
export interface TokenDenylistStore {
  /**
   * Check if a specific token JTI is denied.
   */
  isTokenDenied(jti: string): Promise<boolean>;

  /**
   * Check if all tokens for a user are denied (user-level revocation).
   * Returns the timestamp after which tokens are denied, or null if not denied.
   */
  getUserDeniedAfter(userId: string): Promise<number | null>;

  /**
   * Add a token JTI to the denylist.
   */
  denyToken(
    jti: string,
    expiresAt: Date,
    reason: RevocationReason,
  ): Promise<void>;

  /**
   * Deny all tokens for a user issued before a certain time.
   * This is more efficient than revoking individual JTIs.
   */
  denyAllUserTokens(
    userId: string,
    issuedBefore: Date,
    reason: RevocationReason,
  ): Promise<void>;

  /**
   * Clean up expired entries.
   */
  cleanup(): Promise<number>;

  /**
   * Clear all entries (for testing).
   */
  clear(): Promise<void>;

  /**
   * Get count of entries (for testing/monitoring).
   */
  count(): Promise<{ tokens: number; users: number }>;

  /**
   * Start periodic cleanup.
   */
  startCleanupTimer(): void;

  /**
   * Stop periodic cleanup.
   */
  stopCleanupTimer(): void;
}

// ============================================================================
// In-Memory Store Implementation
// ============================================================================

/**
 * In-memory token denylist store.
 *
 * **Single-instance only!**
 *
 * For multi-instance deployments:
 * - Accept eventual consistency (15 min max exposure)
 * - Or implement PostgreSQL/Redis-backed store
 */
export class InMemoryTokenDenylistStore implements TokenDenylistStore {
  /**
   * Map of JTI -> DenylistEntry for individual token revocation.
   */
   
  private deniedTokens = new Map<string, DenylistEntry>();

  /**
   * Map of userId -> timestamp. All tokens issued before this timestamp are denied.
   * Entries expire after ACCESS_TOKEN_TTL_MS since older tokens are expired anyway.
   */
   
  private userDeniedAfter = new Map<
    string,
    { timestamp: number; expiresAt: number; reason: RevocationReason }
  >();

  private cleanupTimer: NodeJS.Timeout | null = null;

   
  async isTokenDenied(jti: string): Promise<boolean> {
    const entry = this.deniedTokens.get(jti);
    if (!entry) return false;

    // Check if entry has expired (token would be expired anyway)
    if (entry.expiresAt < Date.now()) {
      this.deniedTokens.delete(jti);
      return false;
    }

    return true;
  }

   
  async getUserDeniedAfter(userId: string): Promise<number | null> {
    const entry = this.userDeniedAfter.get(userId);
    if (!entry) return null;

    // Check if entry has expired
    if (entry.expiresAt < Date.now()) {
      this.userDeniedAfter.delete(userId);
      return null;
    }

    return entry.timestamp;
  }

   
  async denyToken(
    jti: string,
    expiresAt: Date,
    reason: RevocationReason,
  ): Promise<void> {
    this.deniedTokens.set(jti, {
      expiresAt: expiresAt.getTime(),
      reason,
      revokedAt: Date.now(),
    });

    logger.debug(
      { jti: jti.slice(0, 8) + "...", reason },
      "Token added to denylist",
    ); // phi-safe
  }

   
  async denyAllUserTokens(
    userId: string,
    issuedBefore: Date,
    reason: RevocationReason,
  ): Promise<void> {
    const now = Date.now();
    this.userDeniedAfter.set(userId, {
      timestamp: issuedBefore.getTime(),
      // Entry expires when all affected tokens would have expired
      expiresAt: now + ACCESS_TOKEN_TTL_MS,
      reason,
    });

    logger.info({ userId, reason }, "All user tokens denied"); // phi-safe
  }

   
  async cleanup(): Promise<number> {
    const now = Date.now();
    let cleaned = 0;

    // Clean up expired token entries
    for (const [jti, entry] of this.deniedTokens.entries()) {
      if (entry.expiresAt < now) {
        this.deniedTokens.delete(jti);
        cleaned++;
      }
    }

    // Clean up expired user entries
    for (const [userId, entry] of this.userDeniedAfter.entries()) {
      if (entry.expiresAt < now) {
        this.userDeniedAfter.delete(userId);
        cleaned++;
      }
    }

    return cleaned;
  }

   
  async clear(): Promise<void> {
    this.deniedTokens.clear();
    this.userDeniedAfter.clear();
  }

   
  async count(): Promise<{ tokens: number; users: number }> {
    return {
      tokens: this.deniedTokens.size,
      users: this.userDeniedAfter.size,
    };
  }

  startCleanupTimer(): void {
    if (this.cleanupTimer) return;

     
    this.cleanupTimer = setInterval(async () => {
      try {
        const cleaned = await this.cleanup();
        if (cleaned > 0 && env.NODE_ENV !== "test") {
          logger.debug({ cleaned }, "Cleaned up expired denylist entries");
        }
      } catch (err) {
        logger.error(
          { err },
          "tokenDenylistService: unexpected error in cleanup interval",
        );
      }
    }, CLEANUP_INTERVAL_MS);

    // Don't prevent process exit
    this.cleanupTimer.unref();
  }

  stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}

// ============================================================================
// Singleton Instance & Public API
// ============================================================================

// Singleton store instance
const store = new InMemoryTokenDenylistStore();

// Start cleanup timer on module load (except in tests)
if (env.NODE_ENV !== "test") {
  store.startCleanupTimer();
}

/**
 * Check if an access token should be denied.
 *
 * Performs two checks:
 * 1. Is the specific token JTI in the denylist?
 * 2. Was the user's tokens bulk-revoked after this token was issued?
 *
 * @param jti - Token's unique identifier
 * @param userId - User ID from token
 * @param iat - Token issue time (seconds since epoch, from JWT)
 * @returns true if token should be denied
 */
export async function isAccessTokenDenied(
  jti: string,
  userId: string,
  iat: number,
): Promise<boolean> {
  // Check 1: Specific token revocation
  if (await store.isTokenDenied(jti)) {
    return true;
  }

  // Check 2: User-level bulk revocation
  const deniedAfter = await store.getUserDeniedAfter(userId);
  if (deniedAfter !== null) {
    // Token is denied if it was issued AT OR BEFORE the denial timestamp.
    // We compare at second granularity since JWT iat is in seconds.
    // Tokens issued in the same second as the denial are denied (fail-secure).
    const deniedAtSeconds = Math.floor(deniedAfter / 1000);
    if (iat <= deniedAtSeconds) {
      return true;
    }
  }

  return false;
}

/**
 * Add a specific access token to the denylist.
 *
 * Use for:
 * - Individual token revocation
 * - Logout with immediate effect
 *
 * @param jti - Token's unique identifier
 * @param expiresAt - When the token naturally expires
 * @param reason - Why the token is being revoked
 */
export async function denyAccessToken(
  jti: string,
  expiresAt: Date,
  reason: RevocationReason,
): Promise<void> {
  await store.denyToken(jti, expiresAt, reason);
}

/**
 * Deny all access tokens for a user issued before the current time.
 *
 * Use for:
 * - Password change/reset (invalidate all sessions immediately)
 * - Account deactivation
 * - Security incident response
 *
 * More efficient than revoking individual JTIs - single entry covers all tokens.
 *
 * @param userId - User whose tokens should be denied
 * @param reason - Why tokens are being revoked
 */
export async function denyAllUserAccessTokens(
  userId: string,
  reason: RevocationReason,
): Promise<void> {
  await store.denyAllUserTokens(userId, new Date(), reason);
}

/**
 * Get the underlying store instance.
 * Used for testing and internal operations.
 */
export function getStore(): TokenDenylistStore {
  return store;
}

/**
 * Clear the denylist (for testing only).
 */
export async function clearDenylist(): Promise<void> {
  await store.clear();
}

/**
 * Get denylist statistics (for monitoring).
 */
export async function getDenylistStats(): Promise<{
  tokens: number;
  users: number;
  enabled: boolean;
}> {
  const counts = await store.count();
  return {
    ...counts,
    enabled: ACCESS_TOKEN_DENYLIST_ENABLED,
  };
}
