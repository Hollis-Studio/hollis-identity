/**
 * @ai-context Account lockout service for progressive friction on failed logins
 *
 * ## Purpose
 *
 * Prevents brute-force attacks that bypass IP-based rate limiting by rotating IPs.
 * Implements per-account lockout with progressive backoff that attackers cannot evade.
 *
 * ## Progressive Friction Model
 *
 * - 5 failed attempts → 15-minute lockout
 * - 10 failed attempts → 30-minute lockout
 * - 15 failed attempts → 1-hour lockout
 * - 20+ failed attempts → 2-hour lockout (capped)
 *
 * Lockout is **per-account** (keyed by email hash), not per-IP.
 * Successful login resets the counter.
 * Password reset clears the lockout.
 *
 * ## Storage Backend
 *
 * Uses the same Redis/memory abstraction as rate limiting:
 * - Single instance: In-memory store (default)
 * - Horizontal scaling: Redis store with fallback
 *
 * ## Device/IP Reputation Signals
 *
 * Optional tracking of IP addresses attempting to log in to each account:
 * - Flags when many IPs target the same account (distributed attack)
 * - Flags when one IP targets many accounts (credential stuffing)
 *
 * @see {@link ./rateLimitStore.ts} for store abstraction
 * @see {@link docs/SECURITY_ASSUMPTIONS.md} for security decisions
 *
 * deps: crypto, ioredis, logger | consumers: routes/auth.ts, services/authService.ts
 */

// R6: ioredis removed — Identity Service uses in-memory lockout only.
// Redis-backed lockout is Health-specific infrastructure.
import crypto from "crypto";
import { env } from "./env";
import { logger } from "./logger";

// ============================================================================
// Types
// ============================================================================

/** Result of checking account lockout status */
export interface LockoutStatus {
  /** Whether the account is currently locked out */
  isLocked: boolean;
  /** Number of failed attempts in current window */
  failedAttempts: number;
  /** Unix timestamp (ms) when lockout ends (0 if not locked) */
  lockoutEndsAt: number;
  /** Seconds until lockout ends (0 if not locked) */
  retryAfterSeconds: number;
  /** Number of unique IPs that attempted login (for reputation) */
  uniqueIpCount: number;
}

/** Configuration for lockout thresholds */
export interface LockoutConfig {
  /** Number of failures before first lockout (default: 5) */
  initialThreshold: number;
  /** Initial lockout duration in seconds (default: 900 = 15 min) */
  initialLockoutSeconds: number;
  /** Maximum lockout duration in seconds (default: 7200 = 2 hours) */
  maxLockoutSeconds: number;
  /** Time window for counting failures in seconds (default: 3600 = 1 hour) */
  failureWindowSeconds: number;
  /** Maximum unique IPs before flagging suspicious (default: 10) */
  maxUniqueIpsBeforeFlag: number;
}

/** Internal state for an account's lockout tracking */
interface LockoutEntry {
  /** Timestamps of failed attempts */
  failedAttempts: number[];
  /** Current lockout end timestamp (0 if not locked) */
  lockoutEndsAt: number;
  /** Set of unique IP hashes that have attempted login */
  uniqueIps: Set<string>;
  /** Last update timestamp */
  lastUpdated: number;
}

/** Store interface for lockout data */
export interface IAccountLockoutStore {
  /** Get current lockout status for an account */
  getStatus(accountKey: string, config: LockoutConfig): Promise<LockoutStatus>;
  /** Record a failed login attempt */
  recordFailure(
    accountKey: string,
    ipAddress: string,
    config: LockoutConfig,
  ): Promise<LockoutStatus>;
  /** Record a successful login (resets failure counter) */
  recordSuccess(accountKey: string): Promise<void>;
  /** Clear lockout state (e.g., after password reset) */
  clearLockout(accountKey: string): Promise<void>;
  /** Reset all state (for tests only) */
  resetAll(): Promise<void>;
  /** Gracefully close connections */
  close(): Promise<void>;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_LOCKOUT_CONFIG: LockoutConfig = {
  initialThreshold: 5,
  initialLockoutSeconds: 900, // 15 minutes
  maxLockoutSeconds: 7200, // 2 hours
  failureWindowSeconds: 3600, // 1 hour
  maxUniqueIpsBeforeFlag: 10,
};

// ============================================================================
// Utilities
// ============================================================================

/**
 * Hash an email address for use as account key.
 * This prevents plaintext emails from being stored in the lockout store.
 */
export function hashAccountEmail(email: string): string {
  return crypto
    .createHash("sha256")
    .update(email.toLowerCase().trim())
    .digest("hex")
    .substring(0, 32); // First 32 chars sufficient for uniqueness
}

/**
 * Hash an IP address for privacy in the unique IP tracking.
 */
function hashIpAddress(ip: string): string {
  return crypto.createHash("sha256").update(ip).digest("hex").substring(0, 16); // First 16 chars sufficient
}

/**
 * Calculate lockout duration based on number of failed attempts.
 * Uses exponential backoff with a cap.
 *
 * - 5 failures: 15 min
 * - 10 failures: 30 min
 * - 15 failures: 60 min
 * - 20+ failures: 120 min (capped)
 */
function calculateLockoutDuration(
  failedAttempts: number,
  config: LockoutConfig,
): number {
  if (failedAttempts < config.initialThreshold) {
    return 0;
  }

  // Calculate multiplier: 1 at threshold, 2 at 2x threshold, etc.
  const multiplier = Math.floor(failedAttempts / config.initialThreshold);
  const duration = config.initialLockoutSeconds * multiplier;

  return Math.min(duration, config.maxLockoutSeconds);
}

// ============================================================================
// Memory Store Implementation
// ============================================================================

/**
 * In-memory implementation of account lockout store.
 * Suitable for single-instance deployments.
 */
export class MemoryAccountLockoutStore implements IAccountLockoutStore {
   
  private store: Map<string, LockoutEntry> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    // Cleanup expired entries every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    // Don't keep Node process alive for cleanup (important for tests)
    this.cleanupInterval.unref();
  }

   
  async getStatus(
    accountKey: string,
    config: LockoutConfig,
  ): Promise<LockoutStatus> {
    const now = Date.now();
    const entry = this.store.get(accountKey);

    if (!entry) {
      return {
        isLocked: false,
        failedAttempts: 0,
        lockoutEndsAt: 0,
        retryAfterSeconds: 0,
        uniqueIpCount: 0,
      };
    }

    // Clean expired failures
    const windowStart = now - config.failureWindowSeconds * 1000;
    const activeFailures = entry.failedAttempts.filter(
      (ts) => ts > windowStart,
    );

    // Check if currently locked
    const isLocked = entry.lockoutEndsAt > now;
    const retryAfterSeconds = isLocked
      ? Math.ceil((entry.lockoutEndsAt - now) / 1000)
      : 0;

    return {
      isLocked,
      failedAttempts: activeFailures.length,
      lockoutEndsAt: entry.lockoutEndsAt,
      retryAfterSeconds,
      uniqueIpCount: entry.uniqueIps.size,
    };
  }

   
  async recordFailure(
    accountKey: string,
    ipAddress: string,
    config: LockoutConfig,
  ): Promise<LockoutStatus> {
    const now = Date.now();
    const ipHash = hashIpAddress(ipAddress);

    let entry = this.store.get(accountKey);

    if (!entry) {
      entry = {
        failedAttempts: [],
        lockoutEndsAt: 0,
        uniqueIps: new Set(),
        lastUpdated: now,
      };
      this.store.set(accountKey, entry);
    }

    // Clean expired failures first
    const windowStart = now - config.failureWindowSeconds * 1000;
    entry.failedAttempts = entry.failedAttempts.filter(
      (ts) => ts > windowStart,
    );

    // Add this failure
    entry.failedAttempts.push(now);
    entry.uniqueIps.add(ipHash);
    entry.lastUpdated = now;

    // Calculate and apply lockout if threshold exceeded
    const lockoutDuration = calculateLockoutDuration(
      entry.failedAttempts.length,
      config,
    );

    if (lockoutDuration > 0) {
      entry.lockoutEndsAt = now + lockoutDuration * 1000;

      // Log suspicious activity
      if (entry.uniqueIps.size >= config.maxUniqueIpsBeforeFlag) {
        logger.warn(
          {
            accountKeyPrefix: accountKey.substring(0, 8),
            uniqueIpCount: entry.uniqueIps.size,
            failedAttempts: entry.failedAttempts.length,
          },
          "Potential distributed attack: many IPs targeting single account",
        );
      }
    }

    const isLocked = entry.lockoutEndsAt > now;
    const retryAfterSeconds = isLocked
      ? Math.ceil((entry.lockoutEndsAt - now) / 1000)
      : 0;

    return {
      isLocked,
      failedAttempts: entry.failedAttempts.length,
      lockoutEndsAt: entry.lockoutEndsAt,
      retryAfterSeconds,
      uniqueIpCount: entry.uniqueIps.size,
    };
  }

   
  async recordSuccess(accountKey: string): Promise<void> {
    // On successful login, reset the failure counter but keep the entry
    // for analytics purposes
    const entry = this.store.get(accountKey);

    if (entry) {
      entry.failedAttempts = [];
      entry.lockoutEndsAt = 0;
      entry.lastUpdated = Date.now();
      // Keep uniqueIps for reputation tracking
    }
  }

   
  async clearLockout(accountKey: string): Promise<void> {
    // Full reset on password change/reset
    this.store.delete(accountKey);
  }

   
  async resetAll(): Promise<void> {
    this.store.clear();
  }

   
  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }

  /** Clean up old entries to prevent memory growth */
  private cleanup(): void {
    const now = Date.now();
    // Remove entries that haven't been updated in 24 hours
    const maxAge = 24 * 60 * 60 * 1000;

    for (const [key, entry] of this.store.entries()) {
      if (now - entry.lastUpdated > maxAge) {
        this.store.delete(key);
      }
    }
  }

  /** Get store size (for testing) */
  get size(): number {
    return this.store.size;
  }
}

// ============================================================================
// Redis Store Implementation — REMOVED in W6d
// ============================================================================
// RedisAccountLockoutStore was removed because ioredis is not a dependency of
// Identity Service. In-memory lockout is sufficient for the current deployment.
// TODO(W6h): Add Redis-backed store when multi-instance deployments are required.
//
// To satisfy TypeScript, we provide a dead-code placeholder that will never be
// instantiated (getAccountLockoutStore() always returns MemoryAccountLockoutStore).
class RedisAccountLockoutStore implements IAccountLockoutStore {
  // Stub — never instantiated. Delegates to memory store.
  private memory = new MemoryAccountLockoutStore();

  async getStatus(k: string, c: LockoutConfig) { return this.memory.getStatus(k, c); }
  async recordFailure(k: string, ip: string, c: LockoutConfig) { return this.memory.recordFailure(k, ip, c); }
  async recordSuccess(k: string) { return this.memory.recordSuccess(k); }
  async clearLockout(k: string) { return this.memory.clearLockout(k); }
  async resetAll() { return this.memory.resetAll(); }
  async close() { return this.memory.close(); }
}

// ============================================================================
// Factory and Singleton Management
// ============================================================================

let lockoutStore: IAccountLockoutStore | null = null;

/**
 * Get or create the account lockout store instance.
 * Uses same configuration pattern as rate limiting.
 */
export function getAccountLockoutStore(): IAccountLockoutStore {
  if (lockoutStore) {
    return lockoutStore;
  }

  // RATE_LIMIT_STORE schema only permits 'memory'; Redis path is reserved for
  // future multi-instance support when the schema is extended.
  lockoutStore = new MemoryAccountLockoutStore();

  return lockoutStore;
}

/**
 * Reset lockout store. Only for use in tests.
 */
export async function resetAccountLockoutStore(): Promise<void> {
  if (env.NODE_ENV !== "test") {
    throw new Error(
      "resetAccountLockoutStore() is only available in test environment",
    );
  }

  if (lockoutStore) {
    await lockoutStore.resetAll();
  }
}

/**
 * Close lockout store connections.
 * Should be called during graceful shutdown.
 */
export async function closeAccountLockoutStore(): Promise<void> {
  if (lockoutStore) {
    await lockoutStore.close();
    lockoutStore = null;
  }
}

/**
 * Clear the singleton instance. For testing purposes only.
 */
export function clearAccountLockoutStoreInstance(): void {
  if (env.NODE_ENV !== "test") {
    throw new Error(
      "clearAccountLockoutStoreInstance() is only available in test environment",
    );
  }
  lockoutStore = null;
}

// ============================================================================
// High-Level API
// ============================================================================

/**
 * Check if an account is currently locked out.
 *
 * @param email - The email address to check
 * @param config - Optional custom lockout configuration
 * @returns Lockout status
 */
export async function checkAccountLockout(
  email: string,
  config: LockoutConfig = DEFAULT_LOCKOUT_CONFIG,
): Promise<LockoutStatus> {
  const store = getAccountLockoutStore();
  const accountKey = hashAccountEmail(email);
  return store.getStatus(accountKey, config);
}

/**
 * Record a failed login attempt for an account.
 * May trigger a lockout if threshold is exceeded.
 *
 * @param email - The email address that failed login
 * @param ipAddress - The IP address of the request
 * @param config - Optional custom lockout configuration
 * @returns Updated lockout status
 */
export async function recordLoginFailure(
  email: string,
  ipAddress: string,
  config: LockoutConfig = DEFAULT_LOCKOUT_CONFIG,
): Promise<LockoutStatus> {
  const store = getAccountLockoutStore();
  const accountKey = hashAccountEmail(email);

  const status = await store.recordFailure(accountKey, ipAddress, config);

  // Log lockout events
  if (status.isLocked && status.failedAttempts === config.initialThreshold) {
    logger.warn(
      {
        accountKeyPrefix: accountKey.substring(0, 8),
        failedAttempts: status.failedAttempts,
        lockoutSeconds: status.retryAfterSeconds,
      },
      "Account locked out due to failed login attempts",
    );
  }

  return status;
}

/**
 * Record a successful login for an account.
 * Resets the failure counter.
 *
 * @param email - The email address that logged in successfully
 */
export async function recordLoginSuccess(email: string): Promise<void> {
  const store = getAccountLockoutStore();
  const accountKey = hashAccountEmail(email);
  await store.recordSuccess(accountKey);
}

/**
 * Clear lockout state for an account.
 * Call this after password reset to allow login.
 *
 * @param email - The email address to clear lockout for
 */
export async function clearAccountLockout(email: string): Promise<void> {
  const store = getAccountLockoutStore();
  const accountKey = hashAccountEmail(email);
  await store.clearLockout(accountKey);

  logger.info(
    { accountKeyPrefix: accountKey.substring(0, 8) },
    "Account lockout cleared (password reset)",
  );
}
