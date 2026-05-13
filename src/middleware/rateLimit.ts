/**
 * @ai-context Rate limiting middleware | consumed by: app.ts, routes/auth.ts
 *
 * Provides rate limiting for auth-sensitive routes to prevent brute-force attacks.
 * Uses in-memory store for single-instance deployments.
 *
 * ## Architecture & Instance Mode
 *
 * This rate limiter is designed for **single-instance deployments** (see `SINGLE_INSTANCE_MODE`).
 * The in-memory store is appropriate for this mode and is the recommended configuration.
 *
 * - **Single-instance**: In-memory store provides effective per-IP rate limiting.
 * - **Cross-instance enforcement**: Out of scope for application-level rate limiting.
 *
 * ## Algorithm: Sliding Window
 *
 * Uses a sliding window algorithm rather than fixed windows:
 * - Tracks individual request timestamps within the window period
 * - Provides smoother rate limiting without "burst at window boundaries" issues
 * - Old timestamps are automatically pruned to prevent memory growth
 *
 * ## Defense in Depth
 *
 * **Application-level rate limiting is a defense-in-depth measure, not the primary protection.**
 *
 * For production abuse protection at scale, use edge-level enforcement via AWS WAF Rate-Based Rules:
 * - Apply rate limiting at the edge (CloudFront/ALB) before requests reach the application
 * - Handles distributed attacks across multiple IPs more effectively
 * - No application-level state sharing needed across instances
 * - Better protection against DDoS and application-layer attacks
 *
 * @see {@link ../lib/instanceModeConfig.ts} for instance mode validation
 * @see {@link ../lib/rateLimitStore.ts} for store abstraction
 * @see {@link docs/SECURITY_ASSUMPTIONS.md} for security architecture decisions
 *
 * deps: express-rate-limit, lib/rateLimitStore, lib/logger
 * consumers: app.ts, routes/auth.ts, routes/ai.ts, routes/nutrition.ts, routes/registration.ts
 */

import rateLimit, {
    ipKeyGenerator,
    MemoryStore,
    type Options as RateLimitOptions,
} from "express-rate-limit";
import { env } from "../lib/env";
import { logger } from "../lib/logger";
import {
    clearStoreInstances,
    closeAllRateLimitStores,
    getRateLimitStoresHealth,
    resetAllRateLimitStores,
    type RateLimitStoreHealth,
} from "../lib/rateLimitStore";
import { sendTooManyRequests } from "../utils/response";

// Re-export for convenience
export {
    clearStoreInstances,
    closeAllRateLimitStores,
    getRateLimitStoresHealth,
    resetAllRateLimitStores
};
export type { RateLimitStoreHealth };

/**
 * Current rate limit store type. 'redis' when REDIS_URL is set, 'memory' otherwise.
 * Exported for health check reporting.
 *
 * AUDIT-02 #2 (accepted): MemoryStore is correct for single-instance (<20 clients).
 * Redis-backed rate limiting is automatically enabled when REDIS_URL is set.
 */
export const RATE_LIMIT_STORE = env.REDIS_URL
  ? ("redis" as const)
  : ("memory" as const);

// Redis-backed rate limiting is automatically enabled when REDIS_URL is set.
// Falls back to MemoryStore when Redis is unavailable (see RATE_LIMIT_REDIS_FALLBACK).

// Skip rate limiting in test and development environments (evaluated dynamically to allow test overrides)
const isTestEnv = () => env.NODE_ENV === "test";
const isDevEnv = () => env.NODE_ENV === "development";

/**
 * E2E Security Test Flag
 * When E2E_SECURITY_TEST=true, rate limiting is enabled even in test environments.
 * This allows testing rate limiting behavior without affecting normal test runs.
 *
 * Usage: E2E_SECURITY_TEST=true npm run test -- rateLimiting.test.ts
 */
const isE2ESecurityTest = () => env.E2E_SECURITY_TEST === "true";

/**
 * AI-M2: Dev/test rate limit multiplier.
 * Instead of completely disabling rate limiting in dev/test, we use 10x higher limits.
 * This ensures rate limiting logic is always exercised while avoiding interference
 * during rapid development and test iteration.
 */
const DEV_TEST_MULTIPLIER = 10;
const isDev = () => isDevEnv() || isTestEnv();

/**
 * Get the effective max requests, applying the dev/test multiplier when appropriate.
 * In production, returns the base value. In dev/test, returns base * 10.
 */
function effectiveMax(base: number): number {
  if (isDev() && !isE2ESecurityTest()) return base * DEV_TEST_MULTIPLIER;
  return base;
}

/**
 * Skip rate limiting in tests UNLESS explicitly testing security.
 * This allows normal tests to run without rate limit interference,
 * while security tests can validate rate limiting behavior.
 */
const shouldSkipInTest = () => isTestEnv() && !isE2ESecurityTest();

/**
 * Skip rule: only skip in test runs (unless explicitly running E2E security tests).
 * Auth/api limiters now use higher limits in dev/test via effectiveMax() instead of skipping.
 */

/** Track all MemoryStore instances for reset functionality in tests */
const memoryStores: MemoryStore[] = [];

/**
 * Creates a rate limit store.
 * Each rate limiter needs its own store instance (express-rate-limit requirement).
 * @param _prefix - Reserved for future use (e.g., Redis key prefixing)
 */
function createRateLimitStore(_prefix: string): MemoryStore {
  const store = new MemoryStore();
  memoryStores.push(store);
  return store;
}

/**
 * Reset all rate limit stores. Only for use in tests to ensure test isolation.
 * This clears all rate limit state, allowing each test to start fresh.
 */
export async function resetRateLimitStore(): Promise<void> {
  if (env.NODE_ENV !== "test") {
    throw new Error(
      "resetRateLimitStore() is only available in test environment",
    );
  }
  // Reset all MemoryStore instances - resetAll() returns a Promise
  await Promise.all(memoryStores.map((store) => store.resetAll()));

  // Also reset the new store abstraction
  await resetAllRateLimitStores();
}

/**
 * Close rate limit store connections.
 * Should be called during graceful shutdown.
 */
export async function closeRateLimitStores(): Promise<void> {
  await closeAllRateLimitStores();
}

/**
 * Strict rate limiter for login/signup endpoints only.
 * - 5 requests per minute per IP in production
 * - Blocks brute-force password guessing
 * - Skipped in dev/test to avoid blocking during rapid iteration
 *
 * Custom handler includes `retryAfterSeconds` in the 429 JSON body
 * so clients can display a countdown timer.
 */
export const loginRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: () => effectiveMax(5), // 5 requests per minute (50 in dev/test) — AI-M2
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many login attempts. Please try again shortly.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skipSuccessfulRequests: false, // Count all requests
  skip: () => shouldSkipInTest(), // Skip only in tests (unless E2E_SECURITY_TEST) — AI-M2
  store: createRateLimitStore("login"),
});

/**
 * Per-email rate limiter for login endpoints.
 * Limits login attempts per email address to prevent credential-stuffing attacks
 * from distributed botnets that rotate IPs.
 *
 * - 10 requests per 15 minutes per email
 * - Applied alongside loginRateLimiter (IP-based) for defense-in-depth
 * - Uses req.body.email as the key; falls back to IP if email not provided
 *
 * This limiter catches the case where many IPs target the same account,
 * which the IP-based loginRateLimiter would miss.
 */
export const loginEmailRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: () => effectiveMax(10), // 10 attempts per email per 15 min (100 in dev/test)
  keyGenerator: (req) => {
    // Extract email from request body for per-account limiting
    const email = (req.body as { email?: string } | undefined)?.email;
    if (email && typeof email === "string") {
      // Normalize email to prevent bypass via case/whitespace
      return `email:${email.trim().toLowerCase()}`;
    }
    // Fall back to IP if no email in body (shouldn't happen on login routes)
    // Use ipKeyGenerator to correctly handle IPv6 /56 prefix bucketing — prevents bypass
    return `ip:${ipKeyGenerator(req.ip ?? req.socket.remoteAddress ?? "0.0.0.0")}`; // url-ok: ip-address - fallback for unknown client
  },
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many login attempts for this account. Please try again later.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skip: () => shouldSkipInTest(),
  store: createRateLimitStore("login-email"),
});

/**
 * Permissive rate limiter for non-login auth endpoints (logout, refresh, forgot-password, etc.)
 * - 15 requests per minute per IP in production
 * - Applied at app.ts level for all /auth/* routes
 * - Login/signup get additional strict limiting via loginRateLimiter at route level
 */
export const authSessionRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: () => effectiveMax(15), // 15 requests per minute (150 in dev/test) — AI-M2
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many authentication attempts. Please try again in a minute.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skip: () => shouldSkipInTest(), // Skip only in tests — AI-M2
  store: createRateLimitStore("auth-session"),
});

/** @deprecated Use `loginRateLimiter` for login/signup, `authSessionRateLimiter` for other auth routes */
export const authRateLimiter = loginRateLimiter;

/**
 * Standard rate limiter for general API endpoints
 * - 100 requests per minute per IP in production
 * - Skipped in development to avoid blocking during rapid iteration
 */
export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: () => effectiveMax(100), // 100 requests per minute (1000 in dev/test) — AI-M2
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many requests. Please slow down.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => shouldSkipInTest(), // Skip only in tests — AI-M2
  store: createRateLimitStore("api"),
});

/**
 * Strict rate limiter for barcode validation endpoint
 * - 10 requests per 10 minutes per IP
 * - Prevents barcode enumeration attacks
 * - Stricter than auth limiter due to unauthenticated access
 */
export const barcodeRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10, // 10 requests per 10 minutes
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many barcode validation attempts. Please try again later.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => shouldSkipInTest(), // Skip in tests unless E2E_SECURITY_TEST, but NOT in dev
  store: createRateLimitStore("barcode"),
});

/**
 * Strict rate limiter for sensitive operations (password reset, account changes)
 * - 3 requests per hour per IP
 * - Strong protection against enumeration/abuse
 */
export const sensitiveRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 requests per hour
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many sensitive operation attempts. Please try again later.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => shouldSkipInTest(), // Skip in tests unless E2E_SECURITY_TEST
  store: createRateLimitStore("sensitive"),
});

/**
 * Rate limiter for AI analysis endpoints (expensive operations)
 * - 10 requests per minute per IP
 * - Prevents cost overruns from AI API usage
 * - NOT skipped in dev since AI calls have real costs
 */
export const aiRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: () => (isDevEnv() ? 30 : 10), // Higher limit in dev for testing, lower in production
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many AI analysis requests. Please wait before trying again.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => shouldSkipInTest(), // Skip in tests unless E2E_SECURITY_TEST
  store: createRateLimitStore("ai"),
});

/**
 * Per-user rate limiter for AI endpoints (defense-in-depth alongside IP-based aiRateLimiter)
 * - 10 requests per minute per authenticated user
 * - Prevents a single user from exhausting AI quota even across multiple IPs
 * - Falls back to req.ip if user is not authenticated (shouldn't happen on AI routes)
 */
export const aiUserRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  keyGenerator: (req) =>
    req.user?.userId ??
    ipKeyGenerator(req.ip ?? req.socket.remoteAddress ?? "0.0.0.0"), // url-ok: ip-address - sentinel fallback for unknown remote address in rate-limit key generation
  handler: (_req, res, _next, options) => {
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many AI requests. Please wait before trying again.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => shouldSkipInTest(),
  store: createRateLimitStore("ai-user"),
});

/**
 * Rate limiter for Stripe webhook endpoint
 * - 1000 requests per minute per IP
 * - More permissive than API limiter (Stripe retries are legitimate)
 * - Applied BEFORE signature verification to protect CPU
 * - Blocks DDoS attempts while allowing burst traffic from Stripe
 *
 * Note: Stripe recommends high rate limits for webhooks since they may send
 * bursts of events during batch processing or retries. 1000/min is high enough
 * for legitimate traffic but low enough to prevent abuse.
 */
export const webhookRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1000, // 1000 requests per minute (permissive for webhook retries)
  handler: (req, res, _next, options) => {
    const ip = req.ip ?? "unknown";
    const retryAfterSeconds = Math.ceil(options.windowMs / 1000);

    // Log rate limit violation for security monitoring
    logger.warn(
      {
        ip,
        path: req.path,
        userAgent: req.headers["user-agent"],
        retryAfterSeconds,
      },
      "Webhook rate limit exceeded",
    );

    res.setHeader("Retry-After", retryAfterSeconds.toString());
    sendTooManyRequests(
      res,
      "Too many webhook requests. Please retry after the specified time.",
      retryAfterSeconds,
    );
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false, // Count all requests
  skip: () => shouldSkipInTest(), // Skip in tests unless E2E_SECURITY_TEST
  store: createRateLimitStore("webhook"),
});

// ============================================================================
// Custom Rate Limiter Factory
// ============================================================================

/**
 * Rate limit configuration presets for common use cases.
 */
export const RATE_LIMIT_PRESETS = {
  /** Strict: 5 requests per minute (auth, sensitive operations) */
  strict: { windowMs: 60_000, max: 5 },
  /** Standard: 100 requests per minute (general API) */
  standard: { windowMs: 60_000, max: 100 },
  /** Relaxed: 500 requests per minute (read-heavy endpoints) */
  relaxed: { windowMs: 60_000, max: 500 },
  /** Hourly: 3 requests per hour (very sensitive operations) */
  hourly: { windowMs: 3600_000, max: 3 },
  /** AI: 10 requests per minute (expensive AI operations) */
  ai: { windowMs: 60_000, max: 10 },
  /** Webhook: 1000 requests per minute (webhooks with retries) */
  webhook: { windowMs: 60_000, max: 1000 },
} as const;

export type RateLimitPreset = keyof typeof RATE_LIMIT_PRESETS;

/**
 * Factory for creating custom rate limiters with specific configurations.
 *
 * @param prefix - Unique prefix for this limiter (used for store isolation)
 * @param options - Partial rate limit options to override defaults
 * @returns Configured rate limiter middleware
 *
 * @example
 * // Create a custom rate limiter for file uploads
 * const uploadRateLimiter = createRateLimiter('upload', {
 *   windowMs: 60_000,
 *   max: 10,
 *   message: { error: 'Too many uploads', code: 'RATE_LIMIT_EXCEEDED' },
 * });
 */
export function createRateLimiter(
  prefix: string,
  options: Partial<RateLimitOptions> = {},
): ReturnType<typeof rateLimit> {
  const defaults: Partial<RateLimitOptions> = {
    windowMs: 60_000,
    max: 100,
    handler: (_req, res, _next, opts) => {
      const retryAfterSeconds = Math.ceil(opts.windowMs / 1000);
      res.setHeader("Retry-After", retryAfterSeconds.toString());
      sendTooManyRequests(
        res,
        "Too many requests. Please slow down.",
        retryAfterSeconds,
      );
    },
    standardHeaders: true,
    legacyHeaders: false,
  };

  return rateLimit({
    ...defaults,
    ...options,
    store: createRateLimitStore(prefix),
  });
}

/**
 * Create a rate limiter from a preset configuration.
 *
 * @param preset - Name of the preset configuration
 * @param prefix - Unique prefix for this limiter
 * @param overrides - Optional overrides for the preset
 * @returns Configured rate limiter middleware
 *
 * @example
 * const strictLimiter = createRateLimiterFromPreset('strict', 'password-reset');
 */
export function createRateLimiterFromPreset(
  preset: RateLimitPreset,
  prefix: string,
  overrides: Partial<RateLimitOptions> = {},
): ReturnType<typeof rateLimit> {
  const presetConfig = RATE_LIMIT_PRESETS[preset];
  return createRateLimiter(prefix, { ...presetConfig, ...overrides });
}
