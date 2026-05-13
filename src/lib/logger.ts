/**
 * @ai-context Structured logging infrastructure using pino
 *
 * Provides consistent, structured logging with:
 * - Request ID tracking
 * - User ID context
 * - Route name tagging
 * - Performance timing
 * - JSON output in production, pretty printing in development
 *
 * Usage:
 *   import { logger, createChildLogger } from '../lib/logger';
 *
 *   // Simple logging
 *   logger.info('Server started');
 *   logger.error({ err }, 'Database connection failed');
 *
 *   // Child logger with context
 *   const userLogger = createChildLogger({ userId: 'abc123' });
 *   userLogger.info('User logged in');
 *
 * deps: pino | consumers: server/src/middleware/*, server/src/routes/*
 */

import pino from "pino";

// ============================================================================
// Configuration
// ============================================================================

// NOTE: process.env is used here intentionally.
// logger.ts is a bootstrap-time dependency imported before validateEnvOnStartup()
// is called. Using the `env` proxy here would throw because the proxy requires
// validation to have run first. Logger must be safe to instantiate at module
// load time, so raw process.env access is acceptable and necessary in this file.
const isDevelopment = process.env.NODE_ENV !== "production";
const isTest = process.env.NODE_ENV === "test";

/**
 * Log level hierarchy: trace < debug < info < warn < error < fatal
 * In production, default to 'info' to reduce noise.
 * In development, default to 'debug' for more visibility.
 * In tests, default to 'silent' to reduce output.
 */
function getDefaultLogLevel(): string {
  if (isTest) return "silent";
  if (isDevelopment) return "debug";
  return "info";
}

const RAW_LOG_LEVEL = process.env.LOG_LEVEL;
const VALID_LOG_LEVELS = ["debug", "info", "warn", "error"] as const;
type ValidLogLevel = (typeof VALID_LOG_LEVELS)[number];
// env-ok: bootstrap-order guard for LOG_LEVEL — validated by envSchema at startup
const logLevel: ValidLogLevel = (
  VALID_LOG_LEVELS as readonly string[]
).includes(RAW_LOG_LEVEL ?? "")
  ? (RAW_LOG_LEVEL as ValidLogLevel)
  : (getDefaultLogLevel() as ValidLogLevel);

// ============================================================================
// Logger Instance
// ============================================================================

// @deferred[OBS-1]: No AsyncLocalStorage request context — requestId not propagated through service layer; acceptable logging fidelity at <20 users; revisit when concurrency or incident response demands it

/**
 * Root logger instance.
 * In development, uses pino-pretty for human-readable output.
 * In production, outputs JSON for log aggregation tools (CloudWatch, Datadog, etc.)
 */
export const logger = pino({
  level: logLevel,
  // Base context included in all logs
  base: {
    service: "hollis-health-api",
    env: process.env.NODE_ENV ?? "development",
    // Instance/container ID for multi-instance ECS deployments
    instanceId: process.env.ECS_TASK_ID ?? process.env.HOSTNAME ?? "local",
  },
  // Customize timestamp format
  timestamp: pino.stdTimeFunctions.isoTime,
  // Redact sensitive fields
  redact: {
    paths: [
      // Auth/security fields
      "req.headers.authorization",
      "req.headers.cookie",
      "password",
      "passwordHash",
      "token",
      "refreshToken",
      "idToken",
      "accessToken",
      "apiKey",
      "*.password",
      "*.passwordHash",
      "*.token",
      "*.refreshToken",
      "*.accessToken",
      "*.apiKey",
      // PHI fields - must never be logged (HIPAA identifiers)
      "email",
      "*.email",
      "dateOfBirth",
      "*.dateOfBirth",
      "dob",
      "*.dob",
      "ssn",
      "*.ssn",
      "phoneNumber",
      "*.phoneNumber",
      "phone",
      "*.phone",
      // Additional HIPAA identifiers
      "firstName",
      "*.firstName",
      "lastName",
      "*.lastName",
      "fullName",
      "*.fullName",
      "address",
      "*.address",
      "streetAddress",
      "*.streetAddress",
      "city",
      "*.city",
      "zipCode",
      "*.zipCode",
      "medicalRecordNumber",
      "*.medicalRecordNumber",
      "mrn",
      "*.mrn",
      "insuranceId",
      "*.insuranceId",
      // Patient barcodes are PHI identifiers (format: HH-XXXXXX)
      "barcode",
      "*.barcode",
      "code",
      "*.code",
      // Request body/query protection (may contain PHI)
      "req.body",
      "req.query",
      "res.body",
    ],
    remove: true,
  },
  // Pretty print in development
  transport: isDevelopment
    ? {
        target: "pino-pretty",
        options: {
          colorize: true,
          translateTime: "HH:MM:ss.l",
          ignore: "pid,hostname,service,env",
          messageFormat: "{requestId} {route} {msg}",
          errorLikeObjectKeys: ["err", "error"],
        },
      }
    : undefined,
});

// ============================================================================
// Child Loggers
// ============================================================================

/**
 * Create a child logger with additional context.
 * Child loggers inherit parent configuration and add extra fields to all logs.
 *
 * @param context Additional context to include in all logs from this logger
 * @returns Child logger instance
 *
 * @example
 * const reqLogger = createChildLogger({
 *   requestId: 'abc123',
 *   userId: 'user456',
 *   route: 'GET /users/:id'
 * });
 * reqLogger.info('Fetching user'); // Includes requestId, userId, route in output
 */
export function createChildLogger(
  context: Record<string, unknown>,
): pino.Logger {
  return logger.child(context);
}

// ============================================================================
// Request Context Types
// ============================================================================

export interface RequestContext {
  requestId: string;
  userId?: string;
  route: string;
  method: string;
  path: string;
  ip?: string;
  userAgent?: string;
}

/**
 * Create a logger for a specific HTTP request.
 * Includes standard request context in all logs.
 */
export function createRequestLogger(context: RequestContext): pino.Logger {
  return logger.child({
    requestId: context.requestId,
    userId: context.userId,
    route: context.route,
    method: context.method,
    path: context.path,
    ip: context.ip,
    userAgent: context.userAgent,
  });
}

// ============================================================================
// Performance Logging
// ============================================================================

/**
 * Timer for measuring operation duration.
 * Returns a function that logs the elapsed time when called.
 *
 * @param operationName Name of the operation being timed
 * @param parentLogger Optional logger to use (defaults to root logger)
 * @returns Function to call when operation completes
 *
 * @example
 * const endTimer = startTimer('compliance-calculation');
 * // ... do work ...
 * endTimer(); // Logs: "compliance-calculation completed" with duration
 */
export function startTimer(
  operationName: string,
  parentLogger: pino.Logger = logger,
): (metadata?: Record<string, unknown>) => void {
  const start = process.hrtime.bigint();

  return (metadata?: Record<string, unknown>) => {
    const end = process.hrtime.bigint();
    const durationMs = Number(end - start) / 1_000_000; // Convert nanoseconds to milliseconds

    parentLogger.info(
      {
        operation: operationName,
        durationMs: Math.round(durationMs * 100) / 100, // Round to 2 decimal places
        ...metadata,
      },
      `${operationName} completed`,
    );
  };
}

/**
 * Async wrapper that automatically times an operation.
 *
 * @param operationName Name of the operation
 * @param fn Async function to time
 * @param parentLogger Optional logger to use
 * @returns Result of the async function
 *
 * @example
 * const result = await timeAsync('fetch-user-data', async () => {
 *   return await prisma.user.findUnique({ where: { id } });
 * });
 */
export async function timeAsync<T>(
  operationName: string,
  fn: () => Promise<T>,
  parentLogger: pino.Logger = logger,
): Promise<T> {
  const end = startTimer(operationName, parentLogger);
  try {
    const result = await fn();
    end({ success: true });
    return result;
  } catch (error) {
    end({
      success: false,
      err: {
        message: error instanceof Error ? error.message : "Unknown error",
      },
    });
    throw error;
  }
}

// ============================================================================
// Metrics Helpers
// ============================================================================

/**
 * Log a counter metric.
 * Useful for tracking counts of events (requests, errors, etc.)
 */
export function logMetric(
  name: string,
  value: number,
  labels: Record<string, string> = {},
  parentLogger: pino.Logger = logger,
): void {
  parentLogger.info(
    {
      metric: name,
      value,
      labels,
      type: "counter",
    },
    `metric:${name}`,
  );
}

/**
 * Log a gauge metric.
 * Useful for tracking values that go up and down (queue size, connections, etc.)
 */
export function logGauge(
  name: string,
  value: number,
  labels: Record<string, string> = {},
  parentLogger: pino.Logger = logger,
): void {
  parentLogger.info(
    {
      metric: name,
      value,
      labels,
      type: "gauge",
    },
    `metric:${name}`,
  );
}

/**
 * Log a histogram metric (distribution of values).
 * Useful for tracking latencies, sizes, etc.
 */
export function logHistogram(
  name: string,
  value: number,
  labels: Record<string, string> = {},
  parentLogger: pino.Logger = logger,
): void {
  parentLogger.info(
    {
      metric: name,
      value,
      labels,
      type: "histogram",
    },
    `metric:${name}`,
  );
}

// ============================================================================
// Export Types
// ============================================================================

export type Logger = pino.Logger;
