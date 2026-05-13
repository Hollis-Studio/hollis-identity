/**
 * Express type augmentation for Identity Service authentication.
 *
 * Extends Request with custom auth properties.
 * organizationId is optional — Workouts users have no org.
 */

declare module 'express-serve-static-core' {
  interface Request {
    user?: {
      userId: string;
      role: string;
      /** Organization ID (optional — absent for Workouts users) */
      organizationId?: string;
      /** JWT ID for session tracking/revocation */
      jti?: string;
      /** Unix timestamp (ms) of MFA verification */
      mfaVerifiedAt?: number;
      /** Whether user has at least one verified MfaCredential */
      mfaEnabled?: boolean;
    };
    /** User ID extracted from JWT (used by SSE auth middleware) */
    userId?: string;
    /** Request ID for tracing */
    requestId?: string;
    /** Pino logger instance attached by middleware */
    log?: import('pino').Logger;
  }
}

export {};
