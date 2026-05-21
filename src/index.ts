/**
 * @ai-context Hollis Identity Service — Express app entry point
 *
 * Sets up middleware, mounts Identity auth routes, and starts the HTTP server.
 *
 * Boot order:
 *   1. Sentry init (early — captures startup errors)
 *   2. Env validation
 *   3. App / routes
 *   4. Server listen
 *   5. SIGTERM / SIGINT graceful shutdown
 */

// ============================================================================
// Sentry — init early so startup errors are captured
// ============================================================================

import * as Sentry from "@sentry/node";
import { env, validateEnvOnStartup } from "./lib/env.js";
import { logger } from "./lib/logger.js";

const sentryDsn = process.env.SENTRY_DSN;

if (sentryDsn && sentryDsn.trim() !== "") {
  const sentryEnv = process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? "development";
  Sentry.init({
    dsn: sentryDsn,
    enabled: sentryEnv !== "development",
    environment: sentryEnv,
    release: process.env.APP_VERSION ?? process.env.IMAGE_TAG ?? "unknown",
    tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? "0.1"),
    // SECURITY: Do NOT send PII to Sentry.
    // Prevents the SDK from auto-attaching IP addresses, usernames, request cookies.
    sendDefaultPii: false,
    beforeSend(event) {
      // Strip PHI-risk fields: request body, user context, cookies, query params
      if (event.request) {
        delete event.request.data;
        delete event.request.cookies;
        delete event.request.query_string;
        if (event.request.headers) {
          // Remove auth headers that may carry tokens
          delete event.request.headers["authorization"];
          delete event.request.headers["cookie"];
        }
      }
      delete event.user;
      return event;
    },
  });
  process.stdout.write("[STARTUP] Sentry error tracking initialized\n");
}

if (!sentryDsn && process.env.NODE_ENV === "production") {
  logger.warn(
    { component: "startup" },
    "SENTRY_DSN is not configured in production — crash reporting is disabled",
  );
}

// ============================================================================
// Imports
// ============================================================================

import crypto from "crypto";
import cors, { type CorsOptions } from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { authRouter, jwksHandler, verifyTokenPostHandler } from "./routes/auth.js";
import { mfaRouter } from "./routes/mfa.js";
import { errorHandler } from "./middleware/errorHandler.js";
import {
  authSessionRateLimiter,
  loginEmailRateLimiter,
  loginRateLimiter,
} from "./middleware/rateLimit.js";
import { prisma } from "./lib/prisma.js";

// ============================================================================
// Helpers
// ============================================================================

function buildCorsOptions(): CorsOptions {
  const origins = env.CORS_ORIGINS?.split(",").map((origin) => origin.trim()).filter(Boolean) ?? [];

  if (origins.length === 0) {
    return {
      origin: env.NODE_ENV === "production" ? false : true,
      credentials: false,
    };
  }

  return {
    origin: origins,
    credentials: false,
  };
}

function requestContext(req: Request, res: Response, next: NextFunction): void {
  const incomingRequestId = req.headers["x-request-id"];
  const requestId = Array.isArray(incomingRequestId)
    ? incomingRequestId[0]
    : incomingRequestId;

  req.requestId = requestId || crypto.randomUUID();
  req.log = logger.child({ requestId: req.requestId });
  res.setHeader("X-Request-Id", req.requestId);
  next();
}

// ============================================================================
// App factory
// ============================================================================

export function createApp(): express.Express {
  const app = express();

// ============================================================================
// Middleware
// ============================================================================

  app.use(requestContext);
  app.use(cors(buildCorsOptions()));
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// ============================================================================
// Health check (Task 6 — DB-aware)
// ============================================================================

  app.get("/health", async (_req, res) => {
    try {
      // Lightweight DB ping — verifies the connection pool is alive
      await prisma.$queryRaw`SELECT 1`;
      res.json({ ok: true, service: "hollis-identity", db: "ok" });
    } catch {
      res.status(503).json({ ok: false, service: "hollis-identity", db: "unreachable" });
    }
  });

// ============================================================================
// OIDC Discovery (Task 3)
// Gated behind ENABLE_OIDC_DISCOVERY (default: false).
// Returns 404 when disabled — less informative to scanners than 501.
// Flip true ONLY when WebAuthn + key rotation + logout webhook are shipped.
// ============================================================================

  app.get("/.well-known/openid-configuration", (_req, res) => {
    if (!env.ENABLE_OIDC_DISCOVERY) {
      res.status(404).json({ success: false, error: "Not found", code: "NOT_FOUND" });
      return;
    }

    const issuer = env.JWT_ISSUER ?? `http://localhost:${env.PORT}`;
    // Strip trailing slash for consistency
    const base = issuer.replace(/\/$/, "");

    res.json({
      issuer: base,
      // JWKS endpoint — RS256 public keys served here
      jwks_uri: `${base}/.well-known/jwks.json`,
      // Token introspection / verification
      introspection_endpoint: `${base}/verify`,
      // These endpoints exist in the identity service
      token_endpoint: `${base}/v1/auth/refresh`,
      userinfo_endpoint: `${base}/v1/auth/me`,
      // Authorization endpoint not implemented (Identity uses direct API; no browser redirect flow)
      authorization_endpoint: null,
      // End-session endpoint not implemented in this pass
      end_session_endpoint: null,
      // Supported algorithms
      id_token_signing_alg_values_supported: ["RS256", "HS256"],
      // Scopes supported by this service
      scopes_supported: ["openid", "profile", "email"],
      // Response types — only code-less direct token issuance
      response_types_supported: ["token"],
      // Token endpoint auth methods — service-to-service callers use Bearer tokens
      token_endpoint_auth_methods_supported: ["none"],
      // Claims available in issued tokens
      claims_supported: [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "jti",
        "userId",
        "role",
        "organizationId",
        "mfaVerifiedAt",
        "mfaEnabled",
        "type",
      ],
      subject_types_supported: ["public"],
    });
  });

// ============================================================================
// Routes — mfa router mounted BEFORE auth router to avoid prefix collision
// ============================================================================

  app.use("/v1/auth/login", loginRateLimiter, loginEmailRateLimiter);
  app.use("/v1/auth/register", loginRateLimiter);
  app.use("/v1/auth", authSessionRateLimiter);

// MFA routes: /v1/auth/mfa/* — must be mounted before /v1/auth so that
// Express does not delegate /v1/auth/mfa/... to the auth router first.
  app.use("/v1/auth/mfa", mfaRouter);

// Auth routes: /v1/auth/*
  app.use("/v1/auth", authRouter);

// JWKS endpoint is root-scoped (not under /v1/auth) per OIDC convention.
// Production publishes RS256 public keys; local HS256 mode returns an empty key set.
  app.get("/.well-known/jwks.json", jwksHandler);
  app.post("/verify", verifyTokenPostHandler);

  app.use((_req, res) => {
    res.status(404).json({ success: false, error: "Not found", code: "NOT_FOUND" });
  });

  app.use(errorHandler);

  return app;
}

// ============================================================================
// Start server
// ============================================================================

const app = createApp();

if (env.NODE_ENV !== "test") {
  validateEnvOnStartup();

  const port = env.PORT;

  const server = app.listen(port, () => {
    logger.info({ port }, "Hollis Identity Service started");
  });

  server.on("error", (err: Error) => {
    logger.fatal({ err, port }, "Server failed to bind — exiting");
    process.exit(1);
  });

// ============================================================================
// Graceful shutdown (Task 5)
// ============================================================================

  async function gracefulShutdown(signal: string): Promise<void> {
    try {
      logger.info({ signal }, "Shutdown signal received, draining connections...");

      // Stop accepting new connections; wait for in-flight requests to drain.
      // Force-exit after 15 s to avoid hanging indefinitely.
      await new Promise<void>((resolve) => {
        const forceExit = setTimeout(() => {
          logger.warn({ signal }, "Graceful shutdown timed out — forcing exit");
          resolve();
        }, 15_000);

        server.close(() => {
          clearTimeout(forceExit);
          resolve();
        });
      });

      // Disconnect Prisma connection pool
      await prisma.$disconnect();

      logger.info({ signal }, "Graceful shutdown complete");
      process.exit(0);
    } catch (err) {
      logger.error({ err, signal }, "Error during graceful shutdown — forcing exit");
      process.exit(1);
    }
  }

  process.on("SIGTERM", () => {
    void gracefulShutdown("SIGTERM");
  });

  process.on("SIGINT", () => {
    void gracefulShutdown("SIGINT");
  });

  process.on("unhandledRejection", (reason: unknown) => {
    logger.fatal({ err: reason }, "Unhandled promise rejection");
    void gracefulShutdown("unhandledRejection").finally(() => process.exit(1));
  });

  process.on("uncaughtException", (err: Error) => {
    logger.fatal({ err }, "Uncaught exception");
    void gracefulShutdown("uncaughtException").finally(() => process.exit(1));
  });
}

export default app;
