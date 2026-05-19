/**
 * @ai-context Hollis Identity Service — Express app entry point
 *
 * Sets up middleware, mounts Identity auth routes, and starts the HTTP server.
 */

import crypto from "crypto";
import cors, { type CorsOptions } from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { authRouter, jwksHandler, verifyTokenPostHandler } from "./routes/auth.js";
import { mfaRouter } from "./routes/mfa.js";
import { env, validateEnvOnStartup } from "./lib/env.js";
import { logger } from "./lib/logger.js";
import { errorHandler } from "./middleware/errorHandler.js";
import {
  authSessionRateLimiter,
  loginEmailRateLimiter,
  loginRateLimiter,
} from "./middleware/rateLimit.js";

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
// Health check
// ============================================================================

  app.get("/health", (_req, res) => {
    res.json({ ok: true, service: "hollis-identity" });
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

const app = createApp();

// ============================================================================
// Start server
// ============================================================================

if (env.NODE_ENV !== "test") {
  validateEnvOnStartup();

  const port = env.PORT;

  app.listen(port, () => {
    logger.info({ port }, "Hollis Identity Service started");
  });
}

export default app;
