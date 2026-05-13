/**
 * @ai-context Hollis Identity Service — Express app entry point
 *
 * Sets up middleware, mounts the auth router (empty stub until W6f),
 * and starts the HTTP server.
 *
 * NOTE: This file may not typecheck until W6d/W6f complete the refactoring
 * and wire in the auth routes. That is expected at this bootstrap stage.
 */

import express from "express";
import { authRouter, jwksHandler } from "./routes/auth.js";
import { mfaRouter } from "./routes/mfa.js";
import { env } from "./lib/env.js";
import { logger } from "./lib/logger.js";

const app = express();

// ============================================================================
// Middleware
// ============================================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// Health check
// ============================================================================

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "hollis-identity" });
});

// ============================================================================
// Routes — mfa router mounted BEFORE auth router to avoid prefix collision
// ============================================================================

// MFA routes: /v1/auth/mfa/* — must be mounted before /v1/auth so that
// Express does not delegate /v1/auth/mfa/... to the auth router first.
app.use("/v1/auth/mfa", mfaRouter);

// Auth routes: /v1/auth/*
app.use("/v1/auth", authRouter);

// JWKS endpoint is root-scoped (not under /v1/auth) per OIDC convention.
// TODO(W6h): migrate to RS256 + publish JWK. HS256 has no public key to publish.
app.get("/.well-known/jwks.json", jwksHandler);

// ============================================================================
// Start server
// ============================================================================

const port = env.PORT;

app.listen(port, () => {
  logger.info({ port }, "Hollis Identity Service started");
});

export default app;
