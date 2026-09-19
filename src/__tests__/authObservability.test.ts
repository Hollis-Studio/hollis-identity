import assert from "node:assert/strict";
import { test } from "node:test";
import express from "express";
import rateLimit from "express-rate-limit";
import { configureProxyTrust } from "../lib/proxyTrust";
import { extractIp } from "../services/authAuditService";
import { AuthError, refresh } from "../services/authService";
import { logAuthFailure } from "../lib/authFailureLogging";
import { signJwt } from "../lib/jwtKeys";
import { prisma } from "../lib/prisma";

test("ALB client IPs have isolated quotas; spoofed leftmost XFF cannot bypass them", async (t) => {
  const app = express();
  configureProxyTrust(app, "production");
  app.use(rateLimit({ windowMs: 60_000, limit: 2 }));
  app.get("/", (req, res) => res.json({ ip: req.ip, auditIp: extractIp(req) }));
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  assert(address && typeof address !== "string");
  const request = (xff: string) => fetch(`http://127.0.0.1:${address.port}/`, {
    headers: { "x-forwarded-for": xff },
  });
  const first = await request("198.51.100.99, 203.0.113.1");
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { ip: "203.0.113.1", auditIp: "203.0.113.1" });
  assert.equal((await request("198.51.100.98, 203.0.113.1")).status, 200);
  assert.equal((await request("198.51.100.97, 203.0.113.1")).status, 429);
  assert.equal((await request("203.0.113.2")).status, 200);
});

test("direct local servers ignore forwarded client IPs", async (t) => {
  const app = express();
  configureProxyTrust(app, "development");
  app.get("/", (req, res) => res.json({ ip: req.ip, auditIp: extractIp(req) }));
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  assert(address && typeof address !== "string");
  const response = await fetch(`http://127.0.0.1:${address.port}/`, {
    headers: { "x-forwarded-for": "203.0.113.1" },
  });
  const result = await response.json() as { ip: string; auditIp: string };
  assert.match(result.ip, /127\.0\.0\.1$/);
  assert.equal(result.auditIp, result.ip);
});

test("only known routine refusals are informational; security refusals and outages remain visible", () => {
  const levels: string[] = [];
  const log = {
    info: () => { levels.push("info"); },
    warn: () => { levels.push("warn"); },
    error: () => { levels.push("error"); },
  };
  logAuthFailure(log, "login", new AuthError("Invalid credentials", "INVALID_CREDENTIALS"));
  logAuthFailure(log, "refresh", new AuthError("Expired", "TOKEN_EXPIRED"));
  logAuthFailure(log, "refresh", new AuthError("Revoked", "TOKEN_REVOKED"));
  logAuthFailure(log, "login", new AuthError("Locked", "ACCOUNT_LOCKED", 429));
  logAuthFailure(log, "refresh", new Error("Database unavailable"));
  logAuthFailure(log, "login", new AuthError("Unexpected auth failure", "UNKNOWN"));
  assert.deepEqual(levels, ["info", "info", "warn", "warn", "error", "error"]);
});

test("refresh distinguishes JWT refusal from database failure and returns HTTP 500 for outages", async (t) => {
  const expired = signJwt({ userId: "test-user", type: "refresh" }, { expiresIn: -1 });
  await assert.rejects(refresh(expired), (error: unknown) =>
    error instanceof AuthError && error.code === "TOKEN_EXPIRED");
  await assert.rejects(refresh("not-a-jwt"), (error: unknown) =>
    error instanceof AuthError && error.code === "TOKEN_INVALID");

  const outage = new Error("Simulated database unavailable");
  // Prisma delegates are dynamic proxies without method descriptors.
  const originalFind = prisma.refreshToken.findUnique;
  const originalAudit = prisma.authAuditLog.create;
  prisma.refreshToken.findUnique = async () => { throw outage; };
  prisma.authAuditLog.create = (async () => ({})) as typeof originalAudit;
  t.after(() => {
    prisma.refreshToken.findUnique = originalFind;
    prisma.authAuditLog.create = originalAudit;
  });
  const token = signJwt({ userId: "test-user", type: "refresh" }, {
    expiresIn: "1h", audience: "hollis-workouts",
  });
  await assert.rejects(refresh(token), (error: unknown) => error === outage);

  const { createApp } = await import("../index");
  assert.equal(createApp().get("trust proxy"), false);
  const server = createApp().listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  assert(address && typeof address !== "string");
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/auth/refresh`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ refreshToken: token }),
  });
  assert.equal(response.status, 500);
  assert.equal((await response.json() as { code: string }).code, "REFRESH_ERROR");
});
