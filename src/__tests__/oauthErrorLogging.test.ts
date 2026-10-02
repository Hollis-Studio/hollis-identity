import assert from "node:assert/strict";
import { test } from "node:test";
import express from "express";
import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { authRouter } from "../routes/auth";
import { validateEnvOnStartup } from "../lib/env";
import { prisma } from "../lib/prisma";

test("OAuth rejects malformed credentials as warnings while database outages stay errors", async (t) => {
  process.env.APPLE_SERVICE_ID = "synthetic-apple-client";
  process.env.GOOGLE_CLIENT_ID = "synthetic-google-client";
  validateEnvOnStartup();
  const levels: string[] = [];
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info: () => levels.push("info"), warn: () => levels.push("warn"),
      error: () => levels.push("error") } as unknown as NonNullable<typeof req.log>;
    next();
  });
  app.use("/auth", authRouter);
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  assert(address && typeof address !== "string");
  const request = (provider: string, idToken: string) => fetch(`http://127.0.0.1:${address.port}/auth/oauth`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ provider, idToken }),
  });

  const malformed = await request("apple", "not-a-jwt");
  assert.equal(malformed.status, 400);
  assert.deepEqual(levels.splice(0), ["warn"]);
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const key = { ...publicKey.export({ format: "jwk" }), kid: "synthetic-kid" };
  t.mock.method(globalThis, "fetch", async (input, init) => {
    if (String(input).startsWith("http://127.0.0.1:")) {
      return originalFetch(input, init);
    }
    if (String(input).includes("appleid.apple.com")) {
      return new Response(JSON.stringify({ keys: [key] }));
    }
    return new Response(JSON.stringify({ iss: "https://accounts.google.com", aud: "synthetic-google-client",
      exp: Math.floor(Date.now() / 1000) + 300, sub: "synthetic-google-subject", email_verified: "true" }));
  });
  const wrongAlgorithm = jwt.sign({ sub: "synthetic-subject" }, "synthetic-secret", {
    algorithm: "HS256", keyid: "synthetic-kid",
  });
  assert.equal((await request("apple", wrongAlgorithm)).status, 400);
  assert.deepEqual(levels.splice(0), ["warn"]);

  const originalTransaction = prisma.$transaction;
  t.after(() => { prisma.$transaction = originalTransaction; });
  prisma.$transaction = (async () => { throw new Error("Synthetic database outage"); }) as typeof prisma.$transaction;
  assert.equal((await request("google", "synthetic-provider-proof")).status, 500);
  assert.deepEqual(levels.splice(0), ["error"]);
});

const originalFetch = globalThis.fetch;
