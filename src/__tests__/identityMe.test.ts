import assert from "node:assert/strict";
import { after, before, beforeEach, it, mock } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { OAUTH_PROVIDERS, UserRoleSchema } from "@hollis-studio/contracts";
import { z } from "zod";
import { validateEnvOnStartup } from "../lib/env";
import { prisma, type OAuthProviderType } from "../lib/prisma";
import { generateAccessTokenWithJti } from "../services/authService";

// Mirrors IdentityMeResponseSchema from @hollis-studio/contracts 0.2.0-alpha.91
// (domain/identity-auth.ts). TODO(contracts alpha.91): import it instead.
const IdentityMeResponseSchema = z.object({
  userId: z.string().min(1),
  email: z.string().min(1),
  displayName: z.string().min(1),
  role: UserRoleSchema,
  organizationId: z.string().nullable(),
  emailVerified: z.boolean(),
  provider: z.enum(["password", ...OAUTH_PROVIDERS]),
  onboardingResetAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

const USER_ID = "me-user";
const CREATED_AT = new Date("2026-01-02T03:04:05.000Z");
const UPDATED_AT = new Date("2026-02-03T04:05:06.000Z");

interface UserRow {
  passwordHash: string;
  displayName: string | null;
  /** Links as Prisma returns them for the route's select: earliest first, at most one. */
  oAuthAccounts: Array<{ provider: OAuthProviderType }>;
}

const originalUserFindUnique = prisma.user.findUnique;
const originalResetFindUnique = prisma.userOnboardingReset.findUnique;
let server: Server;
let baseUrl: string;
let userQueries: unknown[];

function mockUser(row: UserRow): void {
  prisma.user.findUnique = mock.fn(async (args: unknown) => {
    userQueries.push(args);
    return {
      id: USER_ID,
      email: "member@example.invalid",
      role: "CLIENT",
      organizationId: null,
      isActive: true,
      createdAt: CREATED_AT,
      updatedAt: UPDATED_AT,
      emailVerified: new Date(),
      ...row,
    };
  }) as unknown as typeof prisma.user.findUnique;
}

async function getMe(): Promise<{ status: number; body: { data: Record<string, unknown> } }> {
  const { token } = generateAccessTokenWithJti(USER_ID, "CLIENT", null, {
    account: { email: "member@example.invalid", emailVerified: true },
  });
  const response = await fetch(`${baseUrl}/v1/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return { status: response.status, body: (await response.json()) as { data: Record<string, unknown> } };
}

before(async () => {
  validateEnvOnStartup();
  const { createApp } = await import("../index");
  server = createApp().listen(0);
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

beforeEach(() => {
  userQueries = [];
  prisma.userOnboardingReset.findUnique = mock.fn(async () => null) as unknown as typeof prisma.userOnboardingReset.findUnique;
});

after(() => {
  server.close();
  mock.restoreAll();
  prisma.user.findUnique = originalUserFindUnique;
  prisma.userOnboardingReset.findUnique = originalResetFindUnique;
});

it("reports a password account as password, with its stored display name", async () => {
  mockUser({ passwordHash: "$2b$12$hash", displayName: "Sam Member", oAuthAccounts: [] });
  const { status, body } = await getMe();
  assert.equal(status, 200);
  const me = IdentityMeResponseSchema.parse(body.data);
  assert.equal(me.provider, "password");
  assert.equal(me.displayName, "Sam Member");
  assert.equal(me.createdAt, CREATED_AT.toISOString());
  assert.equal("passwordHash" in body.data, false);
  assert.equal("oAuthAccounts" in body.data, false);
});

it("reports an OAuth-only account as the provider it was created with", async () => {
  for (const [link, expected] of [["GOOGLE", "google"], ["APPLE", "apple"]] as const) {
    mockUser({ passwordHash: "", displayName: null, oAuthAccounts: [{ provider: link }] });
    const { status, body } = await getMe();
    assert.equal(status, 200);
    assert.equal(IdentityMeResponseSchema.parse(body.data).provider, expected);
    assert.equal("passwordHash" in body.data, false);
  }
});

it("reports a password account with a linked OAuth identity as password", async () => {
  mockUser({ passwordHash: "$2b$12$hash", displayName: null, oAuthAccounts: [{ provider: "GOOGLE" }] });
  const { body } = await getMe();
  assert.equal(IdentityMeResponseSchema.parse(body.data).provider, "password");
});

it("asks for the earliest OAuth link so a later link cannot change the provider", async () => {
  mockUser({ passwordHash: "", displayName: null, oAuthAccounts: [{ provider: "APPLE" }] });
  await getMe();
  const select = (userQueries[0] as { select: Record<string, unknown> }).select;
  assert.equal(select.passwordHash, true);
  assert.deepEqual(select.oAuthAccounts, {
    select: { provider: true },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    take: 1,
  });
});

it("falls back to the e-mail local part when the account has no display name", async () => {
  for (const displayName of [null, ""]) {
    mockUser({ passwordHash: "", displayName, oAuthAccounts: [{ provider: "GOOGLE" }] });
    const { body } = await getMe();
    assert.equal(IdentityMeResponseSchema.parse(body.data).displayName, "member");
  }
});

it("keeps password as the answer for an account with neither a password nor a link", async () => {
  mockUser({ passwordHash: "", displayName: "Orphan", oAuthAccounts: [] });
  const { body } = await getMe();
  assert.equal(IdentityMeResponseSchema.parse(body.data).provider, "password");
});

it("keeps every field older clients read", async () => {
  mockUser({ passwordHash: "$2b$12$hash", displayName: "Sam Member", oAuthAccounts: [] });
  const { body } = await getMe();
  assert.deepEqual(Object.keys(body.data).sort(), [
    "createdAt", "displayName", "email", "emailVerified", "onboardingResetAt",
    "organizationId", "provider", "role", "updatedAt", "userId",
  ]);
});
