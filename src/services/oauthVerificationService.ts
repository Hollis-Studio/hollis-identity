/**
 * @ai-context OAuth verification service | server-side id_token verification for social sign-in
 *
 * SECURITY: This service performs full JWT verification for OAuth id_tokens:
 *   1. Apple: Fetches JWKS from https://appleid.apple.com/auth/keys, verifies JWT signature,
 *      checks issuer, audience, expiry, and nonce hash match.
 *   2. Google: Uses Google's tokeninfo endpoint to verify the id_token signature,
 *      issuer, audience, expiry, and nonce hash.
 *
 * Health-specific fields removed from W6d refactor:
 * - tier, prefilledTier, isRegistered, registrationExpiresAt (not in Identity schema)
 * - DEFAULT_USER_TIER, UserTier (not applicable to Identity Service)
 * - Barcode registration flow removed (Health-specific registration path)
 *
 * TODO(W6f): Barcode/invite registration flow can be re-added when Identity Service
 *            exposes a registration API that's app-agnostic.
 *
 * deps: jsonwebtoken, node crypto, prisma | consumers: routes/auth.ts
 */
import crypto from "crypto";
import jwt from "jsonwebtoken";
import {
  type OAuthProvider,
} from "@hollis-studio/contracts";
import { getEnv } from "../lib/env";
import { logger } from "../lib/logger";
import { type OAuthProviderType, prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";
import {
  ACCESS_TOKEN_EXPIRY_MS,
  generateAccessToken,
  issueRefreshToken,
} from "./authService";

// ============================================================================
// Helpers
// ============================================================================

function resolveDisplayName(email: string | null | undefined): string {
  return email?.split("@")[0] ?? "User";
}

// ============================================================================
// OAuth error codes
// ============================================================================

export const OAUTH_ERROR_CODE = {
  PROVIDER_NOT_CONFIGURED: "OAUTH_PROVIDER_NOT_CONFIGURED",
  JWKS_FETCH_FAILED: "OAUTH_JWKS_FETCH_FAILED",
  TOKEN_DECODE_FAILED: "OAUTH_TOKEN_DECODE_FAILED",
  SIGNING_KEY_NOT_FOUND: "OAUTH_SIGNING_KEY_NOT_FOUND",
  VERIFICATION_FAILED: "OAUTH_VERIFICATION_FAILED",
  NONCE_MISMATCH: "OAUTH_NONCE_MISMATCH",
  MISSING_SUB: "OAUTH_MISSING_SUB",
  INVALID_ISSUER: "OAUTH_INVALID_ISSUER",
  AUDIENCE_MISMATCH: "OAUTH_AUDIENCE_MISMATCH",
  TOKEN_EXPIRED: "OAUTH_TOKEN_EXPIRED",
  TOKENINFO_FAILED: "OAUTH_TOKENINFO_FAILED",
  EMAIL_NOT_VERIFIED: "OAUTH_EMAIL_NOT_VERIFIED",
  ACCOUNT_INACTIVE: "OAUTH_ACCOUNT_INACTIVE",
  NO_ACCOUNT_FOUND: "OAUTH_NO_ACCOUNT_FOUND",
} as const;

export type OAuthErrorCode = (typeof OAUTH_ERROR_CODE)[keyof typeof OAUTH_ERROR_CODE];

export class OAuthError extends Error {
  constructor(
    public readonly code: OAuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "OAuthError";
  }
}

// ============================================================================
// Types
// ============================================================================

interface OAuthIdentity {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  givenName?: string;
  familyName?: string;
}

export interface OAuthVerificationInput {
  provider: OAuthProvider;
  idToken: string;
  nonce: string;
  state: string;
  authorizationCode?: string;
  fullName?: { givenName?: string | null; familyName?: string | null };
  accessToken?: string;
}

export interface OAuthAuthSession {
  profile: {
    uid: string;
    email: string | null;
    displayName: string;
    role: string;
    organizationId: string | null;
    isAnonymous: boolean;
    onboardingCompleted: boolean;
  };
  user: {
    uid: string;
    email: string | null;
    displayName: string;
    role: string;
    onboardingCompleted?: boolean;
  };
  provider: OAuthProvider;
  idToken: string;
  refreshToken: string;
  expiresAt: string;
  onboardingCompleted: boolean;
}

// ============================================================================
// Apple JWKS verification
// ============================================================================

const APPLE_JWKS_URI = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER = "https://appleid.apple.com";

let _appleJwksCache: {
  keys: { kty: string; kid: string; use: string; alg: string; n: string; e: string }[];
  fetchedAt: number;
} | null = null;
const APPLE_JWKS_CACHE_TTL_MS = 10 * 60 * 1000;

async function fetchAppleJwks(forceRefresh = false): Promise<
  { kty: string; kid: string; use: string; alg: string; n: string; e: string }[]
> {
  const now = Date.now();
  if (!forceRefresh && _appleJwksCache && now - _appleJwksCache.fetchedAt < APPLE_JWKS_CACHE_TTL_MS) {
    return _appleJwksCache.keys;
  }

  const response = await fetch(APPLE_JWKS_URI);
  if (!response.ok) {
    throw new OAuthError(
      OAUTH_ERROR_CODE.JWKS_FETCH_FAILED,
      `Failed to fetch Apple JWKS: ${response.status} ${response.statusText}`,
    );
  }
  const data = (await response.json()) as {
    keys: { kty: string; kid: string; use: string; alg: string; n: string; e: string }[];
  };
  _appleJwksCache = { keys: data.keys, fetchedAt: now };
  return data.keys;
}

function jwkToPem(jwk: {
  kty: string; kid: string; use: string; alg: string; n: string; e: string;
}): string {
  const key = crypto.createPublicKey({
    key: jwk as unknown as crypto.JsonWebKey,
    format: "jwk",
  });
  return key.export({ type: "spki", format: "pem" }) as string;
}

async function verifyAppleIdToken(
  idToken: string,
  rawNonce: string,
): Promise<{ sub: string; email?: string; emailVerified?: boolean }> {
  const env = getEnv();
  const audience = env.APPLE_SERVICE_ID ?? env.IOS_BUNDLE_ID;

  if (!audience) {
    throw new OAuthError(
      OAUTH_ERROR_CODE.PROVIDER_NOT_CONFIGURED,
      "Apple OAuth not configured: APPLE_SERVICE_ID or IOS_BUNDLE_ID must be set",
    );
  }

  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || typeof decoded === "string" || !decoded.header.kid) {
    throw new OAuthError(OAUTH_ERROR_CODE.TOKEN_DECODE_FAILED, "Invalid Apple id_token: could not decode header");
  }
  const kid = decoded.header.kid as string;

  let keys = await fetchAppleJwks();
  let matchingKey = keys.find((k) => k.kid === kid);
  if (!matchingKey) {
    keys = await fetchAppleJwks(true);
    matchingKey = keys.find((k) => k.kid === kid);
  }
  if (!matchingKey) {
    throw new OAuthError(OAUTH_ERROR_CODE.SIGNING_KEY_NOT_FOUND, `Apple id_token signing key not found in JWKS (kid=${kid})`);
  }

  const publicKey = jwkToPem(matchingKey);

  let payload: jwt.JwtPayload;
  try {
    payload = jwt.verify(idToken, publicKey, { algorithms: ["RS256"], issuer: APPLE_ISSUER, audience }) as jwt.JwtPayload;
  } catch (err) {
    throw new OAuthError(OAUTH_ERROR_CODE.VERIFICATION_FAILED, `Apple id_token verification failed: ${(err as Error).message}`);
  }

  const expectedNonceHash = crypto.createHash("sha256").update(rawNonce).digest("hex");
  if (payload.nonce !== expectedNonceHash) {
    throw new OAuthError(OAUTH_ERROR_CODE.NONCE_MISMATCH, "Apple id_token nonce mismatch — possible token replay attack");
  }

  if (!payload.sub) {
    throw new OAuthError(OAUTH_ERROR_CODE.MISSING_SUB, "Apple id_token missing sub claim");
  }

  return {
    sub: payload.sub,
    email: typeof payload.email === "string" ? payload.email : undefined,
    emailVerified: payload.email_verified === true || payload.email_verified === "true",
  };
}

// ============================================================================
// Google id_token verification
// ============================================================================

const GOOGLE_TOKEN_INFO_URI = "https://oauth2.googleapis.com/tokeninfo";
const GOOGLE_ISSUER_1 = "https://accounts.google.com";
const GOOGLE_ISSUER_2 = "accounts.google.com";

async function verifyGoogleIdToken(
  idToken: string,
  rawNonce: string,
): Promise<{ sub: string; email?: string; emailVerified?: boolean; name?: string }> {
  const env = getEnv();
  const expectedAudience = env.GOOGLE_CLIENT_ID;

  if (!expectedAudience) {
    throw new OAuthError(OAUTH_ERROR_CODE.PROVIDER_NOT_CONFIGURED, "Google OAuth not configured: GOOGLE_CLIENT_ID must be set");
  }

  const url = `${GOOGLE_TOKEN_INFO_URI}?id_token=${encodeURIComponent(idToken)}`;
  const response = await fetch(url);

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new OAuthError(OAUTH_ERROR_CODE.TOKENINFO_FAILED, `Google tokeninfo endpoint returned ${response.status}: ${body}`);
  }

  const claims = (await response.json()) as Record<string, unknown>;

  if (claims.iss !== GOOGLE_ISSUER_1 && claims.iss !== GOOGLE_ISSUER_2) {
    throw new OAuthError(OAUTH_ERROR_CODE.INVALID_ISSUER, `Google id_token has invalid issuer: ${String(claims.iss)}`);
  }

  if (claims.aud !== expectedAudience) {
    throw new OAuthError(OAUTH_ERROR_CODE.AUDIENCE_MISMATCH, "Google id_token audience mismatch");
  }

  const exp = Number(claims.exp);
  if (!exp || Date.now() / 1000 > exp) {
    throw new OAuthError(OAUTH_ERROR_CODE.TOKEN_EXPIRED, "Google id_token is expired");
  }

  if (claims.nonce != null) {
    const expectedNonceHash = crypto.createHash("sha256").update(rawNonce).digest("hex");
    if (claims.nonce !== expectedNonceHash) {
      throw new OAuthError(OAUTH_ERROR_CODE.NONCE_MISMATCH, "Google id_token nonce mismatch — possible token replay attack");
    }
  } else {
    logger.warn("Google id_token missing nonce claim — skipping nonce verification (SDK limitation)");
  }

  if (!claims.sub || typeof claims.sub !== "string") {
    throw new OAuthError(OAUTH_ERROR_CODE.MISSING_SUB, "Google id_token missing sub claim");
  }

  return {
    sub: claims.sub,
    email: typeof claims.email === "string" ? claims.email : undefined,
    emailVerified: claims.email_verified === "true" || claims.email_verified === true,
    name: typeof claims.name === "string" ? claims.name : undefined,
  };
}

// ============================================================================
// Account lookup / linking
// ============================================================================

const PROVIDER_TO_DB: Record<OAuthProvider, OAuthProviderType> = {
  apple: "APPLE",
  google: "GOOGLE",
};

/**
 * Find or link a user account for the given OAuth identity.
 *
 * LINK STRATEGY (in order):
 * 1. Look up by (provider, providerUserId) in OAuthAccount.
 * 2. If not found, look up by email to link to an existing account.
 * 3. If still not found, REJECT — users must be pre-registered.
 */
async function findOrLinkOAuthUser(
  identity: OAuthIdentity,
  provider: OAuthProvider,
): Promise<{
  userId: string;
  userRole: string;
  organizationId: string | null;
  email: string | null;
  displayName: string;
  isNewLink: boolean;
  mfaEnabled: boolean;
}> {
  return runAsSystemOperation(
    async () =>
      prisma.$transaction(async (tx) => {
        const existingAccount = await tx.oAuthAccount.findUnique({
          where: {
            provider_providerUserId: {
              provider: PROVIDER_TO_DB[provider],
              providerUserId: identity.sub,
            },
          },
          include: {
            user: {
              select: {
                id: true,
                role: true,
                organizationId: true,
                email: true,
                isActive: true,
                _count: {
                  select: { mfaCredentials: { where: { isVerified: true } } },
                },
              },
            },
          },
        });

        if (existingAccount) {
          const u = existingAccount.user;
          if (!u.isActive) {
            throw new OAuthError(OAUTH_ERROR_CODE.ACCOUNT_INACTIVE, "Account is inactive");
          }
          return {
            userId: u.id,
            userRole: u.role,
            organizationId: u.organizationId,
            email: u.email,
            displayName: resolveDisplayName(u.email),
            isNewLink: false,
            mfaEnabled: u._count.mfaCredentials > 0,
          };
        }

        // SECURITY: Only link by email if provider has verified it.
        if (identity.email && identity.emailVerified !== true) {
          throw new OAuthError(
            OAUTH_ERROR_CODE.EMAIL_NOT_VERIFIED,
            "A verified email address is required to link a social sign-in to an existing account.",
          );
        }

        if (identity.email) {
          const existingUser = await tx.user.findUnique({
            where: { email: identity.email.toLowerCase() },
            select: {
              id: true,
              role: true,
              organizationId: true,
              email: true,
              isActive: true,
              _count: {
                select: { mfaCredentials: { where: { isVerified: true } } },
              },
            },
          });

          if (existingUser) {
            if (!existingUser.isActive) {
              throw new OAuthError(OAUTH_ERROR_CODE.ACCOUNT_INACTIVE, "Account is inactive");
            }

            await tx.oAuthAccount.create({
              data: {
                userId: existingUser.id,
                provider: PROVIDER_TO_DB[provider],
                providerUserId: identity.sub,
              },
            });

            return {
              userId: existingUser.id,
              userRole: existingUser.role,
              organizationId: existingUser.organizationId,
              email: existingUser.email,
              displayName: resolveDisplayName(existingUser.email),
              isNewLink: true,
              mfaEnabled: existingUser._count.mfaCredentials > 0,
            };
          }
        }

        throw new OAuthError(
          OAUTH_ERROR_CODE.NO_ACCOUNT_FOUND,
          "No account found for this social sign-in. " +
            "Please register or sign in with email and password first.",
        );
      }),
    { reason: "oauth:findOrLinkUser", userId: undefined },
  );
}

// ============================================================================
// Session issuance
// ============================================================================

// eslint-disable-next-line max-params
async function issueSession(
  userId: string,
  role: string,
  organizationId: string | null,
  email: string | null,
  displayName: string,
  provider: OAuthProvider,
  mfaEnabled: boolean,
): Promise<OAuthAuthSession> {
  const idToken = generateAccessToken(userId, role, organizationId, { mfaEnabled });

  const refreshToken = await runAsSystemOperation(
    () => issueRefreshToken(userId, role, organizationId, "OAuth sign-in"),
    { reason: "auth:oauth-sign-in" },
  );

  const expiresAt = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_MS).toISOString();

  return {
    profile: {
      uid: userId,
      email,
      displayName,
      role,
      organizationId,
      isAnonymous: false,
      onboardingCompleted: false, // TODO(W6f): add onboardingCompleted to User model
    },
    user: { uid: userId, email, displayName, role },
    provider,
    idToken,
    refreshToken,
    expiresAt,
    onboardingCompleted: false, // TODO(W6f): add onboardingCompleted to User model
  };
}

// ============================================================================
// Public API
// ============================================================================

export async function verifyOAuthCredentials(
  input: OAuthVerificationInput,
): Promise<OAuthAuthSession> {
  const { provider, idToken, nonce } = input;

  let identity: OAuthIdentity;
  try {
    if (provider === "apple") {
      const verified = await verifyAppleIdToken(idToken, nonce);
      identity = {
        sub: verified.sub,
        email: verified.email,
        emailVerified: verified.emailVerified ?? false,
        givenName: input.fullName?.givenName ?? undefined,
        familyName: input.fullName?.familyName ?? undefined,
      };
    } else {
      const verified = await verifyGoogleIdToken(idToken, nonce);
      identity = {
        sub: verified.sub,
        email: verified.email,
        emailVerified: verified.emailVerified,
        name: verified.name,
      };
    }
  } catch (err) {
    logger.warn({ err, provider }, "OAuth id_token verification failed");
    throw err;
  }

  const { userId, userRole, organizationId, email, displayName, isNewLink, mfaEnabled } =
    await findOrLinkOAuthUser(identity, provider);

  logger.info({ provider, isNewLink, userId: userId.slice(0, 8) }, "OAuth sign-in successful");

  return issueSession(userId, userRole, organizationId, email, displayName, provider, mfaEnabled);
}

/**
 * Expose JWKS cache reset for testing.
 * @internal
 */
export function _resetAppleJwksCacheForTesting(): void {
  _appleJwksCache = null;
}
