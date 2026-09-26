/**
 * @ai-context Derives an account's sign-in `provider` for GET /auth/me.
 *
 * ACCOUNT-level, not session-level: access tokens carry no sign-in method, so
 * the answer comes from what the account can prove. "password" when the account
 * has a password (OAuth-only accounts store passwordHash ""), otherwise the
 * OAuth provider linked first (the one the account was created with). A linked
 * account (password plus Google/Apple) is therefore "password". Clients use it
 * for account-level questions: Change Password, deletion re-auth, signup-method
 * telemetry (hollis-workouts#129/#246).
 *
 * deps: contracts (OAuthProvider, IdentityAccountProvider), prisma types, logger | consumers: routes/auth.ts
 */

import type { OAuthProvider } from "@hollis-studio/contracts";
import type { IdentityAccountProvider } from "@hollis-studio/contracts/domain/identity-auth";
import { logger } from "../lib/logger";
import type { OAuthProviderType } from "../lib/prisma";

const DB_TO_PROVIDER: Record<OAuthProviderType, OAuthProvider> = {
  APPLE: "apple",
  GOOGLE: "google",
};

export function resolveAccountProvider(
  passwordHash: string,
  firstLinkedProvider: OAuthProviderType | undefined,
): IdentityAccountProvider {
  if (passwordHash !== "") return "password";
  if (firstLinkedProvider) return DB_TO_PROVIDER[firstLinkedProvider];
  logger.warn(
    { component: "accountProvider" },
    "Account has neither a password nor an OAuth link; reporting provider as password",
  );
  return "password";
}
