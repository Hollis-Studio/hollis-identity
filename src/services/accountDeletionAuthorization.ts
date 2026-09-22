/**
 * @ai-context Decides whether a DELETE /auth/account request is authorized.
 *
 * Current clients first obtain a short-lived deletion grant from
 * POST /auth/account/deletion-authorization (fresh password / MFA / provider
 * proof) and send it as `{ authorization }`. Workouts builds already shipped
 * send no body at all; those are accepted as "legacy" (access token only, the
 * pre-grant behavior) until the sunset from getLegacyAccountDeleteSunset().
 * A request that DOES carry `authorization` must present a valid grant — a bad
 * grant never falls back to the legacy path.
 *
 * deps: jwtKeys | consumers: routes/auth.ts
 */

import { verifyJwt } from "../lib/jwtKeys";

export const ACCOUNT_DELETION_GRANT_TYPE = "account_deletion";
export const ACCOUNT_DELETION_GRANT_PURPOSE = "delete_identity_account";

export type AccountDeletionAuthorizationResult =
  | { ok: true; mode: "grant" | "legacy" }
  | { ok: false; message: string };

function hasAuthorizationField(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    Object.prototype.hasOwnProperty.call(body, "authorization") &&
    (body as { authorization?: unknown }).authorization !== undefined
  );
}

export function resolveAccountDeletionAuthorization(
  body: unknown,
  userId: string,
  options: { now: Date; legacySunset: Date | null },
): AccountDeletionAuthorizationResult {
  if (!hasAuthorizationField(body)) {
    const { now, legacySunset } = options;
    if (legacySunset && now.getTime() < legacySunset.getTime()) {
      return { ok: true, mode: "legacy" };
    }
    return { ok: false, message: "Deletion authorization is required" };
  }

  const authorization = (body as { authorization: unknown }).authorization;
  if (typeof authorization !== "string" || authorization.length < 20) {
    return { ok: false, message: "Deletion authorization is invalid" };
  }
  let grant: { sub?: string; type?: string; purpose?: string };
  try {
    grant = verifyJwt(authorization);
  } catch {
    return { ok: false, message: "Deletion authorization is invalid" };
  }
  if (
    grant.sub !== userId ||
    grant.type !== ACCOUNT_DELETION_GRANT_TYPE ||
    grant.purpose !== ACCOUNT_DELETION_GRANT_PURPOSE
  ) {
    return { ok: false, message: "Deletion authorization is invalid" };
  }
  return { ok: true, mode: "grant" };
}
