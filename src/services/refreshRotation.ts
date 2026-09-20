/** Atomic refresh rotation with a bounded, cross-instance retry window.
 * Only token hashes are persisted. Deterministic signing reconstructs the exact
 * successor after a lost response; no recoverable bearer token is stored.
 */
import crypto from "crypto";
import type { JwtPayload } from "jsonwebtoken";
import { prisma } from "../lib/prisma";
import { signJwt } from "../lib/jwtKeys";

// Workouts times out refresh requests after 30 seconds. Two minutes covers a
// lost-response timeout plus an immediate retry and network/scheduling margin.
// This remains bounded: later replay revokes the entire token family.
export const REFRESH_RETRY_GRACE_MS = 120_000;
const ACCESS_TTL_MS = 90 * 24 * 60 * 60 * 1000;
export class RefreshRotationError extends Error {
  constructor(public readonly code: string) { super("Refresh token is no longer valid"); }
}
const hash = (value: string): string => crypto.createHash("sha256").update(value).digest("hex");

function successor(token: string, claims: JwtPayload, usedAt: Date, expiresAt: Date): string {
  // Keep the predecessor's canonical signed claims, including issuer/audiences,
  // so retries remain deterministic if environment configuration changes.
  return signJwt({
    ...claims,
    iat: Math.floor(usedAt.getTime() / 1000),
    exp: Math.floor(expiresAt.getTime() / 1000),
    jti: hash(`refresh-successor:v1:${token}:${usedAt.toISOString()}`),
  });
}

export async function rotateRefreshToken(token: string, claims: JwtPayload & { userId: string }): Promise<string> {
  const tokenHash = hash(token);
  const initial = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (!initial || initial.userId !== claims.userId) throw new RefreshRotationError("TOKEN_NOT_FOUND");
  const result = await prisma.$transaction(async (tx) => {
    // Serialize the whole family across ECS tasks, including replay revocation.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`refresh-family:${initial.familyId}`}, 0))`;
    const row = await tx.refreshToken.findUnique({ where: { tokenHash } });
    if (!row || row.revokedAt || row.expiresAt.getTime() <= Date.now()) return { error: "TOKEN_REVOKED" };
    const now = new Date();
    if (row.usedAt) {
      if (now.getTime() - row.usedAt.getTime() <= REFRESH_RETRY_GRACE_MS && row.replacedByTokenHash) {
        const replacement = successor(token, claims, row.usedAt, row.expiresAt);
        if (hash(replacement) !== row.replacedByTokenHash) {
          // Signing-key rollover: do not revoke an otherwise valid family or
          // return a different token when exact reconstruction is unavailable.
          throw new Error("Refresh retry signing key unavailable");
        }
        const child = await tx.refreshToken.findUnique({ where: { tokenHash: row.replacedByTokenHash } });
        if (child && !child.revokedAt && child.expiresAt > now) return { token: replacement };
      }
      await tx.refreshToken.updateMany({
        where: { familyId: row.familyId, revokedAt: null },
        data: { revokedAt: now, revokedReason: "token_reuse" },
      });
      // Replayed credentials also revoke previously issued long-lived access
      // tokens, in the same transaction as family revocation.
      const expiresAt = new Date(now.getTime() + ACCESS_TTL_MS + 1000);
      await tx.$executeRaw`
        INSERT INTO "UserTokenDenylistEntry" ("userId", "deniedBefore", "expiresAt", "reason", "revokedAt")
        VALUES (${row.userId}, ${now}, ${expiresAt}, 'token_reuse', CURRENT_TIMESTAMP)
        ON CONFLICT ("userId") DO UPDATE SET
          "deniedBefore" = GREATEST("UserTokenDenylistEntry"."deniedBefore", EXCLUDED."deniedBefore"),
          "expiresAt" = GREATEST("UserTokenDenylistEntry"."expiresAt", EXCLUDED."expiresAt"),
          "reason" = EXCLUDED."reason"
      `;
      return { error: "TOKEN_REUSE_DETECTED" };
    }
    const replacement = successor(token, claims, now, row.expiresAt);
    const replacementHash = hash(replacement);
    await tx.refreshToken.update({ where: { tokenHash }, data: { usedAt: now, replacedByTokenHash: replacementHash } });
    await tx.refreshToken.create({ data: {
      userId: row.userId, tokenHash: replacementHash, familyId: row.familyId,
      generation: row.generation + 1, expiresAt: row.expiresAt,
      deviceId: row.deviceId, userAgent: row.userAgent,
    } });
    return { token: replacement };
  });
  // Throw after commit: throwing in the callback would undo reuse revocation.
  if (result.error) throw new RefreshRotationError(result.error);
  return result.token!;
}
