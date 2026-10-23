/** Fresh proof at the factor-management boundary; bearer sessions alone are insufficient. */
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { verifyJwt, signJwt } from "../lib/jwtKeys";
import { authenticatePasswordUser, AuthError } from "./authService";
import { verifyOAuthReauthenticationProof, OAuthError } from "./oauthVerificationService";
import { validateStepUpToken } from "../middleware/mfa";

export const mfaPrimaryProofSchema = z.discriminatedUnion("method", [
  z.object({ method: z.literal("password"), currentPassword: z.string().min(1).max(128) }),
  z.object({ method: z.literal("oauth"), provider: z.enum(["apple", "google"]), idToken: z.string().min(1), nonce: z.string().min(16).optional(), clientInstallId: z.string().regex(/^[A-Za-z0-9_-]{32,128}$/).optional() }),
]);

export async function authorizeMfaEnrollment(userId: string, proof: unknown, stepUpToken: string | undefined, ip: string): Promise<boolean> {
  const existing = await prisma.mfaCredential.count({ where: { userId, isVerified: true } });
  if (existing > 0) return Boolean(stepUpToken && await validateStepUpToken(stepUpToken, userId, "MODIFY_MFA"));
  const parsed = mfaPrimaryProofSchema.safeParse(proof);
  if (!parsed.success) return false;
  try {
    if (parsed.data.method === "oauth") {
      if (parsed.data.provider === "apple" && !parsed.data.nonce) return false;
      await verifyOAuthReauthenticationProof(userId, parsed.data);
      return true;
    }
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { email: true } });
    if (!user) return false;
    const authenticated = await authenticatePasswordUser(user.email, parsed.data.currentPassword, ip);
    return authenticated.profile.uid === userId;
  } catch (error) {
    if (error instanceof AuthError || error instanceof OAuthError) return false;
    throw error;
  }
}

export function issueMfaEnrollmentAuthorization(userId: string, credentialId: string): string {
  return signJwt({ sub: userId, credentialId, type: "mfa_enrollment" }, { expiresIn: "10m" });
}
export function verifyMfaEnrollmentAuthorization(token: string, userId: string, credentialId: string): boolean {
  try {
    const claims = verifyJwt<{ sub?: string; credentialId?: string; type?: string }>(token);
    return claims.type === "mfa_enrollment" && claims.sub === userId && claims.credentialId === credentialId;
  } catch { return false; }
}
