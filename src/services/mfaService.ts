/**
 * @ai-context MFA Service | Multi-Factor Authentication business logic
 *
 * Provides TOTP (Time-based One-Time Password) and backup code functionality.
 * Supports:
 * - TOTP setup and verification (Google Authenticator, Authy, etc.)
 * - Backup code generation and usage
 * - MFA event logging for audit trail
 * - Step-up authentication for sensitive actions
 *
 * SECURITY:
 * - TOTP secrets are encrypted at rest using AES-256-GCM (via lib/encryption.ts)
 * - Backup codes are hashed before storage
 * - Failed attempts are rate-limited and logged
 * - MFA is recommended (not enforced) for ADMIN and CLINICIAN roles
 *
 * deps: crypto, prisma, @contracts | consumers: routes/mfa.ts
 */

import type {
  MfaCredentialResponseContract,
  MfaCredentialType,
  MfaEventType,
  MfaStatusResponseContract,
  StepUpAuthAction,
  StepUpAuthResponseContract,
  TotpSetupResponseContract,
} from "@hollis-studio/contracts";
import {
  CLINICAL_ROLES,
  isSiteAdminRole,
  MFA_BACKUP_CODE_LENGTH,
  MFA_TOTP_CODE_LENGTH,
  MfaCredentialTypeSchema,
  MfaEventTypeSchema,
  STEP_UP_AUTH_WINDOW_MS,
} from "@hollis-studio/contracts";
import crypto from "crypto";
import { USER_ERRORS } from "../constants/errorMessages";
import { decrypt, encrypt } from "../lib/encryption";
import { logger } from "../lib/logger";
import {
  createMfaErrorWithAttempts,
  getMfaAttemptStatus,
  recordMfaFailure,
} from "../lib/mfaAttemptTracker";
import { prisma } from "../lib/prisma";
import { runAsSystemOperation } from "../lib/tenantContext";

// ============================================================================
// CONSTANTS
// ============================================================================

const TOTP_ISSUER = "Hollis Health";
const TOTP_PERIOD = 30; // seconds
const TOTP_DIGITS = MFA_TOTP_CODE_LENGTH;
const TOTP_ALGORITHM = "SHA1"; // Standard for TOTP compatibility
const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LENGTH = MFA_BACKUP_CODE_LENGTH;

// Roles where MFA is recommended (but not enforced).
// MFA was previously mandatory for clinical roles but is now advisory.
const MFA_RECOMMENDED_ROLES = CLINICAL_ROLES;

// DEPRECATED: MFA is no longer enforced at the middleware level.
// Kept as empty array so isMfaRequired() returns false for all roles.
const MFA_REQUIRED_ROLES: readonly string[] = [];
const TOTP_CREDENTIAL_TYPE = MfaCredentialTypeSchema.enum.TOTP;
const MFA_SUCCESS_EVENT_TYPES = [
  MfaEventTypeSchema.enum.VERIFICATION_SUCCESS,
  MfaEventTypeSchema.enum.STEP_UP_SUCCESS,
] as const;

// ============================================================================
// TYPES
// ============================================================================

export interface MfaServiceError extends Error {
  code: string;
  statusCode: number;
}

interface AdminMfaAccessOptions {
  organizationId?: string;
}

function createMfaError(
  message: string,
  code: string,
  statusCode: number = 400,
): MfaServiceError {
  const error = new Error(message) as MfaServiceError;
  error.code = code;
  error.statusCode = statusCode;
  return error;
}

function resolveAdminMfaOrganizationId(
  organizationId?: string,
): string | undefined {
  // Identity Service has no tenant context — use provided organizationId directly
  if (!organizationId || organizationId.trim().length === 0) {
    return undefined;
  }
  return organizationId;
}

// ============================================================================
// TOTP HELPERS
// ============================================================================

/**
 * Generate a base32 encoded TOTP secret
 */
function generateTotpSecret(): string {
  // 20 bytes = 160 bits, standard for TOTP
  const buffer = crypto.randomBytes(20);
  return base32Encode(buffer);
}

/**
 * Base32 encoding for TOTP secrets (RFC 4648)
 */
function base32Encode(buffer: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  let bits = 0;
  let value = 0;

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }

  return result;
}

/**
 * Base32 decoding for TOTP verification
 */
function base32Decode(encoded: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleanInput = encoded.replace(/=+$/, "").toUpperCase();
  const bytes: number[] = [];
  let value = 0;
  let bits = 0;

  for (const char of cleanInput) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generate a TOTP code for the current time
 * @param secret - Base32 encoded TOTP secret
 * @param timeOffset - Number of periods to offset (default: 0)
 * @returns 6-digit TOTP code
 *
 * NOTE: Exported for testing purposes only. Do not use in production code
 * outside of TOTP verification flows.
 */
export function generateTotpCode(
  secret: string,
  timeOffset: number = 0,
): string {
  const counter = Math.floor(
    (Date.now() / 1000 + timeOffset * TOTP_PERIOD) / TOTP_PERIOD,
  );
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const key = base32Decode(secret);
  const hmac = crypto.createHmac("sha1", key);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, TOTP_DIGITS);
  return otp.toString().padStart(TOTP_DIGITS, "0");
}

/**
 * Verify a TOTP code against a secret
 * Allows for 1 period of clock drift in either direction
 */
function verifyTotpCode(secret: string, code: string): boolean {
  // Check current period and ±1 period for clock drift
  for (const offset of [0, -1, 1]) {
    if (generateTotpCode(secret, offset) === code) {
      return true;
    }
  }
  return false;
}

/**
 * Generate the otpauth:// URI for QR code generation
 */
function generateOtpAuthUri(email: string, secret: string): string {
  const issuer = encodeURIComponent(TOTP_ISSUER);
  const account = encodeURIComponent(email);
  return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=${TOTP_ALGORITHM}&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
}

// ============================================================================
// BACKUP CODE HELPERS
// ============================================================================

/**
 * Generate secure backup codes
 */
function generateBackupCodes(): string[] {
  const codes: string[] = [];
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Exclude confusable chars

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    let code = "";
    for (let j = 0; j < BACKUP_CODE_LENGTH; j++) {
      code += charset[crypto.randomInt(charset.length)];
    }
    codes.push(code);
  }

  return codes;
}

/**
 * Hash backup codes for storage
 */
function hashBackupCodes(codes: string[]): string {
  const hashed = codes.map((code) =>
    crypto.createHash("sha256").update(code.toUpperCase()).digest("hex"),
  );
  return JSON.stringify(hashed);
}

/**
 * Verify and consume a backup code
 */
function verifyBackupCode(
  hashedCodesJson: string,
  inputCode: string,
): { valid: boolean; remaining: string[] } {
   
  const hashedCodes: string[] = JSON.parse(hashedCodesJson);
  const inputHash = crypto
    .createHash("sha256")
    .update(inputCode.toUpperCase())
    .digest("hex");

  const index = hashedCodes.indexOf(inputHash);
  if (index === -1) {
    return { valid: false, remaining: hashedCodes };
  }

  // Remove the used code
  hashedCodes.splice(index, 1);
  return { valid: true, remaining: hashedCodes };
}

// ============================================================================
// SERVICE FUNCTIONS
// ============================================================================

/**
 * Check if MFA is required for a user based on their role.
 * Always returns false — MFA is now advisory, not enforced.
 * @deprecated Use isMfaRecommended() for UI hints.
 */
export function isMfaRequired(role: string): boolean {
  return MFA_REQUIRED_ROLES.includes(role);
}

/**
 * Check if MFA is recommended for a user based on their role.
 * Returns true for clinical/admin roles as a best-practice suggestion.
 */
export function isMfaRecommended(role: string): boolean {
  return MFA_RECOMMENDED_ROLES.includes(
    role as (typeof MFA_RECOMMENDED_ROLES)[number],
  );
}

/**
 * Get MFA status for a user
 */
export async function getMfaStatus(
  userId: string,
  options: AdminMfaAccessOptions = {},
): Promise<MfaStatusResponseContract> {
  const scopedOrganizationId = resolveAdminMfaOrganizationId(
    options.organizationId,
  );

  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { role: true, organizationId: true },
      });

      if (
        !user ||
        (scopedOrganizationId !== undefined &&
          user.organizationId !== scopedOrganizationId)
      ) {
        throw createMfaError(USER_ERRORS.NOT_FOUND, "USER_NOT_FOUND", 404);
      }

      const credentials = await prisma.mfaCredential.findMany({
        where: { userId, isVerified: true },
        orderBy: { createdAt: "asc" },
      });

      const hasVerifiedCredential = credentials.length > 0;
      const hasBackupCodes = credentials.some(
        (c) => c.type === TOTP_CREDENTIAL_TYPE && c.backupCodesRemaining > 0,
      );

      // Get last verification time from MFA events
      const lastVerification = await prisma.mfaEvent.findFirst({
        where: {
          userId,
          eventType: { in: [...MFA_SUCCESS_EVENT_TYPES] },
          success: true,
        },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true },
      });

      return {
        isEnabled: hasVerifiedCredential,
        isRequired: isMfaRequired(user.role),
        isRecommended: isMfaRecommended(user.role),
        credentials: credentials.map(formatCredentialResponse),
        hasBackupCodes,
        lastVerifiedAt: lastVerification?.createdAt.toISOString() ?? null,
      };
    },
    { reason: "auth:mfa-management" },
  );
}

/**
 * Format a credential for API response (excludes secrets)
 */
function formatCredentialResponse(credential: {
  id: string;
  type: MfaCredentialType;
  name: string;
  isVerified: boolean;
  isDefault: boolean;
  lastUsedAt: Date | null;
  backupCodesRemaining: number;
  createdAt: Date;
}): MfaCredentialResponseContract {
  return {
    id: credential.id,
    type: credential.type,
    name: credential.name,
    isVerified: credential.isVerified,
    isDefault: credential.isDefault,
    lastUsedAt: credential.lastUsedAt?.toISOString() ?? null,
    backupCodesRemaining: credential.backupCodesRemaining,
    createdAt: credential.createdAt.toISOString(),
  };
}

/**
 * Initiate TOTP setup for a user
 */
export async function initiateTotpSetup(
  userId: string,
  deviceName: string,
): Promise<TotpSetupResponseContract> {
  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      // Get user email for the QR code
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { email: true },
      });

      if (!user) {
        throw createMfaError(USER_ERRORS.NOT_FOUND, "USER_NOT_FOUND", 404);
      }

      // Generate TOTP secret and backup codes
      const secret = generateTotpSecret();
      const backupCodes = generateBackupCodes();
      const hashedBackupCodes = hashBackupCodes(backupCodes);

      // Encrypt the TOTP secret before storing
      const encryptedSecret = encrypt(secret);

      // Create unverified credential
      const credential = await prisma.mfaCredential.create({
        data: {
          userId,
          type: TOTP_CREDENTIAL_TYPE,
           
          name: deviceName || "Authenticator App",
          totpSecret: encryptedSecret, // Encrypted at rest
          backupCodesHash: hashedBackupCodes,
          backupCodesRemaining: BACKUP_CODE_COUNT,
          isVerified: false,
          isDefault: false,
        },
      });

      // Log setup started event
      await logMfaEvent({
        userId,
        eventType: MfaEventTypeSchema.enum.SETUP_STARTED,
        credentialId: credential.id,
        success: true,
      });

      return {
        credentialId: credential.id,
        secret,
        qrCodeUri: generateOtpAuthUri(user.email, secret),
        backupCodes,
      };
    },
    { reason: "auth:mfa-management" },
  );
}

/**
 * Verify TOTP code to complete setup
 */
export async function verifyTotpSetup(
  userId: string,
  credentialId: string,
  code: string,
): Promise<MfaCredentialResponseContract> {
  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      const credential = await prisma.mfaCredential.findUnique({
        where: { id: credentialId },
        select: {
          id: true,
          type: true,
          name: true,
          isVerified: true,
          isDefault: true,
          lastUsedAt: true,
          backupCodesRemaining: true,
          createdAt: true,
          totpSecret: true,
          userId: true,
        },
      });

      if (
        !credential ||
        credential.userId !== userId ||
        credential.type !== TOTP_CREDENTIAL_TYPE
      ) {
        throw createMfaError("Invalid or expired setup", "INVALID_SETUP", 400);
      }

      // Idempotency: if this credential is already verified, return it.
      // This prevents clients from getting stuck if a prior verification succeeded
      // but the client-side response parsing failed.
      if (credential.isVerified) {
        return formatCredentialResponse(credential);
      }

      if (!credential.totpSecret) {
        throw createMfaError("Invalid or expired setup", "INVALID_SETUP", 400);
      }

      let decryptedSecret: string;
      try {
        decryptedSecret = decrypt(credential.totpSecret);
      } catch {
        await logMfaEvent({
          userId,
          eventType: MfaEventTypeSchema.enum.VERIFICATION_FAILED,
          credentialId,
          success: false,
          errorMessage: "Invalid MFA credential secret",
        });
        throw createMfaError("Invalid or expired setup", "INVALID_SETUP", 400);
      }

      // Verify the code
      if (!verifyTotpCode(decryptedSecret, code)) {
        await logMfaEvent({
          userId,
          eventType: MfaEventTypeSchema.enum.VERIFICATION_FAILED,
          credentialId,
          success: false,
          errorMessage: "Invalid TOTP code during setup",
        });
        throw createMfaError("Invalid verification code", "INVALID_CODE", 400);
      }

      // Mark as verified and set as default if first credential
      const existingCredentials = await prisma.mfaCredential.count({
        where: { userId, isVerified: true },
      });

      const updatedCredential = await prisma.mfaCredential.update({
        where: { id: credentialId },
        data: {
          isVerified: true,
          isDefault: existingCredentials === 0,
          lastUsedAt: new Date(),
        },
        select: {
          id: true,
          type: true,
          name: true,
          isVerified: true,
          isDefault: true,
          lastUsedAt: true,
          backupCodesRemaining: true,
          createdAt: true,
        },
      });

      // Log setup completed
      await logMfaEvent({
        userId,
        eventType: MfaEventTypeSchema.enum.SETUP_COMPLETED,
        credentialId,
        success: true,
      });

      logger.info(
        { userIdSurrogate: userId.slice(0, 8) },
        "[MFA] TOTP setup completed successfully",
      );

      return formatCredentialResponse(updatedCredential);
    },
    { reason: "auth:mfa-management" },
  );
}

/**
 * Internal MFA login verification (for use within system operations)
 */
async function verifyMfaLoginInternal(
  userId: string,
  code: string,
  credentialId?: string,
  isBackupCode?: boolean,
  requestMeta?: { ipAddress?: string; userAgent?: string },
): Promise<{ success: boolean }> {
  // Check for MFA lockout first
  const attemptStatus = await getMfaAttemptStatus(userId);
  if (attemptStatus.isLocked) {
    throw createMfaErrorWithAttempts(
      `MFA verification temporarily locked. Please try again in ${Math.ceil(attemptStatus.retryAfterSeconds / 60)} minutes.`,
      "MFA_LOCKED",
      attemptStatus,
    );
  }

  // Find the credential to use
  let credential;
  if (credentialId) {
    credential = await prisma.mfaCredential.findUnique({
      where: { id: credentialId },
    });
    if (
      credential &&
      (credential.userId !== userId || !credential.isVerified)
    ) {
      credential = null;
    }
  } else {
    // Use default credential
    credential = await prisma.mfaCredential.findFirst({
      where: { userId, isVerified: true, isDefault: true },
    });
    // Fall back to any verified credential
    if (!credential) {
      credential = await prisma.mfaCredential.findFirst({
        where: { userId, isVerified: true },
        orderBy: { createdAt: "asc" },
      });
    }
  }

  if (!credential) {
    throw createMfaError("No MFA credentials found", "NO_MFA_CREDENTIALS", 400);
  }

  // Handle backup code verification
  if (isBackupCode && credential.backupCodesHash) {
    const result = verifyBackupCode(credential.backupCodesHash, code);
    if (!result.valid) {
      await logMfaEvent({
        userId,
        eventType: MfaEventTypeSchema.enum.VERIFICATION_FAILED,
        credentialId: credential.id,
        success: false,
        errorMessage: "Invalid backup code",
        ipAddress: requestMeta?.ipAddress,
        userAgent: requestMeta?.userAgent,
      });
      // Record failure and get updated attempt status
      const updatedStatus = await recordMfaFailure(userId);
      throw createMfaErrorWithAttempts(
        "Invalid backup code",
        "INVALID_BACKUP_CODE",
        updatedStatus,
      );
    }

    // Update remaining codes
    await prisma.mfaCredential.update({
      where: { id: credential.id },
      data: {
        backupCodesHash: JSON.stringify(result.remaining),
        backupCodesRemaining: result.remaining.length,
        lastUsedAt: new Date(),
      },
    });

    await logMfaEvent({
      userId,
      eventType: MfaEventTypeSchema.enum.BACKUP_CODE_USED,
      credentialId: credential.id,
      success: true,
      ipAddress: requestMeta?.ipAddress,
      userAgent: requestMeta?.userAgent,
    });

    logger.warn(
      {
        userIdSurrogate: userId.slice(0, 8),
        remaining: result.remaining.length,
      },
      "[MFA] Backup code used",
    );

    return { success: true };
  }

  // TOTP verification
  if (credential.type === TOTP_CREDENTIAL_TYPE && credential.totpSecret) {
    let decryptedSecret: string;
    try {
      decryptedSecret = decrypt(credential.totpSecret);
    } catch {
      await logMfaEvent({
        userId,
        eventType: MfaEventTypeSchema.enum.VERIFICATION_FAILED,
        credentialId: credential.id,
        success: false,
        errorMessage: "Invalid MFA credential secret",
        ipAddress: requestMeta?.ipAddress,
        userAgent: requestMeta?.userAgent,
      });
      throw createMfaError("Invalid verification code", "INVALID_CODE", 400);
    }

    if (!verifyTotpCode(decryptedSecret, code)) {
      await logMfaEvent({
        userId,
        eventType: MfaEventTypeSchema.enum.VERIFICATION_FAILED,
        credentialId: credential.id,
        success: false,
        errorMessage: "Invalid TOTP code",
        ipAddress: requestMeta?.ipAddress,
        userAgent: requestMeta?.userAgent,
      });
      // Record failure and get updated attempt status
      const updatedStatus = await recordMfaFailure(userId);
      throw createMfaErrorWithAttempts(
        "Invalid verification code",
        "INVALID_CODE",
        updatedStatus,
      );
    }

    await prisma.mfaCredential.update({
      where: { id: credential.id },
      data: { lastUsedAt: new Date() },
    });

    await logMfaEvent({
      userId,
      eventType: MfaEventTypeSchema.enum.VERIFICATION_SUCCESS,
      credentialId: credential.id,
      success: true,
      ipAddress: requestMeta?.ipAddress,
      userAgent: requestMeta?.userAgent,
    });

    return { success: true };
  }

  throw createMfaError("Unsupported MFA type", "UNSUPPORTED_MFA_TYPE", 400);
}

/**
 * Verify MFA code during login
 */
export async function verifyMfaLogin(
  userId: string,
  code: string,
  credentialId?: string,
  isBackupCode?: boolean,
  requestMeta?: { ipAddress?: string; userAgent?: string },
): Promise<{ success: boolean }> {
  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () =>
      verifyMfaLoginInternal(
        userId,
        code,
        credentialId,
        isBackupCode,
        requestMeta,
      ),
    { reason: "auth:mfa-verify" },
  );
}

/**
 * Perform step-up authentication for sensitive actions
 */
export async function performStepUpAuth(
  userId: string,
  action: StepUpAuthAction,
  code: string,
  credentialId?: string,
  requestMeta?: { ipAddress?: string; userAgent?: string },
): Promise<StepUpAuthResponseContract> {
  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      try {
        // Log step-up requirement
        await logMfaEvent({
          userId,
          eventType: MfaEventTypeSchema.enum.STEP_UP_REQUIRED,
          success: true,
          context: { action },
          ipAddress: requestMeta?.ipAddress,
          userAgent: requestMeta?.userAgent,
        });

        // Verify the code (already wrapped in runAsSystemOperation)
        await verifyMfaLoginInternal(
          userId,
          code,
          credentialId,
          false,
          requestMeta,
        );

        // Generate step-up token (short-lived, action-specific)
        const expiresAt = new Date(Date.now() + STEP_UP_AUTH_WINDOW_MS);
        const stepUpToken = crypto.randomBytes(32).toString("hex");

        // Store step-up token (you could use a cache/Redis, but for now we'll use the session)
        // In production, consider using a separate short-lived token store

        await logMfaEvent({
          userId,
          eventType: MfaEventTypeSchema.enum.STEP_UP_SUCCESS,
          credentialId,
          success: true,
          context: { action },
          ipAddress: requestMeta?.ipAddress,
          userAgent: requestMeta?.userAgent,
        });

        return {
          success: true,
          stepUpToken,
          expiresAt: expiresAt.toISOString(),
        };
      } catch (error) {
        await logMfaEvent({
          userId,
          eventType: MfaEventTypeSchema.enum.STEP_UP_FAILED,
          credentialId,
          success: false,
          errorMessage:
            error instanceof Error ? error.message : "Unknown error",
          context: { action },
          ipAddress: requestMeta?.ipAddress,
          userAgent: requestMeta?.userAgent,
        });
        throw error;
      }
    },
    { reason: "auth:mfa-verify" },
  );
}

/**
 * Remove an MFA credential
 */
export async function removeCredential(
  userId: string,
  credentialId: string,
  requestMeta?: { ipAddress?: string; userAgent?: string },
): Promise<void> {
  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      const credential = await prisma.mfaCredential.findUnique({
        where: { id: credentialId },
      });

      if (!credential || credential.userId !== userId) {
        throw createMfaError(
          "Credential not found",
          "CREDENTIAL_NOT_FOUND",
          404,
        );
      }

      // Check if this is the last verified credential
      const verifiedCount = await prisma.mfaCredential.count({
        where: { userId, isVerified: true },
      });

      // Get user role to check if MFA is required
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { role: true },
      });

      if (
        user &&
        isMfaRequired(user.role) &&
        verifiedCount <= 1 &&
        credential.isVerified
      ) {
        throw createMfaError(
          "Cannot remove last MFA credential. MFA is required for your role.",
          "MFA_REQUIRED",
          400,
        );
      }

      await prisma.$transaction(async (tx) => {
        await tx.mfaCredential.delete({ where: { id: credentialId } });

        // If this was the default, set another one as default
        if (credential.isDefault) {
          const nextCredential = await tx.mfaCredential.findFirst({
            where: { userId, isVerified: true },
            orderBy: { createdAt: "asc" },
          });
          if (nextCredential) {
            await tx.mfaCredential.update({
              where: { id: nextCredential.id },
              data: { isDefault: true },
            });
          }
        }
      });

      await logMfaEvent({
        userId,
        eventType: MfaEventTypeSchema.enum.CREDENTIAL_REMOVED,
        credentialId,
        success: true,
        ipAddress: requestMeta?.ipAddress,
        userAgent: requestMeta?.userAgent,
      });

      logger.info(
        { userIdSurrogate: userId.slice(0, 8) },
        "[MFA] Credential removed",
      );
    },
    { reason: "auth:mfa-management" },
  );
}

/**
 * Generate new backup codes (invalidates old ones)
 */
export async function regenerateBackupCodes(
  userId: string,
  credentialId: string,
  code: string,
): Promise<string[]> {
  // Verify the TOTP code before allowing backup code regeneration.
  // This prevents an attacker with a stolen session from silently cycling backup codes.
  // verifyMfaLogin handles rate-limiting, audit logging, and clock-drift tolerance.
  const verifyResult = await verifyMfaLogin(userId, code, credentialId, false);
  if (!verifyResult.success) {
    throw createMfaError("Invalid TOTP code", "INVALID_CODE", 400);
  }

  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      const credential = await prisma.mfaCredential.findUnique({
        where: { id: credentialId },
      });

      if (
        !credential ||
        credential.userId !== userId ||
        credential.type !== TOTP_CREDENTIAL_TYPE ||
        !credential.isVerified
      ) {
        throw createMfaError(
          "TOTP credential not found",
          "CREDENTIAL_NOT_FOUND",
          404,
        );
      }

      const backupCodes = generateBackupCodes();
      const hashedBackupCodes = hashBackupCodes(backupCodes);

      await prisma.mfaCredential.update({
        where: { id: credentialId },
        data: {
          backupCodesHash: hashedBackupCodes,
          backupCodesRemaining: BACKUP_CODE_COUNT,
        },
      });

      logger.info(
        { userIdSurrogate: userId.slice(0, 8) },
        "[MFA] Backup codes regenerated",
      );

      return backupCodes;
    },
    { reason: "auth:mfa-management" },
  );
}

/**
 * Check if a user has MFA enabled
 */
export async function hasMfaEnabled(userId: string): Promise<boolean> {
  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      const count = await prisma.mfaCredential.count({
        where: { userId, isVerified: true },
      });
      return count > 0;
    },
    { reason: "auth:mfa-management" },
  );
}

// ============================================================================
// ADMIN MFA RESET
// ============================================================================

interface AdminMfaResetContext {
  ip?: string;
  userAgent?: string;
}

/**
 * Admin-initiated MFA reset for a user who is locked out.
 *
 * This function:
 * - Removes ALL MFA credentials for the target user
 * - Generates new backup codes
 * - Logs comprehensive audit events for both target and admin users
 *
 * SECURITY:
 * - Requires admin role + active MFA + step-up auth (enforced at route level)
 * - Logs MFA_RESET_BY_ADMIN event on target user
 * - Logs ADMIN_MFA_RESET_PERFORMED event on admin user
 * - Returns backup codes (one-time display, never logged)
 *
 * @param targetUserId - User whose MFA is being reset
 * @param adminUserId - Admin performing the reset
 * @param reason - Reason for reset (for audit log)
 * @param context - Request metadata (IP, user agent)
 * @returns Object with new backup codes
 */
export async function adminResetMfa(
  targetUserId: string,
  adminUserId: string,
  reason: string,
  context: AdminMfaResetContext = {},
  organizationId?: string,
): Promise<{ backupCodes: string[] }> {
  const scopedOrganizationId = resolveAdminMfaOrganizationId(organizationId);

  // MFA operations are cross-tenant by design (auth-related)
  return runAsSystemOperation(
    async () => {
      // Verify target user exists
      const targetUser = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true, email: true, role: true, organizationId: true },
      });

      if (
        !targetUser ||
        (scopedOrganizationId !== undefined &&
          targetUser.organizationId !== scopedOrganizationId)
      ) {
        throw createMfaError("Target user not found", "USER_NOT_FOUND", 404);
      }

      // Verify admin user exists and is actually an admin
      const adminUser = await prisma.user.findUnique({
        where: { id: adminUserId },
        select: { id: true, email: true, role: true, organizationId: true },
      });

      if (
        !adminUser ||
        !isSiteAdminRole(adminUser.role) ||
        adminUser.organizationId == null ||
        adminUser.organizationId !== targetUser.organizationId ||
        (scopedOrganizationId !== undefined &&
          adminUser.organizationId !== scopedOrganizationId)
      ) {
        throw createMfaError(
          "Admin user not found or insufficient permissions",
          "INSUFFICIENT_PERMISSIONS",
          403,
        );
      }

      logger.info(
        {
          targetUserId,
          adminUserId,
          targetRole: targetUser.role,
        },
        "[MFA] Admin initiating MFA reset",
      );

      // Generate new backup codes before the transaction
      const backupCodes = generateBackupCodes();
      const hashedBackupCodes = hashBackupCodes(backupCodes);

      // Remove all existing MFA credentials and create new backup codes atomically.
      // Both operations must succeed together: if the create fails after the deleteMany,
      // the user would be left with zero credentials and unable to log in.
      const deletedBatch = await prisma.$transaction(async (tx) => {
        const deleted = await tx.mfaCredential.deleteMany({
          where: { userId: targetUserId },
        });

        // Seed backup-only credential so the user can still log in while
        // re-enrolling TOTP.
        await tx.mfaCredential.create({
          data: {
            userId: targetUserId,
            type: TOTP_CREDENTIAL_TYPE, // Type is TOTP but only backup codes are active
            name: "Emergency Backup Codes (Admin Reset)",
            isVerified: true, // Pre-verified by admin
            isDefault: true,
            backupCodesHash: hashedBackupCodes,
            backupCodesRemaining: BACKUP_CODE_COUNT,
            totpSecret: null, // No TOTP secret until user sets it up again
          },
        });

        return deleted;
      });

      logger.info(
        { targetUserId, deletedCount: deletedBatch.count },
        "[MFA] Deleted existing MFA credentials",
      );

      // Log audit events
      await logMfaEvent({
        userId: targetUserId,
        eventType: MfaEventTypeSchema.enum.RECOVERY_COMPLETED, // Using existing event type for reset
        success: true,
        ipAddress: context.ip,
        userAgent: context.userAgent,
        context: {
          adminUserId,
          reason,
          action: "admin_mfa_reset",
          credentialsRemoved: deletedBatch.count,
        },
      });

      // Log event on admin user's record too
      await logMfaEvent({
        userId: adminUserId,
        eventType: MfaEventTypeSchema.enum.RECOVERY_INITIATED, // Using existing event type for admin action
        success: true,
        ipAddress: context.ip,
        userAgent: context.userAgent,
        context: {
          targetUserId,
          reason,
          action: "performed_mfa_reset",
        },
      });

      logger.info(
        { targetUserId, adminUserId },
        "[SECURITY] Admin MFA reset completed successfully",
      );

      return { backupCodes };
    },
    { reason: "auth:mfa-management" },
  );
}

// ============================================================================
// MFA EVENT LOGGING
// ============================================================================

interface MfaEventLogData {
  userId: string;
  eventType: MfaEventType;
  credentialId?: string;
  success: boolean;
  errorMessage?: string;
  ipAddress?: string;
  userAgent?: string;
  context?: Record<string, unknown>;
}

/**
 * Log an MFA event for audit purposes
 */
async function logMfaEvent(data: MfaEventLogData): Promise<void> {
  try {
    await prisma.mfaEvent.create({
      data: {
        userId: data.userId,
        eventType: data.eventType,
        credentialId: data.credentialId,
        success: data.success,
        errorMessage: data.errorMessage,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        context: data.context ? (data.context as never) : undefined,
      },
    });
  } catch (error) {
    // Don't fail the main operation if logging fails
    logger.error(
      { err: error, eventType: data.eventType },
      "[MFA] Failed to log MFA event",
    );
  }
}
