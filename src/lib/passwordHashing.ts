/**
 * @ai-context Unified Password Hashing Service | Future-proof credential security
 *
 * Provides a single, consistent interface for all password hashing operations:
 * - Versioned hash metadata for algorithm migration support
 * - Server-side pepper for defense-in-depth (stored in Secrets Manager/KMS)
 * - Consistent bcrypt cost factor across all operations
 * - Rehash-on-login pattern for seamless upgrades
 *
 * Hash Format (v1):
 *   $hh$v1$bcrypt$<cost>$<base64-hash>
 *
 * The versioned prefix allows future algorithm migrations (e.g., to Argon2id)
 * without breaking existing hashes. The "rehash on login" pattern upgrades
 * legacy hashes transparently when users authenticate.
 *
 * SECURITY NOTES:
 * - The pepper is a high-value secret that MUST be in Secrets Manager/KMS
 * - If pepper is lost, ALL password hashes become unverifiable
 * - Pepper rotation requires careful coordination (see docs)
 * - Never log the pepper or derived values
 *
 * AUDIT-02 #38 (accepted): No pepper rotation mechanism implemented.
 * Single-pepper model is sufficient at <20 clients. Rotation would require
 * versioned pepper lookup and re-hash migration — defer until needed.
 *
 * IMPORTANT: All password validation uses shared PASSWORD_POLICY from @contracts.
 * Do NOT add hardcoded password requirements here - update the shared policy instead.
 *
 * deps: bcryptjs, crypto, @contracts | consumers: authService, passwordResetService, adminUserService
 */

import { PASSWORD_POLICY } from "@hollis-studio/contracts";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { env } from "./env";
import { logger } from "./logger";

// ============================================================================
// Configuration
// ============================================================================

/**
 * Standard bcrypt cost factor for ALL password operations.
 *
 * This is the SINGLE SOURCE OF TRUTH for cost factor.
 * Never use a hardcoded cost anywhere else in the codebase.
 *
 * Cost Factor Guidelines:
 * - 10: Fast for development/testing (~60ms)
 * - 12: Good baseline for production (~250ms)
 * - 13: Recommended for production (~500ms) - Current default
 * - 14: High security (~1s)
 * - 15-16: Maximum security (~2-4s) - Use only if justified
 *
 * Reads from validated env.BCRYPT_COST_FACTOR lazily on first use.
 * This avoids the bootstrap-order issue where this module may be imported
 * before validateEnvOnStartup() has been called.
 */
let _passwordHashCost: number | null = null;

export function getPasswordHashCost(): number {
  if (_passwordHashCost === null) {
    _passwordHashCost = env.BCRYPT_COST_FACTOR;
  }
  return _passwordHashCost;
}

/**
 * Minimum acceptable cost factor for existing hashes.
 * Hashes below this threshold will be upgraded on next login.
 */
export const MIN_ACCEPTABLE_COST = 12;

/**
 * Current hash algorithm version.
 * Increment this when changing algorithms (e.g., bcrypt -> argon2id).
 */
export const CURRENT_HASH_VERSION = 1;

/**
 * Hash algorithm identifiers for versioning.
 */
export const HASH_ALGORITHM = {
  BCRYPT: "bcrypt",
  // Future: ARGON2ID: 'argon2id',
} as const;

export type HashAlgorithm =
  (typeof HASH_ALGORITHM)[keyof typeof HASH_ALGORITHM];

// ============================================================================
// Pepper Management
// ============================================================================

/**
 * Server-side pepper for defense-in-depth.
 *
 * CRITICAL: This MUST be stored in Secrets Manager/KMS, not in code or config files.
 * If PASSWORD_PEPPER is not set, pepper is disabled (bcrypt-only mode).
 *
 * The pepper adds a layer of protection:
 * - If database is compromised, hashes are useless without pepper
 * - Even with rainbow tables, pepper prevents offline attacks
 *
 * WARNING: If pepper is lost, ALL password verification fails.
 * Ensure proper secret backup and rotation procedures.
 */
let cachedPepper: string | null = null;

function getPepper(): string | null {
  if (cachedPepper !== null) {
     
    return cachedPepper || null;
  }

  const pepper = env.PASSWORD_PEPPER;

  if (!pepper) {
    // Pepper is optional but recommended
    if (env.NODE_ENV === "production") {
      logger.warn(
        { component: "passwordHashing" },
        "[SECURITY] PASSWORD_PEPPER not configured. Consider adding for defense-in-depth.",
      );
    }
    cachedPepper = "";
    return null;
  }

  // Validate pepper entropy
  if (pepper.length < 32) {
    throw new Error(
      "PASSWORD_PEPPER must be at least 32 characters. " +
        "Generate with: openssl rand -base64 32",
    );
  }

  cachedPepper = pepper;
  return pepper;
}

/**
 * Apply pepper to password using HMAC-SHA256.
 * This ensures the pepper is cryptographically combined, not just concatenated.
 */
function applyPepper(password: string): string {
  const pepper = getPepper();

  if (!pepper) {
    return password;
  }

  // Use HMAC-SHA256 to combine password and pepper
  // This is more secure than simple concatenation
  return crypto.createHmac("sha256", pepper).update(password).digest("base64");
}

// ============================================================================
// Hash Metadata Types
// ============================================================================

export interface HashMetadata {
  version: number;
  algorithm: HashAlgorithm;
  cost: number;
  /** True if pepper was applied when creating this hash */
  peppered: boolean;
}

export interface ParsedHash {
  metadata: HashMetadata;
  /** The raw bcrypt hash (or future algorithm hash) */
  rawHash: string;
}

// ============================================================================
// Hash Format Utilities
// ============================================================================

/**
 * Encode a versioned hash with metadata.
 * Format: $hh$v<version>$<algorithm>$<cost>$<peppered>$<rawHash>
 *
 * Example: $hh$v1$bcrypt$13$1$<bcrypt-hash>
 */
function encodeVersionedHash(rawHash: string, metadata: HashMetadata): string {
  const peppered = metadata.peppered ? "1" : "0";
  return `$hh$v${metadata.version}$${metadata.algorithm}$${metadata.cost}$${peppered}$${rawHash}`;
}

/**
 * Decode a versioned hash to extract metadata.
 * Returns null for legacy (non-versioned) hashes.
 */
function decodeVersionedHash(hash: string): ParsedHash | null {
  // Check for versioned hash prefix
  if (!hash.startsWith("$hh$")) {
    return null;
  }

  // Parse: $hh$v<version>$<algorithm>$<cost>$<peppered>$<rawHash>
  const parts = hash.split("$");
  // parts: ['', 'hh', 'v1', 'bcrypt', '13', '1', '<rawHash...>']

  if (parts.length < 7) {
    return null;
  }

  const versionStr = parts[2];
  const algorithm = parts[3] as HashAlgorithm;
  const costStr = parts[4];
  const pepperedStr = parts[5];
  const rawHash = parts.slice(6).join("$"); // Join remaining parts (bcrypt hash contains $)

  // Parse version
  const versionMatch = versionStr.match(/^v(\d+)$/);
  if (!versionMatch) {
    return null;
  }
  const version = parseInt(versionMatch[1], 10);

  // Parse cost
  const cost = parseInt(costStr, 10);
  if (isNaN(cost)) {
    return null;
  }

  return {
    metadata: {
      version,
      algorithm,
      cost,
      peppered: pepperedStr === "1",
    },
    rawHash,
  };
}

/**
 * Check if a hash is a legacy (non-versioned) bcrypt hash.
 * Legacy format: $2a$<cost>$... or $2b$<cost>$...
 */
function isLegacyBcryptHash(hash: string): boolean {
  return /^\$2[aby]\$\d{2}\$/.test(hash);
}

/**
 * Extract cost factor from a legacy bcrypt hash.
 */
function extractLegacyCost(hash: string): number | null {
  const match = hash.match(/^\$2[aby]\$(\d{2})\$/);
  return match ? parseInt(match[1], 10) : null;
}

// ============================================================================
// Core Hashing Functions
// ============================================================================

/**
 * Hash a password with current security settings.
 *
 * This creates a versioned hash that includes:
 * - Hash version for future algorithm migrations
 * - Algorithm identifier (bcrypt)
 * - Cost factor used
 * - Whether pepper was applied
 *
 * @param password - Plain text password to hash
 * @returns Versioned hash string
 */
export async function hashPassword(password: string): Promise<string> {
  // Apply pepper if configured
  const pepperedPassword = applyPepper(password);
  const peppered = getPepper() !== null;

  // Hash with bcrypt
  const rawHash = await bcrypt.hash(pepperedPassword, getPasswordHashCost());

  // Encode with version metadata
  const metadata: HashMetadata = {
    version: CURRENT_HASH_VERSION,
    algorithm: HASH_ALGORITHM.BCRYPT,
    cost: getPasswordHashCost(),
    peppered,
  };

  return encodeVersionedHash(rawHash, metadata);
}

/**
 * Verify a password against a stored hash.
 *
 * Supports both versioned and legacy hash formats for backwards compatibility.
 *
 * @param password - Plain text password to verify
 * @param storedHash - Hash from database (versioned or legacy)
 * @returns True if password matches
 */
export async function verifyPassword(
  password: string,
  storedHash: string,
): Promise<boolean> {
  const parsed = decodeVersionedHash(storedHash);

  if (parsed) {
    // Versioned hash - apply pepper if it was used when creating
    if (parsed.metadata.peppered) {
      const pepper = getPepper();
      if (!pepper) {
        // Pepper was used to create hash but is now missing - CRITICAL ERROR
        logger.error(
          { component: "passwordHashing" },
          "[SECURITY] Password was peppered but PASSWORD_PEPPER is not configured!",
        );
        return false;
      }
      const pepperedPassword = applyPepper(password);
      return bcrypt.compare(pepperedPassword, parsed.rawHash);
    }

    // No pepper was used
    return bcrypt.compare(password, parsed.rawHash);
  }

  if (isLegacyBcryptHash(storedHash)) {
    // Legacy hash - no pepper was used (pepper didn't exist)
    return bcrypt.compare(password, storedHash);
  }

  // Unknown hash format
  logger.error(
    { component: "passwordHashing", hashPrefix: storedHash.substring(0, 10) },
    "[SECURITY] Unknown hash format encountered",
  );
  return false;
}

/**
 * Check if a hash needs to be rehashed.
 *
 * A hash needs rehashing if:
 * - It's a legacy (non-versioned) hash
 * - Cost factor is below current minimum
 * - Version is outdated (future algorithm migration)
 * - Pepper status doesn't match current config
 *
 * @param storedHash - Hash from database
 * @returns Object with needsRehash flag and reason
 */
export function checkRehashNeeded(storedHash: string): {
  needsRehash: boolean;
  reason?:
    | "legacy_format"
    | "cost_upgrade"
    | "version_upgrade"
    | "pepper_mismatch";
} {
  const parsed = decodeVersionedHash(storedHash);
  const pepperConfigured = getPepper() !== null;

  if (!parsed) {
    // Legacy hash format
    if (isLegacyBcryptHash(storedHash)) {
      return { needsRehash: true, reason: "legacy_format" };
    }
    // Unknown format - can't rehash
    return { needsRehash: false };
  }

  // Check cost factor
  if (
    parsed.metadata.cost < MIN_ACCEPTABLE_COST ||
    parsed.metadata.cost < getPasswordHashCost()
  ) {
    return { needsRehash: true, reason: "cost_upgrade" };
  }

  // Check version (for future algorithm migrations)
  if (parsed.metadata.version < CURRENT_HASH_VERSION) {
    return { needsRehash: true, reason: "version_upgrade" };
  }

  // Check pepper status (only upgrade if pepper is now configured but wasn't used)
  if (pepperConfigured && !parsed.metadata.peppered) {
    return { needsRehash: true, reason: "pepper_mismatch" };
  }

  return { needsRehash: false };
}

/**
 * Rehash a password if needed.
 *
 * This is the "rehash on login" pattern. Call this after successful verification
 * to opportunistically upgrade hashes.
 *
 * @param password - Plain text password (already verified)
 * @param storedHash - Current hash from database
 * @returns New hash if upgrade needed, null otherwise
 */
export async function rehashIfNeeded(
  password: string,
  storedHash: string,
): Promise<string | null> {
  const { needsRehash, reason } = checkRehashNeeded(storedHash);

  if (!needsRehash) {
    return null;
  }

  // Log the upgrade for observability
  logger.info(
    { component: "passwordHashing", reason },
    "[SECURITY] Upgrading password hash on login",
  );

  // Create new hash with current settings
  return hashPassword(password);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get metadata about a stored hash.
 * Useful for admin/debugging without exposing sensitive data.
 */
export function getHashInfo(storedHash: string): {
  format: "versioned" | "legacy" | "unknown";
  algorithm?: string;
  version?: number;
  cost?: number;
  peppered?: boolean;
} {
  const parsed = decodeVersionedHash(storedHash);

  if (parsed) {
    return {
      format: "versioned",
      algorithm: parsed.metadata.algorithm,
      version: parsed.metadata.version,
      cost: parsed.metadata.cost,
      peppered: parsed.metadata.peppered,
    };
  }

  if (isLegacyBcryptHash(storedHash)) {
    const cost = extractLegacyCost(storedHash);
    return {
      format: "legacy",
      algorithm: "bcrypt",
      cost: cost ?? undefined,
      peppered: false,
    };
  }

  return { format: "unknown" };
}

/**
 * Validate password meets security requirements.
 * Uses centralized PASSWORD_POLICY from @hollis-studio/contracts.
 *
 * @param password - Plain text password to validate
 * @returns Object with valid flag and any errors
 * @see shared/contracts/password/index.ts for the authoritative policy.
 */
export function validatePasswordPolicy(password: string): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (password.length < PASSWORD_POLICY.MIN_LENGTH) {
    errors.push(
      `Password must be at least ${PASSWORD_POLICY.MIN_LENGTH} characters`,
    );
  }

  if (password.length > PASSWORD_POLICY.MAX_LENGTH) {
    errors.push(
      `Password must be at most ${PASSWORD_POLICY.MAX_LENGTH} characters`,
    );
  }

  // NOTE: We do NOT enforce character class requirements (uppercase, lowercase, digits, special).
  // Per modern NIST guidance, length and entropy (checked via zxcvbn) are more important
  // than complexity rules, which often lead to predictable patterns.
  // Strength checking happens async via validatePasswordStrength() in the shared password module.

  return {
    valid: errors.length === 0,
    errors,
  };
}
