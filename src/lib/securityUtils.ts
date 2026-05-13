/**
 * @ai-context Security utility functions for auth and anti-enumeration protection
 *
 * Provides timing-safe operations and anti-enumeration delays to prevent
 * information leakage through timing side channels.
 *
 * ## Timing Attack Prevention
 *
 * Timing attacks can reveal information about user existence by measuring
 * response times. For example:
 * - If user exists: lookup + bcrypt comparison (~200ms)
 * - If user doesn't exist: just lookup (~5ms)
 *
 * This difference allows attackers to enumerate valid usernames/emails.
 *
 * We prevent this by:
 * 1. Always performing bcrypt operations (even for non-existent users)
 * 2. Adding consistent random delays to mask timing differences
 * 3. Using crypto.timingSafeEqual for string comparisons
 *
 * deps: crypto, bcryptjs | consumers: routes/auth.ts, routes/registration.ts
 */

import bcrypt from 'bcryptjs';
import crypto from 'crypto';

// ============================================================================
// Constants
// ============================================================================

// Pre-computed bcrypt hash at cost 13. Input: zero-bytes control value — never matches any real password.
// Length must be 60 chars; structure validated in securityUtils.test.ts.
// Used by timingSafePasswordVerify(password, null) to ensure constant-time response regardless of user existence.
const DUMMY_PASSWORD_HASH = '$2b$13$RXv2eQOqNvWKKfd1wo0kaOTmBj5FoCqEWBFB8Fr/ckJFBR9LPImpu';

/**
 * Base delay in milliseconds for anti-enumeration responses.
 * This is the minimum delay added to responses.
 */
const BASE_DELAY_MS = 100;

/**
 * Random jitter range in milliseconds added to base delay.
 * Adds 0-50ms of random delay to prevent timing analysis.
 */
const JITTER_RANGE_MS = 50;

// ============================================================================
// Timing-Safe Operations
// ============================================================================

/**
 * Perform a bcrypt comparison that takes consistent time regardless of
 * whether the user exists or the password is correct.
 *
 * When the user doesn't exist, we still perform a bcrypt comparison
 * against a dummy hash to prevent timing attacks.
 *
 * @param password - The password to verify
 * @param storedHash - The stored hash (null if user doesn't exist)
 * @returns Promise<boolean> - True if password matches
 */
export async function timingSafePasswordVerify(
  password: string,
  storedHash: string | null
): Promise<boolean> {
  // Always perform a bcrypt comparison to maintain consistent timing
  const hashToCompare = storedHash || DUMMY_PASSWORD_HASH;
  const result = await bcrypt.compare(password, hashToCompare);

  // Only return true if we had a real hash and it matched
  return storedHash !== null && result;
}

/**
 * Add an anti-enumeration delay with random jitter.
 *
 * This should be called before returning responses for operations
 * where timing could reveal information (e.g., barcode validation).
 *
 * @param baseMs - Base delay in milliseconds (default: 100)
 * @param jitterMs - Random jitter range in milliseconds (default: 50)
 * @returns Promise that resolves after the delay
 */
export async function antiEnumerationDelay(
  baseMs: number = BASE_DELAY_MS,
  jitterMs: number = JITTER_RANGE_MS
): Promise<void> {
  const jitter = Math.floor(Math.random() * jitterMs);
  const totalDelay = baseMs + jitter;
  return new Promise((resolve) => setTimeout(resolve, totalDelay));
}

/**
 * Timing-safe string comparison using crypto.timingSafeEqual.
 *
 * Use this for comparing sensitive values where timing differences
 * could leak information (tokens, codes, etc.).
 *
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns True if strings are equal
 */
export function timingSafeStringCompare(a: string, b: string): boolean {
  // Strings must be same length for timingSafeEqual
  if (a.length !== b.length) {
    // Still do a comparison to maintain consistent timing
    // Use the longer string's length for both to ensure consistent work
    const maxLen = Math.max(a.length, b.length);
    const paddedA = a.padEnd(maxLen, '\0');
    const paddedB = b.padEnd(maxLen, '\0');
    crypto.timingSafeEqual(Buffer.from(paddedA), Buffer.from(paddedB));
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ============================================================================
// Input Sanitization
// ============================================================================

/**
 * Sanitize a display name to prevent XSS and injection attacks.
 *
 * This removes or escapes dangerous characters while preserving
 * legitimate name characters from various locales.
 *
 * @param displayName - The raw display name input
 * @returns Sanitized display name safe for storage and display
 */
export function sanitizeDisplayName(displayName: string): string {
  // First, trim whitespace
  let sanitized = displayName.trim();

  // Remove null bytes and other control characters (except newlines/tabs)
  // Intentionally matching control characters for security sanitization
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  // HTML entity encode dangerous characters to prevent XSS
  // This is a defense-in-depth measure - the frontend should also escape
  sanitized = sanitized
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

  // Limit length to prevent DoS (reasonable max for display names)
  const MAX_DISPLAY_NAME_LENGTH = 100;
  if (sanitized.length > MAX_DISPLAY_NAME_LENGTH) {
    sanitized = sanitized.substring(0, MAX_DISPLAY_NAME_LENGTH);
  }

  return sanitized;
}

/**
 * Validate that a barcode contains only safe characters.
 *
 * Barcodes should match the pattern HH-XXXXXX where X is alphanumeric.
 * This function ensures no injection characters are present.
 *
 * @param barcode - The barcode to validate
 * @returns True if barcode is safe, false otherwise
 */
export function isSafeBarcodeFormat(barcode: string): boolean {
  // Strict alphanumeric + hyphen pattern
  const SAFE_BARCODE_PATTERN = /^[A-Za-z0-9-]+$/;
  return (
    typeof barcode === 'string' &&
    barcode.length <= 20 && // Reasonable max length
    SAFE_BARCODE_PATTERN.test(barcode)
  );
}
