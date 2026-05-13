/**
 * @ai-context Encryption utilities | Field-level encryption for sensitive data (TOTP secrets, etc.)
 *
 * AES-256-GCM encryption. Key sourced from ENCRYPTION_KEY env var.
 */

import crypto from "crypto";
import { getEnv } from "./env";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

function getEncryptionKey(): Buffer {
  const env = getEnv();
  const keyMaterial = env.ENCRYPTION_KEY;

  if (!keyMaterial) {
    throw new Error("ENCRYPTION_KEY environment variable is not set");
  }

  if (keyMaterial.length === 64) {
    try {
      const key = Buffer.from(keyMaterial, "hex");
      if (key.length === KEY_LENGTH) return key;
    } catch {
      // fall through
    }
  }

  if (keyMaterial.length === 44) {
    try {
      const key = Buffer.from(keyMaterial, "base64");
      if (key.length === KEY_LENGTH) return key;
    } catch {
      // fall through
    }
  }

  const salt = "hollis-identity-encryption-v1";
  return crypto.pbkdf2Sync(keyMaterial, salt, 100000, KEY_LENGTH, "sha256");
}

export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

export function decrypt(encryptedData: string): string {
  const key = getEncryptionKey();
  const combined = Buffer.from(encryptedData, "base64");
  const iv = combined.subarray(0, IV_LENGTH);
  const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("Decryption failed - data may be corrupted or tampered with");
  }
}

export function isEncrypted(value: string): boolean {
  if (value.length < 64) return false;
  return /^[A-Za-z0-9+/]+=*$/.test(value);
}
