import type { Logger } from "./logger";
import { AuthError } from "../services/authService";

const securityRefusals = new Set([
  "ACCOUNT_LOCKED", "ACCOUNT_INACTIVE", "ACCOUNT_DEACTIVATED", "USER_NOT_FOUND",
  "TOKEN_REVOKED", "TOKEN_NOT_FOUND", "TOKEN_INVALID_TYPE", "TOKEN_INVALID",
]);

export function logAuthFailure(log: Pick<Logger, "info" | "warn" | "error"> | undefined,
  operation: "login" | "refresh", error: unknown): void {
  if (!log) return;
  if (error instanceof AuthError && error.statusCode >= 400 && error.statusCode < 500) {
    const routine = error.statusCode === 401 && (operation === "login"
      ? error.code === "INVALID_CREDENTIALS"
      : error.code === "TOKEN_EXPIRED");
    // Persistent LOGIN_FAILED/TOKEN_REFRESH_FAILED audits and account/IP rate
    // controls remain intact. Do not log credentials, token text or user details.
    if (routine) {
      log.info({ operation, code: error.code }, "Authentication refused");
      return;
    }
    if (securityRefusals.has(error.code)) {
      log.warn({ operation, code: error.code }, "Authentication refused");
      return;
    }
  }
  log.error({ err: error, operation }, "Authentication operation failed");
}
