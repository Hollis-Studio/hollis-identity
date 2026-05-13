/**
 * @ai-context Tenant context stub for Identity Service.
 *
 * Identity Service has no PHI multi-tenancy. This module provides the same
 * function signatures used in the lifted auth code so the code compiles without
 * modification. All operations are passed through directly.
 *
 * In Health App the tenant context enforces per-org Prisma query scoping.
 * In Identity Service there is no such requirement — auth models are shared.
 */

import { AsyncLocalStorage } from "async_hooks";

export type SystemOperationReason =
  | "auth:signup"
  | "auth:login"
  | "auth:logout"
  | "auth:refresh"
  | "auth:change-password"
  | "auth:forgot-password"
  | "auth:reset-password"
  | "auth:biometric-token"
  | "auth:biometric-refresh-token"
  | "auth:mfa-verify"
  | "auth:mfa-management"
  | "auth:mfa-session-cleanup"
  | "auth:authorization-check"
  | "auth:issue-session"
  | "auth:oauth-sign-in"
  | "oauth:findOrLinkUser"
  | "oauth:register"
  | "scheduled:password-reset-token-cleanup"
  | string; // allow any domain:action

interface TenantContext {
  organizationId?: string;
}

interface SystemOperationOptions {
  reason: SystemOperationReason;
  userId?: string;
}

const _storage = new AsyncLocalStorage<TenantContext>();

/**
 * Returns the current tenant context, if any.
 * Always returns undefined in Identity Service (no tenant isolation).
 */
export function getTenantContext(): TenantContext | undefined {
  return _storage.getStore();
}

/**
 * Run a callback without tenant scoping.
 * In Identity Service, this is a simple pass-through.
 */
export async function runAsSystemOperation<T>(
  fn: () => Promise<T>,
  _options: SystemOperationOptions,
): Promise<T> {
  return fn();
}
