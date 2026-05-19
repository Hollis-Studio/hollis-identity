/**
 * @ai-context Rate limit store abstraction for Identity Service local middleware.
 *
 * App-level limiters are in-memory defense-in-depth. Production edge-level
 * rate enforcement is owned by AWS WAF in the Terraform stack.
 */

export interface RateLimitStoreHealth {
  status: 'healthy' | 'degraded' | 'unavailable';
  type: 'memory';
}

export async function getRateLimitStoresHealth(): Promise<RateLimitStoreHealth> {
  return { status: 'healthy', type: 'memory' };
}

export async function resetAllRateLimitStores(): Promise<void> {
  // no-op — memory stores are reset individually
}

export async function closeAllRateLimitStores(): Promise<void> {
  // no-op
}

export function clearStoreInstances(): void {
  // no-op
}
