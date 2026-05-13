/**
 * @ai-context Rate limit store abstraction for Identity Service (in-memory only).
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
