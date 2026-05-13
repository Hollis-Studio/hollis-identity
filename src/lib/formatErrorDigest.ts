/**
 * @ai-context Dev-mode error digest formatter for Identity Service.
 */

import { sanitizeErrorMessage } from "@hollis/contracts";

export interface ErrorDigestOptions {
  method?: string;
  path?: string;
  requestId?: string;
  statusCode?: number;
  extra?: Record<string, unknown>;
}

export function formatErrorDigest(err: Error, options: ErrorDigestOptions = {}): string {
  const { method = '?', path = '?', requestId, statusCode, extra } = options;
  const lines: string[] = [
    `═══ Error Digest ═══`,
    `  ${method} ${path}${statusCode ? ` → ${statusCode}` : ''}`,
    `  ${sanitizeErrorMessage(err.message)}`,
  ];
  if (requestId) lines.push(`  requestId: ${requestId}`);
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      lines.push(`  ${k}: ${String(v)}`);
    }
  }
  if (err.stack) {
    const appFrames = err.stack
      .split('\n')
      .filter((l) => l.includes('src/') && !l.includes('node_modules'))
      .slice(0, 5);
    if (appFrames.length) {
      lines.push('  Stack:');
      appFrames.forEach((f) => lines.push(`    ${f.trim()}`));
    }
  }
  lines.push('════════════════════');
  return lines.join('\n');
}
