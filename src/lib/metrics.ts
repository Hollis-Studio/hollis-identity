/**
 * @ai-context Lightweight metrics stub for Identity Service.
 * Logs metrics as structured pino output.
 */

import { logger } from './logger';

interface MetricTags {
  [key: string]: string | number | boolean;
}

interface TimerResult {
  end(tags?: MetricTags): void;
}

// Metrics are emitted at `info`, not `debug`. Production runs LOG_LEVEL=info
// (see lib/logger.ts), so a debug-level metric is dropped before it reaches
// CloudWatch — which silently hid every counter this module exists to publish,
// including `auth_denylist_check_failed`. The `metric:<name>` message and the
// { metric, type, ... } shape are unchanged so existing greps and any future
// metric filter keep working.
export const metrics = {
  increment(name: string, tags?: MetricTags): void {
    logger.info({ metric: name, type: 'counter', ...tags }, `metric:${name}`);
  },

  gauge(name: string, value: number, tags?: MetricTags): void {
    logger.info({ metric: name, type: 'gauge', value, ...tags }, `metric:${name}`);
  },

  startTimer(name: string): TimerResult {
    const start = Date.now();
    return {
      end(tags?: MetricTags): void {
        const durationMs = Date.now() - start;
        logger.info({ metric: name, type: 'histogram', durationMs, ...tags }, `metric:${name}`);
      },
    };
  },
};
