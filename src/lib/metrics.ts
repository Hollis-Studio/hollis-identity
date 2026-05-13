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

export const metrics = {
  increment(name: string, tags?: MetricTags): void {
    logger.debug({ metric: name, type: 'counter', ...tags }, `metric:${name}`);
  },

  gauge(name: string, value: number, tags?: MetricTags): void {
    logger.debug({ metric: name, type: 'gauge', value, ...tags }, `metric:${name}`);
  },

  startTimer(name: string): TimerResult {
    const start = Date.now();
    return {
      end(tags?: MetricTags): void {
        const durationMs = Date.now() - start;
        logger.debug({ metric: name, type: 'histogram', durationMs, ...tags }, `metric:${name}`);
      },
    };
  },
};
