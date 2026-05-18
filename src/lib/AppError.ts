/**
 * @ai-context Standard application error class for consistent API error responses
 */

import { sanitizeErrorMessage, sanitizeErrorObject } from '@hollis-studio/contracts';

export const ERROR_CODES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

export class AppError extends Error {
  public readonly details?: unknown;

  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly statusCode: number,
    details?: unknown
  ) {
    super(sanitizeErrorMessage(message));
    this.name = 'AppError';
    this.details = details === undefined ? undefined : sanitizeErrorObject(details);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AppError);
    }
  }

  static badRequest(message: string, details?: unknown): AppError {
    return new AppError(ERROR_CODES.VALIDATION_ERROR, message, 400, details);
  }

  static notFound(resource: string): AppError {
    return new AppError(ERROR_CODES.NOT_FOUND, `${resource} not found`, 404);
  }

  static unauthorized(message = 'Unauthorized'): AppError {
    return new AppError(ERROR_CODES.UNAUTHORIZED, message, 401);
  }

  static forbidden(message = 'Forbidden'): AppError {
    return new AppError(ERROR_CODES.FORBIDDEN, message, 403);
  }

  static conflict(message: string): AppError {
    return new AppError(ERROR_CODES.CONFLICT, message, 409);
  }

  static internal(message = 'Internal server error'): AppError {
    return new AppError(ERROR_CODES.INTERNAL_ERROR, message, 500);
  }

  toJSON(): Record<string, unknown> {
    return {
      success: false,
      error: this.message,
      code: this.code,
      ...(this.details !== undefined ? { details: this.details } : {}),
    };
  }
}
