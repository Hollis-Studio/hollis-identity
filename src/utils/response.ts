/**
 * @ai-context Standardized API response helpers for Identity Service.
 */

import type { NextFunction, Request, Response } from "express";
import { formatErrorDigest } from "../lib/formatErrorDigest";
import { logger } from "../lib/logger";

export interface SuccessResponse<T> {
  success: true;
  data: T;
}

export interface ErrorResponse {
  success: false;
  error: string;
  details?: string;
  code?: string;
  requestId?: string;
}

function logDevSendError(res: Response, errorMessage: string, statusCode: number, code?: string): void {
  if (process.env.NODE_ENV !== "development") return;
  if (statusCode === 401 && (code === "UNAUTHORIZED" || code === undefined)) return;
  const req = res.req;
  const digest = formatErrorDigest(new Error(errorMessage), {
    method: req.method,
    path: req.path,
    requestId: (req as Request | undefined)?.requestId,
    statusCode,
    extra: code != null ? { code } : undefined,
  });
  process.stderr.write(`\n${digest}\n\n`);
}

export function sendSuccess<T>(res: Response, data: T, statusCode: number = 200): void {
  res.status(statusCode).json({ success: true, data } satisfies SuccessResponse<T>);
}

export function sendCreated<T>(res: Response, data: T): void {
  sendSuccess(res, data, 201);
}

export function sendError(
  res: Response,
  error: string,
  statusCode: number = 500,
  details?: string,
  code?: string,
  requestId?: string,
): void {
  logDevSendError(res, error, statusCode, code);
  const response: ErrorResponse = { success: false, error };
  if (details) response.details = details;
  if (code) response.code = code;
  if (requestId) response.requestId = requestId;
  res.status(statusCode).json(response);
}

export function sendNotFound(res: Response, resource: string): void {
  sendError(res, `${resource} not found`, 404, undefined, "NOT_FOUND");
}

export function sendBadRequest(res: Response, message: string, details?: string): void {
  sendError(res, message, 400, details, "BAD_REQUEST");
}

export function sendUnauthorized(
  res: Response,
  message = "Unauthorized",
  code = "UNAUTHORIZED",
): void {
  sendError(res, message, 401, undefined, code);
}

export function sendForbidden(res: Response, message = "Forbidden", code = "FORBIDDEN"): void {
  sendError(res, message, 403, undefined, code);
}

export function sendConflict(res: Response, message: string): void {
  sendError(res, message, 409, undefined, "CONFLICT");
}

export function sendTooManyRequests(
  res: Response,
  message = "Too many requests",
  retryAfterSeconds?: number,
): void {
  const response: ErrorResponse & { retryAfterSeconds?: number } = {
    success: false,
    error: message,
    code: "RATE_LIMIT_EXCEEDED",
  };
  if (retryAfterSeconds !== undefined) response.retryAfterSeconds = retryAfterSeconds;
  res.status(429).json(response);
}

// Keep NextFunction in scope for completeness (not used but keeps parity with health)
export type { NextFunction };

// Augment Request with requestId
declare global {
  namespace Express {
    interface Request {
      requestId?: string;
    }
  }
}
