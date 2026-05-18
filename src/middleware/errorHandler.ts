/**
 * @ai-context Express error handling middleware for Identity Service.
 *
 * Sentry removed — not a dependency of Identity Service.
 * SessionError removed — Identity Service uses token-based sessions only.
 *
 * deps: ../lib/AppError, express | consumers: src/index.ts
 */

import {
  HTTP_STATUS,
  sanitizeErrorMessage,
  sanitizeErrorObject,
} from "@hollis-studio/contracts";
import { Prisma } from "../lib/prisma";
import type { NextFunction, Request, Response } from "express";
import type { ParsedQs } from "qs";
import { AppError } from "../lib/AppError";
import { env } from "../lib/env";
import { formatErrorDigest } from "../lib/formatErrorDigest";
import { logger } from "../lib/logger";

function logDevDigest(err: Error, req: Request, statusCode: number): void {
  if (env.NODE_ENV !== "development") return;
  const digest = formatErrorDigest(err, {
    method: req.method,
    path: req.path,
    requestId: req.requestId,
    statusCode,
  });
  process.stderr.write(`\n${digest}\n\n`);
}

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const errWithType = err as Error & { type?: string; statusCode?: number };
  if (
    errWithType.type === "entity.too.large" ||
    errWithType.statusCode === HTTP_STATUS.PAYLOAD_TOO_LARGE
  ) {
    logger.warn(
      { path: req.path, requestId: req.requestId, contentLength: req.headers["content-length"] },
      "Request payload too large",
    );
    logDevDigest(err, req, HTTP_STATUS.PAYLOAD_TOO_LARGE);
    res.status(HTTP_STATUS.PAYLOAD_TOO_LARGE).json({
      success: false,
      error: "Request payload is too large. Please reduce the file size and try again.",
      code: "PAYLOAD_TOO_LARGE",
      requestId: req.requestId,
    });
    return;
  }

  if (err instanceof SyntaxError && "body" in err) {
    logger.warn({ path: req.path, requestId: req.requestId }, "Invalid JSON in request body");
    logDevDigest(err, req, HTTP_STATUS.BAD_REQUEST);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: "Invalid JSON in request body",
      code: "INVALID_JSON",
      requestId: req.requestId,
    });
    return;
  }

  if (err instanceof AppError) {
    if (err.statusCode >= 500) {
      logger.error({ err, requestId: req.requestId }, "AppError (server error)");
      logDevDigest(err, req, err.statusCode);
    } else if (err.statusCode >= 400) {
      logger.warn(
        { code: err.code, message: err.message, statusCode: err.statusCode, requestId: req.requestId, path: req.path },
        "AppError (client error)",
      );
      logDevDigest(err, req, err.statusCode);
    }
    res.status(err.statusCode).json({ ...err.toJSON(), requestId: req.requestId });
    return;
  }

  // Sanitize Prisma errors before logging (no PHI in messages)
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    logger.error(
      { prismaCode: err.code, requestId: req.requestId, path: req.path },
      "Prisma error",
    );
    logDevDigest(err, req, HTTP_STATUS.INTERNAL_SERVER_ERROR);
  } else {
    logger.error({ err, requestId: req.requestId, path: req.path }, "Unexpected error in request");
    logDevDigest(err, req, HTTP_STATUS.INTERNAL_SERVER_ERROR);
  }

  const response = {
    success: false as const,
    error:
      env.NODE_ENV === "development"
        ? sanitizeErrorMessage(err.message) || "An unexpected error occurred"
        : "An unexpected error occurred",
    code: "INTERNAL_ERROR",
    requestId: req.requestId,
  };

  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json(response);
}

export function asyncWrapper<
  P = Record<string, string>,
  ResBody = unknown,
  ReqBody = unknown,
  ReqQuery = ParsedQs,
>(
  fn: (
    req: Request<P, ResBody, ReqBody, ReqQuery>,
    res: Response<ResBody>,
    next: NextFunction,
  ) => Promise<void>,
): (req: Request<P, ResBody, ReqBody, ReqQuery>, res: Response<ResBody>, next: NextFunction) => void {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Keep sanitizeErrorObject in scope (used by AppError)
export { sanitizeErrorObject };
