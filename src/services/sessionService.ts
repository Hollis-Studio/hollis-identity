/**
 * @ai-context Session service stub for Identity Service.
 *
 * SessionError is referenced by errorHandler.ts. This stub provides the class.
 * Full session management is in authService.ts (token-based, no server-side sessions).
 */

export class SessionError extends Error {
  constructor(
    message: string,
    public code: string = "SESSION_ERROR",
    public statusCode: number = 401,
  ) {
    super(message);
    this.name = "SessionError";
  }
}
