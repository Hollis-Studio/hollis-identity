/**
 * @ai-context Common validation patterns for Identity Service.
 *
 * NOTE: USER_ID_REGEX is kept here for backward compatibility but is NOT used
 * in authService.ts — the barcode format check was removed in W6d as it is
 * Health-specific business logic. Identity Service is agnostic to userId format.
 */

/**
 * @deprecated Health-specific barcode format (HH-XXXXXX).
 * Not used by Identity Service — userId format is app-specific.
 */
export const USER_ID_REGEX = /^HH-[A-Z0-9]{6}$/;
