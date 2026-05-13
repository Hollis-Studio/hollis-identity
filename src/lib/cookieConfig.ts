/**
 * @ai-context Cookie configuration | Centralized cookie settings for auth tokens
 */

import type { CookieOptions } from 'express';
import { env } from './env';

function getCookieDomain(): string | undefined {
  return env.COOKIE_DOMAIN || undefined;
}

export const AUTH_COOKIES = {
  ACCESS_TOKEN: 'hollis_access_token',
  REFRESH_TOKEN: 'hollis_refresh_token',
} as const;

export const getAccessTokenCookieOptions = (isProduction: boolean): CookieOptions => {
  const domain = getCookieDomain();
  const isCrossSubdomain = !!domain;
  return {
    httpOnly: true,
    secure: isCrossSubdomain || isProduction,
    sameSite: isCrossSubdomain ? 'none' : 'lax',
    path: '/',
    maxAge: 15 * 60 * 1000,
    ...(domain && { domain }),
  };
};

export const getRefreshTokenCookieOptions = (isProduction: boolean): CookieOptions => {
  const domain = getCookieDomain();
  const isCrossSubdomain = !!domain;
  return {
    httpOnly: true,
    secure: isCrossSubdomain || isProduction,
    sameSite: isCrossSubdomain ? 'none' : 'lax',
    path: '/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    ...(domain && { domain }),
  };
};

export const getClearCookieOptions = (isProduction: boolean): CookieOptions => {
  const domain = getCookieDomain();
  const isCrossSubdomain = !!domain;
  return {
    httpOnly: true,
    secure: isCrossSubdomain || isProduction,
    sameSite: isCrossSubdomain ? 'none' : 'lax',
    path: '/',
    ...(domain && { domain }),
  };
};

export function setAuthCookies(
  res: { cookie: (name: string, value: string, options: CookieOptions) => void },
  accessToken: string,
  refreshToken: string,
  isProduction: boolean
): void {
  res.cookie(AUTH_COOKIES.ACCESS_TOKEN, accessToken, getAccessTokenCookieOptions(isProduction));
  res.cookie(AUTH_COOKIES.REFRESH_TOKEN, refreshToken, getRefreshTokenCookieOptions(isProduction));
}

export function clearAuthCookies(
  res: { clearCookie: (name: string, options: CookieOptions) => void },
  isProduction: boolean
): void {
  res.clearCookie(AUTH_COOKIES.ACCESS_TOKEN, getClearCookieOptions(isProduction));
  res.clearCookie(AUTH_COOKIES.REFRESH_TOKEN, {
    ...getClearCookieOptions(isProduction),
    path: '/auth',
  });
}
