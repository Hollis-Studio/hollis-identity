/**
 * @ai-context JWT key material helper | centralizes Identity token signing, verification, and JWKS export
 *
 * Production uses RS256 with a private signing key and public JWKS. HS256 remains
 * available for local tests and development only.
 */

import crypto from "crypto";
import jwt, { type Algorithm, type Secret, type SignOptions, type VerifyOptions } from "jsonwebtoken";
import { getEnv } from "./env";

export interface PublicJwk {
  kty: string;
  kid: string;
  use: "sig";
  alg: "RS256";
  n: string;
  e: string;
}

function normalizePem(value: string): string {
  return value.replace(/\\n/g, "\n");
}

export function getJwtAlgorithm(): Algorithm {
  return getEnv().JWT_ALGORITHM;
}

export function signJwt(payload: string | Buffer | object, options?: SignOptions): string {
  const env = getEnv();

  if (env.JWT_ALGORITHM === "RS256") {
    if (!env.JWT_PRIVATE_KEY) {
      throw new Error("JWT_PRIVATE_KEY is required for RS256 signing");
    }

    return jwt.sign(payload, normalizePem(env.JWT_PRIVATE_KEY), {
      algorithm: "RS256",
      keyid: env.JWT_KEY_ID,
      ...options,
    });
  }

  return jwt.sign(payload, env.JWT_SECRET, {
    algorithm: "HS256",
    ...options,
  });
}

export function verifyJwt<T extends object | string>(
  token: string,
  options?: VerifyOptions,
): T {
  const env = getEnv();

  if (env.JWT_ALGORITHM === "RS256") {
    const verificationKey = getPublicVerificationKey();
    return jwt.verify(token, verificationKey, {
      algorithms: ["RS256"],
      ...options,
    }) as T;
  }

  return jwt.verify(token, env.JWT_SECRET, {
    algorithms: ["HS256"],
    ...options,
  }) as T;
}

function getPublicVerificationKey(): Secret {
  const env = getEnv();
  if (env.JWT_PUBLIC_KEY) {
    return normalizePem(env.JWT_PUBLIC_KEY);
  }
  if (!env.JWT_PRIVATE_KEY) {
    throw new Error("JWT_PRIVATE_KEY or JWT_PUBLIC_KEY is required for RS256 verification");
  }

  return crypto
    .createPublicKey(normalizePem(env.JWT_PRIVATE_KEY))
    .export({ type: "spki", format: "pem" });
}

export function getPublicJwks(): { keys: PublicJwk[] } {
  const env = getEnv();
  if (env.JWT_ALGORITHM !== "RS256") {
    return { keys: [] };
  }
  if (!env.JWT_KEY_ID) {
    throw new Error("JWT_KEY_ID is required for JWKS export");
  }

  const publicKey = crypto.createPublicKey(getPublicVerificationKey());
  const jwk = publicKey.export({ format: "jwk" });

  if (jwk.kty !== "RSA" || !jwk.n || !jwk.e) {
    throw new Error("JWT public key is not an RSA key");
  }

  return {
    keys: [
      {
        kty: jwk.kty,
        kid: env.JWT_KEY_ID,
        use: "sig",
        alg: "RS256",
        n: jwk.n,
        e: jwk.e,
      },
    ],
  };
}
