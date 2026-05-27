import { Pool, type PoolConfig } from "pg";

function buildProductionSslConfig(): PoolConfig["ssl"] {
  const ca = process.env.DATABASE_SSL_CA?.replace(/\\n/g, "\n");
  // With a CA bundle, fully verify the RDS server cert. Without one, fall back
  // to an encrypted-but-unverified connection — RDS presents a cert signed by
  // the Amazon RDS CA, which isn't in Node's default trust store, so strict
  // verification fails with "self-signed certificate in certificate chain".
  // Mirrors the Workouts server's fallback; provide DATABASE_SSL_CA to harden.
  return ca ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: false };
}

// pg derives TLS settings from both the connection string's libpq params
// (sslmode/sslrootcert/etc.) AND the explicit `ssl` option. Newer pg versions
// parse `sslmode=require` as `verify-full`, which shadows our CA-based `ssl`
// object and surfaces as "self-signed certificate in certificate chain" even
// though the correct RDS CA is supplied. Strip libpq SSL params from the URL
// the Pool uses so the `ssl` object is the single source of truth.
function stripLibpqSslParams(url: string): string {
  if (!url) return url;
  try {
    const u = new URL(url);
    for (const p of ["sslmode", "ssl", "sslrootcert", "sslcert", "sslkey", "sslnegotiation"]) {
      u.searchParams.delete(p);
    }
    return u.toString();
  } catch {
    return url;
  }
}

export function buildPgPool(params: {
  databaseUrl: string;
  nodeEnv: string;
  poolOptions?: PoolConfig;
}): Pool {
  const isProduction = params.nodeEnv === "production";
  const connectionString = isProduction
    ? stripLibpqSslParams(params.databaseUrl)
    : params.databaseUrl;

  return new Pool({
    connectionString,
    ...(isProduction ? { ssl: buildProductionSslConfig() } : {}),
    ...params.poolOptions,
  });
}
