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

export function buildPgPool(params: {
  databaseUrl: string;
  nodeEnv: string;
  poolOptions?: PoolConfig;
}): Pool {
  const isProduction = params.nodeEnv === "production";
  let connectionString = params.databaseUrl;

  if (isProduction) {
    try {
      const u = new URL(params.databaseUrl);
      u.searchParams.delete("sslmode");
      connectionString = u.toString();
    } catch {
      // not a valid URL — fall through with original
    }
  }

  return new Pool({
    connectionString,
    ...(isProduction ? { ssl: buildProductionSslConfig() } : {}),
    ...params.poolOptions,
  });
}
