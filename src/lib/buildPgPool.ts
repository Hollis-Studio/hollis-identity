import { Pool, type PoolConfig } from "pg";

function buildProductionSslConfig(): PoolConfig["ssl"] {
  const ca = process.env.DATABASE_SSL_CA?.replace(/\\n/g, "\n");
  return ca ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: true };
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
