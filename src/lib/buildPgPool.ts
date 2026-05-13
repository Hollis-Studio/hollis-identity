import { Pool, type PoolConfig } from "pg";

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
    ...(isProduction ? { ssl: { rejectUnauthorized: false } } : {}),
    ...params.poolOptions,
  });
}
