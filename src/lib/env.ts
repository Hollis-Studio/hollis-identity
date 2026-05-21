/**
 * @ai-context Centralized environment validation for Identity Service.
 *
 * Validates only vars relevant to Identity Service:
 * - Core: DATABASE_URL, JWT_SECRET/JWT_PRIVATE_KEY, JWT_ISSUER, JWT_AUDIENCES, PASSWORD_PEPPER, PORT, LOG_LEVEL
 * - Encryption: ENCRYPTION_KEY (for MFA TOTP secret encryption)
 * - OAuth: APPLE_SERVICE_ID, IOS_BUNDLE_ID, GOOGLE_CLIENT_ID (for social sign-in id_token verification)
 * - Security: BCRYPT_COST_FACTOR, ACCESS_TOKEN_DENYLIST_ENABLED, COOKIE_DOMAIN
 * - AWS/SES: AWS_REGION (for future email/SES integration)
 * - Dev/test: E2E_SECURITY_TEST, REDIS_URL
 *
 * deps: zod | consumers: index.ts (startup), authService.ts, etc.
 */

import { z } from "zod";

// ============================================================================
// Constants
// ============================================================================

const MIN_SECRET_LENGTH = 32;

const FORBIDDEN_SECRET_VALUES = [
  "secret",
  "password",
  "changeme",
  "your-secret-here",
  "your_secret_here",
  "jwt-secret",
  "jwt_secret",
  "development-secret",
  "dev-secret",
  "test-secret",
  "test",
  "default",
  "placeholder",
  "supersecret",
  "super-secret",
  "12345678",
  "123456789012345678901234567890",
  "xxxxxxxx",
];

function hasMinimumEntropy(value: string): boolean {
  if (value.length < MIN_SECRET_LENGTH) return false;
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /[0-9]/.test(value);
  const hasSpecial = /[^a-zA-Z0-9]/.test(value);
  return [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length >= 3;
}

// ============================================================================
// Custom Zod Refinements
// ============================================================================

const secretSchema = z.string().refine(
  (val) => {
    if (!val || val.trim() === "") return false;
    const isProduction = process.env.NODE_ENV === "production";
    if (!isProduction) return val.length >= 8;
    const lowerVal = val.toLowerCase();
    if (
      FORBIDDEN_SECRET_VALUES.some((forbidden) => lowerVal.includes(forbidden))
    )
      return false;
    return hasMinimumEntropy(val);
  },
  {
    message: `Secret must be at least ${MIN_SECRET_LENGTH} characters with mixed character classes. Generate with: openssl rand -base64 32`,
  },
);

const optionalSecretSchema = z
  .string()
  .optional()
  .refine(
    (val) => {
      if (!val) return true;
      const isProduction = process.env.NODE_ENV === "production";
      if (!isProduction) return true;
      return val.length >= MIN_SECRET_LENGTH;
    },
    {
      message: `Optional secret, if provided, must be at least ${MIN_SECRET_LENGTH} characters`,
    },
  );

const urlSchema = z
  .string()
  .url()
  .refine(
    (val) =>
      val.startsWith("http://") ||
      val.startsWith("https://") ||
      val.startsWith("postgresql://"),
    {
      message:
        "Must be a valid URL with http://, https://, or postgresql:// protocol",
    },
  );

const portSchema = z.coerce.number().int().min(1).max(65535);

const dataMigrationModeFlagSchema = z.enum(["1"]).optional();

// ============================================================================
// Environment Schema
// ============================================================================

const envSchema = z.object({
  // Core
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  PORT: portSchema.default(4001),

  // JWT
  JWT_ALGORITHM: z.enum(["HS256", "RS256"]).default("HS256"),
  JWT_SECRET: secretSchema,
  JWT_PRIVATE_KEY: z.string().optional(),
  JWT_PUBLIC_KEY: z.string().optional(),
  JWT_KEY_ID: z.string().optional(),
  JWT_ISSUER: z.string().min(1).optional(),
  JWT_AUDIENCES: z.string().optional(), // comma-separated list

  // Database
  DATABASE_URL: urlSchema,
  DATABASE_SSL_CA: z.string().optional(),

  // Encryption (for MFA TOTP secrets)
  ENCRYPTION_KEY: secretSchema,

  // Password hashing
  BCRYPT_COST_FACTOR: z.coerce.number().int().min(10).max(16).default(13),
  PASSWORD_PEPPER: z
    .string()
    .min(32, "Password pepper must be at least 32 characters")
    .optional(),

  // Logging
  LOG_LEVEL: z
    .enum(["debug", "info", "warn", "error"])
    .optional()
    .default("info"),
  LOG_DB_QUERIES: z.string().optional(),
  ECS_TASK_ID: z.string().optional(),

  // Security
  COOKIE_DOMAIN: z.string().optional(),
  ACCESS_TOKEN_DENYLIST_ENABLED: z
    .string()
    .transform((val) => val !== "false")
    .default(true),
  CORS_ORIGINS: z.string().optional(),

  // Rate limiting
  REDIS_URL: z.string().optional(),
  RATE_LIMIT_REDIS_FALLBACK: z.enum(["memory", "error"]).optional(),
  E2E_SECURITY_TEST: z.string().optional(),

  // OAuth (social sign-in id_token verification)
  APPLE_SERVICE_ID: z.string().optional(),
  APPLE_TEAM_ID: z.string().optional(),
  IOS_BUNDLE_ID: z.string().optional(),
  GOOGLE_CLIENT_ID: z.string().optional(),

  // AWS (for future email/SES)
  AWS_REGION: z.string().optional(),

  // Email (for password reset + verification notifications)
  EMAIL_PROVIDER: z.enum(["console", "ses"]).default("console"),
  EMAIL_FROM: z.string().email().default("noreply@hollis.health"),
  RESET_PASSWORD_URL: urlSchema.optional(),
  VERIFY_EMAIL_URL: urlSchema.optional(),

  // Sentry
  SENTRY_DSN: z.string().optional(),
  SENTRY_ENVIRONMENT: z.string().optional(),
  SENTRY_TRACES_SAMPLE_RATE: z.coerce.number().min(0).max(1).default(0.1),

  // Observability
  APP_VERSION: z.string().optional(),
  IMAGE_TAG: z.string().optional(),

  // Feature flags
  // ENABLE_OIDC_DISCOVERY: gate /.well-known/openid-configuration.
  // Default false — flip true ONLY when WebAuthn + key rotation + logout webhook are shipped.
  ENABLE_OIDC_DISCOVERY: z
    .string()
    .default("false")
    .transform((val) => val === "true"),

  // Dev/test
  DEV_ADMIN_SECRET: optionalSecretSchema,
  DATA_MIGRATION_RUN: dataMigrationModeFlagSchema,
  RUN_DATA_MIGRATIONS: dataMigrationModeFlagSchema,

  // Instance/deployment
  HOST: z.string().optional(),
  HOSTNAME: z.string().optional(),
});

// ============================================================================
// Type Exports
// ============================================================================

export type Env = z.infer<typeof envSchema>;

type RawDataMigrationModeEnv = Partial<
  Pick<NodeJS.ProcessEnv, "DATA_MIGRATION_RUN" | "RUN_DATA_MIGRATIONS">
>;

// ============================================================================
// Validation State
// ============================================================================

let _validatedEnv: Env | null = null;

const dataMigrationModeEnvSchema = z.object({
  DATA_MIGRATION_RUN: dataMigrationModeFlagSchema,
  RUN_DATA_MIGRATIONS: dataMigrationModeFlagSchema,
});

function pickDataMigrationModeEnv(
  rawEnv: RawDataMigrationModeEnv = process.env,
): RawDataMigrationModeEnv {
  return {
    DATA_MIGRATION_RUN: rawEnv.DATA_MIGRATION_RUN,
    RUN_DATA_MIGRATIONS: rawEnv.RUN_DATA_MIGRATIONS,
  };
}

// ============================================================================
// Validation Functions
// ============================================================================

export function validateEnv(): Env {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const errors = result.error.issues.map((issue) => {
      const path = issue.path.join(".");
      return `  - ${path}: ${issue.message}`;
    });

    throw new Error(
      `\n${"=".repeat(60)}\n` +
        `FATAL: Environment validation failed\n` +
        `${"=".repeat(60)}\n\n` +
        `The following environment variables are missing or invalid:\n\n` +
        errors.join("\n") +
        `\n\n` +
        `See README.md for required environment variables.\n` +
        `Example .env file: .env.example\n` +
        `\n${"=".repeat(60)}\n`,
    );
  }

  return result.data;
}

export function isDataMigrationModeEnabled(
  rawEnv: RawDataMigrationModeEnv = process.env,
): boolean {
  const result = dataMigrationModeEnvSchema.safeParse(
    pickDataMigrationModeEnv(rawEnv),
  );
  if (!result.success) return false;
  return (
    result.data.DATA_MIGRATION_RUN === "1" ||
    result.data.RUN_DATA_MIGRATIONS === "1"
  );
}

export function hasDataMigrationModeFlag(
  rawEnv: RawDataMigrationModeEnv = process.env,
): boolean {
  const flags = pickDataMigrationModeEnv(rawEnv);
  return (
    flags.DATA_MIGRATION_RUN !== undefined ||
    flags.RUN_DATA_MIGRATIONS !== undefined
  );
}

export function validateEnvOnStartup(): void {
  if (isDataMigrationModeEnabled()) {
    _validatedEnv = validateEnv();
    return;
  }

  const validated = validateEnv();
  _validatedEnv = validated;

  const isProduction = validated.NODE_ENV === "production";
  const warnings: string[] = [];
  const errors: string[] = [];

  if (isProduction) {
    if (validated.JWT_ALGORITHM !== "RS256") {
      errors.push("Production Identity must use JWT_ALGORITHM=RS256.");
    }
    if (!validated.JWT_PRIVATE_KEY) {
      errors.push("JWT_PRIVATE_KEY is required when NODE_ENV=production.");
    }
    if (!validated.JWT_KEY_ID) {
      errors.push("JWT_KEY_ID is required when NODE_ENV=production.");
    }
    if (!validated.APPLE_SERVICE_ID) {
      warnings.push(
        "APPLE_SERVICE_ID not set. Apple Sign In will be unavailable.",
      );
    }
    if (!validated.GOOGLE_CLIENT_ID) {
      warnings.push(
        "GOOGLE_CLIENT_ID not set. Google Sign In will be unavailable.",
      );
    }
    if (validated.EMAIL_PROVIDER === "ses" && !validated.AWS_REGION) {
      errors.push("EMAIL_PROVIDER=ses but AWS_REGION is not set.");
    }
    if (validated.EMAIL_PROVIDER === "ses" && !validated.RESET_PASSWORD_URL) {
      errors.push("EMAIL_PROVIDER=ses but RESET_PASSWORD_URL is not set.");
    }
    if (!validated.SENTRY_DSN) {
      warnings.push(
        "SENTRY_DSN is not configured — crash reporting is disabled.",
      );
    }
  }

  if (warnings.length > 0) {
    process.stderr.write(
      "\nConfiguration warnings:\n" +
        warnings.map((w) => `  - ${w}`).join("\n") +
        "\n",
    );
  }

  if (errors.length > 0) {
    const label = isProduction ? "Production" : "Environment";
    throw new Error(
      `\n${"=".repeat(60)}\n` +
        `FATAL: ${label} configuration errors\n` +
        `${"=".repeat(60)}\n\n` +
        errors.map((e) => `  - ${e}`).join("\n") +
        `\n\n${"=".repeat(60)}\n`,
    );
  }

  const jwtSecretLower = validated.JWT_SECRET.toLowerCase();
  if (isProduction) {
    for (const forbidden of FORBIDDEN_SECRET_VALUES) {
      if (jwtSecretLower.includes(forbidden)) {
        throw new Error(
          `FATAL: JWT_SECRET contains a forbidden pattern: "${forbidden}"\n` +
            `Generate a secure secret with: openssl rand -base64 32`,
        );
      }
    }
  }
}

export function getEnv(): Env {
  if (!_validatedEnv) {
    _validatedEnv = validateEnv();
  }
  return _validatedEnv;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
export const env = new Proxy({} as Env, {
  get(_target, prop: string) {
    const validated = getEnv();
    return validated[prop as keyof Env];
  },
});

export function isEnvValidated(): boolean {
  return _validatedEnv !== null;
}

export function resetEnvValidation(): void {
  _validatedEnv = null;
}
