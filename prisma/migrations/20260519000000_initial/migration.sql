-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('ADMIN', 'CLINICIAN', 'TRAINER', 'CLIENT');

-- CreateEnum
CREATE TYPE "AuthAuditEventType" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'REGISTER_SUCCESS', 'REGISTER_FAILED', 'LOGOUT', 'TOKEN_REFRESH_SUCCESS', 'TOKEN_REFRESH_FAILED', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED', 'EMAIL_VERIFICATION_SENT', 'EMAIL_VERIFICATION_COMPLETED');

-- CreateEnum
CREATE TYPE "MfaCredentialType" AS ENUM ('TOTP', 'WEBAUTHN');

-- CreateEnum
CREATE TYPE "MfaEventType" AS ENUM ('SETUP_STARTED', 'SETUP_COMPLETED', 'SETUP_CANCELLED', 'VERIFICATION_SUCCESS', 'VERIFICATION_FAILED', 'BACKUP_CODE_USED', 'CREDENTIAL_REMOVED', 'RECOVERY_INITIATED', 'RECOVERY_COMPLETED', 'STEP_UP_REQUIRED', 'STEP_UP_SUCCESS', 'STEP_UP_FAILED');

-- CreateEnum
CREATE TYPE "OAuthProviderType" AS ENUM ('APPLE', 'GOOGLE');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "UserRole" NOT NULL DEFAULT 'CLIENT',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "emailVerified" TIMESTAMP(3),
    "organizationId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefreshToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "familyId" TEXT NOT NULL,
    "generation" INTEGER NOT NULL DEFAULT 0,
    "usedAt" TIMESTAMP(3),
    "replacedByTokenHash" TEXT,
    "deviceId" TEXT,
    "userAgent" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MfaCredential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "MfaCredentialType" NOT NULL,
    "name" TEXT NOT NULL,
    "totpSecret" TEXT,
    "webauthnCredentialId" TEXT,
    "webauthnPublicKey" TEXT,
    "webauthnCounter" INTEGER,
    "webauthnTransports" TEXT[],
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "lastUsedAt" TIMESTAMP(3),
    "backupCodesHash" TEXT,
    "backupCodesRemaining" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MfaCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MfaEvent" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "eventType" "MfaEventType" NOT NULL,
    "credentialId" TEXT,
    "success" BOOLEAN NOT NULL DEFAULT true,
    "errorMessage" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "context" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MfaEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "StepUpToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "StepUpToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PendingMfaSession" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "jti" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PendingMfaSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccessTokenDenylistEntry" (
    "id" TEXT NOT NULL,
    "jti" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AccessTokenDenylistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserTokenDenylistEntry" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deniedBefore" TIMESTAMP(3) NOT NULL,
    "reason" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserTokenDenylistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccountLockoutEntry" (
    "accountKey" TEXT NOT NULL,
    "failedAttempts" TIMESTAMP(3)[],
    "lockoutEndsAt" TIMESTAMP(3),
    "uniqueIpHashes" TEXT[],
    "lastUpdated" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AccountLockoutEntry_pkey" PRIMARY KEY ("accountKey")
);

-- CreateTable
CREATE TABLE "PasswordResetToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PasswordResetToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailVerificationToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailVerificationToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthAuditLog" (
    "id" TEXT NOT NULL,
    "actorId" TEXT,
    "eventType" "AuthAuditEventType" NOT NULL,
    "success" BOOLEAN NOT NULL DEFAULT true,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthAuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OAuthAccount" (
    "id" TEXT NOT NULL,
    "provider" "OAuthProviderType" NOT NULL,
    "providerUserId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OAuthAccount_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_organizationId_idx" ON "User"("organizationId");

-- CreateIndex
CREATE INDEX "User_role_isActive_idx" ON "User"("role", "isActive");

-- CreateIndex
CREATE INDEX "User_isActive_idx" ON "User"("isActive");

-- CreateIndex
CREATE UNIQUE INDEX "RefreshToken_tokenHash_key" ON "RefreshToken"("tokenHash");

-- CreateIndex
CREATE INDEX "RefreshToken_userId_idx" ON "RefreshToken"("userId");

-- CreateIndex
CREATE INDEX "RefreshToken_familyId_idx" ON "RefreshToken"("familyId");

-- CreateIndex
CREATE INDEX "RefreshToken_expiresAt_idx" ON "RefreshToken"("expiresAt");

-- CreateIndex
CREATE INDEX "RefreshToken_userId_revokedAt_idx" ON "RefreshToken"("userId", "revokedAt");

-- CreateIndex
CREATE INDEX "MfaCredential_userId_type_idx" ON "MfaCredential"("userId", "type");

-- CreateIndex
CREATE INDEX "MfaCredential_userId_isVerified_idx" ON "MfaCredential"("userId", "isVerified");

-- CreateIndex
CREATE INDEX "MfaEvent_userId_createdAt_idx" ON "MfaEvent"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "MfaEvent_eventType_success_idx" ON "MfaEvent"("eventType", "success");

-- CreateIndex
CREATE INDEX "MfaEvent_createdAt_idx" ON "MfaEvent"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "StepUpToken_tokenHash_key" ON "StepUpToken"("tokenHash");

-- CreateIndex
CREATE INDEX "StepUpToken_userId_action_idx" ON "StepUpToken"("userId", "action");

-- CreateIndex
CREATE INDEX "StepUpToken_expiresAt_idx" ON "StepUpToken"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "PendingMfaSession_tokenHash_key" ON "PendingMfaSession"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "PendingMfaSession_jti_key" ON "PendingMfaSession"("jti");

-- CreateIndex
CREATE INDEX "PendingMfaSession_userId_idx" ON "PendingMfaSession"("userId");

-- CreateIndex
CREATE INDEX "PendingMfaSession_expiresAt_idx" ON "PendingMfaSession"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "AccessTokenDenylistEntry_jti_key" ON "AccessTokenDenylistEntry"("jti");

-- CreateIndex
CREATE INDEX "AccessTokenDenylistEntry_expiresAt_idx" ON "AccessTokenDenylistEntry"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "UserTokenDenylistEntry_userId_key" ON "UserTokenDenylistEntry"("userId");

-- CreateIndex
CREATE INDEX "UserTokenDenylistEntry_expiresAt_idx" ON "UserTokenDenylistEntry"("expiresAt");

-- CreateIndex
CREATE INDEX "AccountLockoutEntry_lockoutEndsAt_idx" ON "AccountLockoutEntry"("lockoutEndsAt");

-- CreateIndex
CREATE INDEX "AccountLockoutEntry_lastUpdated_idx" ON "AccountLockoutEntry"("lastUpdated");

-- CreateIndex
CREATE UNIQUE INDEX "PasswordResetToken_tokenHash_key" ON "PasswordResetToken"("tokenHash");

-- CreateIndex
CREATE INDEX "PasswordResetToken_userId_idx" ON "PasswordResetToken"("userId");

-- CreateIndex
CREATE INDEX "PasswordResetToken_expiresAt_idx" ON "PasswordResetToken"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "EmailVerificationToken_tokenHash_key" ON "EmailVerificationToken"("tokenHash");

-- CreateIndex
CREATE INDEX "EmailVerificationToken_userId_idx" ON "EmailVerificationToken"("userId");

-- CreateIndex
CREATE INDEX "EmailVerificationToken_expiresAt_idx" ON "EmailVerificationToken"("expiresAt");

-- CreateIndex
CREATE INDEX "AuthAuditLog_actorId_createdAt_idx" ON "AuthAuditLog"("actorId", "createdAt");

-- CreateIndex
CREATE INDEX "AuthAuditLog_eventType_success_idx" ON "AuthAuditLog"("eventType", "success");

-- CreateIndex
CREATE INDEX "AuthAuditLog_createdAt_idx" ON "AuthAuditLog"("createdAt");

-- CreateIndex
CREATE INDEX "OAuthAccount_userId_idx" ON "OAuthAccount"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthAccount_provider_providerUserId_key" ON "OAuthAccount"("provider", "providerUserId");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthAccount_userId_provider_key" ON "OAuthAccount"("userId", "provider");

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MfaCredential" ADD CONSTRAINT "MfaCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MfaEvent" ADD CONSTRAINT "MfaEvent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "StepUpToken" ADD CONSTRAINT "StepUpToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PendingMfaSession" ADD CONSTRAINT "PendingMfaSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PasswordResetToken" ADD CONSTRAINT "PasswordResetToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailVerificationToken" ADD CONSTRAINT "EmailVerificationToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthAuditLog" ADD CONSTRAINT "AuthAuditLog_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuthAccount" ADD CONSTRAINT "OAuthAccount_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
