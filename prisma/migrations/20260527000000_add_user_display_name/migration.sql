-- Add optional human-readable displayName to User.
-- Additive + nullable: backward-compatible with all suite apps reading the table.
ALTER TABLE "User" ADD COLUMN "displayName" TEXT;
