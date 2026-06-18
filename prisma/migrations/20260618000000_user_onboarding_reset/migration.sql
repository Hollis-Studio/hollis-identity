-- Cross-device "Reset Onboarding" epoch.
--
-- Additive: a brand-new table with a single FK to "User". No existing table is
-- altered and no existing query references this table, so deploying the new
-- server image BEFORE this migration runs is safe — the /me onboarding-reset
-- read is wrapped defensively and degrades to "no reset pending", and the
-- /v1/auth/onboarding/reset endpoint is the only writer. Run
-- `npx prisma migrate deploy` to activate the cross-device reset behavior.

CREATE TABLE "UserOnboardingReset" (
  "userId"    TEXT NOT NULL,
  "resetAt"   TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "UserOnboardingReset_pkey" PRIMARY KEY ("userId")
);

ALTER TABLE "UserOnboardingReset"
  ADD CONSTRAINT "UserOnboardingReset_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
