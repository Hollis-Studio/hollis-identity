-- Shared service-wide counters for express-rate-limit across ECS tasks.
CREATE TABLE "RateLimitCounter" (
  "key"       TEXT NOT NULL,
  "totalHits" INTEGER NOT NULL,
  "resetTime" TIMESTAMPTZ NOT NULL,
  CONSTRAINT "RateLimitCounter_pkey" PRIMARY KEY ("key")
);

CREATE INDEX "RateLimitCounter_resetTime_idx" ON "RateLimitCounter"("resetTime");
