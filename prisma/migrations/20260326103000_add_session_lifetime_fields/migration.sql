ALTER TABLE "Session"
ADD COLUMN "expiresAt" TIMESTAMP(3),
ADD COLUMN "lastActivityAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

UPDATE "Session"
SET
  "expiresAt" = "createdAt" + interval '30 days',
  "lastActivityAt" = GREATEST("createdAt", "updatedAt")
WHERE "expiresAt" IS NULL;

ALTER TABLE "Session"
ALTER COLUMN "expiresAt" SET NOT NULL;

CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");
CREATE INDEX "Session_lastActivityAt_idx" ON "Session"("lastActivityAt");
