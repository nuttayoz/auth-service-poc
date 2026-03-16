-- AlterTable
ALTER TABLE "RootKey" ADD COLUMN     "createdByUserId" TEXT,
ADD COLUMN     "lastUsedAt" TIMESTAMP(3),
ADD COLUMN     "orgId" TEXT;

-- Backfill ownership for any existing root keys from audit + user records.
WITH created_audits AS (
  SELECT DISTINCT ON ((metadata ->> 'rootKeyId'))
    metadata ->> 'rootKeyId' AS "rootKeyId",
    "actorUserId"
  FROM "AuditLog"
  WHERE action = 'root_key.create'
    AND metadata ? 'rootKeyId'
    AND "actorUserId" IS NOT NULL
  ORDER BY (metadata ->> 'rootKeyId'), "createdAt" ASC
)
UPDATE "RootKey" rk
SET "createdByUserId" = created_audits."actorUserId"
FROM created_audits
WHERE rk.id = created_audits."rootKeyId"
  AND rk."createdByUserId" IS NULL;

UPDATE "RootKey" rk
SET "orgId" = u."orgId"
FROM "User" u
WHERE rk."createdByUserId" = u.id
  AND rk."orgId" IS NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "RootKey" WHERE "orgId" IS NULL) THEN
    RAISE EXCEPTION 'Cannot backfill orgId for all RootKey rows';
  END IF;
END $$;

ALTER TABLE "RootKey" ALTER COLUMN "orgId" SET NOT NULL;

-- CreateIndex
CREATE INDEX "RootKey_orgId_status_idx" ON "RootKey"("orgId", "status");

-- CreateIndex
CREATE INDEX "RootKey_createdByUserId_idx" ON "RootKey"("createdByUserId");

-- AddForeignKey
ALTER TABLE "RootKey" ADD CONSTRAINT "RootKey_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Org"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RootKey" ADD CONSTRAINT "RootKey_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
