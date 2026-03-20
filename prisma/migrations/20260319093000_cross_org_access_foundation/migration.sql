-- CreateEnum
CREATE TYPE "UserOrgAccessSource" AS ENUM ('DIRECT', 'EXTERNAL');

-- CreateEnum
CREATE TYPE "UserOrgAccessStatus" AS ENUM ('ACTIVE', 'REVOKED');

-- AlterTable
ALTER TABLE "Session" ADD COLUMN "homeOrgId" TEXT;

-- Backfill session home org from the owning user.
UPDATE "Session" AS s
SET "homeOrgId" = u."orgId"
FROM "User" AS u
WHERE s."userId" = u."id";

ALTER TABLE "Session" ALTER COLUMN "homeOrgId" SET NOT NULL;

-- CreateTable
CREATE TABLE "UserOrgAccess" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "role" "UserRole" NOT NULL,
    "source" "UserOrgAccessSource" NOT NULL DEFAULT 'DIRECT',
    "projectGrantId" TEXT,
    "zitadelRoleAssignmentId" TEXT,
    "status" "UserOrgAccessStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserOrgAccess_pkey" PRIMARY KEY ("id")
);

-- Backfill direct org access for all existing local users.
INSERT INTO "UserOrgAccess" (
    "id",
    "userId",
    "orgId",
    "role",
    "source",
    "status",
    "createdAt",
    "updatedAt"
)
SELECT
    md5(u."id" || ':' || u."orgId"),
    u."id",
    u."orgId",
    u."role",
    'DIRECT'::"UserOrgAccessSource",
    'ACTIVE'::"UserOrgAccessStatus",
    u."createdAt",
    u."updatedAt"
FROM "User" AS u;

-- CreateIndex
CREATE INDEX "Session_homeOrgId_idx" ON "Session"("homeOrgId");

-- CreateIndex
CREATE UNIQUE INDEX "UserOrgAccess_userId_orgId_key" ON "UserOrgAccess"("userId", "orgId");

-- CreateIndex
CREATE INDEX "UserOrgAccess_orgId_status_idx" ON "UserOrgAccess"("orgId", "status");

-- CreateIndex
CREATE INDEX "UserOrgAccess_userId_status_idx" ON "UserOrgAccess"("userId", "status");

-- AddForeignKey
ALTER TABLE "UserOrgAccess" ADD CONSTRAINT "UserOrgAccess_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserOrgAccess" ADD CONSTRAINT "UserOrgAccess_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Org"("id") ON DELETE CASCADE ON UPDATE CASCADE;
