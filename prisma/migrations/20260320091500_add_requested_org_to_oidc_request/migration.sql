-- AlterTable
ALTER TABLE "OidcRequest"
ADD COLUMN "requestedOrgId" TEXT,
ADD COLUMN "requestedOrgDomain" TEXT;
