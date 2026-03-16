-- AlterEnum
ALTER TYPE "ProvisioningJobType" ADD VALUE 'ADMIN_SIGNUP';

-- AlterTable
ALTER TABLE "ProvisioningJob" ADD COLUMN     "orgDomain" TEXT,
ADD COLUMN     "orgName" TEXT,
ADD COLUMN     "resultOrgId" TEXT,
ALTER COLUMN "orgId" DROP NOT NULL,
ALTER COLUMN "requestedByUserId" DROP NOT NULL;

-- CreateIndex
CREATE INDEX "ProvisioningJob_jobType_status_idx" ON "ProvisioningJob"("jobType", "status");

-- CreateIndex
CREATE INDEX "ProvisioningJob_resultOrgId_idx" ON "ProvisioningJob"("resultOrgId");
