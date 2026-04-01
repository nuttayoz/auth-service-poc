-- AlterTable
ALTER TABLE "ProvisioningJob" ADD COLUMN     "requestedByRootKeyId" TEXT;

-- CreateIndex
CREATE INDEX "ProvisioningJob_requestedByRootKeyId_idx" ON "ProvisioningJob"("requestedByRootKeyId");
