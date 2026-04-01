-- CreateEnum
CREATE TYPE "ProvisioningJobType" AS ENUM ('USER_CREATE');

-- CreateEnum
CREATE TYPE "ProvisioningJobStatus" AS ENUM ('QUEUED', 'PROCESSING', 'SUCCEEDED', 'FAILED', 'RECONCILIATION_REQUIRED');

-- CreateTable
CREATE TABLE "ProvisioningJob" (
    "id" TEXT NOT NULL,
    "jobType" "ProvisioningJobType" NOT NULL DEFAULT 'USER_CREATE',
    "orgId" TEXT NOT NULL,
    "requestedByUserId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "firstName" TEXT,
    "lastName" TEXT,
    "userName" TEXT NOT NULL,
    "requestedRole" "UserRole" NOT NULL,
    "status" "ProvisioningJobStatus" NOT NULL DEFAULT 'QUEUED',
    "resultUserId" TEXT,
    "errorMessage" TEXT,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProvisioningJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ProvisioningJob_orgId_status_idx" ON "ProvisioningJob"("orgId", "status");

-- CreateIndex
CREATE INDEX "ProvisioningJob_requestedByUserId_idx" ON "ProvisioningJob"("requestedByUserId");

-- CreateIndex
CREATE INDEX "ProvisioningJob_email_idx" ON "ProvisioningJob"("email");
