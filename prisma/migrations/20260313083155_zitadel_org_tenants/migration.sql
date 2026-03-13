/*
  Warnings:

  - You are about to drop the column `flow` on the `OidcRequest` table. All the data in the column will be lost.
  - You are about to drop the column `zitadelSub` on the `User` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "User_zitadelSub_key";

-- AlterTable
ALTER TABLE "OidcRequest" DROP COLUMN "flow";

-- AlterTable
ALTER TABLE "User" DROP COLUMN "zitadelSub";

-- DropEnum
DROP TYPE "OidcRequestFlow";
