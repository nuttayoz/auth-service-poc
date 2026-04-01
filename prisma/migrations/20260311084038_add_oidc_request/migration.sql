-- CreateTable
CREATE TABLE "OidcRequest" (
    "id" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "codeVerifier" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "redirectUri" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OidcRequest_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "OidcRequest_state_key" ON "OidcRequest"("state");

-- CreateIndex
CREATE INDEX "OidcRequest_createdAt_idx" ON "OidcRequest"("createdAt");
