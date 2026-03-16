-- Keep only the newest active root key per org before enforcing uniqueness.
WITH ranked_active_keys AS (
  SELECT
    id,
    "orgId",
    ROW_NUMBER() OVER (
      PARTITION BY "orgId"
      ORDER BY "createdAt" DESC, id DESC
    ) AS rn
  FROM "RootKey"
  WHERE status = 'ACTIVE'
)
UPDATE "RootKey" rk
SET
  status = 'REVOKED',
  "revokedAt" = COALESCE(rk."revokedAt", NOW())
FROM ranked_active_keys rak
WHERE rk.id = rak.id
  AND rak.rn > 1;

CREATE UNIQUE INDEX "RootKey_one_active_per_org_idx"
  ON "RootKey" ("orgId")
  WHERE status = 'ACTIVE';
