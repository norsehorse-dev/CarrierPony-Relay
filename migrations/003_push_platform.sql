-- 003: per-device push platform.
--
-- Every registration before this migration is an iPhone, so the default
-- 'apns' makes the existing fleet correct with no backfill. Android devices
-- send platform=fcm on /v1/register-push from CarrierPony Android 1.0.
--
-- Idempotent: the column is added only when it is not already present, so
-- re-running the installer or re-applying migrations is safe. MySQL 8 has no
-- ADD COLUMN IF NOT EXISTS, hence the information_schema guard.

SET @add_col := (
  SELECT COUNT(*) = 0
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'devices'
    AND COLUMN_NAME = 'platform'
);
SET @ddl := IF(
  @add_col,
  "ALTER TABLE devices ADD COLUMN platform VARCHAR(8) NOT NULL DEFAULT 'apns' AFTER push_token",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
