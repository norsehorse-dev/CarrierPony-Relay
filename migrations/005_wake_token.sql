-- 005: per-device wake token for the push gateway.
--
-- A self-hosted relay cannot push on its own. A user can opt in to be woken
-- through the CarrierPony push gateway; the app registers with the gateway,
-- gets a wake_token, and hands it here. When a message is stored for that
-- device, the relay nudges the gateway with the token. NULL means the device
-- has not opted in and is never sent to the gateway.
--
-- Idempotent: the column is added only when absent (MySQL 8 has no
-- ADD COLUMN IF NOT EXISTS).

SET @add_col := (
  SELECT COUNT(*) = 0
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'devices'
    AND COLUMN_NAME = 'wake_token'
);
SET @ddl := IF(
  @add_col,
  "ALTER TABLE devices ADD COLUMN wake_token VARCHAR(64) NULL AFTER push_token",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
