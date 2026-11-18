-- 008: remember whether a stored message should alert.
--
-- The F-Droid build has no FCM. Without a UnifiedPush distributor it falls back
-- to a periodic background check that asks the inbox what is waiting, without
-- decrypting or acknowledging anything. To avoid posting "New message" for read
-- receipts, profile syncs and self-copies, it needs to know which stored
-- messages were sent silent. The sender already tells the relay (the silent
-- flag that picks the push shape); this keeps it with the message as alert = 0.
--
-- Default 1, so rows stored before this migration count as alerting.
-- Idempotent: each column is added only when absent.

SET @add_col := (
  SELECT COUNT(*) = 0
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'messages'
    AND COLUMN_NAME = 'alert'
);
SET @ddl := IF(
  @add_col,
  "ALTER TABLE messages ADD COLUMN alert TINYINT(1) NOT NULL DEFAULT 1 AFTER size_bytes",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @add_col := (
  SELECT COUNT(*) = 0
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sealed_messages'
    AND COLUMN_NAME = 'alert'
);
SET @ddl := IF(
  @add_col,
  "ALTER TABLE sealed_messages ADD COLUMN alert TINYINT(1) NOT NULL DEFAULT 1 AFTER size_bytes",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
