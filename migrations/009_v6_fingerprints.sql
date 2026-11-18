-- 009: room for OpenPGP v6 fingerprints.
--
-- A v4 fingerprint is 40 hex characters (SHA-1). A v6 key (RFC 9580) has a
-- 64-character SHA-256 fingerprint, so every column that holds a fingerprint
-- goes from CHAR(40) to VARCHAR(64). Existing rows are untouched: a 40-character
-- value reads back exactly as before.
--
-- Idempotent: a column is changed only while it is still CHAR(40), and a table
-- or column that does not exist on this relay is skipped. Nullability is kept.
--
-- devices.fpr references identities.fpr, and neither MySQL nor MariaDB will
-- change a column that a foreign key uses. The key is dropped first (only while
-- one of the two columns still needs changing) and put back at the end (only
-- when it is missing), so a run that was interrupted can simply be run again.
--
-- Each ALTER rebuilds its table. messages holds the queued envelopes, so make
-- sure the database volume has free space at least the size of that table.

SET @needs := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME IN ('identities', 'devices')
    AND COLUMN_NAME = 'fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
SET @fk := (
  SELECT CONSTRAINT_NAME
  FROM information_schema.KEY_COLUMN_USAGE
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'devices'
    AND COLUMN_NAME = 'fpr'
    AND REFERENCED_TABLE_NAME = 'identities'
  LIMIT 1
);
SET @ddl := IF(
  @needs > 0 AND @fk IS NOT NULL,
  CONCAT('ALTER TABLE devices DROP FOREIGN KEY ', @fk),
  'DO 0'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE identities MODIFY fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'identities'
    AND COLUMN_NAME = 'fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE devices MODIFY fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'devices'
    AND COLUMN_NAME = 'fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE messages MODIFY to_fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'messages'
    AND COLUMN_NAME = 'to_fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE challenges MODIFY fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'challenges'
    AND COLUMN_NAME = 'fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE pairing_offers MODIFY offerer_fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'pairing_offers'
    AND COLUMN_NAME = 'offerer_fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE pairing_offers MODIFY responder_fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'pairing_offers'
    AND COLUMN_NAME = 'responder_fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE reports MODIFY reporter_fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'reports'
    AND COLUMN_NAME = 'reporter_fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := (
  SELECT IF(
    COUNT(*) = 1,
    CONCAT('ALTER TABLE reports MODIFY reported_fpr VARCHAR(64) ', IF(MAX(IS_NULLABLE) = 'YES', 'NULL', 'NOT NULL')),
    'DO 0'
  )
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'reports'
    AND COLUMN_NAME = 'reported_fpr'
    AND LOWER(COLUMN_TYPE) = 'char(40)'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk := (
  SELECT CONSTRAINT_NAME
  FROM information_schema.KEY_COLUMN_USAGE
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'devices'
    AND COLUMN_NAME = 'fpr'
    AND REFERENCED_TABLE_NAME = 'identities'
  LIMIT 1
);
SET @ddl := IF(
  @fk IS NULL,
  'ALTER TABLE devices ADD CONSTRAINT fk_dev_ident FOREIGN KEY (fpr) REFERENCES identities(fpr) ON DELETE CASCADE',
  'DO 0'
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
