-- 007: keep accepted pairing offers long enough for the offerer to collect them.
--
-- Before this, the reaper deleted every offer once expires_at passed, accepted
-- or not, and pair/status never reported an expired offer. An offerer whose app
-- was not opened between the responder's accept and the offer's expiry lost the
-- pairing silently: the row was gone, the client got a 404 and forgot the
-- invite, and the responder's messages could never be verified.
--
-- accepted_at records when the responder accepted. The reaper now deletes open
-- offers at expiry and accepted offers only after pair_accepted_keep_days.
--
-- Idempotent: the column and index are added only when absent.

SET @add_col := (
  SELECT COUNT(*) = 0
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'pairing_offers'
    AND COLUMN_NAME = 'accepted_at'
);
SET @ddl := IF(
  @add_col,
  "ALTER TABLE pairing_offers ADD COLUMN accepted_at DATETIME NULL AFTER responder_pubkey",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @add_idx := (
  SELECT COUNT(*) = 0
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'pairing_offers'
    AND INDEX_NAME = 'idx_state_accepted'
);
SET @ddl := IF(
  @add_idx,
  "ALTER TABLE pairing_offers ADD KEY idx_state_accepted (state, accepted_at)",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
