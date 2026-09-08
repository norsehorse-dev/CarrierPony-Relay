-- 004: remember which APNs environment each device's token belongs to.
--
-- An APNs token is only valid against the environment that minted it: a build
-- signed aps-environment=development against api.sandbox.push.apple.com, a
-- distributed build against api.push.apple.com. The relay had one configured
-- environment for the whole fleet, so with 'sandbox' set the developer's Xcode
-- builds received notifications and every TestFlight tester received none.
-- APNs reports that as 400 BadDeviceToken, which the sender ignored, so the
-- failure was silent on both ends.
--
-- NULL means "not yet known". cp_apns_deliver() tries the configured default,
-- falls back to the other environment on BadDeviceToken, and writes back
-- whichever answered 200, so the fleet resolves itself with no backfill and
-- each device pays the extra round trip at most once.
--
-- Idempotent: the column is added only when it is not already present.

SET @add_col := (
  SELECT COUNT(*) = 0
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'devices'
    AND COLUMN_NAME = 'apns_env'
);
SET @ddl := IF(
  @add_col,
  "ALTER TABLE devices ADD COLUMN apns_env VARCHAR(10) NULL AFTER platform",
  "DO 0"
);
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
