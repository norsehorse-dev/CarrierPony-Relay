-- 003: per-device push platform.
--
-- Every registration before this migration is an iPhone, so the default
-- 'apns' makes the existing fleet correct with no backfill. Android devices
-- send platform=fcm on /v1/register-push from CarrierPony Android 1.0.

ALTER TABLE devices
  ADD COLUMN platform VARCHAR(8) NOT NULL DEFAULT 'apns' AFTER push_token;
