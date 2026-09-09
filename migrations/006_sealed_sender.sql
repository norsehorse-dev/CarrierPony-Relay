-- 006: sealed sender with roster hiding.
--
-- Fingerprint-free delivery. A device is known only by a random device_id plus a
-- device_key it proves with an HMAC; messages are addressed to opaque rotating
-- mailbox ids the client derives from a per-pair secret. See
-- CarrierPony-2.0-SealedSender-Design.md. New tables, so CREATE TABLE IF NOT
-- EXISTS is already idempotent.

CREATE TABLE IF NOT EXISTS sealed_devices (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  device_id   CHAR(32) NOT NULL,
  device_key  CHAR(64) NOT NULL,
  wake_token  VARCHAR(64) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME NULL,
  UNIQUE KEY uq_sealed_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS mailboxes (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  mailbox           CHAR(64) NOT NULL,
  sealed_device_pk  BIGINT UNSIGNED NOT NULL,
  expires_at        DATETIME NOT NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_mailbox (mailbox),
  KEY k_mbx_device (sealed_device_pk),
  KEY k_mbx_expires (expires_at),
  CONSTRAINT fk_mbx_dev FOREIGN KEY (sealed_device_pk) REFERENCES sealed_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sealed_messages (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_id  CHAR(32) NOT NULL,
  mailbox     CHAR(64) NOT NULL,
  envelope    LONGTEXT NOT NULL,
  size_bytes  INT UNSIGNED NOT NULL,
  received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME NOT NULL,
  UNIQUE KEY uq_sealed_msg (message_id),
  KEY k_smsg_mailbox (mailbox),
  KEY k_smsg_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
