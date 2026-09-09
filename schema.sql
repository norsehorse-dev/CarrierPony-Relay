CREATE TABLE IF NOT EXISTS identities (
  fpr         CHAR(40) NOT NULL PRIMARY KEY,
  pubkey      MEDIUMTEXT NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS devices (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  fpr         CHAR(40) NOT NULL,
  device_id   CHAR(32) NOT NULL,
  label       VARCHAR(64) NULL,
  push_token  VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME NULL,
  UNIQUE KEY uq_device (fpr, device_id),
  KEY k_dev_fpr (fpr),
  CONSTRAINT fk_dev_ident FOREIGN KEY (fpr) REFERENCES identities(fpr) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS messages (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_id  CHAR(32) NOT NULL,
  to_fpr      CHAR(40) NOT NULL,
  envelope    LONGTEXT NOT NULL,
  size_bytes  INT UNSIGNED NOT NULL,
  received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME NOT NULL,
  UNIQUE KEY uq_message_id (message_id),
  KEY k_msg_to (to_fpr),
  KEY k_msg_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS deliveries (
  message_pk  BIGINT UNSIGNED NOT NULL,
  device_pk   BIGINT UNSIGNED NOT NULL,
  acked_at    DATETIME NULL,
  PRIMARY KEY (message_pk, device_pk),
  KEY k_del_device (device_pk, acked_at),
  CONSTRAINT fk_del_msg FOREIGN KEY (message_pk) REFERENCES messages(id) ON DELETE CASCADE,
  CONSTRAINT fk_del_dev FOREIGN KEY (device_pk) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS challenges (
  nonce       CHAR(64) NOT NULL PRIMARY KEY,
  fpr         CHAR(40) NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME NOT NULL,
  KEY k_chal_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
