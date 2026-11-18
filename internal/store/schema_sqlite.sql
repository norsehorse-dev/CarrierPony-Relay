-- SQLite layout of the relay's tables. It mirrors schema.sql plus the
-- migrations, which stay the reference for MySQL. Times are UTC text,
-- 'YYYY-MM-DD HH:MM:SS', written by the relay.

CREATE TABLE IF NOT EXISTS identities (
  fpr         TEXT NOT NULL PRIMARY KEY,
  pubkey      TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fpr         TEXT NOT NULL REFERENCES identities(fpr) ON DELETE CASCADE,
  device_id   TEXT NOT NULL,
  label       TEXT NULL,
  push_token  TEXT NULL,
  wake_token  TEXT NULL,
  platform    TEXT NOT NULL DEFAULT 'apns',
  apns_env    TEXT NULL,
  created_at  TEXT NOT NULL,
  last_seen   TEXT NULL,
  UNIQUE (fpr, device_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id  TEXT NOT NULL UNIQUE,
  to_fpr      TEXT NOT NULL,
  envelope    TEXT NOT NULL,
  size_bytes  INTEGER NOT NULL,
  alert       INTEGER NOT NULL DEFAULT 1,
  received_at TEXT NOT NULL,
  expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS k_msg_to ON messages (to_fpr);
CREATE INDEX IF NOT EXISTS k_msg_expires ON messages (expires_at);

CREATE TABLE IF NOT EXISTS deliveries (
  message_pk  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  device_pk   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  acked_at    TEXT NULL,
  PRIMARY KEY (message_pk, device_pk)
);
CREATE INDEX IF NOT EXISTS k_del_device ON deliveries (device_pk, acked_at);

CREATE TABLE IF NOT EXISTS challenges (
  nonce       TEXT NOT NULL PRIMARY KEY,
  fpr         TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS k_chal_expires ON challenges (expires_at);

CREATE TABLE IF NOT EXISTS pairing_offers (
  token            TEXT NOT NULL PRIMARY KEY,
  offerer_fpr      TEXT NOT NULL,
  offerer_pubkey   TEXT NOT NULL,
  responder_fpr    TEXT NULL,
  responder_pubkey TEXT NULL,
  accepted_at      TEXT NULL,
  state            TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted')),
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_offerer_state ON pairing_offers (offerer_fpr, state);
CREATE INDEX IF NOT EXISTS idx_expires ON pairing_offers (expires_at);
CREATE INDEX IF NOT EXISTS idx_state_accepted ON pairing_offers (state, accepted_at);

CREATE TABLE IF NOT EXISTS sealed_devices (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id   TEXT NOT NULL UNIQUE,
  device_key  TEXT NOT NULL,
  wake_token  TEXT NULL,
  created_at  TEXT NOT NULL,
  last_seen   TEXT NULL
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox           TEXT NOT NULL UNIQUE,
  sealed_device_pk  INTEGER NOT NULL REFERENCES sealed_devices(id) ON DELETE CASCADE,
  expires_at        TEXT NOT NULL,
  created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS k_mbx_device ON mailboxes (sealed_device_pk);
CREATE INDEX IF NOT EXISTS k_mbx_expires ON mailboxes (expires_at);

CREATE TABLE IF NOT EXISTS sealed_messages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id  TEXT NOT NULL UNIQUE,
  mailbox     TEXT NOT NULL,
  envelope    TEXT NOT NULL,
  size_bytes  INTEGER NOT NULL,
  alert       INTEGER NOT NULL DEFAULT 1,
  received_at TEXT NOT NULL,
  expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS k_smsg_mailbox ON sealed_messages (mailbox);
CREATE INDEX IF NOT EXISTS k_smsg_expires ON sealed_messages (expires_at);

CREATE TABLE IF NOT EXISTS reports (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_fpr    TEXT NOT NULL,
  reported_fpr    TEXT NOT NULL,
  category        TEXT NOT NULL,
  description     TEXT NULL,
  content         TEXT NULL,
  attachment_meta TEXT NULL,
  status          TEXT NOT NULL DEFAULT 'open',
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS k_rep_reported ON reports (reported_fpr);
CREATE INDEX IF NOT EXISTS k_rep_status ON reports (status);
CREATE INDEX IF NOT EXISTS k_rep_created ON reports (created_at);
