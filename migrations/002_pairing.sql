CREATE TABLE IF NOT EXISTS pairing_offers (
  token            CHAR(32)   NOT NULL,
  offerer_fpr      CHAR(40)   NOT NULL,
  offerer_pubkey   MEDIUMTEXT NOT NULL,
  responder_fpr    CHAR(40)       NULL,
  responder_pubkey MEDIUMTEXT     NULL,
  state            ENUM('open','accepted') NOT NULL DEFAULT 'open',
  created_at       DATETIME   NOT NULL,
  expires_at       DATETIME   NOT NULL,
  PRIMARY KEY (token),
  KEY idx_offerer_state (offerer_fpr, state),
  KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
