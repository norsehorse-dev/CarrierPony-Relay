-- 010: the reports table.
--
-- The report endpoint stores what a user chose to send when reporting another
-- identity. The table was created by hand on the first relay and never made it
-- into the schema, so a relay installed from this repository answered every
-- report with a database error. Fingerprint columns are wide enough for v6.
--
-- CREATE TABLE IF NOT EXISTS, so a relay that already has the table is left
-- as it is.

CREATE TABLE IF NOT EXISTS reports (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  reporter_fpr    VARCHAR(64) NOT NULL,
  reported_fpr    VARCHAR(64) NOT NULL,
  category        VARCHAR(32) NOT NULL,
  description     TEXT NULL,
  content         MEDIUMTEXT NULL,
  attachment_meta TEXT NULL,
  status          VARCHAR(16) NOT NULL DEFAULT 'open',
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY k_rep_reported (reported_fpr),
  KEY k_rep_status (status),
  KEY k_rep_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
