package store

import "context"

// The statements here are the ones MySQL and SQLite spell differently.
// Everything else is written once, in the handlers, in SQL both understand.

// UpsertIdentity stores an identity's public key, replacing the key of an
// identity that is already there.
func (s *Store) UpsertIdentity(ctx context.Context, fpr, pubkey, now string) error {
	q := "INSERT INTO identities (fpr, pubkey, created_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE pubkey = VALUES(pubkey)"
	if s.Driver == "sqlite" {
		q = "INSERT INTO identities (fpr, pubkey, created_at) VALUES (?, ?, ?) ON CONFLICT (fpr) DO UPDATE SET pubkey = excluded.pubkey"
	}
	_, err := s.DB.ExecContext(ctx, q, fpr, pubkey, now)
	return err
}

// UpsertDevice registers a device under an identity. A device that is already
// there gets the new label and a fresh last_seen; a new one has no last_seen
// until it first polls.
func (s *Store) UpsertDevice(ctx context.Context, fpr, deviceID string, label any, now string) error {
	q := "INSERT INTO devices (fpr, device_id, label, created_at) VALUES (?, ?, ?, ?) " +
		"ON DUPLICATE KEY UPDATE last_seen = ?, label = VALUES(label)"
	if s.Driver == "sqlite" {
		q = "INSERT INTO devices (fpr, device_id, label, created_at) VALUES (?, ?, ?, ?) " +
			"ON CONFLICT (fpr, device_id) DO UPDATE SET last_seen = ?, label = excluded.label"
	}
	_, err := s.DB.ExecContext(ctx, q, fpr, deviceID, label, now, now)
	return err
}

// insertIgnore is the opening of an INSERT that skips a row whose unique key is
// already taken instead of failing.
func (s *Store) insertIgnore() string {
	if s.Driver == "sqlite" {
		return "INSERT OR IGNORE INTO "
	}
	return "INSERT IGNORE INTO "
}

// InsertSealedDevice registers a sealed device unless its id is taken. It
// reports whether this call created the row.
func (s *Store) InsertSealedDevice(ctx context.Context, deviceID, deviceKey string, wakeToken any, now string) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		s.insertIgnore()+"sealed_devices (device_id, device_key, wake_token, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
		deviceID, deviceKey, wakeToken, now, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ClaimMailboxes gives each mailbox that has no owner to a device, in one
// statement. A mailbox another device already owns is left alone, and two
// devices claiming the same one at once are settled by the unique key.
func (s *Store) ClaimMailboxes(ctx context.Context, device int64, mailboxes []string, expires map[string]string, now string) error {
	if len(mailboxes) == 0 {
		return nil
	}
	q := s.insertIgnore() + "mailboxes (mailbox, sealed_device_pk, expires_at, created_at) VALUES "
	args := make([]any, 0, len(mailboxes)*4)
	for i, m := range mailboxes {
		if i > 0 {
			q += ","
		}
		q += "(?, ?, ?, ?)"
		args = append(args, m, device, expires[m], now)
	}
	_, err := s.DB.ExecContext(ctx, q, args...)
	return err
}
