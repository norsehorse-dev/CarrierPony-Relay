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
