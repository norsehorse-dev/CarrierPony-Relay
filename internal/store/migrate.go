package store

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	relay "github.com/norsehorse-dev/CarrierPony-Relay"
)

// statements splits a .sql file the way tools/apply_migration.php does: lines
// that are only a comment are dropped first, so a semicolon inside a comment
// cannot cut a statement in two, and the rest is split on semicolons.
func statements(sql string) []string {
	var kept []string
	for _, line := range strings.Split(strings.ReplaceAll(sql, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	var out []string
	for _, chunk := range strings.Split(strings.Join(kept, "\n"), ";") {
		if code := strings.TrimSpace(chunk); code != "" {
			out = append(out, code)
		}
	}
	return out
}

// Migrate brings a MySQL database to the current layout: schema.sql, then every
// file in migrations/ in order. Each one changes something only when it is
// missing, so running it again does nothing. It returns the files it applied.
//
// A SQLite database needs none of this. Its tables are created when the file
// is first opened.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	if s.Driver != "mysql" {
		return nil, nil
	}
	names, err := fs.Glob(relay.SQL, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	names = append([]string{"schema.sql"}, names...)

	// The migrations keep values in session variables between statements, so
	// every statement of a run has to go down the same connection.
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var applied []string
	for _, name := range names {
		raw, err := relay.SQL.ReadFile(name)
		if err != nil {
			return applied, err
		}
		for _, stmt := range statements(string(raw)) {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return applied, fmt.Errorf("%s: %w", name, err)
			}
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// CheckSchema reports whether a MySQL database has what this relay needs. It
// looks for the newest thing each migration adds, so a database that was never
// migrated, or only partly, is caught at startup with a clear message instead
// of failing later in the middle of a request.
func (s *Store) CheckSchema(ctx context.Context) error {
	if s.Driver != "mysql" {
		return nil
	}
	probes := []string{
		"SELECT fpr, pubkey FROM identities LIMIT 0",
		"SELECT push_token, wake_token, platform, apns_env, last_seen FROM devices LIMIT 0",
		"SELECT alert, size_bytes FROM messages LIMIT 0",
		"SELECT acked_at FROM deliveries LIMIT 0",
		"SELECT nonce FROM challenges LIMIT 0",
		"SELECT accepted_at, responder_pubkey FROM pairing_offers LIMIT 0",
		"SELECT wake_token FROM sealed_devices LIMIT 0",
		"SELECT sealed_device_pk FROM mailboxes LIMIT 0",
		"SELECT alert FROM sealed_messages LIMIT 0",
		"SELECT attachment_meta, status FROM reports LIMIT 0",
	}
	for _, q := range probes {
		rows, err := s.DB.QueryContext(ctx, q)
		if err != nil {
			return fmt.Errorf("the database is missing part of the relay's schema (%v). Run \"carrierpony-relay migrate\"", err)
		}
		rows.Close()
	}
	// v6 fingerprints are 64 characters. A column still at 40 would cut them.
	var narrow int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.COLUMNS
		 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('identities', 'devices', 'messages', 'challenges', 'pairing_offers')
		   AND COLUMN_NAME IN ('fpr', 'to_fpr', 'offerer_fpr', 'responder_fpr') AND CHARACTER_MAXIMUM_LENGTH < 64`).Scan(&narrow)
	if err != nil {
		return err
	}
	if narrow > 0 {
		return fmt.Errorf("%d fingerprint columns are too narrow for v6 keys. Run \"carrierpony-relay migrate\"", narrow)
	}
	return nil
}
