package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

func TestSQLiteIsCreatedWithEveryTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub dir", "relay.db")
	s, err := Open(config.Database{Driver: "sqlite", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, table := range []string{"identities", "devices", "messages", "deliveries", "challenges",
		"pairing_offers", "sealed_devices", "mailboxes", "sealed_messages", "reports"} {
		var n int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Errorf("%s: %v", table, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("database file mode is %v, want 0600", info.Mode().Perm())
	}
	var mode string
	var fk int
	if err := s.DB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v", mode, err)
	}
	if err := s.DB.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d, %v", fk, err)
	}
}

func TestSQLiteOpensAnExistingFileAndKeepsItsRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	s, err := Open(config.Database{Driver: "sqlite", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	now := Stamp(time.Now())
	if _, err := s.DB.Exec("INSERT INTO challenges (nonce, fpr, created_at, expires_at) VALUES (?, ?, ?, ?)", "n", "F", now, now); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(config.Database{Driver: "sqlite", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM challenges").Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows after reopening: %d, %v", n, err)
	}
}

func TestDeletingADeviceRemovesItsDeliveries(t *testing.T) {
	s, err := Open(config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := Stamp(time.Now())
	for _, q := range []string{
		"INSERT INTO identities (fpr, pubkey, created_at) VALUES ('F', 'k', '" + now + "')",
		"INSERT INTO devices (id, fpr, device_id, created_at) VALUES (1, 'F', 'd', '" + now + "')",
		"INSERT INTO messages (id, message_id, to_fpr, envelope, size_bytes, received_at, expires_at) VALUES (1, 'm', 'F', 'e', 1, '" + now + "', '" + now + "')",
		"INSERT INTO deliveries (message_pk, device_pk) VALUES (1, 1)",
		"DELETE FROM identities WHERE fpr = 'F'",
	} {
		if _, err := s.DB.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var devices, deliveries int
	s.DB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&devices)
	s.DB.QueryRow("SELECT COUNT(*) FROM deliveries").Scan(&deliveries)
	if devices != 0 || deliveries != 0 {
		t.Fatalf("after deleting the identity: %d devices, %d deliveries", devices, deliveries)
	}
}

func TestStampIsUTCToTheSecond(t *testing.T) {
	loc := time.FixedZone("x", -6*3600)
	got := Stamp(time.Date(2026, 11, 17, 21, 5, 9, 999, loc))
	if got != "2026-11-18 03:05:09" {
		t.Fatalf("Stamp = %q", got)
	}
}
