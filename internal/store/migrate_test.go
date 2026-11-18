package store

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	relay "github.com/norsehorse-dev/CarrierPony-Relay"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

func TestStatements(t *testing.T) {
	got := statements("-- a comment; with a semicolon\r\nCREATE TABLE a (\n  id INT -- not a full-line comment\n);\n\n   -- indented comment\nSET @x := 1;\nSELECT 1")
	want := []string{"CREATE TABLE a (\n  id INT -- not a full-line comment\n)", "SET @x := 1", "SELECT 1"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d: %q, want %q", i, got[i], want[i])
		}
	}
	if len(statements(" \n-- only a comment\n;;\n")) != 0 {
		t.Error("empty input produced statements")
	}
}

func TestTheSchemaAndEveryMigrationAreInTheBinary(t *testing.T) {
	raw, err := relay.SQL.ReadFile("schema.sql")
	if err != nil || !strings.Contains(string(raw), "CREATE TABLE IF NOT EXISTS identities") {
		t.Fatalf("schema.sql: %v", err)
	}
	names, _ := fs.Glob(relay.SQL, "migrations/*.sql")
	if len(names) < 9 {
		t.Fatalf("only %d migrations are embedded: %v", len(names), names)
	}
	for _, name := range names {
		raw, _ := relay.SQL.ReadFile(name)
		if len(statements(string(raw))) == 0 {
			t.Errorf("%s has no statements", name)
		}
	}
}

func TestMigrateAndCheckSchemaLeaveSQLiteAlone(t *testing.T) {
	st, err := Open(config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	applied, err := st.Migrate(context.Background())
	if err != nil || len(applied) != 0 {
		t.Errorf("Migrate on SQLite: %v, %v", applied, err)
	}
	if err := st.CheckSchema(context.Background()); err != nil {
		t.Errorf("CheckSchema on SQLite: %v", err)
	}
}
