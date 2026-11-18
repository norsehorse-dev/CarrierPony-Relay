// Package store opens the relay's database, MySQL or SQLite, and holds the few
// things the two need done differently.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

// TimeLayout is how every time is stored and compared: UTC, to the second. It
// is what MySQL prints for a DATETIME and it sorts as text, so the same value
// and the same comparison work in both databases.
const TimeLayout = "2006-01-02 15:04:05"

//go:embed schema_sqlite.sql
var sqliteSchema string

// Store is an open database.
type Store struct {
	DB     *sql.DB
	Driver string // "mysql" or "sqlite"
}

// Stamp formats a time the way the store keeps it.
func Stamp(t time.Time) string {
	return t.UTC().Format(TimeLayout)
}

// Open connects to the configured database and checks that it answers. A
// SQLite file is created with its tables if it is new. A MySQL database is
// expected to carry the schema already.
func Open(cfg config.Database) (*Store, error) {
	switch cfg.Driver {
	case "mysql":
		return openMySQL(cfg)
	case "sqlite":
		return openSQLite(cfg)
	}
	return nil, fmt.Errorf("unknown database driver %q", cfg.Driver)
}

func openMySQL(cfg config.Database) (*Store, error) {
	mc := mysql.NewConfig()
	mc.User = cfg.User
	mc.Passwd = cfg.Password
	mc.DBName = cfg.Name
	if strings.HasPrefix(cfg.Host, "/") {
		mc.Net = "unix"
		mc.Addr = cfg.Host
	} else {
		mc.Net = "tcp"
		mc.Addr = cfg.Host
		if _, _, err := net.SplitHostPort(cfg.Host); err != nil {
			mc.Addr = net.JoinHostPort(cfg.Host, "3306")
		}
	}
	mc.Params = map[string]string{"charset": "utf8mb4"}
	// Ask the server how large a packet it takes instead of assuming, so a
	// large envelope is refused by the server's own limit and nothing lower.
	mc.MaxAllowedPacket = 0
	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("mysql: %w", err)
	}
	return &Store{DB: db, Driver: "mysql"}, nil
}

func openSQLite(cfg config.Database) (*Store, error) {
	if dir := filepath.Dir(cfg.Path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("sqlite: %w", err)
		}
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	// A transaction takes the write lock when it begins. Otherwise two that
	// read first and write later can each hold what the other needs.
	q.Set("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Opaque: url.PathEscape(cfg.Path), RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	if err := os.Chmod(cfg.Path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	return &Store{DB: db, Driver: "sqlite"}, nil
}

// Close releases the database.
func (s *Store) Close() error {
	return s.DB.Close()
}
