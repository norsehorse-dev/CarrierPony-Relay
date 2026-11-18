// Package config reads the relay's TOML configuration file.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is everything the relay reads from config.toml. Every field has a
// default, so a file only needs the settings that differ.
type Config struct {
	// Address the relay listens on. It is meant to sit behind a reverse proxy
	// that terminates TLS, so the default is loopback only.
	Listen string `toml:"listen"`
	// How often the relay clears out expired and delivered rows, in minutes.
	// 0 turns the built-in pass off, for a relay that runs
	// "carrierpony-relay reap" from cron instead.
	ReapEveryMinutes int `toml:"reap_every_minutes"`

	Database    Database    `toml:"database"`
	Limits      Limits      `toml:"limits"`
	PushGateway PushGateway `toml:"push_gateway"`
}

// Database selects and locates the store. Driver is "mysql" or "sqlite".
type Database struct {
	Driver string `toml:"driver"`

	// MySQL or MariaDB. Host may be a hostname, host:port, or the path of a
	// unix socket.
	Host     string `toml:"host"`
	Name     string `toml:"name"`
	User     string `toml:"user"`
	Password string `toml:"password"`

	// SQLite: path of the database file. It is created if it does not exist.
	Path string `toml:"path"`
}

// Limits carries the same names and defaults as the PHP relay's config.php.
type Limits struct {
	ChallengeTTL          int   `toml:"challenge_ttl"`
	MessageTTLMaxDays     int   `toml:"message_ttl_max_days"`
	MaxEnvelopeBytes      int64 `toml:"max_envelope_bytes"`
	InboxBytesBudget      int64 `toml:"inbox_bytes_budget"`
	PairOfferTTL          int   `toml:"pair_offer_ttl"`
	PairAcceptedKeepDays  int   `toml:"pair_accepted_keep_days"`
	PairMaxOpen           int   `toml:"pair_max_open"`
	SealedPendingCap      int   `toml:"sealed_pending_cap"`
	DeviceStaleDays       int   `toml:"device_stale_days"`
	SealedDeviceStaleDays int   `toml:"sealed_device_stale_days"`
}

// PushGateway is where opted-in devices are woken. An empty URL turns gateway
// wakes off.
type PushGateway struct {
	URL string `toml:"url"`
}

// Default returns the configuration of a relay with no config file settings.
func Default() Config {
	return Config{
		Listen:           "127.0.0.1:8080",
		ReapEveryMinutes: 5,
		Database: Database{
			Driver: "sqlite",
			Host:   "127.0.0.1",
			Name:   "carrierpony",
			User:   "carrierpony",
			Path:   "/var/lib/carrierpony/relay.db",
		},
		Limits: Limits{
			ChallengeTTL:          300,
			MessageTTLMaxDays:     30,
			MaxEnvelopeBytes:      26214400,
			InboxBytesBudget:      8388608,
			PairOfferTTL:          86400,
			PairAcceptedKeepDays:  30,
			PairMaxOpen:           20,
			SealedPendingCap:      20,
			DeviceStaleDays:       0,
			SealedDeviceStaleDays: 60,
		},
		PushGateway: PushGateway{URL: "https://push.carrierpony.com"},
	}
}

// Load reads a config file over the defaults. A setting the relay does not
// know is an error, so a misspelled name cannot silently leave a default in
// place.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		names := make([]string, len(extra))
		for i, k := range extra {
			names[i] = k.String()
		}
		return cfg, fmt.Errorf("%s: unknown setting: %s", path, strings.Join(names, ", "))
	}
	return cfg, cfg.Validate()
}

// Validate reports the first setting the relay cannot run with.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is empty")
	}
	if c.ReapEveryMinutes < 0 {
		return fmt.Errorf("reap_every_minutes cannot be negative")
	}
	switch c.Database.Driver {
	case "mysql":
		if c.Database.Host == "" || c.Database.Name == "" || c.Database.User == "" {
			return fmt.Errorf("database: mysql needs host, name and user")
		}
	case "sqlite":
		if c.Database.Path == "" {
			return fmt.Errorf("database: sqlite needs path")
		}
	default:
		return fmt.Errorf("database: driver must be \"mysql\" or \"sqlite\", not %q", c.Database.Driver)
	}
	l := c.Limits
	if l.ChallengeTTL <= 0 || l.MessageTTLMaxDays <= 0 || l.MaxEnvelopeBytes <= 0 || l.InboxBytesBudget <= 0 ||
		l.PairOfferTTL <= 0 || l.PairMaxOpen <= 0 || l.SealedPendingCap <= 0 {
		return fmt.Errorf("limits: challenge_ttl, message_ttl_max_days, max_envelope_bytes, inbox_bytes_budget, " +
			"pair_offer_ttl, pair_max_open and sealed_pending_cap must be above zero")
	}
	if l.DeviceStaleDays < 0 || l.SealedDeviceStaleDays < 0 || l.PairAcceptedKeepDays < 0 {
		return fmt.Errorf("limits: the *_days settings cannot be negative")
	}
	return nil
}
