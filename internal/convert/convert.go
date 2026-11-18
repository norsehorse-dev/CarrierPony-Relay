// Package convert turns the PHP relay's config.php into the Go relay's
// config.toml, so an existing relay can switch without retyping its settings.
package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

// FromPHP maps the settings of a config.php, given as the JSON PHP prints for
// the array it returns, onto a Go relay config. Settings it does not carry
// over, and why, come back as notes.
func FromPHP(phpJSON []byte) (config.Config, []string, error) {
	cfg := config.Default()
	var php map[string]any
	if err := json.Unmarshal(phpJSON, &php); err != nil {
		return cfg, nil, fmt.Errorf("config.php did not return an array of settings: %w", err)
	}
	var notes []string
	used := map[string]bool{}
	section := func(name string) map[string]any {
		used[name] = true
		m, _ := php[name].(map[string]any)
		return m
	}
	text := func(m map[string]any, key string, into *string) {
		if s, isString := m[key].(string); isString && s != "" {
			*into = s
		}
	}

	// An existing relay keeps its MySQL database and everything in it.
	db := section("db")
	if db == nil {
		return cfg, nil, fmt.Errorf("config.php has no 'db' block")
	}
	cfg.Database = config.Database{Driver: "mysql", Host: "127.0.0.1"}
	text(db, "host", &cfg.Database.Host)
	text(db, "name", &cfg.Database.Name)
	text(db, "user", &cfg.Database.User)
	text(db, "pass", &cfg.Database.Password)
	if port, has := number(db["port"]); has && port != 3306 {
		cfg.Database.Host = fmt.Sprintf("%s:%d", cfg.Database.Host, port)
	}

	limits := []struct {
		key  string
		into any
	}{
		{"challenge_ttl", &cfg.Limits.ChallengeTTL},
		{"message_ttl_max_days", &cfg.Limits.MessageTTLMaxDays},
		{"max_envelope_bytes", &cfg.Limits.MaxEnvelopeBytes},
		{"inbox_bytes_budget", &cfg.Limits.InboxBytesBudget},
		{"pair_offer_ttl", &cfg.Limits.PairOfferTTL},
		{"pair_accepted_keep_days", &cfg.Limits.PairAcceptedKeepDays},
		{"pair_max_open", &cfg.Limits.PairMaxOpen},
		{"sealed_pending_cap", &cfg.Limits.SealedPendingCap},
		{"device_stale_days", &cfg.Limits.DeviceStaleDays},
		{"sealed_device_stale_days", &cfg.Limits.SealedDeviceStaleDays},
	}
	for _, l := range limits {
		used[l.key] = true
		n, has := number(php[l.key])
		if !has {
			continue
		}
		switch into := l.into.(type) {
		case *int:
			*into = int(n)
		case *int64:
			*into = n
		}
	}

	// In config.php a missing push_gateway block meant the CarrierPony
	// gateway, and a null url meant no gateway at all.
	if _, present := php["push_gateway"]; present {
		cfg.PushGateway.URL = ""
		text(section("push_gateway"), "url", &cfg.PushGateway.URL)
	}

	if apns := section("apns"); truthy(apns["enabled"]) {
		cfg.APNs.Enabled = true
		text(apns, "key_file", &cfg.APNs.KeyFile)
		text(apns, "key_id", &cfg.APNs.KeyID)
		text(apns, "team_id", &cfg.APNs.TeamID)
		text(apns, "bundle_id", &cfg.APNs.BundleID)
		text(apns, "environment", &cfg.APNs.Environment)
	}
	if fcm := section("fcm"); truthy(fcm["enabled"]) {
		cfg.FCM.Enabled = true
		text(fcm, "service_account_file", &cfg.FCM.ServiceAccountFile)
		if _, has := fcm["token_cache"]; has {
			notes = append(notes, "fcm.token_cache is not carried over: the access token is kept in memory now, and that file can be deleted.")
		}
	}

	for _, key := range []string{"gnupg_home", "verifier_bin", "verifier_shadow"} {
		if _, has := php[key]; has {
			used[key] = true
			notes = append(notes, key+" is not carried over: this relay checks login signatures itself, with no gpg and no cp-verify.")
		}
	}
	var unknown []string
	for key := range php {
		if !used[key] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	for _, key := range unknown {
		notes = append(notes, key+" is not carried over: this relay has no such setting.")
	}
	return cfg, notes, cfg.Validate()
}

// number reads a PHP integer setting, which may arrive as a number or as a
// numeric string.
func number(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		if x != math.Trunc(x) {
			return 0, false
		}
		return int64(x), true
	case string:
		var n int64
		if _, err := fmt.Sscanf(x, "%d", &n); err == nil && fmt.Sprint(n) == strings.TrimSpace(x) {
			return n, true
		}
	}
	return 0, false
}

// truthy is PHP's !empty() for the values an 'enabled' setting takes.
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != "" && x != "0"
	}
	return false
}

// Render writes a config as the text of a config.toml, with the notes as
// comments at the top. Push blocks that are off are left out.
func Render(cfg config.Config, source string, notes []string) (string, error) {
	var out bytes.Buffer
	out.WriteString("# CarrierPony relay configuration, converted from " + source + ".\n")
	out.WriteString("# config.sample.toml describes every setting. This file holds the database\n")
	out.WriteString("# password, so keep it readable only by the user the relay runs as.\n")
	for _, note := range notes {
		out.WriteString("#\n# Note: " + note + "\n")
	}
	out.WriteString("\n")
	enc := toml.NewEncoder(&out)
	enc.Indent = ""
	top := struct {
		Listen           string `toml:"listen"`
		ReapEveryMinutes int    `toml:"reap_every_minutes"`
	}{cfg.Listen, cfg.ReapEveryMinutes}
	if err := enc.Encode(top); err != nil {
		return "", err
	}
	type mysqlBlock struct {
		Driver   string `toml:"driver"`
		Host     string `toml:"host"`
		Name     string `toml:"name"`
		User     string `toml:"user"`
		Password string `toml:"password"`
	}
	type sqliteBlock struct {
		Driver string `toml:"driver"`
		Path   string `toml:"path"`
	}
	var database any = sqliteBlock{cfg.Database.Driver, cfg.Database.Path}
	if cfg.Database.Driver == "mysql" {
		database = mysqlBlock{cfg.Database.Driver, cfg.Database.Host, cfg.Database.Name, cfg.Database.User, cfg.Database.Password}
	}
	sections := []struct {
		name  string
		value any
	}{{"database", database}, {"limits", cfg.Limits}, {"push_gateway", cfg.PushGateway}}
	if cfg.APNs.Enabled {
		sections = append(sections, struct {
			name  string
			value any
		}{"apns", cfg.APNs})
	}
	if cfg.FCM.Enabled {
		sections = append(sections, struct {
			name  string
			value any
		}{"fcm", cfg.FCM})
	}
	for _, s := range sections {
		if err := enc.Encode(map[string]any{s.name: s.value}); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}
