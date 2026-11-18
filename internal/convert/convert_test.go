package convert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

const livePHP = `{
  "db": {"host": "127.0.0.1", "name": "carrierpony", "user": "cp", "pass": "p\"a\\ss 'word' #1", "charset": "utf8mb4"},
  "gnupg_home": "/var/lib/carrierpony/gnupg",
  "verifier_bin": "/usr/local/bin/cp-verify",
  "verifier_shadow": false,
  "challenge_ttl": 300,
  "message_ttl_max_days": 30,
  "max_envelope_bytes": 26214400,
  "inbox_bytes_budget": "4194304",
  "pair_max_open": 5,
  "device_stale_days": 45,
  "apns": {"enabled": true, "key_file": "/etc/carrierpony/AuthKey_ABC.p8", "key_id": "ABC", "team_id": "TEAM", "bundle_id": "com.carrierpony.app", "environment": "sandbox"},
  "fcm": {"enabled": 1, "service_account_file": "/etc/carrierpony/fcm.json", "token_cache": "/var/lib/carrierpony/fcm_token.json"},
  "something_else": 7
}`

func TestFromPHP(t *testing.T) {
	cfg, notes, err := FromPHP([]byte(livePHP))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database != (config.Database{Driver: "mysql", Host: "127.0.0.1", Name: "carrierpony", User: "cp", Password: `p"a\ss 'word' #1`}) {
		t.Errorf("database: %+v", cfg.Database)
	}
	l := cfg.Limits
	if l.ChallengeTTL != 300 || l.InboxBytesBudget != 4194304 || l.PairMaxOpen != 5 || l.DeviceStaleDays != 45 {
		t.Errorf("limits from the file: %+v", l)
	}
	if l.PairOfferTTL != 86400 || l.SealedPendingCap != 20 || l.SealedDeviceStaleDays != 60 {
		t.Errorf("limits not in the file should keep their defaults: %+v", l)
	}
	if cfg.PushGateway.URL != "https://push.carrierpony.com" {
		t.Errorf("a config.php without push_gateway means the default gateway, got %q", cfg.PushGateway.URL)
	}
	if !cfg.APNs.Enabled || cfg.APNs.KeyID != "ABC" || cfg.APNs.Environment != "sandbox" || !cfg.FCM.Enabled || cfg.FCM.ServiceAccountFile != "/etc/carrierpony/fcm.json" {
		t.Errorf("push: %+v %+v", cfg.APNs, cfg.FCM)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"gnupg_home", "verifier_bin", "verifier_shadow", "fcm.token_cache", "something_else"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no note about %s in:\n%s", want, joined)
		}
	}
	if len(notes) != 5 {
		t.Errorf("%d notes: %v", len(notes), notes)
	}
}

func TestGatewaySetting(t *testing.T) {
	base := `{"db":{"host":"h","name":"n","user":"u","pass":"p"}`
	for body, want := range map[string]string{
		base + `}`:                                             "https://push.carrierpony.com",
		base + `,"push_gateway":{"url":null}}`:                 "",
		base + `,"push_gateway":[]}`:                           "",
		base + `,"push_gateway":{"url":"https://gw.example"}}`: "https://gw.example",
	} {
		cfg, _, err := FromPHP([]byte(body))
		if err != nil || cfg.PushGateway.URL != want {
			t.Errorf("%s: gateway %q, %v, want %q", body, cfg.PushGateway.URL, err, want)
		}
	}
}

func TestPushThatIsOffStaysOff(t *testing.T) {
	cfg, _, err := FromPHP([]byte(`{"db":{"host":"h","name":"n","user":"u","pass":"p"},
		"apns":{"enabled":false,"key_file":"/x.p8"},"fcm":{"enabled":0}}`))
	if err != nil || cfg.APNs.Enabled || cfg.FCM.Enabled {
		t.Fatalf("%+v %+v %v", cfg.APNs, cfg.FCM, err)
	}
	text, _ := Render(cfg, "config.php", nil)
	if strings.Contains(text, "[apns]") || strings.Contains(text, "[fcm]") {
		t.Errorf("push blocks that are off were written:\n%s", text)
	}
}

func TestProblemsAreReported(t *testing.T) {
	for _, body := range []string{`not json`, `[]`, `{}`, `{"db":{"host":"h","name":"","user":"u"}}`,
		`{"db":{"host":"h","name":"n","user":"u"},"apns":{"enabled":true}}`,
		`{"db":{"host":"h","name":"n","user":"u"},"max_envelope_bytes":0}`} {
		if _, _, err := FromPHP([]byte(body)); err == nil {
			t.Errorf("accepted: %s", body)
		}
	}
}

func TestTheRenderedFileLoadsBackTheSame(t *testing.T) {
	cfg, notes, err := FromPHP([]byte(livePHP))
	if err != nil {
		t.Fatal(err)
	}
	text, err := Render(cfg, "/opt/carrierpony/config.php", notes)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte(text), 0o600)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("the rendered file does not load: %v\n%s", err, text)
	}
	// The sqlite path is not written for a MySQL relay and loads as its default.
	loaded.Database.Path = cfg.Database.Path
	if loaded != cfg {
		t.Errorf("round trip changed the config\n got %+v\nwant %+v", loaded, cfg)
	}
	if !strings.Contains(text, "# Note: gnupg_home is not carried over") {
		t.Errorf("notes are missing from the file:\n%s", text)
	}
}
