package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOverridesOnlyWhatIsSet(t *testing.T) {
	cfg, err := Load(write(t, `
listen = "127.0.0.1:9000"
[database]
driver = "mysql"
password = "secret"
[limits]
max_envelope_bytes = 30000
[push_gateway]
url = ""
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9000" || cfg.Database.Driver != "mysql" || cfg.Database.Password != "secret" {
		t.Fatalf("settings from the file were not applied: %+v", cfg)
	}
	if cfg.ReapEveryMinutes != 5 {
		t.Fatalf("reap_every_minutes = %d", cfg.ReapEveryMinutes)
	}
	if cfg.Database.Name != "carrierpony" || cfg.Limits.ChallengeTTL != 300 || cfg.Limits.InboxBytesBudget != 8388608 {
		t.Fatalf("defaults were lost: %+v", cfg)
	}
	if cfg.Limits.MaxEnvelopeBytes != 30000 {
		t.Fatalf("max_envelope_bytes = %d", cfg.Limits.MaxEnvelopeBytes)
	}
	if cfg.PushGateway.URL != "" {
		t.Fatalf("an empty gateway url should turn the gateway off, got %q", cfg.PushGateway.URL)
	}
}

func TestAnAbsentGatewayBlockKeepsTheDefault(t *testing.T) {
	cfg, err := Load(write(t, `listen = "127.0.0.1:9000"`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PushGateway.URL != "https://push.carrierpony.com" {
		t.Fatalf("gateway url = %q", cfg.PushGateway.URL)
	}
}

func TestUnknownSettingIsRefused(t *testing.T) {
	_, err := Load(write(t, "[limits]\nchallange_ttl = 10\n"))
	if err == nil || !strings.Contains(err.Error(), "limits.challange_ttl") {
		t.Fatalf("want an error naming the setting, got %v", err)
	}
}

func TestBadValuesAreRefused(t *testing.T) {
	for _, body := range []string{
		"[database]\ndriver = \"postgres\"\n",
		"[database]\ndriver = \"sqlite\"\npath = \"\"\n",
		"[database]\ndriver = \"mysql\"\nuser = \"\"\n",
		"[limits]\nmax_envelope_bytes = 0\n",
		"[limits]\ndevice_stale_days = -1\n",
		"listen = \"\"\n",
		"reap_every_minutes = -1\n",
		"listen = 5\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("accepted: %q", body)
		}
	}
}
