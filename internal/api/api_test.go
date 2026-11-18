package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/store"
)

func newServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.Default()
	cfg.Database = config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")}
	cfg.Limits.MaxEnvelopeBytes = 30000
	st, err := store.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, st)
	ts := httptest.NewServer(s)
	t.Cleanup(func() { ts.Close(); st.Close() })
	return s, ts
}

func do(t *testing.T, ts *httptest.Server, method, path, body string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header.Get("Content-Type"), string(raw)
}

func TestRouting(t *testing.T) {
	_, ts := newServer(t)
	good := `{"fpr":"` + strings.Repeat("A", 40) + `"}`
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/v1/challenge", 200},
		{"POST", "/v1/challenge/", 200},
		{"POST", "//v1/challenge//", 200},
		{"POST", "/v1/challenge?x=1", 200},
		{"GET", "/v1/challenge", 404},
		{"PUT", "/v1/challenge", 404},
		{"POST", "/v1/Challenge", 404},
		{"POST", "/v1//challenge", 404},
		{"POST", "/v1/%63hallenge", 404},
		{"POST", "/v1/nope", 404},
		{"POST", "/", 404},
		{"POST", "/v1/send", 501},
	} {
		status, ctype, body := do(t, ts, c.method, c.path, good)
		if status != c.status {
			t.Errorf("%s %s: status %d, want %d (%s)", c.method, c.path, status, c.status, body)
		}
		if ctype != "application/json" {
			t.Errorf("%s %s: content type %q", c.method, c.path, ctype)
		}
		if c.status == 404 && body != `{"error":"not_found"}` {
			t.Errorf("%s %s: body %s", c.method, c.path, body)
		}
	}
}

func TestBodyParsing(t *testing.T) {
	_, ts := newServer(t)
	for _, body := range []string{``, `not json`, `"hello"`, `[1,2]`, `5`, `null`, `{"fpr":null}`, `{"fpr":""}`,
		`{"other":1}`, `{"fpr":"` + strings.Repeat("A", 40) + `"} trailing`} {
		status, _, got := do(t, ts, "POST", "/v1/challenge", body)
		if status != 400 || got != `{"error":"missing:fpr"}` {
			t.Errorf("body %q: %d %s", body, status, got)
		}
	}
	for _, body := range []string{`{"fpr":0}`, `{"fpr":false}`, `{"fpr":[]}`, `{"fpr":{}}`, `{"fpr":["` + strings.Repeat("A", 40) + `"]}`,
		`{"fpr":"` + strings.Repeat("A", 39) + `"}`, `{"fpr":"` + strings.Repeat("A", 40) + `\n"}`, `{"fpr":"` + strings.Repeat("G", 40) + `"}`,
		`{"fpr":" ` + strings.Repeat("A", 40) + `"}`, `{"fpr":"` + strings.Repeat("A", 50) + `"}`} {
		status, _, got := do(t, ts, "POST", "/v1/challenge", body)
		if status != 400 || got != `{"error":"bad_fpr"}` {
			t.Errorf("body %q: %d %s", body, status, got)
		}
	}
	for _, body := range []string{`{"fpr":"` + strings.Repeat("a", 40) + `"}`, `{"fpr":"` + strings.Repeat("0aF", 21) + `0"}`,
		` {"fpr":"` + strings.Repeat("B", 64) + `","fpr2":1} ` + "\n", `{"fpr":"x","fpr":"` + strings.Repeat("C", 40) + `"}`} {
		status, _, got := do(t, ts, "POST", "/v1/challenge", body)
		if status != 200 {
			t.Errorf("body %q: %d %s", body, status, got)
		}
	}
}

func TestBodyLimits(t *testing.T) {
	s, ts := newServer(t)
	pad := func(n int) string { return `{"pad":"` + strings.Repeat("x", n) + `"}` }
	if status, _, body := do(t, ts, "POST", "/v1/challenge", pad(smallBody)); status != 413 || body != `{"error":"too_large"}` {
		t.Errorf("small endpoint over its limit: %d %s", status, body)
	}
	if status, _, _ := do(t, ts, "POST", "/v1/challenge", pad(smallBody-100)); status != 400 {
		t.Errorf("small endpoint under its limit: %d", status)
	}
	limit := int(s.maxEnvelopeBody())
	if limit != 40000+65536 {
		t.Fatalf("envelope body limit = %d", limit)
	}
	if status, _, body := do(t, ts, "POST", "/v1/send", pad(limit)); status != 413 || body != `{"error":"too_large"}` {
		t.Errorf("envelope endpoint over its limit: %d %s", status, body)
	}
	if status, _, _ := do(t, ts, "POST", "/v1/send", pad(limit-100)); status != 501 {
		t.Errorf("envelope endpoint under its limit: %d", status)
	}
	// Without a Content-Length the limit still holds.
	req, _ := http.NewRequest("POST", ts.URL+"/v1/challenge", io.MultiReader(strings.NewReader(pad(smallBody))))
	req.ContentLength = -1
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 413 {
		t.Errorf("chunked body over the limit: %d", res.StatusCode)
	}
}

func TestChallengeStoresANonceThatExpires(t *testing.T) {
	s, ts := newServer(t)
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	status, _, body := do(t, ts, "POST", "/v1/challenge", `{"fpr":"`+strings.Repeat("ab", 20)+`"}`)
	if status != 200 {
		t.Fatalf("%d %s", status, body)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil || len(got) != 1 {
		t.Fatalf("body %s", body)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got["nonce"]) {
		t.Fatalf("nonce %q", got["nonce"])
	}
	var fpr, created, expires string
	if err := s.store.DB.QueryRow("SELECT fpr, created_at, expires_at FROM challenges WHERE nonce = ?", got["nonce"]).Scan(&fpr, &created, &expires); err != nil {
		t.Fatal(err)
	}
	if fpr != strings.Repeat("AB", 20) || created != "2026-11-17 12:00:00" || expires != "2026-11-17 12:05:00" {
		t.Fatalf("stored %q %q %q", fpr, created, expires)
	}
	_, _, second := do(t, ts, "POST", "/v1/challenge", `{"fpr":"`+strings.Repeat("ab", 20)+`"}`)
	if second == body {
		t.Fatal("two challenges returned the same nonce")
	}
}

func TestAnswersKeepTheirFieldOrderAndDoNotEscapeKeys(t *testing.T) {
	body, err := object{{"b", "x+/=<>&"}, {"a", 1}, {"c", true}, {"d", nil}}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"b":"x+/=<>&","a":1,"c":true,"d":null}` {
		t.Fatalf("%s", body)
	}
}

func TestAPanicBecomesA500(t *testing.T) {
	s, ts := newServer(t)
	s.routes["/v1/boom"] = route{handle: func(*Server, *http.Request, input) result { panic("boom") }}
	status, _, body := do(t, ts, "POST", "/v1/boom", `{}`)
	if status != 500 || body != `{"error":"server_error"}` {
		t.Fatalf("%d %s", status, body)
	}
	if status, _, _ := do(t, ts, "POST", "/v1/challenge", `{"fpr":"`+strings.Repeat("A", 40)+`"}`); status != 200 {
		t.Fatalf("the server did not survive the panic: %d", status)
	}
}
