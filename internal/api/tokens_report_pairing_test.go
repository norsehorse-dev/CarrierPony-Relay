package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func registered(t *testing.T, ts *httptest.Server, v6 bool) *identity {
	t.Helper()
	id := newIdentity(t, ts, v6)
	if status, body := id.register(); status != 200 {
		t.Fatalf("register: %d %v", status, body)
	}
	return id
}

func TestPushAndWakeTokens(t *testing.T) {
	s, ts := newServer(t)
	alice := registered(t, ts, false)
	other := randomHex(16)

	status, body := alice.call("/v1/register-push", map[string]any{"device_id": other, "push_token": "t"})
	wantError(t, "push token for a device that is not registered", status, body, 403, "unknown_device")
	status, body = alice.call("/v1/register-push", map[string]any{"device_id": alice.device, "push_token": "t", "platform": ""})
	wantError(t, "empty platform", status, body, 400, "bad_platform")
	if status, body := alice.call("/v1/register-push", map[string]any{"device_id": alice.device, "push_token": strings.Repeat("T", 300), "platform": nil}); status != 200 {
		t.Fatalf("register-push: %d %v", status, body)
	}
	var token, platform string
	s.store.DB.QueryRow("SELECT push_token, platform FROM devices WHERE device_id = ?", alice.device).Scan(&token, &platform)
	if len(token) != 255 || platform != "apns" {
		t.Errorf("stored a %d character token for %q", len(token), platform)
	}
	alice.call("/v1/register-push", map[string]any{"device_id": alice.device, "push_token": "tok", "platform": "FCM"})
	s.store.DB.QueryRow("SELECT push_token, platform FROM devices WHERE device_id = ?", alice.device).Scan(&token, &platform)
	if token != "tok" || platform != "fcm" {
		t.Errorf("stored %q for %q", token, platform)
	}

	wake := randomHex(32)
	status, body = alice.call("/v1/register-wake", map[string]any{"device_id": alice.device, "wake_token": strings.ToUpper(wake)})
	wantError(t, "uppercase wake token", status, body, 400, "bad_wake_token")
	status, body = alice.call("/v1/register-wake", map[string]any{"device_id": other, "wake_token": wake})
	wantError(t, "wake token for a device that is not registered", status, body, 403, "unknown_device")
	alice.call("/v1/register-wake", map[string]any{"device_id": alice.device, "wake_token": wake})
	var stored *string
	s.store.DB.QueryRow("SELECT wake_token FROM devices WHERE device_id = ?", alice.device).Scan(&stored)
	if stored == nil || *stored != wake {
		t.Errorf("wake token not stored: %v", stored)
	}
	alice.call("/v1/register-wake", map[string]any{"device_id": alice.device, "wake_token": ""})
	s.store.DB.QueryRow("SELECT wake_token FROM devices WHERE device_id = ?", alice.device).Scan(&stored)
	if stored != nil {
		t.Errorf("an empty wake token did not clear the stored one: %q", *stored)
	}
}

func TestReportIsStoredTrimmed(t *testing.T) {
	s, ts := newServer(t)
	alice := registered(t, ts, true)
	target := strings.Repeat("c", 64)
	status, body := alice.call("/v1/report", map[string]any{"reported_fpr": target, "category": "Other",
		"description": strings.Repeat("€", 5000), "content": strings.Repeat("c", 21000)})
	if status != 200 || body["ok"] != true {
		t.Fatalf("report: %d %v", status, body)
	}
	var reporter, reported, category, description, content, state string
	var meta *string
	err := s.store.DB.QueryRow("SELECT reporter_fpr, reported_fpr, category, description, content, attachment_meta, status FROM reports").
		Scan(&reporter, &reported, &category, &description, &content, &meta, &state)
	if err != nil {
		t.Fatal(err)
	}
	if reporter != alice.fpr || reported != strings.ToUpper(target) || category != "other" || state != "open" {
		t.Errorf("stored %q %q %q %q", reporter, reported, category, state)
	}
	if description != strings.Repeat("€", 4000) || len(content) != 20000 || meta != nil {
		t.Errorf("description %d bytes, content %d bytes, meta %v", len(description), len(content), meta)
	}
	status, body = alice.call("/v1/report", map[string]any{"reported_fpr": target, "category": "rude"})
	wantError(t, "unknown category", status, body, 400, "bad_category")
}

func TestPairing(t *testing.T) {
	s, ts := newServer(t)
	s.cfg.Limits.PairMaxOpen = 2
	s.cfg.Limits.PairOfferTTL = 600
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	alice, bob := registered(t, ts, false), registered(t, ts, true)

	status, body := alice.call("/v1/pair/offer", map[string]any{"pubkey": alice.pubkey})
	if status != 200 || body["expires_in"] != float64(600) {
		t.Fatalf("offer: %d %v", status, body)
	}
	token := body["token"].(string)
	status, body = bob.call("/v1/pair/status", map[string]any{"token": token})
	wantError(t, "status of someone else's offer", status, body, 403, "not_your_offer")
	if status, body = alice.call("/v1/pair/status", map[string]any{"token": token}); status != 200 || body["state"] != "open" || len(body) != 1 {
		t.Errorf("status of an open offer: %d %v", status, body)
	}
	status, body = bob.call("/v1/pair/accept", map[string]any{"token": token, "pubkey": bob.pubkey})
	if status != 200 || body["offerer_fpr"] != alice.fpr || body["offerer_pubkey"] != alice.pubkey {
		t.Fatalf("accept: %d %v", status, body)
	}
	status, body = bob.call("/v1/pair/accept", map[string]any{"token": token, "pubkey": bob.pubkey})
	wantError(t, "accept twice", status, body, 410, "offer_closed")
	status, body = bob.call("/v1/pair/accept", map[string]any{"token": randomHex(16), "pubkey": bob.pubkey})
	wantError(t, "accept an unknown token", status, body, 404, "no_such_offer")

	// A v4 offerer collects a v6 responder, and still can after the offer's
	// own expiry has passed.
	advance(time.Hour)
	status, body = alice.call("/v1/pair/status", map[string]any{"token": token})
	if status != 200 || body["state"] != "accepted" || body["responder_fpr"] != bob.fpr || body["responder_pubkey"] != bob.pubkey {
		t.Errorf("status of an accepted offer: %d %v", status, body)
	}

	first, _ := alice.call("/v1/pair/offer", map[string]any{"pubkey": alice.pubkey})
	_, second := alice.call("/v1/pair/offer", map[string]any{"pubkey": alice.pubkey})
	if first != 200 || second["token"] == nil {
		t.Fatalf("two open offers should be allowed: %d %v", first, second)
	}
	status, body = alice.call("/v1/pair/offer", map[string]any{"pubkey": alice.pubkey})
	wantError(t, "a third open offer", status, body, 429, "too_many_offers")

	// One second before expiry the offer is open; at expiry it is not.
	open := second["token"].(string)
	advance(599 * time.Second)
	if _, body = alice.call("/v1/pair/status", map[string]any{"token": open}); body["state"] != "open" {
		t.Errorf("one second before expiry: %v", body)
	}
	advance(time.Second)
	if _, body = alice.call("/v1/pair/status", map[string]any{"token": open}); body["state"] != "expired" {
		t.Errorf("at expiry: %v", body)
	}
	status, body = bob.call("/v1/pair/accept", map[string]any{"token": open, "pubkey": bob.pubkey})
	wantError(t, "accept an expired offer", status, body, 410, "offer_closed")
	if status, _ = alice.call("/v1/pair/offer", map[string]any{"pubkey": alice.pubkey}); status != 200 {
		t.Errorf("expired offers still count against the limit: %d", status)
	}
}

func TestSendWakesOptedInDevicesThroughTheGateway(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	var paths []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		mu.Lock()
		got = append(got, body)
		paths = append(paths, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type"))
		mu.Unlock()
	}))
	defer gateway.Close()
	s, ts := newServer(t)
	s.cfg.PushGateway.URL = gateway.URL + "/"
	alice, bob := registered(t, ts, false), registered(t, ts, false)
	second := randomHex(16)
	bob.call("/v1/register-device", map[string]any{"pubkey": bob.pubkey, "device_id": second})
	wake := randomHex(32)
	bob.call("/v1/register-wake", map[string]any{"device_id": bob.device, "wake_token": wake})

	waitFor := func(n int) []map[string]any {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			if len(got) >= n {
				out := append([]map[string]any(nil), got...)
				mu.Unlock()
				return out
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("the gateway saw %d wakes, want %d", len(got), n)
		return nil
	}
	alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD"})
	wakes := waitFor(1)
	if len(wakes) != 1 || wakes[0]["wake_token"] != wake || wakes[0]["silent"] != false || len(wakes[0]) != 2 {
		t.Fatalf("wakes: %v", wakes)
	}
	if paths[0] != "POST /v1/wake application/json" {
		t.Errorf("gateway call was %q", paths[0])
	}
	alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD", "silent": 1})
	if wakes = waitFor(2); wakes[1]["silent"] != true {
		t.Errorf("a silent send was not passed on as silent: %v", wakes[1])
	}

	// With the gateway turned off, or the token cleared, nothing is sent.
	bob.call("/v1/register-wake", map[string]any{"device_id": bob.device})
	alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD"})
	bob.call("/v1/register-wake", map[string]any{"device_id": bob.device, "wake_token": wake})
	s.cfg.PushGateway.URL = ""
	alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD"})
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Errorf("the gateway saw %d wakes, want 2", len(got))
	}
}

func TestAGatewayThatIsDownDoesNotFailOrSlowASend(t *testing.T) {
	s, ts := newServer(t)
	s.cfg.PushGateway.URL = "http://127.0.0.1:1"
	alice, bob := registered(t, ts, false), registered(t, ts, false)
	bob.call("/v1/register-wake", map[string]any{"device_id": bob.device, "wake_token": randomHex(32)})
	start := time.Now()
	status, body := alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD"})
	if status != 200 {
		t.Fatalf("send: %d %v", status, body)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("send took %v with the gateway down", took)
	}
}
