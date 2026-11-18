package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/push"
)

// pushWorld stands in for Apple and Google and records what the relay sends.
type pushWorld struct {
	mu    sync.Mutex
	calls []string
}

func (w *pushWorld) seen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.calls...)
}

func (w *pushWorld) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := w.seen(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("saw %d push calls, want %d: %v", len(w.seen()), n, w.seen())
	return nil
}

// withOwnPush gives a test server APNs and FCM credentials that talk to
// stand-ins. Production refuses every token as BadDeviceToken, sandbox takes
// it, and FCM reports every token as unregistered.
func withOwnPush(t *testing.T, s *Server) *pushWorld {
	t.Helper()
	world := &pushWorld{}
	record := func(line string) {
		world.mu.Lock()
		world.calls = append(world.calls, line)
		world.mu.Unlock()
	}
	apple := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		record("apns " + r.URL.Path + " " + r.Header.Get("apns-push-type") + " " + string(body))
		if strings.HasPrefix(r.URL.Path, "/production/") {
			w.WriteHeader(400)
			io.WriteString(w, `{"reason":"BadDeviceToken"}`)
		}
	}))
	apple.EnableHTTP2 = true
	apple.StartTLS()
	t.Cleanup(apple.Close)
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			io.WriteString(w, `{"access_token":"a","expires_in":3600}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		record("fcm " + string(body))
		w.WriteHeader(404)
	}))
	t.Cleanup(google.Close)

	dir := t.TempDir()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	p8 := filepath.Join(dir, "key.p8")
	os.WriteFile(p8, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), 0o600)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	account, _ := json.Marshal(map[string]string{"client_email": "a@b", "project_id": "p",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))})
	sa := filepath.Join(dir, "sa.json")
	os.WriteFile(sa, account, 0o600)

	apns, err := push.NewAPNs(config.APNs{KeyFile: p8, KeyID: "K", TeamID: "T", BundleID: "com.carrierpony.app", Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	apns.UseHosts(apple.URL+"/production", apple.URL+"/sandbox", apple.Client())
	fcm, err := push.NewFCM(config.FCM{ServiceAccountFile: sa})
	if err != nil {
		t.Fatal(err)
	}
	fcm.UseEndpoints(google.URL+"/token", google.URL, google.Client())
	s.apns, s.fcm = apns, fcm
	return world
}

func TestSendPushesToTheRecipientsDevices(t *testing.T) {
	s, ts := newServer(t)
	s.cfg.PushGateway.URL = ""
	world := withOwnPush(t, s)
	alice, bob := registered(t, ts, false), registered(t, ts, true)
	android, silentDevice := randomHex(16), randomHex(16)
	for _, d := range []string{android, silentDevice} {
		bob.call("/v1/register-device", map[string]any{"pubkey": bob.pubkey, "device_id": d})
	}
	bob.call("/v1/register-push", map[string]any{"device_id": bob.device, "push_token": "iphone-token"})
	bob.call("/v1/register-push", map[string]any{"device_id": android, "push_token": "android-token", "platform": "fcm"})
	alice.call("/v1/register-push", map[string]any{"device_id": alice.device, "push_token": "senders-own-token"})

	if status, body := alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD", "kind": "request"}); status != 200 {
		t.Fatalf("send: %d %v", status, body)
	}
	calls := world.waitFor(t, 3)
	request := push.ShapeFor(false, "request")
	want := map[string]bool{
		"apns /production/3/device/iphone-token alert " + request.APNsPayload:                                          true,
		"apns /sandbox/3/device/iphone-token alert " + request.APNsPayload:                                             true,
		`fcm {"message":{"token":"android-token","data":{"wake":"1","kind":"request"},"android":{"priority":"HIGH"}}}`: true,
	}
	for _, c := range calls {
		if !want[c] {
			t.Errorf("unexpected push call: %s", c)
		}
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("missing push calls: %v", want)
	}

	// The environment that worked is remembered and the dead token cleared.
	deadline := time.Now().Add(3 * time.Second)
	var env, androidToken *string
	for time.Now().Before(deadline) {
		s.store.DB.QueryRow("SELECT apns_env FROM devices WHERE device_id = ?", bob.device).Scan(&env)
		s.store.DB.QueryRow("SELECT push_token FROM devices WHERE device_id = ?", android).Scan(&androidToken)
		if env != nil && androidToken == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if env == nil || *env != "sandbox" {
		t.Errorf("apns_env was not remembered: %v", env)
	}
	if androidToken != nil {
		t.Errorf("the unregistered FCM token was not cleared: %q", *androidToken)
	}
	var iphoneToken *string
	s.store.DB.QueryRow("SELECT push_token FROM devices WHERE device_id = ?", bob.device).Scan(&iphoneToken)
	if iphoneToken == nil || *iphoneToken != "iphone-token" {
		t.Errorf("the working APNs token was changed: %v", iphoneToken)
	}

	// The next send goes straight to sandbox, as a background push when
	// silent, and no longer tries the cleared Android token.
	alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD", "silent": true})
	calls = world.waitFor(t, 4)
	time.Sleep(200 * time.Millisecond)
	calls = world.seen()
	if len(calls) != 4 || calls[3] != "apns /sandbox/3/device/iphone-token background "+push.ShapeFor(true, "").APNsPayload {
		t.Errorf("second send pushed: %v", calls[3:])
	}
}

func TestARelayWithoutPushCredentialsPushesNothing(t *testing.T) {
	s, ts := newServer(t)
	if s.apns != nil || s.fcm != nil {
		t.Fatal("a default config turned own push on")
	}
	alice, bob := registered(t, ts, false), registered(t, ts, false)
	bob.call("/v1/register-push", map[string]any{"device_id": bob.device, "push_token": "iphone-token"})
	if status, body := alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": "QUJD"}); status != 200 {
		t.Fatalf("send: %d %v", status, body)
	}
}

func TestBadPushCredentialsStopTheRelayFromStarting(t *testing.T) {
	cfg := config.Default()
	cfg.Database = config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")}
	cfg.APNs = config.APNs{Enabled: true, KeyFile: filepath.Join(t.TempDir(), "missing.p8"), KeyID: "K", TeamID: "T",
		BundleID: "b", Environment: "production"}
	if _, err := New(cfg, nil); err == nil {
		t.Error("a missing APNs key did not stop New")
	}
	cfg.APNs.Enabled = false
	cfg.FCM = config.FCM{Enabled: true, ServiceAccountFile: filepath.Join(t.TempDir(), "missing.json")}
	if _, err := New(cfg, nil); err == nil {
		t.Error("a missing FCM service account did not stop New")
	}
}
