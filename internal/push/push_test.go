package push

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

func TestShapesMatchThePHPRelay(t *testing.T) {
	// These are the exact strings the PHP relay's cp_push_shape produced.
	message := `{"aps":{"alert":{"title":"CarrierPony","body":"New message"},"sound":"default","content-available":1}}`
	request := `{"aps":{"alert":{"title":"CarrierPony","body":"Someone wants to connect.","loc-key":"Someone wants to connect. Tap to review."},"sound":"default","content-available":1}}`
	silent := `{"aps":{"content-available":1}}`
	for _, tc := range []struct {
		silent   bool
		kind     string
		payload  string
		pushType string
		priority int
		data     string
	}{
		{false, "message", message, "alert", 10, "wake=1"},
		{false, "request", request, "alert", 10, "wake=1,kind=request"},
		{false, "anything else", message, "alert", 10, "wake=1"},
		{true, "message", silent, "background", 5, "wake=1,silent=1"},
		{true, "request", silent, "background", 5, "wake=1,silent=1"},
	} {
		got := ShapeFor(tc.silent, tc.kind)
		var data []string
		for _, pair := range got.FCMData {
			data = append(data, pair[0]+"="+pair[1])
		}
		if got.APNsPayload != tc.payload || got.APNsType != tc.pushType || got.APNsPriority != tc.priority || strings.Join(data, ",") != tc.data {
			t.Errorf("ShapeFor(%v, %q) = %+v", tc.silent, tc.kind, got)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(got.APNsPayload), &parsed); err != nil {
			t.Errorf("payload is not JSON: %v", err)
		}
	}
}

// ---- APNs -------------------------------------------------------------------

type apnsCall struct {
	host, path, proto, body string
	header                  http.Header
}

// apple stands in for both APNs hosts. answer decides the reply per host.
type apple struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	calls  []apnsCall
	answer func(host string) (int, string)
}

func newApple(t *testing.T) *apple {
	a := &apple{t: t, answer: func(string) (int, string) { return 200, "" }}
	a.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		host := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
		a.mu.Lock()
		a.calls = append(a.calls, apnsCall{host: host, path: r.URL.EscapedPath(), proto: r.Proto, body: string(body), header: r.Header.Clone()})
		answer := a.answer
		a.mu.Unlock()
		status, reason := answer(host)
		w.WriteHeader(status)
		if reason != "" {
			json.NewEncoder(w).Encode(map[string]string{"reason": reason})
		}
	}))
	a.server.EnableHTTP2 = true
	a.server.StartTLS()
	t.Cleanup(a.server.Close)
	return a
}

func newAPNs(t *testing.T, a *apple, environment string) (*APNs, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "AuthKey_TEST.p8")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	apns, err := NewAPNs(config.APNs{Enabled: true, KeyFile: path, KeyID: "KEYID12345", TeamID: "TEAMID1234",
		BundleID: "com.carrierpony.app", Environment: environment})
	if err != nil {
		t.Fatal(err)
	}
	// Each environment gets its own path prefix on the one stand-in server.
	apns.UseHosts(a.server.URL+"/production", a.server.URL+"/sandbox", a.server.Client())
	return apns, key
}

func TestAPNsRequest(t *testing.T) {
	apple := newApple(t)
	apns, key := newAPNs(t, apple, "production")
	d := apns.Deliver(context.Background(), "abc/def 123", ShapeFor(false, "request"), "")
	if !d.Delivered || d.Dead || d.Environment != "production" {
		t.Fatalf("delivery: %+v", d)
	}
	c := apple.calls[0]
	if c.proto != "HTTP/2.0" {
		t.Errorf("APNs was called over %s", c.proto)
	}
	if c.path != "/production/3/device/abc%2Fdef%20123" {
		t.Errorf("path %q", c.path)
	}
	if c.body != ShapeFor(false, "request").APNsPayload {
		t.Errorf("body %s", c.body)
	}
	for name, want := range map[string]string{"apns-topic": "com.carrierpony.app", "apns-push-type": "alert",
		"apns-priority": "10", "content-type": "application/json"} {
		if got := c.header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// The provider token is a valid ES256 JWT for this key, key id and team.
	auth := c.header.Get("authorization")
	if !strings.HasPrefix(auth, "bearer ") {
		t.Fatalf("authorization %q", auth)
	}
	parts := strings.Split(strings.TrimPrefix(auth, "bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var header, claims map[string]any
	rawHeader, _ := base64.RawURLEncoding.DecodeString(parts[0])
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(rawHeader, &header)
	json.Unmarshal(rawClaims, &claims)
	if header["alg"] != "ES256" || header["kid"] != "KEYID12345" || claims["iss"] != "TEAMID1234" {
		t.Errorf("token header %v claims %v", header, claims)
	}
	if iat, _ := claims["iat"].(float64); time.Since(time.Unix(int64(iat), 0)) > time.Minute {
		t.Errorf("iat %v", claims["iat"])
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("the provider token's signature does not verify")
	}

	// The token is reused, then replaced once it is 50 minutes old.
	apns.Deliver(context.Background(), "t", ShapeFor(true, ""), "production")
	if apple.calls[1].header.Get("authorization") != auth {
		t.Error("a second push made a new provider token")
	}
	if apple.calls[1].header.Get("apns-push-type") != "background" || apple.calls[1].header.Get("apns-priority") != "5" {
		t.Errorf("silent push headers: %v", apple.calls[1].header)
	}
	apns.now = func() time.Time { return time.Now().Add(51 * time.Minute) }
	apns.Deliver(context.Background(), "t", ShapeFor(true, ""), "production")
	if apple.calls[2].header.Get("authorization") == auth {
		t.Error("the provider token was not renewed after 51 minutes")
	}
}

func TestAPNsEnvironments(t *testing.T) {
	for _, tc := range []struct {
		name      string
		preferred string
		known     string
		answer    func(host string) (int, string)
		want      Delivery
		hosts     string
	}{
		{"the configured environment works", "production", "", func(string) (int, string) { return 200, "" },
			Delivery{Delivered: true, Environment: "production"}, "production"},
		{"the environment seen to work is tried first", "production", "sandbox", func(string) (int, string) { return 200, "" },
			Delivery{Delivered: true, Environment: "sandbox"}, "sandbox"},
		{"a development token falls through to sandbox", "production", "", func(h string) (int, string) {
			if h == "production" {
				return 400, "BadDeviceToken"
			}
			return 200, ""
		}, Delivery{Delivered: true, Environment: "sandbox"}, "production,sandbox"},
		{"a distributed token falls through to production", "sandbox", "", func(h string) (int, string) {
			if h == "sandbox" {
				return 400, "BadDeviceToken"
			}
			return 200, ""
		}, Delivery{Delivered: true, Environment: "production"}, "sandbox,production"},
		{"a token wrong on both is left alone", "production", "", func(string) (int, string) { return 400, "BadDeviceToken" },
			Delivery{}, "production,sandbox"},
		{"410 means the token is dead", "production", "", func(string) (int, string) { return 410, "Unregistered" },
			Delivery{Dead: true}, "production"},
		{"Unregistered means dead whatever the status", "production", "", func(string) (int, string) { return 400, "Unregistered" },
			Delivery{Dead: true}, "production"},
		{"a refused provider token is not about the device", "production", "", func(string) (int, string) { return 403, "InvalidProviderToken" },
			Delivery{}, "production"},
		{"throttling is not about the device", "production", "", func(string) (int, string) { return 429, "TooManyRequests" },
			Delivery{}, "production"},
		{"an outage is not about the device", "production", "", func(string) (int, string) { return 503, "" },
			Delivery{}, "production"},
	} {
		apple := newApple(t)
		apple.answer = tc.answer
		apns, _ := newAPNs(t, apple, tc.preferred)
		got := apns.Deliver(context.Background(), "token", ShapeFor(false, "message"), tc.known)
		var hosts []string
		for _, c := range apple.calls {
			hosts = append(hosts, c.host)
		}
		if got != tc.want || strings.Join(hosts, ",") != tc.hosts {
			t.Errorf("%s: got %+v after calling %v, want %+v after %s", tc.name, got, hosts, tc.want, tc.hosts)
		}
	}
}

func TestAPNsThatCannotBeReachedIsNotADeadToken(t *testing.T) {
	apple := newApple(t)
	apns, _ := newAPNs(t, apple, "production")
	apns.UseHosts("https://127.0.0.1:1", "https://127.0.0.1:1", apple.server.Client())
	if got := apns.Deliver(context.Background(), "token", ShapeFor(false, "message"), ""); got != (Delivery{}) {
		t.Errorf("got %+v", got)
	}
}

func TestAPNsKeyProblemsStopTheRelayFromStarting(t *testing.T) {
	dir := t.TempDir()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKCS8PrivateKey(p384)
	files := map[string][]byte{
		"not-pem.p8": []byte("hello"),
		"garbage.p8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("nope")}),
		"rsa.p8":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}),
		"p384.p8":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER}),
	}
	for name, content := range files {
		os.WriteFile(filepath.Join(dir, name), content, 0o600)
	}
	for _, name := range []string{"missing.p8", "not-pem.p8", "garbage.p8", "rsa.p8", "p384.p8"} {
		if _, err := NewAPNs(config.APNs{KeyFile: filepath.Join(dir, name)}); err == nil {
			t.Errorf("%s was accepted as an APNs key", name)
		}
	}
}

// ---- FCM --------------------------------------------------------------------

type google struct {
	server      *httptest.Server
	mu          sync.Mutex
	tokenCalls  []string
	sendCalls   []apnsCall
	sendStatus  int
	sendBody    string
	tokenStatus int
	expiresIn   int
	issued      int
}

func newGoogle(t *testing.T) *google {
	g := &google{sendStatus: 200, sendBody: `{"name":"projects/p/messages/1"}`, tokenStatus: 200, expiresIn: 3600}
	g.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.URL.Path == "/token" {
			g.tokenCalls = append(g.tokenCalls, string(body))
			g.issued++
			w.WriteHeader(g.tokenStatus)
			if g.tokenStatus == 200 {
				json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + string(rune('0'+g.issued)), "expires_in": g.expiresIn})
			}
			return
		}
		g.sendCalls = append(g.sendCalls, apnsCall{path: r.URL.Path, body: string(body), header: r.Header.Clone()})
		w.WriteHeader(g.sendStatus)
		io.WriteString(w, g.sendBody)
	}))
	t.Cleanup(g.server.Close)
	return g
}

func newFCM(t *testing.T, g *google) (*FCM, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	account, _ := json.Marshal(map[string]string{"client_email": "relay@test-project.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "project_id": "test-project"})
	path := filepath.Join(t.TempDir(), "service-account.json")
	os.WriteFile(path, account, 0o600)
	fcm, err := NewFCM(config.FCM{Enabled: true, ServiceAccountFile: path})
	if err != nil {
		t.Fatal(err)
	}
	fcm.UseEndpoints(g.server.URL+"/token", g.server.URL, g.server.Client())
	return fcm, key
}

func TestFCMRequest(t *testing.T) {
	g := newGoogle(t)
	fcm, key := newFCM(t, g)
	status, unregistered := fcm.Send(context.Background(), `tok"en`, ShapeFor(false, "request"))
	if status != 200 || unregistered {
		t.Fatalf("send: %d %v", status, unregistered)
	}
	c := g.sendCalls[0]
	if c.path != "/v1/projects/test-project/messages:send" {
		t.Errorf("path %q", c.path)
	}
	if c.header.Get("authorization") != "Bearer access-1" || c.header.Get("content-type") != "application/json" {
		t.Errorf("headers %v", c.header)
	}
	if want := `{"message":{"token":"tok\"en","data":{"wake":"1","kind":"request"},"android":{"priority":"HIGH"}}}`; c.body != want {
		t.Errorf("body\n got %s\nwant %s", c.body, want)
	}

	// The token request carries a valid RS256 assertion for the account.
	form := g.tokenCalls[0]
	if !strings.Contains(form, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer") {
		t.Errorf("token request: %s", form)
	}
	assertion := form[strings.Index(form, "assertion=")+len("assertion="):]
	if i := strings.Index(assertion, "&"); i >= 0 {
		assertion = assertion[:i]
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d parts", len(parts))
	}
	var header, claims map[string]any
	rawHeader, _ := base64.RawURLEncoding.DecodeString(parts[0])
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(rawHeader, &header)
	json.Unmarshal(rawClaims, &claims)
	if header["alg"] != "RS256" || header["typ"] != "JWT" || claims["iss"] != "relay@test-project.iam.gserviceaccount.com" ||
		claims["scope"] != "https://www.googleapis.com/auth/firebase.messaging" || claims["aud"] != "https://oauth2.googleapis.com/token" {
		t.Errorf("assertion header %v claims %v", header, claims)
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != 3600 {
		t.Errorf("assertion lifetime: %v to %v", claims["iat"], claims["exp"])
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("the assertion's signature does not verify: %v", err)
	}

	// The access token is reused until a minute before it runs out.
	fcm.Send(context.Background(), "t", ShapeFor(true, ""))
	if len(g.tokenCalls) != 1 {
		t.Errorf("%d token requests for two sends", len(g.tokenCalls))
	}
	if want := `{"message":{"token":"t","data":{"wake":"1","silent":"1"},"android":{"priority":"HIGH"}}}`; g.sendCalls[1].body != want {
		t.Errorf("silent body %s", g.sendCalls[1].body)
	}
	fcm.now = func() time.Time { return time.Now().Add(3600*time.Second - 59*time.Second) }
	fcm.Send(context.Background(), "t", ShapeFor(true, ""))
	if len(g.tokenCalls) != 2 || g.sendCalls[2].header.Get("authorization") != "Bearer access-2" {
		t.Errorf("the access token was not renewed in its last minute: %d token requests", len(g.tokenCalls))
	}
}

func TestFCMUnregistered(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"ok", 200, `{}`, false},
		{"404", 404, `not json`, true},
		{"UNREGISTERED in the details", 400, `{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"UNREGISTERED"}]}}`, true},
		{"NOT_FOUND status", 400, `{"error":{"status":"NOT_FOUND"}}`, true},
		{"a bad request that is not about the token", 400, `{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"INVALID_ARGUMENT"}]}}`, false},
		{"quota", 429, `{"error":{"status":"RESOURCE_EXHAUSTED"}}`, false},
		{"an outage", 503, ``, false},
	} {
		g := newGoogle(t)
		g.sendStatus, g.sendBody = tc.status, tc.body
		fcm, _ := newFCM(t, g)
		status, unregistered := fcm.Send(context.Background(), "t", ShapeFor(false, "message"))
		if status != tc.status || unregistered != tc.want {
			t.Errorf("%s: got %d %v", tc.name, status, unregistered)
		}
	}
}

func TestFCMWithoutAnAccessTokenSendsNothing(t *testing.T) {
	g := newGoogle(t)
	g.tokenStatus = 401
	fcm, _ := newFCM(t, g)
	status, unregistered := fcm.Send(context.Background(), "t", ShapeFor(false, "message"))
	if status != 0 || unregistered || len(g.sendCalls) != 0 {
		t.Errorf("got %d %v with %d sends", status, unregistered, len(g.sendCalls))
	}
}

func TestFCMAccountProblemsStopTheRelayFromStarting(t *testing.T) {
	dir := t.TempDir()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))
	files := map[string]string{
		"not-json.json": "hello",
		"empty.json":    "{}",
		"no-key.json":   `{"client_email":"a@b","project_id":"p"}`,
		"bad-key.json":  `{"client_email":"a@b","project_id":"p","private_key":"nope"}`,
	}
	ecAccount, _ := json.Marshal(map[string]string{"client_email": "a@b", "project_id": "p", "private_key": ecPEM})
	files["ec-key.json"] = string(ecAccount)
	for name, content := range files {
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	}
	for _, name := range []string{"missing.json", "not-json.json", "empty.json", "no-key.json", "bad-key.json", "ec-key.json"} {
		if _, err := NewFCM(config.FCM{ServiceAccountFile: filepath.Join(dir, name)}); err == nil {
			t.Errorf("%s was accepted as a service account", name)
		}
	}
}
