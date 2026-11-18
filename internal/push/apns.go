package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

// The two APNs hosts. A device token is only valid on the one that matches how
// the app that minted it was signed.
const (
	apnsProduction = "https://api.push.apple.com"
	apnsSandbox    = "https://api.sandbox.push.apple.com"
)

// apnsTokenLife is how long one provider token is reused. Apple accepts a
// token for an hour and refuses one refreshed more often than every 20 minutes.
const apnsTokenLife = 50 * time.Minute

// APNs sends pushes to iPhones with a provider token (a .p8 key).
type APNs struct {
	key       *ecdsa.PrivateKey
	keyID     string
	teamID    string
	bundleID  string
	preferred string
	hosts     map[string]string
	client    *http.Client
	now       func() time.Time

	mu      sync.Mutex
	token   string
	tokenAt time.Time
}

// NewAPNs reads the signing key named in the config. It fails when the key
// cannot be used, so a relay configured to push does not start up silently
// unable to.
func NewAPNs(cfg config.APNs) (*APNs, error) {
	raw, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("apns: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("apns: %s is not a PEM file", cfg.KeyFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns: %s: %w", cfg.KeyFile, err)
	}
	key, isEC := parsed.(*ecdsa.PrivateKey)
	if !isEC || key.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("apns: %s is not a P-256 key", cfg.KeyFile)
	}
	return &APNs{
		key: key, keyID: cfg.KeyID, teamID: cfg.TeamID, bundleID: cfg.BundleID, preferred: cfg.Environment,
		hosts: map[string]string{"production": apnsProduction, "sandbox": apnsSandbox},
		// APNs only speaks HTTP/2.
		client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			ForceAttemptHTTP2: true, IdleConnTimeout: 5 * time.Minute, TLSHandshakeTimeout: 5 * time.Second}},
		now: time.Now,
	}, nil
}

func segment(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// providerToken returns the ES256 token APNs authenticates the relay by,
// making a new one when the last is close to an hour old.
func (a *APNs) providerToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.token != "" && now.Sub(a.tokenAt) < apnsTokenLife {
		return a.token, nil
	}
	input := segment(map[string]string{"alg": "ES256", "kid": a.keyID}) + "." +
		segment(map[string]any{"iss": a.teamID, "iat": now.Unix()})
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS wants the two numbers as fixed 32-byte values, not DER.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	a.token = input + "." + base64.RawURLEncoding.EncodeToString(sig)
	a.tokenAt = now
	return a.token, nil
}

// send posts to one APNs environment. It returns the HTTP status, 0 when the
// request did not get through, and APNs' reason string for a refusal.
func (a *APNs) send(ctx context.Context, deviceToken string, shape Shape, environment string) (int, string) {
	host, known := a.hosts[environment]
	if !known {
		return 0, ""
	}
	token, err := a.providerToken()
	if err != nil {
		return 0, ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host+"/3/device/"+url.PathEscape(deviceToken),
		bytes.NewReader([]byte(shape.APNsPayload)))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", a.bundleID)
	req.Header.Set("apns-push-type", shape.APNsType)
	req.Header.Set("apns-priority", strconv.Itoa(shape.APNsPriority))
	req.Header.Set("content-type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer res.Body.Close()
	reason := ""
	if res.StatusCode >= 400 {
		var body struct {
			Reason string `json:"reason"`
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		if json.Unmarshal(raw, &body) == nil {
			reason = body.Reason
		}
	}
	return res.StatusCode, reason
}

// Delivery is the outcome of pushing to one iPhone.
type Delivery struct {
	Delivered bool
	// Dead means APNs says the token is no longer registered.
	Dead bool
	// Environment is the one that accepted the push, when Delivered.
	Environment string
}

// Deliver pushes to one device, working out which APNs environment its token
// belongs to.
//
// A token from a build signed for development only works on the sandbox host,
// and one from a distributed build only on production, so a single configured
// environment is wrong for part of the fleet: with "sandbox" set, Xcode builds
// get notifications and every TestFlight tester silently gets none. So this
// tries the environment last seen to work for the device, then the configured
// one, and on BadDeviceToken the other. The caller remembers the one that
// answers 200, so a device pays for the second try at most once.
func (a *APNs) Deliver(ctx context.Context, deviceToken string, shape Shape, known string) Delivery {
	var candidates []string
	for _, env := range []string{known, a.preferred, "production", "sandbox"} {
		if env == "" {
			continue
		}
		seen := false
		for _, c := range candidates {
			seen = seen || c == env
		}
		if !seen {
			candidates = append(candidates, env)
		}
	}
	for _, env := range candidates {
		code, reason := a.send(ctx, deviceToken, shape, env)
		if code == http.StatusOK {
			return Delivery{Delivered: true, Environment: env}
		}
		if code == http.StatusGone || reason == "Unregistered" {
			return Delivery{Dead: true}
		}
		// BadDeviceToken means "right token, wrong environment" at least as
		// often as it means a junk token, so the other host gets a try before
		// the token is written off.
		if code == http.StatusBadRequest && reason == "BadDeviceToken" {
			continue
		}
		// Anything else (a bad provider token, throttling, an outage) is not
		// about this device. Leave it alone and try again on the next message.
		return Delivery{}
	}
	return Delivery{}
}

// UseHosts points the two environments somewhere else and sets the client that
// reaches them. Tests use it to stand in for Apple.
func (a *APNs) UseHosts(production, sandbox string, client *http.Client) {
	a.hosts = map[string]string{"production": production, "sandbox": sandbox}
	a.client = client
}
