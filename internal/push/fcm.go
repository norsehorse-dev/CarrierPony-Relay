package push

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
)

const (
	googleTokenURL = "https://oauth2.googleapis.com/token"
	fcmBaseURL     = "https://fcm.googleapis.com"
	fcmScope       = "https://www.googleapis.com/auth/firebase.messaging"
)

var errNotRSA = errors.New("not an RSA key")

// FCM sends data-only wakes to Android devices with a Google service account.
// The app refreshes its inbox and posts its own notification.
type FCM struct {
	key       *rsa.PrivateKey
	email     string
	projectID string
	tokenURL  string
	baseURL   string
	client    *http.Client
	now       func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

// NewFCM reads the service account file named in the config. Like NewAPNs it
// fails rather than leave the relay quietly unable to push.
func NewFCM(cfg config.FCM) (*FCM, error) {
	raw, err := os.ReadFile(cfg.ServiceAccountFile)
	if err != nil {
		return nil, fmt.Errorf("fcm: %w", err)
	}
	var account struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		ProjectID   string `json:"project_id"`
	}
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, fmt.Errorf("fcm: %s: %w", cfg.ServiceAccountFile, err)
	}
	if account.ClientEmail == "" || account.PrivateKey == "" || account.ProjectID == "" {
		return nil, fmt.Errorf("fcm: %s needs client_email, private_key and project_id", cfg.ServiceAccountFile)
	}
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("fcm: the private_key in %s is not PEM", cfg.ServiceAccountFile)
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, isRSA := parsed.(*rsa.PrivateKey)
		if !isRSA {
			return nil, fmt.Errorf("fcm: the private_key in %s: %w", cfg.ServiceAccountFile, errNotRSA)
		}
		key = rsaKey
	} else if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("fcm: the private_key in %s: %w", cfg.ServiceAccountFile, err)
	}
	return &FCM{
		key: key, email: account.ClientEmail, projectID: account.ProjectID,
		tokenURL: googleTokenURL, baseURL: fcmBaseURL,
		client: &http.Client{Timeout: 5 * time.Second},
		now:    time.Now,
	}, nil
}

// accessToken returns the OAuth token FCM calls are made with, fetching a new
// one a minute before the current one runs out. It is kept in memory only.
func (f *FCM) accessToken(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if f.access != "" && now.Before(f.expires.Add(-time.Minute)) {
		return f.access, nil
	}
	input := segment(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + segment(map[string]any{
		"iss": f.email, "scope": fcmScope, "aud": googleTokenURL, "iat": now.Unix(), "exp": now.Unix() + 3600})
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {input + "." + base64.RawURLEncoding.EncodeToString(sig)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	res, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if json.Unmarshal(raw, &body) != nil || body.AccessToken == "" {
		return "", fmt.Errorf("no access token in the answer, status %d", res.StatusCode)
	}
	if body.ExpiresIn <= 0 {
		body.ExpiresIn = 3600
	}
	f.access = body.AccessToken
	f.expires = now.Add(time.Duration(body.ExpiresIn) * time.Second)
	return f.access, nil
}

// Send wakes one Android device. It returns the HTTP status, 0 when the request
// did not get through, and whether FCM says the token is no longer registered.
func (f *FCM) Send(ctx context.Context, deviceToken string, shape Shape) (int, bool) {
	access, err := f.accessToken(ctx)
	if err != nil {
		return 0, false
	}
	// The data fields are written in a fixed order.
	var data bytes.Buffer
	data.WriteByte('{')
	for i, pair := range shape.FCMData {
		if i > 0 {
			data.WriteByte(',')
		}
		k, _ := json.Marshal(pair[0])
		v, _ := json.Marshal(pair[1])
		data.Write(k)
		data.WriteByte(':')
		data.Write(v)
	}
	data.WriteByte('}')
	token, _ := json.Marshal(deviceToken)
	payload := `{"message":{"token":` + string(token) + `,"data":` + data.String() + `,"android":{"priority":"HIGH"}}}`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.baseURL+"/v1/projects/"+url.PathEscape(f.projectID)+"/messages:send", strings.NewReader(payload))
	if err != nil {
		return 0, false
	}
	req.Header.Set("authorization", "Bearer "+access)
	req.Header.Set("content-type", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return res.StatusCode, true
	}
	if res.StatusCode >= 400 {
		var body struct {
			Error struct {
				Status  string `json:"status"`
				Details []struct {
					ErrorCode string `json:"errorCode"`
				} `json:"details"`
			} `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		json.Unmarshal(raw, &body)
		status := body.Error.Status
		if len(body.Error.Details) > 0 && body.Error.Details[0].ErrorCode != "" {
			status = body.Error.Details[0].ErrorCode
		}
		return res.StatusCode, status == "UNREGISTERED" || status == "NOT_FOUND"
	}
	return res.StatusCode, false
}

// UseEndpoints points the token and send calls somewhere else. Tests use it to
// stand in for Google.
func (f *FCM) UseEndpoints(tokenURL, baseURL string, client *http.Client) {
	f.tokenURL, f.baseURL, f.client = tokenURL, baseURL, client
}
