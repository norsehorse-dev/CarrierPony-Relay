package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// sealedClient is a device on the sealed path.
type sealedClient struct {
	t        *testing.T
	ts       *httptest.Server
	now      func() time.Time
	dev, key string
}

func newSealed(t *testing.T, s *Server, ts *httptest.Server) *sealedClient {
	return &sealedClient{t: t, ts: ts, now: func() time.Time { return s.now() }, dev: randomHex(16), key: randomHex(32)}
}

func (c *sealedClient) proof(action string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(c.key))
	mac.Write([]byte(action + ":" + c.dev + ":" + strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *sealedClient) post(path string, body map[string]any) (int, map[string]any) {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	status, _, answer := do(c.t, c.ts, "POST", "/v1/sealed/"+path, string(raw))
	var got map[string]any
	json.Unmarshal([]byte(answer), &got)
	return status, got
}

// signed posts with a valid proof for action, made at the relay's clock plus skew.
func (c *sealedClient) signed(path, action string, extra map[string]any, skew time.Duration) (int, map[string]any) {
	c.t.Helper()
	ts := c.now().Add(skew).Unix()
	body := map[string]any{"device_id": c.dev, "ts": ts, "auth": c.proof(action, ts)}
	for k, v := range extra {
		body[k] = v
	}
	return c.post(path, body)
}

func (c *sealedClient) register() {
	c.t.Helper()
	if status, body := c.post("register-device", map[string]any{"device_id": c.dev, "device_key": c.key}); status != 200 {
		c.t.Fatalf("sealed register: %d %v", status, body)
	}
}

func (c *sealedClient) inbox(extra map[string]any) []map[string]any {
	c.t.Helper()
	status, body := c.signed("inbox", "inbox", extra, 0)
	if status != 200 {
		c.t.Fatalf("sealed inbox: %d %v", status, body)
	}
	var out []map[string]any
	for _, m := range body["messages"].([]any) {
		out = append(out, m.(map[string]any))
	}
	return out
}

func fixedClock(s *Server) func(time.Duration) {
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	return func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
}

func TestSealedProof(t *testing.T) {
	s, ts := newServer(t)
	fixedClock(s)
	c := newSealed(t, s, ts)
	c.register()
	box := []string{randomHex(32)}

	for _, tc := range []struct {
		name   string
		skew   time.Duration
		status int
	}{
		{"now", 0, 200}, {"300 seconds old", -300 * time.Second, 200}, {"301 seconds old", -301 * time.Second, 401},
		{"300 seconds ahead", 300 * time.Second, 200}, {"301 seconds ahead", 301 * time.Second, 401},
	} {
		if status, body := c.signed("register-mailboxes", "mbx", map[string]any{"mailboxes": box}, tc.skew); status != tc.status {
			t.Errorf("proof %s: %d %v, want %d", tc.name, status, body, tc.status)
		}
	}
	ts0 := s.now().Unix()
	good := c.proof("mbx", ts0)
	for name, body := range map[string]map[string]any{
		"proof for another action":  {"device_id": c.dev, "ts": ts0, "auth": c.proof("inbox", ts0), "mailboxes": box},
		"proof for another time":    {"device_id": c.dev, "ts": ts0 + 1, "auth": good, "mailboxes": box},
		"proof in uppercase":        {"device_id": c.dev, "ts": ts0, "auth": upperASCII(good), "mailboxes": box},
		"proof that is not hex":     {"device_id": c.dev, "ts": ts0, "auth": "zz", "mailboxes": box},
		"proof with another key":    {"device_id": c.dev, "ts": ts0, "auth": (&sealedClient{dev: c.dev, key: randomHex(32)}).proof("mbx", ts0), "mailboxes": box},
		"timestamp that is no time": {"device_id": c.dev, "ts": "soon", "auth": good, "mailboxes": box},
	} {
		if status, got := c.post("register-mailboxes", body); status != 401 || got["error"] != "bad_auth" {
			t.Errorf("%s: %d %v", name, status, got)
		}
	}
	if status, got := c.post("register-mailboxes", map[string]any{"device_id": c.dev, "ts": strconv.FormatInt(ts0, 10), "auth": good, "mailboxes": box}); status != 200 {
		t.Errorf("timestamp sent as a string: %d %v", status, got)
	}
}

func TestSealedDeviceCanOnlyBeChangedByItsOwner(t *testing.T) {
	s, ts := newServer(t)
	c := newSealed(t, s, ts)
	c.register()
	thief := &sealedClient{t: t, ts: ts, now: c.now, dev: c.dev, key: randomHex(32)}
	status, body := thief.post("register-device", map[string]any{"device_id": c.dev, "device_key": thief.key, "wake_token": randomHex(32)})
	wantError(t, "re-register with another key", status, body, 401, "bad_auth")
	status, body = thief.signed("register-device", "register", map[string]any{"device_key": thief.key, "wake_token": randomHex(32)}, 0)
	wantError(t, "re-register with a proof from another key", status, body, 401, "bad_auth")

	wake := randomHex(32)
	if status, body = c.signed("register-device", "register", map[string]any{"device_key": c.key, "wake_token": wake}, 0); status != 200 {
		t.Fatalf("owner update: %d %v", status, body)
	}
	var key string
	var stored *string
	s.store.DB.QueryRow("SELECT device_key, wake_token FROM sealed_devices WHERE device_id = ?", c.dev).Scan(&key, &stored)
	if key != c.key || stored == nil || *stored != wake {
		t.Errorf("stored key or wake token is wrong")
	}
}

func TestSealedRegistrationRace(t *testing.T) {
	s, ts := newServer(t)
	c := newSealed(t, s, ts)
	results := make(chan int, 12)
	for i := 0; i < 12; i++ {
		go func() {
			status, _ := c.post("register-device", map[string]any{"device_id": c.dev, "device_key": c.key})
			results <- status
		}()
	}
	for i := 0; i < 12; i++ {
		// The first to arrive creates the device. The rest find it there and
		// are asked for a proof, or raced the insert with the same key.
		if status := <-results; status != 200 && status != 401 {
			t.Errorf("racing first registration answered %d", status)
		}
	}
	var n int
	s.store.DB.QueryRow("SELECT COUNT(*) FROM sealed_devices WHERE device_id = ?", c.dev).Scan(&n)
	if n != 1 {
		t.Errorf("%d rows for one device", n)
	}
}

func TestSealedMailboxesSendInboxAck(t *testing.T) {
	s, ts := newServer(t)
	s.cfg.Limits.SealedPendingCap = 3
	advance := fixedClock(s)
	owner, other := newSealed(t, s, ts), newSealed(t, s, ts)
	owner.register()
	other.register()
	a, b, c := randomHex(32), randomHex(32), randomHex(32)

	soon := s.now().Add(time.Hour).Unix()
	status, body := owner.signed("register-mailboxes", "mbx", map[string]any{"mailboxes": []any{a, map[string]any{"mailbox": b, "expires_at": soon}, a, "junk", 5, []any{c}}}, 0)
	if status != 200 || body["registered"] != float64(2) {
		t.Fatalf("register mailboxes: %d %v", status, body)
	}
	var expA, expB string
	s.store.DB.QueryRow("SELECT expires_at FROM mailboxes WHERE mailbox = ?", a).Scan(&expA)
	s.store.DB.QueryRow("SELECT expires_at FROM mailboxes WHERE mailbox = ?", b).Scan(&expB)
	if expA != "2026-12-17 12:00:00" || expB != "2026-11-17 13:00:00" {
		t.Errorf("expiries stored as %q and %q", expA, expB)
	}
	// Another device cannot take a mailbox that is owned, only claim free ones.
	status, body = other.signed("register-mailboxes", "mbx", map[string]any{"mailboxes": []any{a, c}}, 0)
	if status != 200 || body["registered"] != float64(1) {
		t.Errorf("claiming a taken mailbox: %d %v", status, body)
	}
	var ownerOfA int64
	s.store.DB.QueryRow("SELECT d.id FROM mailboxes m JOIN sealed_devices d ON d.id = m.sealed_device_pk WHERE m.mailbox = ? AND d.device_id = ?", a, owner.dev).Scan(&ownerOfA)
	if ownerOfA == 0 {
		t.Error("the mailbox changed owner")
	}

	// A deposit needs no login. Unregistered and registered addresses answer
	// alike.
	if status, body = owner.post("send", map[string]any{"mailbox": randomHex(32), "envelope": "QUJD"}); status != 200 || len(body) != 1 || body["ok"] != true {
		t.Errorf("deposit to an unregistered mailbox: %d %v", status, body)
	}
	if status, body = owner.post("send", map[string]any{"mailbox": a, "envelope": "QUJD"}); status != 200 || len(body) != 1 || body["ok"] != true {
		t.Errorf("deposit: %d %v", status, body)
	}
	advance(time.Second)
	owner.post("send", map[string]any{"mailbox": b, "envelope": "QUJERQ==", "silent": true})
	var stored int
	s.store.DB.QueryRow("SELECT COUNT(*) FROM sealed_messages").Scan(&stored)
	if stored != 2 {
		t.Fatalf("%d messages stored, want 2", stored)
	}

	msgs := owner.inbox(nil)
	if len(msgs) != 2 || msgs[0]["mailbox"] != a || msgs[1]["mailbox"] != b || msgs[0]["alert"] != float64(1) || msgs[1]["alert"] != float64(0) {
		t.Fatalf("inbox: %v", msgs)
	}
	if got := other.inbox(nil); len(got) != 0 {
		t.Errorf("another device sees %d of these messages", len(got))
	}
	first, second := msgs[0]["message_id"].(string), msgs[1]["message_id"].(string)
	if got := owner.inbox(map[string]any{"skip": []any{first, "junk"}}); len(got) != 1 || got[0]["message_id"] != second {
		t.Errorf("skip list: %v", got)
	}

	if status, body = other.signed("ack", "ack", map[string]any{"message_ids": []any{first, second}}, 0); status != 200 || body["deleted"] != float64(0) {
		t.Errorf("another device acked these messages: %d %v", status, body)
	}
	if status, body = owner.signed("ack", "ack", map[string]any{"message_ids": []any{first, first, "junk"}}, 0); status != 200 || body["deleted"] != float64(1) {
		t.Errorf("ack: %d %v", status, body)
	}

	// The mailbox with the one hour expiry stops taking deposits when it runs
	// out, and the message already in it stops being returned at its own expiry.
	advance(time.Hour)
	owner.post("send", map[string]any{"mailbox": b, "envelope": "QUJD"})
	s.store.DB.QueryRow("SELECT COUNT(*) FROM sealed_messages WHERE mailbox = ?", b).Scan(&stored)
	if stored != 1 {
		t.Errorf("an expired mailbox took a deposit: %d messages", stored)
	}

	// The flood cap: three pending per mailbox, then throttled.
	for i := 0; i < 3; i++ {
		if _, body = owner.post("send", map[string]any{"mailbox": a, "envelope": "QUJD"}); body["throttled"] != nil {
			t.Errorf("deposit %d was throttled early", i+1)
		}
	}
	if _, body = owner.post("send", map[string]any{"mailbox": a, "envelope": "QUJD"}); body["throttled"] != true || body["ok"] != true {
		t.Errorf("deposit past the cap: %v", body)
	}
}
