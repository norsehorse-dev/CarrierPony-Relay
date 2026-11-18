package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"net/http/httptest"
)

// identity is a throwaway key that can log in to the relay under test.
type identity struct {
	t      *testing.T
	ts     *httptest.Server
	entity *openpgp.Entity
	fpr    string
	pubkey string
	device string
}

func newIdentity(t *testing.T, ts *httptest.Server, v6 bool) *identity {
	t.Helper()
	algo := packet.PubKeyAlgoEdDSA
	if v6 {
		algo = packet.PubKeyAlgoEd25519
	}
	cfg := &packet.Config{Algorithm: algo, V6Keys: v6}
	e, err := openpgp.NewEntity("CarrierPony", "", "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v6 {
		// A v6 identity signs with a subkey, as the apps do.
		if err := e.AddSigningSubkey(cfg); err != nil {
			t.Fatal(err)
		}
	}
	var raw, out bytes.Buffer
	if err := e.Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	w, _ := armor.Encode(&out, "PGP PUBLIC KEY BLOCK", nil)
	w.Write(raw.Bytes())
	w.Close()
	return &identity{t: t, ts: ts, entity: e, fpr: strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)),
		pubkey: out.String(), device: randomHex(16)}
}

func (id *identity) sign(data string) string {
	var out bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&out, []*openpgp.Entity{id.entity}, strings.NewReader(data), &openpgp.SignParams{}); err != nil {
		id.t.Fatal(err)
	}
	return out.String()
}

// call logs in as fpr (the identity's own unless given) and posts extra.
func (id *identity) call(path string, extra map[string]any, as ...string) (int, map[string]any) {
	id.t.Helper()
	fpr := id.fpr
	if len(as) > 0 {
		fpr = as[0]
	}
	_, _, body := do(id.t, id.ts, "POST", "/v1/challenge", `{"fpr":"`+fpr+`"}`)
	var ch map[string]string
	json.Unmarshal([]byte(body), &ch)
	req := map[string]any{"fpr": fpr, "nonce": ch["nonce"], "sig": id.sign(ch["nonce"])}
	for k, v := range extra {
		req[k] = v
	}
	raw, _ := json.Marshal(req)
	status, _, answer := do(id.t, id.ts, "POST", path, string(raw))
	var got map[string]any
	json.Unmarshal([]byte(answer), &got)
	return status, got
}

func (id *identity) register() (int, map[string]any) {
	return id.call("/v1/register-device", map[string]any{"pubkey": id.pubkey, "device_id": id.device, "label": "test"})
}

func wantError(t *testing.T, what string, status int, body map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || body["error"] != wantCode {
		t.Errorf("%s: got %d %v, want %d %s", what, status, body, wantStatus, wantCode)
	}
}

func TestIdentityPath(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "v4"
		if v6 {
			name = "v6"
		}
		t.Run(name, func(t *testing.T) {
			_, ts := newServer(t)
			alice, bob, mallory := newIdentity(t, ts, v6), newIdentity(t, ts, v6), newIdentity(t, ts, v6)
			if want := map[bool]int{false: 40, true: 64}[v6]; len(alice.fpr) != want {
				t.Fatalf("fingerprint is %d characters", len(alice.fpr))
			}

			status, body := alice.call("/v1/inbox", map[string]any{"device_id": alice.device})
			wantError(t, "login before registering", status, body, 401, "bad_signature")

			for _, id := range []*identity{alice, bob} {
				if status, body := id.register(); status != 200 || body["ok"] != true {
					t.Fatalf("register: %d %v", status, body)
				}
			}

			// Nobody can register or log in under a fingerprint that is not
			// their own key's.
			status, body = mallory.call("/v1/register-device", map[string]any{"pubkey": mallory.pubkey, "device_id": mallory.device}, alice.fpr)
			wantError(t, "register own key under another fingerprint", status, body, 401, "bad_signature")
			status, body = mallory.call("/v1/register-device", map[string]any{"pubkey": alice.pubkey, "device_id": mallory.device}, alice.fpr)
			wantError(t, "register another's key without their signature", status, body, 401, "bad_signature")
			status, body = mallory.call("/v1/inbox", map[string]any{"device_id": alice.device}, alice.fpr)
			wantError(t, "log in as someone else", status, body, 401, "bad_signature")
			var stored string
			s := ts.Config.Handler.(*Server)
			s.store.DB.QueryRow("SELECT pubkey FROM identities WHERE fpr = ?", alice.fpr).Scan(&stored)
			if stored != alice.pubkey {
				t.Fatal("a refused registration changed the stored key")
			}

			envelope := base64.StdEncoding.EncodeToString([]byte("hello relay"))
			status, body = alice.call("/v1/send", map[string]any{"to_fpr": strings.ToLower(bob.fpr), "envelope": envelope})
			if status != 200 || len(body["message_id"].(string)) != 32 {
				t.Fatalf("send: %d %v", status, body)
			}
			first := body["message_id"].(string)
			status, body = alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": envelope, "silent": true})
			if status != 200 {
				t.Fatalf("silent send: %d %v", status, body)
			}
			second := body["message_id"].(string)
			status, body = alice.call("/v1/send", map[string]any{"to_fpr": mallory.fpr, "envelope": envelope})
			wantError(t, "send to an unregistered identity", status, body, 404, "unknown_recipient")

			status, body = bob.call("/v1/inbox", map[string]any{"device_id": bob.device})
			msgs, _ := body["messages"].([]any)
			if status != 200 || len(msgs) != 2 {
				t.Fatalf("inbox: %d %v", status, body)
			}
			m0, m1 := msgs[0].(map[string]any), msgs[1].(map[string]any)
			if m0["message_id"] != first || m1["message_id"] != second || m0["envelope"] != envelope {
				t.Errorf("inbox order or content is wrong: %v", msgs)
			}
			if m0["alert"] != float64(1) || m1["alert"] != float64(0) {
				t.Errorf("alert flags: %v %v", m0["alert"], m1["alert"])
			}
			status, body = alice.call("/v1/inbox", map[string]any{"device_id": alice.device})
			if msgs, _ := body["messages"].([]any); status != 200 || len(msgs) != 0 {
				t.Errorf("the sender's inbox is not empty: %d %v", status, body)
			}
			status, body = alice.call("/v1/inbox", map[string]any{"device_id": bob.device})
			wantError(t, "inbox of another identity's device", status, body, 403, "unknown_device")

			status, body = alice.call("/v1/ack", map[string]any{"device_id": alice.device, "message_ids": []string{first, second}})
			if status != 200 || body["acked"] != float64(0) {
				t.Errorf("the sender acked the recipient's messages: %d %v", status, body)
			}
			status, body = bob.call("/v1/ack", map[string]any{"device_id": bob.device, "message_ids": []string{first, second}})
			if status != 200 || body["acked"] != float64(2) {
				t.Errorf("ack: %d %v", status, body)
			}
			var left int
			s.store.DB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&left)
			if left != 0 {
				t.Errorf("%d messages left after every device acked", left)
			}
			var nonces int
			s.store.DB.QueryRow("SELECT COUNT(*) FROM challenges").Scan(&nonces)
			if nonces != 0 {
				t.Errorf("%d nonces left unspent", nonces)
			}
		})
	}
}

func TestANonceWorksOnceEvenWhenRequestsRace(t *testing.T) {
	_, ts := newServer(t)
	alice := newIdentity(t, ts, true)
	alice.register()
	_, _, body := do(t, ts, "POST", "/v1/challenge", `{"fpr":"`+alice.fpr+`"}`)
	var ch map[string]string
	json.Unmarshal([]byte(body), &ch)
	raw, _ := json.Marshal(map[string]any{"fpr": alice.fpr, "nonce": ch["nonce"], "sig": alice.sign(ch["nonce"]), "device_id": alice.device})
	results := make(chan int, 16)
	for i := 0; i < 16; i++ {
		go func() {
			status, _, _ := do(t, ts, "POST", "/v1/inbox", string(raw))
			results <- status
		}()
	}
	okCount := 0
	for i := 0; i < 16; i++ {
		if <-results == 200 {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("%d of 16 racing requests were accepted with one nonce", okCount)
	}
}

func TestInboxStreamsPastTheContextOfTheHandler(t *testing.T) {
	s, ts := newServer(t)
	s.cfg.Limits.InboxBytesBudget = 1 << 20
	alice, bob := newIdentity(t, ts, false), newIdentity(t, ts, false)
	alice.register()
	bob.register()
	envelope := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 20000))
	for i := 0; i < 5; i++ {
		if status, body := alice.call("/v1/send", map[string]any{"to_fpr": bob.fpr, "envelope": envelope}); status != 200 {
			t.Fatalf("send: %d %v", status, body)
		}
	}
	status, body := bob.call("/v1/inbox", map[string]any{"device_id": bob.device})
	msgs, _ := body["messages"].([]any)
	if status != 200 || len(msgs) != 5 {
		t.Fatalf("inbox returned %d messages, status %d", len(msgs), status)
	}
}
