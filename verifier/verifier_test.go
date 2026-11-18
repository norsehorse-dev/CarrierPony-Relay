package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

const nonce = "5b1e0c7a9f3d48e2a6c1b7d09e4f2a8c5b1e0c7a9f3d48e2a6c1b7d09e4f2a8c"

type ident struct {
	e   *openpgp.Entity
	pub string
	fpr string
}

func newIdent(t *testing.T, v6, signingSubkey, mlkem bool) ident {
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
	if signingSubkey {
		if err := e.AddSigningSubkey(cfg); err != nil {
			t.Fatal(err)
		}
	}
	if mlkem {
		kc := &packet.Config{Algorithm: packet.PubKeyAlgoMlkem768X25519, V6Keys: true}
		if err := e.AddEncryptionSubkey(kc); err != nil {
			t.Fatal(err)
		}
	}
	return ident{e: e, pub: armorKey(t, e), fpr: strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))}
}

func armorKey(t *testing.T, e *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.String()
}

func sign(t *testing.T, e *openpgp.Entity, data string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, []*openpgp.Entity{e}, strings.NewReader(data), &openpgp.SignParams{}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestShapes(t *testing.T) {
	cases := []struct {
		name                     string
		v6, signingSubkey, mlkem bool
		fprLen                   int
	}{
		{"v4 primary signs", false, false, false, 40},
		{"v4 signing subkey", false, true, false, 40},
		{"v6 primary signs", true, false, false, 64},
		{"v6 signing subkey", true, true, false, 64},
		{"v6 signing subkey with ML-KEM", true, true, true, 64},
		{"v6 primary signs with ML-KEM", true, false, true, 64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := newIdent(t, c.v6, c.signingSubkey, c.mlkem)
			if len(id.fpr) != c.fprLen {
				t.Fatalf("fingerprint length %d, want %d", len(id.fpr), c.fprLen)
			}
			got, err := Fingerprint(id.pub)
			if err != nil || got != id.fpr {
				t.Fatalf("Fingerprint = %q, %v", got, err)
			}
			sig := sign(t, id.e, nonce)
			if err := Verify(id.pub, id.fpr, []byte(nonce), sig); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			if err := Verify(id.pub, strings.ToLower(id.fpr), []byte(nonce), sig); err != nil {
				t.Fatalf("lowercase fingerprint rejected: %v", err)
			}
			if err := Verify(id.pub, id.fpr, []byte(nonce+"x"), sig); err != ErrBadSignature {
				t.Fatalf("tampered data: %v", err)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		a := newIdent(t, v6, true, v6)
		b := newIdent(t, v6, true, v6)
		sigB := sign(t, b.e, nonce)
		if err := Verify(a.pub, a.fpr, []byte(nonce), sigB); err != ErrBadSignature {
			t.Fatalf("signature from another identity: %v", err)
		}
		if err := Verify(b.pub, a.fpr, []byte(nonce), sigB); err != ErrFingerprintDiff {
			t.Fatalf("key that does not hash to the claimed fingerprint: %v", err)
		}
	}
}

// An attacker takes the victim's public primary key and attaches their own
// signing subkey, keeping the binding signature their own key made. The
// fingerprint still matches the victim, so only the binding check stops it.
func TestGraftedSubkey(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		victim := newIdent(t, v6, true, false)
		attacker := newIdent(t, v6, true, false)

		var buf bytes.Buffer
		w, _ := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
		victim.e.PrimaryKey.Serialize(w)
		for _, id := range victim.e.Identities {
			id.Serialize(w)
		}
		for _, ds := range victim.e.DirectSignatures {
			ds.Packet.Serialize(w)
		}
		for _, sk := range attacker.e.Subkeys {
			sk.Serialize(w, false)
		}
		w.Close()

		sig := sign(t, attacker.e, nonce)
		if err := Verify(buf.String(), victim.fpr, []byte(nonce), sig); err == nil {
			t.Fatalf("v6=%v: grafted subkey was accepted", v6)
		}
	}
}

func TestTwoCertificates(t *testing.T) {
	a := newIdent(t, true, false, false)
	b := newIdent(t, true, false, false)
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	a.e.Serialize(w)
	b.e.Serialize(w)
	w.Close()
	if err := Verify(buf.String(), a.fpr, []byte(nonce), sign(t, a.e, nonce)); err != ErrBadKey {
		t.Fatalf("two certificates in one block: %v", err)
	}
}

func TestBadInput(t *testing.T) {
	a := newIdent(t, true, false, false)
	sig := sign(t, a.e, nonce)
	if err := Verify(a.pub, a.fpr[:63], []byte(nonce), sig); err != ErrBadFingerprint {
		t.Fatal(err)
	}
	if err := Verify("not a key", a.fpr, []byte(nonce), sig); err != ErrBadKey {
		t.Fatal(err)
	}
	if err := Verify(a.pub, a.fpr, []byte(nonce), "not a signature"); err != ErrBadSignature {
		t.Fatal(err)
	}
	for _, s := range []string{"", strings.Repeat("A", 39), strings.Repeat("G", 40), strings.Repeat("A", 50)} {
		if ValidFingerprint(s) {
			t.Fatalf("accepted %q", s)
		}
	}
}

func signAt(t *testing.T, e *openpgp.Entity, data string, when time.Time) string {
	t.Helper()
	var buf bytes.Buffer
	cfg := &packet.Config{Time: func() time.Time { return when }}
	if err := openpgp.ArmoredDetachSign(&buf, []*openpgp.Entity{e}, strings.NewReader(data), &openpgp.SignParams{Config: cfg}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// A client whose clock runs ahead of the server's dates its signature in the
// server's future. GnuPG accepts that, every client in use relies on it, and
// the nonce is what makes a login fresh, so the verifier accepts it too.
func TestClientClockAhead(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		id := newIdent(t, v6, false, v6)
		for _, ahead := range []time.Duration{5 * time.Second, 10 * time.Minute, 72 * time.Hour} {
			sig := signAt(t, id.e, nonce, time.Now().Add(ahead))
			if err := Verify(id.pub, id.fpr, []byte(nonce), sig); err != nil {
				t.Fatalf("v6=%v clock %v ahead must verify: %v", v6, ahead, err)
			}
			if err := Verify(id.pub, id.fpr, []byte(nonce+"x"), sig); err != ErrBadSignature {
				t.Fatalf("v6=%v clock %v ahead, wrong challenge must fail, got %v", v6, ahead, err)
			}
			other := newIdent(t, v6, false, v6)
			if err := Verify(other.pub, other.fpr, []byte(nonce), sig); err != ErrBadSignature {
				t.Fatalf("v6=%v clock %v ahead, wrong key must fail, got %v", v6, ahead, err)
			}
		}
	}
}

// A signature dated before its own key existed is still refused, as GnuPG
// refuses it.
func TestSignatureOlderThanKey(t *testing.T) {
	id := newIdent(t, false, false, false)
	// The library will not make such a signature through its signing API, so
	// the packet is built directly.
	old := time.Now().Add(-48 * time.Hour)
	keyID := id.e.PrimaryKey.KeyId
	raw := &packet.Signature{
		Version:           4,
		SigType:           packet.SigTypeBinary,
		PubKeyAlgo:        id.e.PrimaryKey.PubKeyAlgo,
		Hash:              crypto.SHA256,
		CreationTime:      old,
		IssuerKeyId:       &keyID,
		IssuerFingerprint: id.e.PrimaryKey.Fingerprint,
	}
	h := sha256.New()
	h.Write([]byte(nonce))
	if err := raw.Sign(h, id.e.PrivateKey, &packet.Config{Time: func() time.Time { return old }}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := raw.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	sig := armorBytes(t, "PGP SIGNATURE", buf.Bytes())
	code, detail := VerifyDetail(id.pub, id.fpr, []byte(nonce), sig)
	if code != ErrBadSignature {
		t.Fatalf("a signature older than its key must fail, got %v (%s)", code, detail)
	}
	// The same hand-built packet with a current date verifies, so the failure
	// above is the date and nothing else.
	raw.CreationTime = time.Now()
	h = sha256.New()
	h.Write([]byte(nonce))
	if err := raw.Sign(h, id.e.PrivateKey, nil); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := raw.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	if err := Verify(id.pub, id.fpr, []byte(nonce), armorBytes(t, "PGP SIGNATURE", buf.Bytes())); err != nil {
		t.Fatalf("the same packet with a current date must verify: %v", err)
	}
}

// The login a live relay logged as "signature expired": made by a phone a few
// seconds ahead of the server. Checks the date is read from a real client's
// signature. The key is not here, so this stops at the clock.
func TestClockIsReadFromARealSignature(t *testing.T) {
	const logged = `-----BEGIN PGP SIGNATURE-----

wnUEABYIAB0Fgmr3+ScWIQScIRlDiBm7wT8RlxIkvWTugwrWogAKCRAkvWTugwrW
ok3pAPwPafm43n2aSj0xMsS3ZH4GTN/vau4SgmRd5Iv/cEsnWQD/a6ZztVxGx+Ko
434xEtUeiPH3LGpcmwz+7i6usicbSAw=
=TsjI
-----END PGP SIGNATURE-----
`
	raw, err := dearmor(logged)
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(normalize(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.(*packet.Signature).CreationTime.Unix(); got != 1794636071 {
		t.Fatalf("creation time %d", got)
	}
}
