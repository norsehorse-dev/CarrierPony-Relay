package verifier

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// oldLayout rewrites the which-th v4 EdDSA signature packet in a binary key
// the way the old iOS encoder wrote it, when R or S is short enough to show
// the fault. ok is false when that signature has two full-width values.
func oldLayout(t *testing.T, key []byte, which int) (out []byte, ok bool) {
	t.Helper()
	seen := 0
	i := 0
	for i < len(key) {
		tag, bodyStart, bodyLength, good := header(key, i)
		if !good {
			t.Fatal("test key is not a clean packet sequence")
		}
		end := bodyStart + bodyLength
		body := key[bodyStart:end]
		if tag == tagSignature && body[0] == 4 && body[2] == eddsaLegacy {
			if seen == which {
				j := 4
				j += 2 + uint16At(body, j)
				j += 2 + uint16At(body, j)
				j += 2
				rewritten := append([]byte{}, body[:j]...)
				for n := 0; n < 2; n++ {
					length := (uint16At(body, j) + 7) / 8
					if length < valueLength {
						ok = true
					}
					rewritten = append(rewritten, body[j], body[j+1])
					rewritten = append(rewritten, make([]byte, valueLength-length)...)
					rewritten = append(rewritten, body[j+2:j+2+length]...)
					j += 2 + length
				}
				out = append(out, packetBytes(tagSignature, rewritten)...)
				i = end
				seen++
				continue
			}
			seen++
		}
		out = append(out, key[i:end]...)
		i = end
	}
	return out, ok
}

func binaryKey(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func armorBytes(t *testing.T, kind string, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, kind, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	w.Close()
	return buf.String()
}

// A v4 identity whose which-th key signature (0 is the user ID certification,
// 1 the subkey binding) is in the old encoder's layout.
func oldLayoutIdent(t *testing.T, which int) (ident, string) {
	t.Helper()
	for attempt := 0; attempt < 5000; attempt++ {
		id := newIdent(t, false, false, false)
		key, ok := oldLayout(t, binaryKey(t, id.e), which)
		if ok {
			return id, armorBytes(t, "PGP PUBLIC KEY BLOCK", key)
		}
	}
	t.Fatal("no identity with a short signature value in 5000 tries")
	return ident{}, ""
}

func TestOldEncoderSelfCertification(t *testing.T) {
	id, pub := oldLayoutIdent(t, 0)
	// Without the repair the library refuses the key itself.
	if _, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pub)); err == nil {
		t.Log("library read the mislabelled key unaided")
	}
	if err := Verify(pub, id.fpr, []byte(nonce), sign(t, id.e, nonce)); err != nil {
		t.Fatalf("key with an old-layout certification must verify: %v", err)
	}
	if got, err := Fingerprint(pub); err != nil || got != id.fpr {
		t.Fatalf("fingerprint of an old-layout key: %q %v", got, err)
	}
	if err := Verify(pub, id.fpr, []byte(nonce+"x"), sign(t, id.e, nonce)); err != ErrBadSignature {
		t.Fatalf("a wrong challenge must still fail, got %v", err)
	}
}

func TestOldEncoderSubkeyBinding(t *testing.T) {
	id, pub := oldLayoutIdent(t, 1)
	if err := Verify(pub, id.fpr, []byte(nonce), sign(t, id.e, nonce)); err != nil {
		t.Fatalf("key with an old-layout binding must verify: %v", err)
	}
}

func TestOldEncoderLoginSignature(t *testing.T) {
	id := newIdent(t, false, false, false)
	for attempt := 0; attempt < 5000; attempt++ {
		block, err := armor.Decode(strings.NewReader(sign(t, id.e, nonce)))
		if err != nil {
			t.Fatal(err)
		}
		var raw bytes.Buffer
		raw.ReadFrom(block.Body)
		sig, ok := oldLayout(t, raw.Bytes(), 0)
		if !ok {
			continue
		}
		if err := Verify(id.pub, id.fpr, []byte(nonce), armorBytes(t, "PGP SIGNATURE", sig)); err != nil {
			t.Fatalf("an old-layout login signature must verify: %v", err)
		}
		return
	}
	t.Fatal("no short signature value in 5000 tries")
}

// The repair cannot make a bad signature pass: a mislabelled packet whose
// value has been altered is repaired into a well-formed signature that fails.
func TestRepairDoesNotForgive(t *testing.T) {
	id, pub := oldLayoutIdent(t, 0)
	block, _ := armor.Decode(strings.NewReader(pub))
	var raw bytes.Buffer
	raw.ReadFrom(block.Body)
	key := raw.Bytes()
	// Flip a bit near the end of the first signature packet (inside S).
	i := 0
	for i < len(key) {
		tag, bodyStart, bodyLength, _ := header(key, i)
		if tag == tagSignature {
			key[bodyStart+bodyLength-1] ^= 0x01
			break
		}
		i = bodyStart + bodyLength
	}
	bad := armorBytes(t, "PGP PUBLIC KEY BLOCK", key)
	if err := Verify(bad, id.fpr, []byte(nonce), sign(t, id.e, nonce)); err == nil {
		t.Fatal("a key with a forged certification must not verify")
	}
}

func TestNormalizeLeavesGoodKeysAlone(t *testing.T) {
	for _, id := range []ident{newIdent(t, false, false, false), newIdent(t, true, false, true)} {
		key := binaryKey(t, id.e)
		if got := normalize(key); !bytes.Equal(got, key) {
			t.Fatal("a correctly written key was changed")
		}
	}
	junk := []byte{0x01, 0x02, 0x03}
	if got := normalize(junk); !bytes.Equal(got, junk) {
		t.Fatal("bytes that are not packets were changed")
	}
}
