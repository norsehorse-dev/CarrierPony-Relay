// Package verifier checks the detached OpenPGP signature a CarrierPony client
// makes over a relay login challenge. It handles v4 and v6 (RFC 9580) keys,
// which is why it exists: GnuPG does not read v6 keys.
package verifier

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

var (
	ErrBadFingerprint  = errors.New("bad_fpr")
	ErrBadKey          = errors.New("bad_pubkey")
	ErrFingerprintDiff = errors.New("fpr_mismatch")
	ErrBadSignature    = errors.New("bad_signature")
)

// ValidFingerprint reports whether s is a v4 (40 hex) or v6 (64 hex) fingerprint.
func ValidFingerprint(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Fingerprint returns the uppercase hex primary-key fingerprint of an armored
// public key that holds exactly one certificate.
func Fingerprint(armoredKey string) (string, error) {
	e, err := readOne(armoredKey)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)), nil
}

// Verify succeeds only when armoredKey is a single certificate whose primary
// fingerprint equals fpr, and armoredSig is a valid detached signature over
// data made by that certificate's primary key or by a signing subkey the
// primary key has bound. The fingerprint is the identity, so the primary key
// is pinned by it; the library checks the subkey binding (and the embedded
// back-signature), so a subkey grafted onto someone else's primary key is
// rejected.
func Verify(armoredKey, fpr string, data []byte, armoredSig string) error {
	code, _ := VerifyDetail(armoredKey, fpr, data, armoredSig)
	return code
}

// VerifyDetail is Verify plus the underlying reason for a failure, for logs.
// The reason is free text from the OpenPGP library and must never be used to
// make a decision or be shown to a client.
func VerifyDetail(armoredKey, fpr string, data []byte, armoredSig string) (code error, detail string) {
	if !ValidFingerprint(fpr) {
		return ErrBadFingerprint, ""
	}
	e, err := readOne(armoredKey)
	if err != nil {
		return err, ""
	}
	got := hex.EncodeToString(e.PrimaryKey.Fingerprint)
	if !strings.EqualFold(got, fpr) {
		return ErrFingerprintDiff, ""
	}
	// A v4 fingerprint must come from a v4 key and a v6 fingerprint from a v6
	// key. The lengths already force this (SHA-1 vs SHA-256); keep it explicit.
	if (len(fpr) == 64) != (e.PrimaryKey.Version == 6) {
		return ErrFingerprintDiff, ""
	}
	sig, err := dearmor(armoredSig)
	if err != nil {
		return ErrBadSignature, "signature is not armored: " + err.Error()
	}
	sig = normalize(sig)
	cfg := &packet.Config{Time: clockFor(sig)}
	_, signer, err := openpgp.VerifyDetachedSignature(
		openpgp.EntityList{e}, bytes.NewReader(data), bytes.NewReader(sig), cfg)
	if err != nil {
		return ErrBadSignature, err.Error()
	}
	if signer == nil {
		return ErrBadSignature, "no signer"
	}
	return nil, ""
}

// clockFor returns the clock to verify sig against: the real time, or the
// signature's own creation time when that is later.
//
// The library refuses a signature dated even one second ahead of the clock it
// is given. A phone whose clock runs a few seconds fast stamps its login
// signature slightly in the server's future, so on the real clock that phone
// could never log in. GnuPG, which this replaces, does not compare a
// signature's date with the current time at all, and every client in use was
// built against that.
//
// Nothing is lost by this. What makes a login fresh is the nonce: the relay
// issues it, it is single use and short lived, and the signature has to cover
// it. The date inside the signature is written by the client and proves
// nothing. A signature dated before its key was created is still refused.
func clockFor(sig []byte) func() time.Time {
	stamp := time.Time{}
	if p, err := packet.Read(bytes.NewReader(sig)); err == nil {
		if s, ok := p.(*packet.Signature); ok {
			stamp = s.CreationTime
		}
	}
	return func() time.Time {
		now := time.Now()
		if stamp.After(now) {
			return stamp
		}
		return now
	}
}

// readOne parses an armored public key that must hold exactly one certificate.
// Signatures an older iOS build mislabelled are put right first (see repair.go).
func readOne(armoredKey string) (*openpgp.Entity, error) {
	key, err := dearmor(armoredKey)
	if err != nil {
		return nil, ErrBadKey
	}
	list, err := openpgp.ReadKeyRing(bytes.NewReader(normalize(key)))
	if err != nil || len(list) != 1 {
		return nil, ErrBadKey
	}
	return list[0], nil
}

// dearmor returns the binary contents of one ASCII-armored block, at most 1 MiB.
func dearmor(armored string) ([]byte, error) {
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(block.Body, 1<<20))
}
