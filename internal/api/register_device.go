package api

import (
	"context"
	"log"
	"net/http"

	"github.com/norsehorse-dev/CarrierPony-Relay/verifier"
)

// maxKeyBytes is the largest armored public key the relay stores.
const maxKeyBytes = 100000

// registerDevice creates or updates an identity and one of its devices. It is
// the only request that carries the public key, so the signature is checked
// against the key in the request, which must hash to the fingerprint claimed.
func (s *Server) registerDevice(ctx context.Context, in input) result {
	if name := in.firstMissing("fpr", "pubkey", "device_id", "nonce", "sig"); name != "" {
		return missing(name)
	}
	fpr, valid := in.fingerprint("fpr")
	if !valid {
		return fail(http.StatusBadRequest, "bad_fpr")
	}
	deviceID := in.text("device_id")
	if !reHex32.MatchString(deviceID) {
		return fail(http.StatusBadRequest, "bad_device_id")
	}
	pubkey := in.text("pubkey")
	if len(pubkey) > maxKeyBytes {
		return fail(http.StatusBadRequest, "bad_pubkey")
	}
	nonce := in.text("nonce")
	spent, err := s.spendChallenge(ctx, fpr, nonce)
	if err != nil {
		log.Printf("carrierpony: register-device: %v", err)
		return serverError()
	}
	if !spent {
		return fail(http.StatusUnauthorized, "bad_challenge")
	}
	if verifier.Verify(pubkey, fpr, []byte(nonce), in.text("sig")) != nil {
		return fail(http.StatusUnauthorized, "bad_signature")
	}

	var label any
	if _, sent := in["label"]; sent && in["label"] != nil {
		label = cutBytes(in.text("label"), 64)
	}
	now := s.stamp()
	if err := s.store.UpsertIdentity(ctx, fpr, pubkey, now); err != nil {
		log.Printf("carrierpony: register-device: %v", err)
		return serverError()
	}
	if err := s.store.UpsertDevice(ctx, fpr, deviceID, label, now); err != nil {
		log.Printf("carrierpony: register-device: %v", err)
		return serverError()
	}
	return ok(field{"ok", true})
}
