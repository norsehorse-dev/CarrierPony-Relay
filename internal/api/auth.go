package api

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"

	"github.com/norsehorse-dev/CarrierPony-Relay/verifier"
)

// spendChallenge uses up a nonce issued to a fingerprint. It reports false when
// there is no such unexpired nonce. Deleting and counting in one statement
// means a nonce is good for exactly one request even when two arrive together.
func (s *Server) spendChallenge(ctx context.Context, fpr, nonce string) (bool, error) {
	res, err := s.store.DB.ExecContext(ctx,
		"DELETE FROM challenges WHERE nonce = ? AND fpr = ? AND expires_at > ?", nonce, fpr, s.stamp())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// authenticate checks a login: a nonce the relay issued to this fingerprint,
// signed by the key registered for it. It returns the fingerprint, or the
// refusal to send. The verifier pins the key to the fingerprint, so a login can
// only ever speak for its own identity.
func (s *Server) authenticate(ctx context.Context, in input) (string, *result) {
	if name := in.firstMissing("fpr", "nonce", "sig"); name != "" {
		res := missing(name)
		return "", &res
	}
	fpr, valid := in.fingerprint("fpr")
	if !valid {
		res := fail(http.StatusBadRequest, "bad_fpr")
		return "", &res
	}
	nonce := in.text("nonce")
	spent, err := s.spendChallenge(ctx, fpr, nonce)
	if err != nil {
		log.Printf("carrierpony: login: %v", err)
		res := serverError()
		return "", &res
	}
	if !spent {
		res := fail(http.StatusUnauthorized, "bad_challenge")
		return "", &res
	}
	var pubkey string
	err = s.store.DB.QueryRowContext(ctx, "SELECT pubkey FROM identities WHERE fpr = ?", fpr).Scan(&pubkey)
	if errors.Is(err, sql.ErrNoRows) {
		// An identity that never registered has no key to check against. The
		// answer is the same as for a wrong signature.
		res := fail(http.StatusUnauthorized, "bad_signature")
		return "", &res
	}
	if err != nil {
		log.Printf("carrierpony: login: %v", err)
		res := serverError()
		return "", &res
	}
	if verifier.Verify(pubkey, fpr, []byte(nonce), in.text("sig")) != nil {
		res := fail(http.StatusUnauthorized, "bad_signature")
		return "", &res
	}
	return fpr, nil
}

// authed wraps a handler that needs a login. The handler gets the fingerprint.
func authed(h func(s *Server, ctx context.Context, fpr string, in input) result) handler {
	return func(s *Server, ctx context.Context, in input) result {
		fpr, refusal := s.authenticate(ctx, in)
		if refusal != nil {
			return *refusal
		}
		return h(s, ctx, fpr, in)
	}
}

// deviceOf returns the row id of a device registered under a fingerprint.
func (s *Server) deviceOf(ctx context.Context, fpr, deviceID string) (int64, bool, error) {
	var id int64
	err := s.store.DB.QueryRowContext(ctx, "SELECT id FROM devices WHERE fpr = ? AND device_id = ?", fpr, deviceID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}
