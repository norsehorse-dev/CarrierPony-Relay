package api

import (
	"context"
	"log"
	"net/http"
)

// challenge issues a one-time nonce for a fingerprint. The client signs it to
// log in. Any well-formed fingerprint gets one, registered or not, so the
// endpoint does not reveal who has an account.
func (s *Server) challenge(ctx context.Context, in input) result {
	if name := in.firstMissing("fpr"); name != "" {
		return missing(name)
	}
	fpr, valid := in.fingerprint("fpr")
	if !valid {
		return fail(http.StatusBadRequest, "bad_fpr")
	}
	nonce := randomHex(32)
	_, err := s.store.DB.ExecContext(ctx,
		"INSERT INTO challenges (nonce, fpr, created_at, expires_at) VALUES (?, ?, ?, ?)",
		nonce, fpr, s.stamp(), s.stampIn(s.cfg.Limits.ChallengeTTL))
	if err != nil {
		log.Printf("carrierpony: challenge: %v", err)
		return serverError()
	}
	return ok(field{"nonce", nonce})
}
