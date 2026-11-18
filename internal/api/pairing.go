package api

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
)

// Pairing lets two people exchange public keys through the relay with a short
// token: one opens an offer, the other accepts it, and the first collects the
// result. The relay sees both keys, as it does at registration.

// pairOffer opens an offer carrying the offerer's public key.
func (s *Server) pairOffer(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("pubkey"); name != "" {
		return missing(name)
	}
	pubkey := in.text("pubkey")
	if len(pubkey) > maxKeyBytes {
		return fail(http.StatusBadRequest, "bad_pubkey")
	}
	now := s.stamp()
	var open int
	err := s.store.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pairing_offers WHERE offerer_fpr = ? AND state = 'open' AND expires_at > ?", fpr, now).Scan(&open)
	if err != nil {
		log.Printf("carrierpony: pair/offer: %v", err)
		return serverError()
	}
	if open >= s.cfg.Limits.PairMaxOpen {
		return fail(http.StatusTooManyRequests, "too_many_offers")
	}
	ttl := s.cfg.Limits.PairOfferTTL
	token := randomHex(16)
	_, err = s.store.DB.ExecContext(ctx,
		"INSERT INTO pairing_offers (token, offerer_fpr, offerer_pubkey, state, created_at, expires_at) VALUES (?, ?, ?, 'open', ?, ?)",
		token, fpr, pubkey, now, s.stampIn(ttl))
	if err != nil {
		log.Printf("carrierpony: pair/offer: %v", err)
		return serverError()
	}
	return ok(field{"token", token}, field{"expires_in", ttl})
}

// pairAccept accepts an open offer and returns the offerer's key. The update
// only matches an offer that is still open and unexpired, so an offer can be
// accepted once.
func (s *Server) pairAccept(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("token", "pubkey"); name != "" {
		return missing(name)
	}
	token := in.text("token")
	if !reHex32.MatchString(token) {
		return fail(http.StatusBadRequest, "bad_token")
	}
	pubkey := in.text("pubkey")
	if len(pubkey) > maxKeyBytes {
		return fail(http.StatusBadRequest, "bad_pubkey")
	}
	now := s.stamp()
	res, err := s.store.DB.ExecContext(ctx,
		`UPDATE pairing_offers
		 SET state = 'accepted', responder_fpr = ?, responder_pubkey = ?, accepted_at = ?
		 WHERE token = ? AND state = 'open' AND expires_at > ?`, fpr, pubkey, now, token, now)
	if err != nil {
		log.Printf("carrierpony: pair/accept: %v", err)
		return serverError()
	}
	var offererFpr, offererPubkey string
	err = s.store.DB.QueryRowContext(ctx, "SELECT offerer_fpr, offerer_pubkey FROM pairing_offers WHERE token = ?", token).
		Scan(&offererFpr, &offererPubkey)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(http.StatusNotFound, "no_such_offer")
	}
	if err != nil {
		log.Printf("carrierpony: pair/accept: %v", err)
		return serverError()
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fail(http.StatusGone, "offer_closed")
	}
	return ok(field{"offerer_fpr", offererFpr}, field{"offerer_pubkey", offererPubkey})
}

// pairStatus tells the offerer where their offer stands, and hands over the
// responder's key once it is accepted. An accepted offer stays collectable past
// its expiry, until the reaper removes it. An open one past its expiry can
// never be accepted, so it is reported as expired.
func (s *Server) pairStatus(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("token"); name != "" {
		return missing(name)
	}
	token := in.text("token")
	if !reHex32.MatchString(token) {
		return fail(http.StatusBadRequest, "bad_token")
	}
	var offerer, state, expires string
	var responderFpr, responderPubkey sql.NullString
	err := s.store.DB.QueryRowContext(ctx,
		"SELECT offerer_fpr, state, responder_fpr, responder_pubkey, expires_at FROM pairing_offers WHERE token = ?", token).
		Scan(&offerer, &state, &responderFpr, &responderPubkey, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(http.StatusNotFound, "no_such_offer")
	}
	if err != nil {
		log.Printf("carrierpony: pair/status: %v", err)
		return serverError()
	}
	if upperASCII(offerer) != fpr {
		return fail(http.StatusForbidden, "not_your_offer")
	}
	if state == "accepted" {
		return ok(field{"state", "accepted"}, field{"responder_fpr", nullable(responderFpr)}, field{"responder_pubkey", nullable(responderPubkey)})
	}
	if state == "open" && expires <= s.stamp() {
		return ok(field{"state", "expired"})
	}
	return ok(field{"state", state})
}

func nullable(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}
