package api

import (
	"context"
	"log"
	"net/http"
	"strings"
)

// envelopeSize checks that a string is standard padded base64 and returns the
// number of bytes it decodes to, without decoding it. A large attachment is
// never held in memory twice just to be measured.
func envelopeSize(b64 string) (int64, bool) {
	n := len(b64)
	if n == 0 || n%4 != 0 {
		return 0, false
	}
	pad := 0
	if strings.HasSuffix(b64, "==") {
		pad = 2
	} else if strings.HasSuffix(b64, "=") {
		pad = 1
	}
	for i := 0; i < n; i++ {
		c := b64[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
		case c == '=' && i >= n-pad:
		default:
			return 0, false
		}
	}
	return int64(n/4*3 - pad), true
}

// expiry settles when a message expires: the time the sender asked for when it
// is in the future and within the relay's maximum, otherwise the maximum.
func (s *Server) expiry(in input) int64 {
	now := s.now().Unix()
	max := now + int64(s.cfg.Limits.MessageTTLMaxDays)*86400
	asked := integer(in["expires_at"])
	if asked <= now || asked > max {
		return max
	}
	return asked
}

// storeFailed answers for a message the database would not take. A refusal over
// size is 413, so the app can say the attachment is too big for this relay.
func storeFailed(where string, err error) result {
	log.Printf("carrierpony: %s: store failed: %v", where, err)
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "packet") || strings.Contains(msg, "gone away") {
		return fail(http.StatusRequestEntityTooLarge, "too_large")
	}
	return fail(http.StatusInternalServerError, "store_failed")
}

// send stores an envelope for every device of the recipient. The relay never
// looks inside the envelope.
func (s *Server) send(ctx context.Context, _ string, in input) result {
	if name := in.firstMissing("to_fpr", "envelope"); name != "" {
		return missing(name)
	}
	to, valid := in.fingerprint("to_fpr")
	if !valid {
		return fail(http.StatusBadRequest, "bad_to_fpr")
	}
	envelope := in.text("envelope")
	size, valid := envelopeSize(envelope)
	if !valid {
		return fail(http.StatusBadRequest, "bad_envelope")
	}
	if size > s.cfg.Limits.MaxEnvelopeBytes {
		return fail(http.StatusRequestEntityTooLarge, "too_large")
	}
	expires := s.expiry(in)

	rows, err := s.store.DB.QueryContext(ctx, "SELECT id FROM devices WHERE fpr = ?", to)
	if err != nil {
		log.Printf("carrierpony: send: %v", err)
		return serverError()
	}
	var devices []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			log.Printf("carrierpony: send: %v", err)
			return serverError()
		}
		devices = append(devices, id)
	}
	if err := rows.Close(); err != nil {
		log.Printf("carrierpony: send: %v", err)
		return serverError()
	}
	if len(devices) == 0 {
		return fail(http.StatusNotFound, "unknown_recipient")
	}

	// A silent send (a control message, a copy to the sender's other devices)
	// is stored with alert 0, so a background check can tell it from a real
	// message without opening it.
	silent := truthy(in["silent"])
	alert := 1
	if silent {
		alert = 0
	}
	messageID := randomHex(16)
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return storeFailed("send", err)
	}
	res, err := tx.ExecContext(ctx,
		"INSERT INTO messages (message_id, to_fpr, envelope, size_bytes, alert, received_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		messageID, to, envelope, size, alert, s.stamp(), stampUnix(expires))
	if err != nil {
		tx.Rollback()
		return storeFailed("send", err)
	}
	pk, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return storeFailed("send", err)
	}
	for _, device := range devices {
		if _, err := tx.ExecContext(ctx, "INSERT INTO deliveries (message_pk, device_pk) VALUES (?, ?)", pk, device); err != nil {
			tx.Rollback()
			return storeFailed("send", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return storeFailed("send", err)
	}

	// The sender may mark a deposit as a contact request, so a push can say so.
	// A silent one is never a request.
	kind := "message"
	if !silent && in.text("kind") == "request" {
		kind = "request"
	}
	s.notify(ctx, devices, silent, kind)

	return ok(field{"message_id", messageID}, field{"expires_at", expires})
}
