package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// The sealed path never sees a fingerprint. A device is known only by a random
// device_id and a device_key it proves with an HMAC, and messages are addressed
// to opaque mailbox ids the apps derive from a secret the two sides share. The
// relay cannot tell who is writing to whom.

// sealedProofWindow is how far a proof's timestamp may be from the relay's
// clock, in seconds. A replay inside it only repeats the same action for the
// same device.
const sealedProofWindow = 300

type sealedDevice struct {
	id        int64
	deviceKey string
	wakeToken sql.NullString
}

// sealedDeviceByID finds a sealed device. A malformed id is simply not found.
func (s *Server) sealedDeviceByID(ctx context.Context, deviceID string) (*sealedDevice, error) {
	if !reHex32.MatchString(deviceID) {
		return nil, nil
	}
	var d sealedDevice
	err := s.store.DB.QueryRowContext(ctx, "SELECT id, device_key, wake_token FROM sealed_devices WHERE device_id = ?", deviceID).
		Scan(&d.id, &d.deviceKey, &d.wakeToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// sealedProof checks that a request comes from the device that holds the key:
// auth = HMAC-SHA256(device_key, "action:device_id:ts"), keyed with the 64
// character hex string itself, sent as lowercase hex. The action is part of
// the message, so a proof for one endpoint is no use at another.
func (s *Server) sealedProof(d *sealedDevice, action, deviceID string, ts int64, auth string) bool {
	diff := s.now().Unix() - ts
	if diff > sealedProofWindow || diff < -sealedProofWindow {
		return false
	}
	if !reHex64.MatchString(auth) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(d.deviceKey))
	mac.Write([]byte(action + ":" + deviceID + ":" + strconv.FormatInt(ts, 10)))
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(auth))
}

// sealedLogin finds the device of a request and checks its proof for an
// action. It returns the device, or the refusal to send.
func (s *Server) sealedLogin(ctx context.Context, action string, in input) (*sealedDevice, *result) {
	deviceID := in.text("device_id")
	d, err := s.sealedDeviceByID(ctx, deviceID)
	if err != nil {
		log.Printf("carrierpony: sealed/%s: %v", action, err)
		res := serverError()
		return nil, &res
	}
	if d == nil {
		res := fail(http.StatusNotFound, "unknown_device")
		return nil, &res
	}
	if !s.sealedProof(d, action, deviceID, integer(in["ts"]), in.text("auth")) {
		res := fail(http.StatusUnauthorized, "bad_auth")
		return nil, &res
	}
	return d, nil
}

func (s *Server) touchSealedDevice(ctx context.Context, id int64) error {
	_, err := s.store.DB.ExecContext(ctx, "UPDATE sealed_devices SET last_seen = ? WHERE id = ?", s.stamp(), id)
	return err
}

// marks returns n comma-separated placeholders.
func marks(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// sealedRegisterDevice creates a sealed device, or lets its owner change its
// wake token. Creating one needs no proof: the id and key are the device's own
// random values. Changing one needs the proof, so nobody else can.
func (s *Server) sealedRegisterDevice(ctx context.Context, in input) result {
	if name := in.firstMissing("device_id", "device_key"); name != "" {
		return missing(name)
	}
	deviceID, deviceKey := in.text("device_id"), in.text("device_key")
	if !reHex32.MatchString(deviceID) {
		return fail(http.StatusBadRequest, "bad_device_id")
	}
	if !reHex64.MatchString(deviceKey) {
		return fail(http.StatusBadRequest, "bad_device_key")
	}
	var wake any
	if in.has("wake_token") {
		wake = cutBytes(in.text("wake_token"), 64)
	}

	existing, err := s.sealedDeviceByID(ctx, deviceID)
	if err != nil {
		log.Printf("carrierpony: sealed/register-device: %v", err)
		return serverError()
	}
	if existing == nil {
		created, err := s.store.InsertSealedDevice(ctx, deviceID, deviceKey, wake, s.stamp())
		if err != nil {
			log.Printf("carrierpony: sealed/register-device: %v", err)
			return serverError()
		}
		if created {
			return ok(field{"ok", true})
		}
		// Another request registered this id between the lookup and the
		// insert. If it was the same device, with the same key, that is fine.
		existing, err = s.sealedDeviceByID(ctx, deviceID)
		if err != nil || existing == nil {
			log.Printf("carrierpony: sealed/register-device: lost a race and found no row: %v", err)
			return fail(http.StatusInternalServerError, "register_failed")
		}
		if hmac.Equal([]byte(existing.deviceKey), []byte(deviceKey)) {
			return ok(field{"ok", true})
		}
	}
	if !s.sealedProof(existing, "register", deviceID, integer(in["ts"]), in.text("auth")) {
		return fail(http.StatusUnauthorized, "bad_auth")
	}
	if _, err := s.store.DB.ExecContext(ctx, "UPDATE sealed_devices SET wake_token = ?, last_seen = ? WHERE id = ?",
		wake, s.stamp(), existing.id); err != nil {
		log.Printf("carrierpony: sealed/register-device: %v", err)
		return serverError()
	}
	return ok(field{"ok", true})
}

// maxMailboxesPerCall is the most mailboxes one registration may carry.
const maxMailboxesPerCall = 512

// sealedRegisterMailboxes claims mailbox addresses for a device and refreshes
// the expiry of the ones it already owns. A mailbox belongs to the first
// device to claim it and cannot be moved. That stops a group member, who can
// also derive a peer's group address, from taking over that peer's mail.
func (s *Server) sealedRegisterMailboxes(ctx context.Context, in input) result {
	if name := in.firstMissing("device_id", "ts", "auth", "mailboxes"); name != "" {
		return missing(name)
	}
	d, refusal := s.sealedLogin(ctx, "mbx", in)
	if refusal != nil {
		return *refusal
	}
	list, isList := values(in["mailboxes"])
	if !isList || len(list) == 0 {
		return fail(http.StatusBadRequest, "no_mailboxes")
	}
	if len(list) > maxMailboxesPerCall {
		return fail(http.StatusBadRequest, "too_many")
	}
	if err := s.touchSealedDevice(ctx, d.id); err != nil {
		log.Printf("carrierpony: sealed/register-mailboxes: %v", err)
		return serverError()
	}

	// Each entry is a mailbox id, or an object with the id and an expiry.
	// Malformed entries are skipped and a repeated id is counted once, with
	// the expiry of its last appearance.
	now := s.now().Unix()
	longest := now + int64(s.cfg.Limits.MessageTTLMaxDays)*86400
	var order []string
	expires := map[string]string{}
	for _, item := range list {
		var id string
		asked := longest
		switch m := item.(type) {
		case map[string]any:
			id = input(m).text("mailbox")
			if m["expires_at"] != nil {
				asked = integer(m["expires_at"])
			}
		case []any:
			continue
		default:
			id = input{"m": item}.text("m")
		}
		if !reHex64.MatchString(id) {
			continue
		}
		if asked <= now || asked > longest {
			asked = longest
		}
		if _, seen := expires[id]; !seen {
			order = append(order, id)
		}
		expires[id] = stampUnix(asked)
	}
	if len(order) == 0 {
		return ok(field{"ok", true}, field{"registered", 0})
	}

	if err := s.store.ClaimMailboxes(ctx, d.id, order, expires, s.stamp()); err != nil {
		log.Printf("carrierpony: sealed/register-mailboxes: %v", err)
		return serverError()
	}
	// One update per distinct expiry, touching only the rows this device owns.
	byExpiry := map[string][]string{}
	var expiries []string
	for _, id := range order {
		e := expires[id]
		if _, seen := byExpiry[e]; !seen {
			expiries = append(expiries, e)
		}
		byExpiry[e] = append(byExpiry[e], id)
	}
	for _, e := range expiries {
		ids := byExpiry[e]
		args := append([]any{e, d.id}, anySlice(ids)...)
		if _, err := s.store.DB.ExecContext(ctx,
			"UPDATE mailboxes SET expires_at = ? WHERE sealed_device_pk = ? AND mailbox IN ("+marks(len(ids))+")", args...); err != nil {
			log.Printf("carrierpony: sealed/register-mailboxes: %v", err)
			return serverError()
		}
	}
	var owned int
	args := append([]any{d.id}, anySlice(order)...)
	if err := s.store.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM mailboxes WHERE sealed_device_pk = ? AND mailbox IN ("+marks(len(order))+")", args...).Scan(&owned); err != nil {
		log.Printf("carrierpony: sealed/register-mailboxes: %v", err)
		return serverError()
	}
	return ok(field{"ok", true}, field{"registered", owned})
}

func anySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// sealedSend stores an envelope in a mailbox. It takes no login at all: knowing
// the address is the permission. A deposit to an address that is not
// registered answers the same plain ok, so the endpoint cannot be used to find
// out which addresses exist.
func (s *Server) sealedSend(ctx context.Context, in input) result {
	if name := in.firstMissing("mailbox", "envelope"); name != "" {
		return missing(name)
	}
	mailbox := in.text("mailbox")
	if !reHex64.MatchString(mailbox) {
		return fail(http.StatusBadRequest, "bad_mailbox")
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
	now := s.stamp()

	var wake sql.NullString
	err := s.store.DB.QueryRowContext(ctx,
		`SELECT d.wake_token
		 FROM mailboxes m JOIN sealed_devices d ON d.id = m.sealed_device_pk
		 WHERE m.mailbox = ? AND m.expires_at > ?`, mailbox, now).Scan(&wake)
	if errors.Is(err, sql.ErrNoRows) {
		return ok(field{"ok", true})
	}
	if err != nil {
		log.Printf("carrierpony: sealed/send: %v", err)
		return serverError()
	}
	var pending int
	if err := s.store.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sealed_messages WHERE mailbox = ? AND expires_at > ?", mailbox, now).Scan(&pending); err != nil {
		log.Printf("carrierpony: sealed/send: %v", err)
		return serverError()
	}
	if pending >= s.cfg.Limits.SealedPendingCap {
		return ok(field{"ok", true}, field{"throttled", true})
	}

	silent := truthy(in["silent"])
	alert := 1
	if silent {
		alert = 0
	}
	if _, err := s.store.DB.ExecContext(ctx,
		"INSERT INTO sealed_messages (message_id, mailbox, envelope, size_bytes, alert, received_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		randomHex(16), mailbox, envelope, size, alert, now, stampUnix(expires)); err != nil {
		return storeFailed("sealed/send", err)
	}
	if wake.Valid {
		s.gatewayWake(wake.String, silent)
	}
	return ok(field{"ok", true})
}

// sealedInbox returns the messages waiting in every mailbox a device owns.
func (s *Server) sealedInbox(ctx context.Context, in input) result {
	if name := in.firstMissing("device_id", "ts", "auth"); name != "" {
		return missing(name)
	}
	d, refusal := s.sealedLogin(ctx, "inbox", in)
	if refusal != nil {
		return *refusal
	}
	// The app may list messages it keeps failing to open. Leaving them out
	// lets newer ones through; it still asks for them again now and then.
	var skip []any
	if list, isList := values(in["skip"]); isList {
		if len(list) > 200 {
			list = list[:200]
		}
		for _, item := range list {
			if id, isString := item.(string); isString && reHex32.MatchString(id) {
				skip = append(skip, id)
			}
		}
	}
	if err := s.touchSealedDevice(ctx, d.id); err != nil {
		log.Printf("carrierpony: sealed/inbox: %v", err)
		return serverError()
	}
	q := `SELECT s.id, s.size_bytes
		 FROM sealed_messages s
		 JOIN mailboxes m ON m.mailbox = s.mailbox
		 WHERE m.sealed_device_pk = ? AND s.expires_at > ?`
	args := []any{d.id, s.stamp()}
	if len(skip) > 0 {
		q += " AND s.message_id NOT IN (" + marks(len(skip)) + ")"
		args = append(args, skip...)
	}
	q += " ORDER BY s.received_at ASC, s.id ASC LIMIT 200"
	rows, err := s.store.DB.QueryContext(ctx, q, args...)
	if err != nil {
		log.Printf("carrierpony: sealed/inbox: %v", err)
		return serverError()
	}
	waiting, err := scanCandidates(rows)
	if err != nil {
		log.Printf("carrierpony: sealed/inbox: %v", err)
		return serverError()
	}
	ids := pickWithinBudget(waiting, s.cfg.Limits.InboxBytesBudget)

	return result{status: http.StatusOK, stream: func(w io.Writer) error {
		return streamMessages(w, ids, func(id int64) (object, error) {
			var messageID, mailbox, envelope, received, expires string
			var alert int
			err := s.store.DB.QueryRowContext(ctx,
				"SELECT message_id, mailbox, envelope, alert, received_at, expires_at FROM sealed_messages WHERE id = ?", id).
				Scan(&messageID, &mailbox, &envelope, &alert, &received, &expires)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return object{{"message_id", messageID}, {"mailbox", mailbox}, {"envelope", envelope}, {"alert", alert},
				{"received_at", received}, {"expires_at", expires}}, nil
		})
	}}
}

// sealedAck deletes messages a device has taken. A device can only delete from
// mailboxes it owns.
func (s *Server) sealedAck(ctx context.Context, in input) result {
	if name := in.firstMissing("device_id", "ts", "auth", "message_ids"); name != "" {
		return missing(name)
	}
	d, refusal := s.sealedLogin(ctx, "ack", in)
	if refusal != nil {
		return *refusal
	}
	list, isList := values(in["message_ids"])
	if !isList || len(list) == 0 {
		return fail(http.StatusBadRequest, "no_ids")
	}
	var ids []any
	for _, item := range list {
		if id, isString := item.(string); isString && reHex32.MatchString(id) {
			ids = append(ids, id)
		}
	}
	if len(ids) > 200 {
		ids = ids[:200]
	}
	if len(ids) == 0 {
		return ok(field{"ok", true}, field{"deleted", 0})
	}
	args := append(ids, d.id)
	res, err := s.store.DB.ExecContext(ctx,
		"DELETE FROM sealed_messages WHERE message_id IN ("+marks(len(ids))+
			") AND mailbox IN (SELECT mailbox FROM mailboxes WHERE sealed_device_pk = ?)", args...)
	if err != nil {
		log.Printf("carrierpony: sealed/ack: %v", err)
		return serverError()
	}
	deleted, _ := res.RowsAffected()
	return ok(field{"ok", true}, field{"deleted", deleted})
}
