package api

import (
	"context"
	"log"
	"net/http"
)

// ack marks messages as delivered to one device. A message is deleted once
// every device it was stored for has acked it.
func (s *Server) ack(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("device_id", "message_ids"); name != "" {
		return missing(name)
	}
	deviceID := in.text("device_id")
	if !reHex32.MatchString(deviceID) {
		return fail(http.StatusBadRequest, "bad_device_id")
	}
	ids, isList := values(in["message_ids"])
	if !isList {
		return fail(http.StatusBadRequest, "bad_message_ids")
	}
	device, found, err := s.deviceOf(ctx, fpr, deviceID)
	if err != nil {
		log.Printf("carrierpony: ack: %v", err)
		return serverError()
	}
	if !found {
		return fail(http.StatusForbidden, "unknown_device")
	}

	now := s.stamp()
	var acked int64
	for _, item := range ids {
		id, isString := item.(string)
		if !isString || !reHex32.MatchString(id) {
			continue
		}
		res, err := s.store.DB.ExecContext(ctx,
			`UPDATE deliveries SET acked_at = ?
			 WHERE device_pk = ? AND acked_at IS NULL
			   AND message_pk IN (SELECT id FROM messages WHERE message_id = ?)`, now, device, id)
		if err != nil {
			log.Printf("carrierpony: ack: %v", err)
			return serverError()
		}
		n, _ := res.RowsAffected()
		acked += n
	}

	if err := s.deleteFinishedMessages(ctx, now); err != nil {
		log.Printf("carrierpony: ack: %v", err)
		return serverError()
	}
	return ok(field{"acked", acked})
}

// deleteFinishedMessages removes messages no device is still waiting for, and
// messages past their expiry.
func (s *Server) deleteFinishedMessages(ctx context.Context, now string) error {
	if _, err := s.store.DB.ExecContext(ctx,
		`DELETE FROM messages
		 WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.message_pk = messages.id AND d.acked_at IS NULL)`); err != nil {
		return err
	}
	_, err := s.store.DB.ExecContext(ctx, "DELETE FROM messages WHERE expires_at <= ?", now)
	return err
}
