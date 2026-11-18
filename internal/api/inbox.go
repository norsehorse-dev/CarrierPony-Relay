package api

import (
	"context"
	"database/sql"
	"io"
	"log"
	"net/http"
)

// candidate is a waiting message: its row and the size of its envelope.
type candidate struct {
	id   int64
	size int64
}

// pickWithinBudget chooses which waiting messages one poll returns: oldest
// first, up to the byte budget. A message over the budget still goes out, but
// alone, and smaller ones behind a message that does not fit are not held back
// by it. The rest stay queued for the next poll.
func pickWithinBudget(waiting []candidate, budget int64) []int64 {
	var pick []int64
	var total int64
	for _, c := range waiting {
		if len(pick) > 0 && total+c.size > budget {
			continue
		}
		pick = append(pick, c.id)
		total += c.size
		if total >= budget {
			break
		}
	}
	return pick
}

func scanCandidates(rows *sql.Rows) ([]candidate, error) {
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.size); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// streamMessages writes {"messages":[...]} one row at a time, so the relay
// holds one envelope in memory however much is waiting. fetch returns the
// fields of one message, or nil if it is gone.
func streamMessages(w io.Writer, ids []int64, fetch func(id int64) (object, error)) error {
	if _, err := io.WriteString(w, `{"messages":[`); err != nil {
		return err
	}
	first := true
	for _, id := range ids {
		msg, err := fetch(id)
		if err != nil {
			return err
		}
		if msg == nil {
			continue
		}
		body, err := msg.MarshalJSON()
		if err != nil {
			return err
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]}")
	return err
}

// inbox returns the messages waiting for one device. They stay until acked.
func (s *Server) inbox(ctx context.Context, fpr string, in input) result {
	if name := in.firstMissing("device_id"); name != "" {
		return missing(name)
	}
	deviceID := in.text("device_id")
	if !reHex32.MatchString(deviceID) {
		return fail(http.StatusBadRequest, "bad_device_id")
	}
	device, found, err := s.deviceOf(ctx, fpr, deviceID)
	if err != nil {
		log.Printf("carrierpony: inbox: %v", err)
		return serverError()
	}
	if !found {
		return fail(http.StatusForbidden, "unknown_device")
	}
	now := s.stamp()
	if _, err := s.store.DB.ExecContext(ctx, "UPDATE devices SET last_seen = ? WHERE id = ?", now, device); err != nil {
		log.Printf("carrierpony: inbox: %v", err)
		return serverError()
	}
	rows, err := s.store.DB.QueryContext(ctx,
		`SELECT m.id, m.size_bytes
		 FROM deliveries d
		 JOIN messages m ON m.id = d.message_pk
		 WHERE d.device_pk = ? AND d.acked_at IS NULL AND m.expires_at > ?
		 ORDER BY m.received_at ASC, m.id ASC
		 LIMIT 200`, device, now)
	if err != nil {
		log.Printf("carrierpony: inbox: %v", err)
		return serverError()
	}
	waiting, err := scanCandidates(rows)
	if err != nil {
		log.Printf("carrierpony: inbox: %v", err)
		return serverError()
	}
	ids := pickWithinBudget(waiting, s.cfg.Limits.InboxBytesBudget)

	return result{status: http.StatusOK, stream: func(w io.Writer) error {
		return streamMessages(w, ids, func(id int64) (object, error) {
			var messageID, envelope, received, expires string
			var alert int
			err := s.store.DB.QueryRowContext(ctx,
				"SELECT message_id, envelope, alert, received_at, expires_at FROM messages WHERE id = ?", id).
				Scan(&messageID, &envelope, &alert, &received, &expires)
			if err == sql.ErrNoRows {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return object{{"message_id", messageID}, {"envelope", envelope}, {"alert", alert},
				{"received_at", received}, {"expires_at", expires}}, nil
		})
	}}
}
