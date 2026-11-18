package api

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/push"
)

// maxPushBatches bounds how many sends are pushing to their recipients at
// once. Past it a push is dropped, and the message waits for the next poll.
const maxPushBatches = 64

type pushTarget struct {
	device   int64
	token    string
	platform string
	apnsEnv  string
}

// pushLocally pushes to the recipient's devices with this relay's own APNs and
// FCM credentials, when it has any. It reads the tokens now and does the
// network calls after the sender has their answer. Tokens a platform reports
// dead are cleared so they do not pile up.
func (s *Server) pushLocally(ctx context.Context, devices []int64, silent bool, kind string) {
	if len(devices) == 0 || (s.apns == nil && s.fcm == nil) {
		return
	}
	args := make([]any, len(devices))
	for i, d := range devices {
		args[i] = d
	}
	rows, err := s.store.DB.QueryContext(ctx,
		"SELECT id, push_token, platform, apns_env FROM devices WHERE id IN ("+marks(len(devices))+
			") AND push_token IS NOT NULL AND push_token <> ''", args...)
	if err != nil {
		log.Printf("carrierpony: push: %v", err)
		return
	}
	var targets []pushTarget
	for rows.Next() {
		var t pushTarget
		var platform, env sql.NullString
		if err := rows.Scan(&t.device, &t.token, &platform, &env); err != nil {
			rows.Close()
			log.Printf("carrierpony: push: %v", err)
			return
		}
		t.platform, t.apnsEnv = platform.String, env.String
		targets = append(targets, t)
	}
	rows.Close()
	if len(targets) == 0 {
		return
	}
	select {
	case s.pushes <- struct{}{}:
	default:
		log.Printf("carrierpony: push dropped, %d batches already in flight", maxPushBatches)
		return
	}
	shape := push.ShapeFor(silent, kind)
	go func() {
		defer func() { <-s.pushes }()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, t := range targets {
			dead := false
			if t.platform == "fcm" {
				if s.fcm == nil {
					continue
				}
				_, dead = s.fcm.Send(ctx, t.token, shape)
			} else {
				if s.apns == nil {
					continue
				}
				d := s.apns.Deliver(ctx, t.token, shape, t.apnsEnv)
				dead = d.Dead
				if d.Delivered && d.Environment != t.apnsEnv {
					if _, err := s.store.DB.ExecContext(ctx, "UPDATE devices SET apns_env = ? WHERE id = ?", d.Environment, t.device); err != nil {
						log.Printf("carrierpony: push: %v", err)
					}
				}
			}
			if dead {
				// Only clear the token that was just refused. The device may
				// have registered a new one while this push was in flight.
				if _, err := s.store.DB.ExecContext(ctx,
					"UPDATE devices SET push_token = NULL WHERE id = ? AND push_token = ?", t.device, t.token); err != nil {
					log.Printf("carrierpony: push: %v", err)
				}
			}
		}
	}()
}
