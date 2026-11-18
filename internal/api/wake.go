package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// maxWakesInFlight bounds how many gateway calls run at once. A wake past the
// limit is dropped: it is only a nudge, and the device still gets its message
// on the next poll.
const maxWakesInFlight = 64

// notify wakes the recipient's devices after a message is stored: through the
// push gateway for devices that opted in to it, and with this relay's own APNs
// and FCM credentials for devices that registered a push token here.
func (s *Server) notify(ctx context.Context, devices []int64, silent bool, kind string) {
	s.wakeThroughGateway(ctx, devices, silent)
	s.pushLocally(ctx, devices, silent, kind)
}

// wakeThroughGateway nudges the push gateway for each of the devices that has a
// wake token. It runs even on a relay with no push credentials of its own,
// which is the whole point for a self-hosted one.
func (s *Server) wakeThroughGateway(ctx context.Context, devices []int64, silent bool) {
	if len(devices) == 0 || s.cfg.PushGateway.URL == "" {
		return
	}
	args := make([]any, len(devices))
	for i, d := range devices {
		args[i] = d
	}
	rows, err := s.store.DB.QueryContext(ctx,
		"SELECT wake_token FROM devices WHERE id IN ("+marks(len(devices))+") AND wake_token IS NOT NULL AND wake_token <> ''", args...)
	if err != nil {
		log.Printf("carrierpony: wake: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			log.Printf("carrierpony: wake: %v", err)
			return
		}
		s.gatewayWake(token, silent)
	}
}

// gatewayWake asks the push gateway to nudge one device. The gateway gets the
// opaque token and whether the wake is silent, never a sender or any content.
// It runs after the answer to the sender is on its way and its failure changes
// nothing: a gateway that is down must not fail or slow a delivery.
func (s *Server) gatewayWake(token string, silent bool) {
	if token == "" || s.cfg.PushGateway.URL == "" {
		return
	}
	select {
	case s.wakes <- struct{}{}:
	default:
		log.Printf("carrierpony: wake dropped, %d already in flight", maxWakesInFlight)
		return
	}
	endpoint := strings.TrimRight(s.cfg.PushGateway.URL, "/") + "/v1/wake"
	payload, _ := json.Marshal(object{{"wake_token", token}, {"silent", silent}})
	go func() {
		defer func() { <-s.wakes }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := s.http.Do(req)
		if err != nil {
			return
		}
		res.Body.Close()
	}()
}
