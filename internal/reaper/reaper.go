// Package reaper removes what the relay no longer needs to keep: expired and
// delivered messages, spent logins, lapsed mailboxes and offers, and devices
// that stopped coming back.
package reaper

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/store"
)

// Counts is how many rows one run removed, by kind.
type Counts struct {
	ExpiredMessages    int64
	AckedMessages      int64
	StaleChallenges    int64
	StaleDevices       int64
	StaleOffers        int64
	ExpiredSealed      int64
	StaleMailboxes     int64
	StaleSealedDevices int64
}

// Total is the number of rows removed.
func (c Counts) Total() int64 {
	return c.ExpiredMessages + c.AckedMessages + c.StaleChallenges + c.StaleDevices +
		c.StaleOffers + c.ExpiredSealed + c.StaleMailboxes + c.StaleSealedDevices
}

// Line is the one-line report of a run, in the format the PHP reaper printed.
func (c Counts) Line(at time.Time) string {
	return fmt.Sprintf("%s reaper: expired_messages=%d acked_messages=%d stale_challenges=%d stale_devices=%d "+
		"stale_offers=%d expired_sealed=%d stale_mailboxes=%d stale_sealed_devices=%d",
		store.Stamp(at), c.ExpiredMessages, c.AckedMessages, c.StaleChallenges, c.StaleDevices,
		c.StaleOffers, c.ExpiredSealed, c.StaleMailboxes, c.StaleSealedDevices)
}

// Run does one pass at the given time. It stops at the first statement that
// fails and returns what it had removed until then.
func Run(ctx context.Context, st *store.Store, limits config.Limits, at time.Time) (Counts, error) {
	var c Counts
	now := store.Stamp(at)
	daysAgo := func(days int) string { return store.Stamp(at.Add(-time.Duration(days) * 24 * time.Hour)) }
	del := func(into *int64, query string, args ...any) error {
		res, err := st.DB.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		*into = n
		return err
	}

	// Devices that stopped checking in would otherwise hold their copy of
	// every message until it expires. Off unless device_stale_days is set.
	if limits.DeviceStaleDays > 0 {
		if err := del(&c.StaleDevices,
			"DELETE FROM devices WHERE last_seen IS NOT NULL AND last_seen < ?", daysAgo(limits.DeviceStaleDays)); err != nil {
			return c, err
		}
	}
	if err := del(&c.ExpiredMessages, "DELETE FROM messages WHERE expires_at <= ?", now); err != nil {
		return c, err
	}
	if err := del(&c.AckedMessages,
		`DELETE FROM messages
		 WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.message_pk = messages.id AND d.acked_at IS NULL)`); err != nil {
		return c, err
	}
	if err := del(&c.StaleChallenges, "DELETE FROM challenges WHERE expires_at <= ?", now); err != nil {
		return c, err
	}
	if err := del(&c.ExpiredSealed, "DELETE FROM sealed_messages WHERE expires_at <= ?", now); err != nil {
		return c, err
	}
	// A mailbox past its expiry stays while it still holds a message, so a
	// live message is never cut off from the device that can collect it.
	if err := del(&c.StaleMailboxes,
		`DELETE FROM mailboxes
		 WHERE expires_at <= ?
		   AND NOT EXISTS (SELECT 1 FROM sealed_messages s WHERE s.mailbox = mailboxes.mailbox)`, now); err != nil {
		return c, err
	}
	// Sealed devices are anonymous and nothing else ever removes them. The
	// default of 60 days is twice the longest a message lives, so removing a
	// device, and its mailboxes with it, cannot cut off a live message.
	if limits.SealedDeviceStaleDays > 0 {
		if err := del(&c.StaleSealedDevices,
			"DELETE FROM sealed_devices WHERE last_seen IS NOT NULL AND last_seen < ?", daysAgo(limits.SealedDeviceStaleDays)); err != nil {
			return c, err
		}
	}
	// An open offer dies at its expiry. An accepted one is kept longer, so an
	// offerer whose app was closed when the other side accepted can still
	// collect the pairing. Offers accepted before accepted_at existed fall
	// back to their expiry.
	keep := limits.PairAcceptedKeepDays
	if keep < 1 {
		keep = 1
	}
	if err := del(&c.StaleOffers,
		`DELETE FROM pairing_offers
		 WHERE (state = 'open' AND expires_at <= ?)
		    OR (state = 'accepted' AND COALESCE(accepted_at, expires_at) < ?)`, now, daysAgo(keep)); err != nil {
		return c, err
	}
	return c, nil
}

// Every runs a pass at each interval until the context ends. A pass that
// removed something, or failed, is logged.
func Every(ctx context.Context, interval time.Duration, st *store.Store, limits config.Limits) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			passCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			counts, err := Run(passCtx, st, limits, at)
			cancel()
			if err != nil {
				log.Printf("carrierpony: reaper: %v", err)
			}
			if counts.Total() > 0 {
				log.Print(counts.Line(at))
			}
		}
	}
}
