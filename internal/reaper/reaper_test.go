package reaper

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/store"
)

func TestRun(t *testing.T) {
	st, err := store.Open(config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) string { return store.Stamp(at.Add(-d)) }
	in := func(d time.Duration) string { return store.Stamp(at.Add(d)) }
	day := 24 * time.Hour
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.DB.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	now := store.Stamp(at)

	exec("INSERT INTO identities (fpr, pubkey, created_at) VALUES ('A', 'k', ?), ('B', 'k', ?)", now, now)
	// Device 1 polled yesterday, device 2 31 days ago, device 3 never.
	exec("INSERT INTO devices (id, fpr, device_id, created_at, last_seen) VALUES (1, 'A', 'd1', ?, ?), (2, 'B', 'd2', ?, ?), (3, 'B', 'd3', ?, NULL)",
		now, ago(day), now, ago(31*day), now)
	// Message 1 is live and unacked, 2 expired a second ago, 3 expires right
	// now, 4 is acked by its only device, 5 is acked by one device of two.
	exec(`INSERT INTO messages (id, message_id, to_fpr, envelope, size_bytes, received_at, expires_at) VALUES
		(1, 'm1', 'A', 'e', 1, ?, ?), (2, 'm2', 'A', 'e', 1, ?, ?), (3, 'm3', 'A', 'e', 1, ?, ?), (4, 'm4', 'A', 'e', 1, ?, ?), (5, 'm5', 'B', 'e', 1, ?, ?)`,
		now, in(day), now, ago(time.Second), now, now, now, in(day), now, in(day))
	exec("INSERT INTO deliveries (message_pk, device_pk, acked_at) VALUES (1, 1, NULL), (2, 1, NULL), (3, 1, NULL), (4, 1, ?), (5, 3, ?), (5, 1, NULL)", now, now)
	exec("INSERT INTO challenges (nonce, fpr, created_at, expires_at) VALUES ('old', 'A', ?, ?), ('edge', 'A', ?, ?), ('live', 'A', ?, ?)",
		now, ago(time.Second), now, now, now, in(time.Second))
	// Sealed device 1 is active, 2 was last seen 61 days ago, 3 exactly 60 days ago.
	exec("INSERT INTO sealed_devices (id, device_id, device_key, created_at, last_seen) VALUES (1, 's1', 'k', ?, ?), (2, 's2', 'k', ?, ?), (3, 's3', 'k', ?, ?)",
		now, now, now, ago(61*day), now, ago(60*day))
	exec(`INSERT INTO mailboxes (mailbox, sealed_device_pk, expires_at, created_at) VALUES
		('live', 1, ?, ?), ('dead', 1, ?, ?), ('held', 1, ?, ?), ('gone-with-device', 2, ?, ?)`,
		in(day), now, ago(time.Second), now, ago(time.Second), now, in(day), now)
	exec(`INSERT INTO sealed_messages (message_id, mailbox, envelope, size_bytes, received_at, expires_at) VALUES
		('s-live', 'held', 'e', 1, ?, ?), ('s-old', 'live', 'e', 1, ?, ?)`, now, in(day), now, ago(time.Second))
	exec(`INSERT INTO pairing_offers (token, offerer_fpr, offerer_pubkey, state, created_at, expires_at, accepted_at) VALUES
		('open-live', 'A', 'k', 'open', ?, ?, NULL), ('open-dead', 'A', 'k', 'open', ?, ?, NULL),
		('acc-recent', 'A', 'k', 'accepted', ?, ?, ?), ('acc-old', 'A', 'k', 'accepted', ?, ?, ?), ('acc-legacy', 'A', 'k', 'accepted', ?, ?, NULL)`,
		now, in(time.Hour), now, ago(time.Second), now, ago(10*day), ago(29*day), now, ago(40*day), ago(31*day), now, ago(31*day))

	limits := config.Default().Limits
	limits.DeviceStaleDays = 30
	counts, err := Run(context.Background(), st, limits, at)
	if err != nil {
		t.Fatal(err)
	}
	want := Counts{ExpiredMessages: 2, AckedMessages: 1, StaleChallenges: 2, StaleDevices: 1, StaleOffers: 3,
		ExpiredSealed: 1, StaleMailboxes: 1, StaleSealedDevices: 1}
	if counts != want {
		t.Errorf("counts\n got %+v\nwant %+v", counts, want)
	}
	left := func(table, column string) map[string]bool {
		rows, err := st.DB.Query("SELECT " + column + " FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var v string
			rows.Scan(&v)
			out[v] = true
		}
		return out
	}
	check := func(what string, got map[string]bool, names ...string) {
		t.Helper()
		if len(got) != len(names) {
			t.Errorf("%s left: %v, want %v", what, got, names)
			return
		}
		for _, n := range names {
			if !got[n] {
				t.Errorf("%s left: %v, want %v", what, got, names)
				return
			}
		}
	}
	check("messages", left("messages", "message_id"), "m1", "m5")
	check("devices", left("devices", "device_id"), "d1", "d3")
	check("identities", left("identities", "fpr"), "A", "B")
	check("challenges", left("challenges", "nonce"), "live")
	check("sealed devices", left("sealed_devices", "device_id"), "s1", "s3")
	check("mailboxes", left("mailboxes", "mailbox"), "live", "held")
	check("sealed messages", left("sealed_messages", "message_id"), "s-live")
	check("offers", left("pairing_offers", "token"), "open-live", "acc-recent")

	again, err := Run(context.Background(), st, limits, at)
	if err != nil || again.Total() != 0 {
		t.Errorf("a second pass removed %d more rows, %v", again.Total(), err)
	}
	if got := want.Line(at); got != "2026-11-17 12:00:00 reaper: expired_messages=2 acked_messages=1 stale_challenges=2 stale_devices=1 "+
		"stale_offers=3 expired_sealed=1 stale_mailboxes=1 stale_sealed_devices=1" {
		t.Errorf("line: %s", got)
	}
}

func TestStaleDevicesAreKeptWhenTheSettingIsOff(t *testing.T) {
	st, err := store.Open(config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	old := store.Stamp(at.Add(-400 * 24 * time.Hour))
	st.DB.Exec("INSERT INTO identities (fpr, pubkey, created_at) VALUES ('A', 'k', ?)", old)
	st.DB.Exec("INSERT INTO devices (fpr, device_id, created_at, last_seen) VALUES ('A', 'd', ?, ?)", old, old)
	st.DB.Exec("INSERT INTO sealed_devices (device_id, device_key, created_at, last_seen) VALUES ('s', 'k', ?, ?)", old, old)
	limits := config.Default().Limits
	limits.SealedDeviceStaleDays = 0
	counts, err := Run(context.Background(), st, limits, at)
	if err != nil || counts.Total() != 0 {
		t.Fatalf("removed %d rows with both settings off, %v", counts.Total(), err)
	}
}

func TestEveryKeepsRunningUntilStopped(t *testing.T) {
	st, err := store.Open(config.Database{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "relay.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	old := store.Stamp(time.Now().Add(-time.Hour))
	st.DB.Exec("INSERT INTO challenges (nonce, fpr, created_at, expires_at) VALUES ('n', 'A', ?, ?)", old, old)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Every(ctx, 20*time.Millisecond, st, config.Default().Limits); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		st.DB.QueryRow("SELECT COUNT(*) FROM challenges").Scan(&n)
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the expired nonce was never removed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Every did not stop when its context ended")
	}
}
