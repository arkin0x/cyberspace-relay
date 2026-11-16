package server

import (
	"strings"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// The per-author avatar limit (owner, 2026-11-16) on the EVENT path, with
// the real onosendai profile (pubkey_kind_limits: 11333, 12 an hour, burst
// 6), real nostrdb and real websockets. Only events signed by the key and
// stored count: forged events, duplicates and a replayed older avatar cost
// nothing. The 7th avatar from one key is refused, on a new connection too;
// another key and other kinds pass.
func TestOnosendaiAvatarPerAuthorLimit(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	alice, bob := newKey(t), newKey(t)
	now := time.Now().Unix()

	// stored waits for nostrdb's writer, which indexes after the OK.
	stored := func(id string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got, _ := r.db.Query([]nostr.Filter{{IDs: []string{id}}}, 1); len(got) == 1 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("event %s was never stored", id)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	avatar := func(k key, at int64) nostr.Event {
		return k.signAt(t, at, 11333, `{"v":1}`, []string{"name", "shape"})
	}
	publish := func(c *conn, evt nostr.Event, wantOK bool, wantPrefix string) {
		t.Helper()
		ok, msg := c.publish(evt)
		if ok != wantOK || !strings.HasPrefix(msg, wantPrefix) {
			t.Fatalf("event at %d: got %v %q, want %v %q...", evt.CreatedAt, ok, msg, wantOK, wantPrefix)
		}
		if ok {
			stored(evt.ID)
		}
	}

	c := mustDial(t, r.wsRoot)
	// Forged: alice's pubkey, a bad signature. Refused before the limit.
	for i := 0; i < 8; i++ {
		forged := avatar(alice, now-500+int64(i))
		forged.Sig = strings.Repeat("0", 128)
		publish(c, forged, false, "invalid: signature")
	}
	var last nostr.Event
	for i := 0; i < 3; i++ {
		last = avatar(alice, now-100+int64(i))
		publish(c, last, true, "")
	}
	// A duplicate and a replayed older avatar are refused for what they are
	// and give their tokens back.
	publish(c, last, false, "duplicate:")
	publish(c, avatar(alice, now-1000), false, "blocked:")

	c2 := mustDial(t, r.wsRoot)
	for i := 3; i < 6; i++ {
		last = avatar(alice, now-100+int64(i))
		publish(c2, last, true, "")
	}
	// The 7th, on a third connection: the limit is per key, not per socket.
	c3 := mustDial(t, r.wsRoot)
	publish(c3, avatar(alice, now-50), false, "rate-limited: at most 12 avatars an hour per key; try again in ")

	// Another key is untouched, and alice's other kinds are not limited.
	publish(c3, avatar(bob, now-10), true, "")
	publish(c3, alice.spawn(t), true, "")
}
