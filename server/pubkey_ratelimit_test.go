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
			waitStored(t, r, evt.ID)
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
	publish(c3, avatar(alice, now-50), false, "rate-limited: avatars are limited to 12 an hour per key; try again in ")

	// Another key is untouched, and alice's other kinds are not limited.
	publish(c3, avatar(bob, now-10), true, "")
	publish(c3, alice.spawn(t), true, "")
}

// Regression (review of #40): copies of one avatar sent at the same moment on
// many connections all passed the duplicate check (nostrdb indexes after the
// OK), each spent a token, and the author's next avatars were refused. Now
// exactly one copy is taken, the rest are told it is a duplicate or already
// being processed, and the author keeps the rest of the burst.
func TestAvatarFanOutCannotSpendItsAuthorsBudget(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	owner := newKey(t)
	now := time.Now().Unix()
	evt := owner.signAt(t, now-100, 11333, `{"v":1}`)

	const copies = 8
	conns := make([]*conn, copies)
	for i := range conns {
		conns[i] = mustDial(t, r.wsRoot)
	}
	type answer struct {
		ok  bool
		msg string
	}
	answers := make(chan answer, copies)
	start := make(chan struct{})
	for _, c := range conns {
		c := c
		go func() {
			<-start
			c.send("EVENT", evt)
			m := c.next(5 * time.Second)
			for m != nil && !(len(m) >= 4 && m[0] == "OK" && m[1] == evt.ID) {
				m = c.next(5 * time.Second)
			}
			if m == nil {
				answers <- answer{false, "no OK"}
				return
			}
			ok, _ := m[2].(bool)
			msg, _ := m[3].(string)
			answers <- answer{ok, msg}
		}()
	}
	close(start)
	accepted := 0
	for i := 0; i < copies; i++ {
		a := <-answers
		switch {
		case a.ok:
			accepted++
		case !strings.HasPrefix(a.msg, "duplicate:") && !strings.HasPrefix(a.msg, "error: this event is already being processed"):
			t.Fatalf("a copy was refused as %q, want duplicate: or the in-flight error", a.msg)
		}
	}
	if accepted != 1 {
		t.Fatalf("%d of %d simultaneous copies were accepted, want 1", accepted, copies)
	}

	// One token spent: the owner still has 5 of the burst of 6.
	c := mustDial(t, r.wsRoot)
	for i := 1; i <= 5; i++ {
		if ok, msg := c.publish(owner.signAt(t, now-100+int64(i), 11333, `{"v":1}`)); !ok {
			t.Fatalf("the owner's avatar %d after the fan-out was refused: %s", i, msg)
		}
	}
	if ok, msg := c.publish(owner.signAt(t, now-50, 11333, `{"v":1}`)); ok || !strings.HasPrefix(msg, "rate-limited:") {
		t.Fatalf("the 7th avatar: %v %q", ok, msg)
	}
}

// Regression (review of #40): a key signed valid avatars under upper- and
// mixed-case spellings of its pubkey, each a fresh budget, and nostrdb then
// dropped them after deleting the stored avatar. Now any spelling but lower
// case is refused before the signature check, and the stored avatar stays.
func TestAvatarPubkeyCaseCannotDodgeTheLimit(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	var k key
	for k.pub == "" || !letters(k, 2) {
		k = newKey(t)
	}
	now := time.Now().Unix()
	c := mustDial(t, r.wsRoot)
	var last nostr.Event
	for i := 0; i < 6; i++ {
		last = k.signAt(t, now-100+int64(i), 11333, `{"v":1}`)
		if ok, msg := c.publish(last); !ok {
			t.Fatalf("avatar %d: %s", i+1, msg)
		}
		// Each indexed before the next: the replaceable check reads
		// nostrdb, so back-to-back versions can all stay stored (an older
		// grain race this test does not cover).
		waitStored(t, r, last.ID)
	}

	for _, spelling := range []string{strings.ToUpper(k.pub), strings.ToUpper(k.pub[:1]) + k.pub[1:]} {
		other := k
		other.pub = spelling
		evt := other.signAt(t, now-10, 11333, `{"v":2}`)
		if ok, msg := c.publish(evt); ok || !strings.HasPrefix(msg, "invalid: pubkey must be 64 lower-case hex") {
			t.Fatalf("pubkey spelled %s...: %v %q", spelling[:4], ok, msg)
		}
	}
	got, err := r.db.Query([]nostr.Filter{{Authors: []string{k.pub}, Kinds: []int{11333}}}, 5)
	if err != nil || len(got) != 1 || got[0].ID != last.ID {
		t.Fatalf("the stored avatar after the case attempts: %v %v", got, err)
	}
}

// Speakeasy events skip the per-author limit (review of #40): they never
// leave the speakeasy, and the same avatar sent to the root and to a
// speakeasy must not cost twice.
func TestSpeakeasyAvatarsSkipThePerAuthorLimit(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	var k key
	for k.pub == "" || !letters(k, 1) {
		k = newKey(t)
	}
	id := k.pub[:1]
	r.register(t, id)
	r.storeRoot(t, k.spawn(t))
	url := r.wsRoot + "/C/" + id
	c := mustDial(t, url)
	if ok, msg := c.auth(k, url, c.challenge); !ok {
		t.Fatalf("speakeasy AUTH: %s", msg)
	}
	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		if ok, msg := c.publish(k.signAt(t, now-100+int64(i), 11333, `{"v":1}`)); !ok {
			t.Fatalf("speakeasy avatar %d refused: %s", i+1, msg)
		}
	}
	// The root still has the whole burst.
	root := mustDial(t, r.wsRoot)
	for i := 0; i < 6; i++ {
		if ok, msg := root.publish(k.signAt(t, now-80+int64(i), 11333, `{"v":1}`)); !ok {
			t.Fatalf("root avatar %d after the speakeasy ones: %s", i+1, msg)
		}
	}
}

// waitStored waits for nostrdb's writer, which indexes after the OK.
func waitStored(t *testing.T, r *relayUnderTest, id string) {
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

// An ephemeral event is not kept, so a resend is not a duplicate: it is
// accepted and broadcast again (review of #40; the in-flight table releases
// kinds the store does not keep).
func TestEphemeralResendIsNotADuplicate(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	k := newKey(t)
	evt := k.sign(t, 23330, "hi")
	c := mustDial(t, r.wsRoot)
	for i := 0; i < 2; i++ {
		if ok, msg := c.publish(evt); !ok {
			t.Fatalf("ephemeral send %d refused: %q", i+1, msg)
		}
	}
}
