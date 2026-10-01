package regiongate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAdmitPubkeyForReaders(t *testing.T) {
	ctx := context.Background()
	member := newSigner(t)
	box := cubeAround(t, member.pubkey, 40)
	src := &fakeSource{events: []nostr.Event{newChain(t, member).spawn}}
	g := gateFor(t, ModeStructural, box, src)

	if ok, msg := g.AdmitPubkey(ctx, member.pubkey); !ok {
		t.Fatalf("member refused as reader: %s", msg)
	}
	if ok, _ := g.AdmitPubkey(ctx, newSigner(t).pubkey); ok {
		t.Fatal("a pubkey with no chain was admitted as reader")
	}
	op := newSigner(t)
	if ok, _ := gateFor(t, ModeStructural, box, src, op.pubkey).AdmitPubkey(ctx, op.pubkey); !ok {
		t.Fatal("exempt pubkey refused as reader")
	}
}

func TestLiveAllowedNeverBlocksAndFollowsMoves(t *testing.T) {
	member := newSigner(t)
	box := cubeAround(t, member.pubkey, 40)
	b := newChain(t, member)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g := gateFor(t, ModeStructural, box, src)

	if g.LiveAllowed("") {
		t.Fatal("an unauthenticated connection must get no live events")
	}
	// Unknown pubkey: nothing yet, a background lookup admits it.
	if g.LiveAllowed(member.pubkey) {
		t.Fatal("an unknown pubkey must not get live events before its lookup")
	}
	waitFor(t, func() bool { return g.LiveAllowed(member.pubkey) })

	// The member leaves the region (published elsewhere). Until the
	// verdict expires it still reads; after, the refresh cuts it off.
	src.mu.Lock()
	src.events = append(src.events, b.move(ActHop, offset(t, box.Base.Hex(), 1<<41)))
	src.mu.Unlock()
	if !g.LiveAllowed(member.pubkey) {
		t.Fatal("a fresh admitted verdict must hold until it expires")
	}
	now := time.Now().Add(601 * time.Second)
	g.mu.Lock()
	g.now = func() time.Time { return now }
	g.mu.Unlock()
	if !g.LiveAllowed(member.pubkey) {
		t.Fatal("an expired verdict keeps answering while it is refreshed")
	}
	waitFor(t, func() bool { return !g.LiveAllowed(member.pubkey) })
}

func TestSpeakeasyHTTPGuard(t *testing.T) {
	// Only the websocket, NIP-11 and NIP-86 reach the relay, and only at "/".
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	guard := SpeakeasyGuard(inner)
	cases := []struct {
		method, path string
		headers      map[string]string
		pass         bool
	}{
		{"GET", "/", map[string]string{"Upgrade": "websocket"}, true},
		{"GET", "/", map[string]string{"Accept": "application/nostr+json"}, true},
		{"POST", "/", map[string]string{"Content-Type": "application/nostr+json+rpc"}, true},
		{"GET", "/", nil, false},                    // the web client
		{"GET", "/api/v1/events/query", nil, false}, // events through the server pool
		{"GET", "/api/v1/relay/stats", nil, false},  // counts by kind
		{"GET", "/api/v1/events/abc", map[string]string{"Upgrade": "websocket"}, false},
		{"POST", "/api/v1/client/auth", nil, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		if (w.Code == 299) != c.pass {
			t.Errorf("%s %s %v: passed=%v want %v", c.method, c.path, c.headers, w.Code == 299, c.pass)
		}
	}
}
