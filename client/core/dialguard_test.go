package core

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"

	"golang.org/x/net/websocket"
)

// The dial guard refuses before any socket is opened, for the URL as given
// and in its normalized form, on every way the client connects.
func TestDialGuardRefusesBeforeDialing(t *testing.T) {
	refused := errors.New("refused")
	SetDialGuard(func(u string) error {
		if strings.HasSuffix(u, "/secret") {
			return refused
		}
		return nil
	})
	t.Cleanup(func() { SetDialGuard(nil) })

	rp := newTestPool(0)
	var dials int32
	rp.dialFn = func(string, time.Duration) (*websocket.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, nil
	}
	for _, u := range []string{"wss://relay.example/secret", "relay.example/secret/", "WSS://Relay.Example/secret", "https://relay.example/secret"} {
		if _, err := rp.Acquire(u); !errors.Is(err, refused) {
			t.Fatalf("Acquire(%q): want the guard's refusal, got %v", u, err)
		}
		if err := rp.EnsureConnectedForSend(u, time.Second); !errors.Is(err, refused) {
			t.Fatalf("EnsureConnectedForSend(%q): %v", u, err)
		}
		if err := rp.Connect(u); !errors.Is(err, refused) {
			t.Fatalf("Connect(%q): %v", u, err)
		}
	}
	if dials != 0 {
		t.Fatalf("%d dials to a refused URL", dials)
	}
	if _, err := rp.Acquire("wss://relay.example"); err != nil || dials != 1 {
		t.Fatalf("an allowed URL: %v, %d dials", err, dials)
	}
}

// The shared pool never answers a NIP-42 challenge: one visitor's AUTH would
// serve their private events to every other visitor.
func TestSendAuthIsRefused(t *testing.T) {
	rp := newTestPool(0)
	rp.messageRouter.RouteAuth("wss://relay.example", "challenge")
	if err := rp.SendAuth("wss://relay.example", &nostr.Event{Kind: 22242}); !errors.Is(err, ErrSharedAuth) {
		t.Fatalf("want ErrSharedAuth, got %v", err)
	}
	for _, st := range rp.AuthRequests() {
		if st.Authed {
			t.Fatal("a relay was marked authed")
		}
	}
}
