package regiongate

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"

	"golang.org/x/net/websocket"
)

// authRelay is a relay that, like wss://cyberspace.nostr1.com, refuses
// every REQ until the connection answers its AUTH challenge, and caps pages.
func authRelay(t *testing.T, events []nostr.Event, pageCap int) string {
	t.Helper()
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		send := func(v ...interface{}) {
			b, _ := json.Marshal(v)
			_ = websocket.Message.Send(ws, string(b))
		}
		const challenge = "chal-123"
		send("AUTH", challenge)
		authed := false
		for {
			var msg string
			if websocket.Message.Receive(ws, &msg) != nil {
				return
			}
			var arr []json.RawMessage
			_ = json.Unmarshal([]byte(msg), &arr)
			var typ string
			_ = json.Unmarshal(arr[0], &typ)
			switch typ {
			case "AUTH":
				var evt nostr.Event
				_ = json.Unmarshal(arr[1], &evt)
				ok := evt.Kind == 22242 && validation.CheckSignature(evt)
				hasChallenge := false
				for _, tg := range evt.Tags {
					if len(tg) >= 2 && tg[0] == "challenge" && tg[1] == challenge {
						hasChallenge = true
					}
				}
				authed = ok && hasChallenge
				send("OK", evt.ID, authed, "")
			case "REQ":
				var id string
				_ = json.Unmarshal(arr[1], &id)
				if !authed {
					send("CLOSED", id, "auth-required: you must auth")
					continue
				}
				var f map[string]interface{}
				_ = json.Unmarshal(arr[2], &f)
				until, hasUntil := f["until"].(float64)
				var page []nostr.Event
				for _, e := range events {
					if !hasUntil || e.CreatedAt <= int64(until) {
						page = append(page, e)
					}
				}
				sort.Slice(page, func(i, j int) bool { return page[i].CreatedAt > page[j].CreatedAt })
				if len(page) > pageCap {
					page = page[:pageCap]
				}
				for _, e := range page {
					send("EVENT", id, e)
				}
				send("EOSE", id)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func TestRelaySourceAuthsAndPages(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	events := []nostr.Event{b.spawn}
	for i := 1; i <= 34; i++ {
		events = append(events, b.move(ActHop, offset(t, s.pubkey, int64(i))))
	}
	key, err := AuthKey("")
	if err != nil {
		t.Fatal(err)
	}
	src := RelaySource{Relays: []string{authRelay(t, events, 10)}, Timeout: 10 * time.Second, AuthKey: key}
	got, err := src.Movement(context.Background(), s.pubkey, nil, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("fetched %d of %d events through auth + paging", len(got), len(events))
	}
	vd := verifier().Verify(s.pubkey, got)
	if vd.Length != len(events) || vd.PositionEvent != b.last.ID {
		t.Fatalf("fetched chain does not verify to its head: %+v", vd)
	}

	// Without a key the relay's refusal is an error, not an empty chain.
	if _, err := (RelaySource{Relays: src.Relays, Timeout: 5 * time.Second}).Movement(context.Background(), s.pubkey, nil, 10); err == nil {
		t.Fatal("an auth-required refusal must surface as an error")
	}
}

func TestAuthKeyParsing(t *testing.T) {
	if _, err := AuthKey(strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthKey("nope"); err == nil {
		t.Fatal("bad key accepted")
	}
}
