package handlers

import (
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
)

const (
	recipientPK = "1111111111111111111111111111111111111111111111111111111111111111"
	strangerPK  = "2222222222222222222222222222222222222222222222222222222222222222"
)

func giftWrap(recipient string) nostr.Event {
	return nostr.Event{Kind: 1059, Tags: [][]string{{"p", recipient}}}
}

func TestCanServeProtectedEvent(t *testing.T) {
	wrap := giftWrap(recipientPK)

	// Non-protected events are always servable, even unauthenticated.
	if !CanServeProtectedEvent(nostr.Event{Kind: 1}, "") {
		t.Error("non-protected kind should be servable unauthenticated")
	}
	// Gift wrap: unauthenticated callers get nothing.
	if CanServeProtectedEvent(wrap, "") {
		t.Error("gift wrap must not be served to an unauthenticated client")
	}
	// Gift wrap: a stranger (authed as someone else) gets nothing.
	if CanServeProtectedEvent(wrap, strangerPK) {
		t.Error("gift wrap must not be served to a non-recipient")
	}
	// Gift wrap: the p-tagged recipient gets it.
	if !CanServeProtectedEvent(wrap, recipientPK) {
		t.Error("gift wrap must be served to its p-tagged recipient")
	}
}

func TestFilterRequestsProtectedKind(t *testing.T) {
	if !FilterRequestsProtectedKind(nostr.Filter{Kinds: []int{1, 1059}}) {
		t.Error("filter listing 1059 should be flagged")
	}
	if FilterRequestsProtectedKind(nostr.Filter{Kinds: []int{1, 7}}) {
		t.Error("filter without protected kinds should not be flagged")
	}
	// A no-kinds filter doesn't *explicitly* request a protected kind — the
	// post-query gate handles silent omission for broad filters.
	if FilterRequestsProtectedKind(nostr.Filter{}) {
		t.Error("empty-kinds filter should not be flagged as explicitly requesting")
	}
}

func TestPrivateFilters(t *testing.T) {
	// Unauthenticated: the protected part of a filter with kinds is dropped,
	// its open kinds stay; a kindless filter is gated.
	exact, gated := PrivateFilters([]nostr.Filter{
		{Kinds: []int{1059}},
		{Kinds: []int{7, 1059}, Tags: map[string][]string{}},
		{Kinds: []int{7}},
		{Authors: []string{strangerPK}},
	}, "")
	if len(exact) != 2 || exact[0].Kinds[0] != 7 || len(exact[0].Kinds) != 1 || exact[1].Kinds[0] != 7 {
		t.Fatalf("unauthenticated exact = %+v", exact)
	}
	if len(gated) != 1 || len(gated[0].Authors) != 1 {
		t.Fatalf("unauthenticated gated = %+v", gated)
	}

	// Authenticated: the protected part is narrowed to the caller's p tag,
	// and the caller's filter is not changed in place.
	orig := nostr.Filter{Kinds: []int{1059}, Tags: map[string][]string{"p": {strangerPK, recipientPK}}}
	exact, _ = PrivateFilters([]nostr.Filter{orig}, recipientPK)
	if len(exact) != 1 || len(exact[0].Tags["p"]) != 1 || exact[0].Tags["p"][0] != recipientPK {
		t.Fatalf("authed exact = %+v", exact)
	}
	if len(orig.Tags["p"]) != 2 {
		t.Fatal("PrivateFilters changed the caller's filter")
	}
	// A #p that leaves the caller out matches none of their gift wraps.
	exact, _ = PrivateFilters([]nostr.Filter{{Kinds: []int{1059}, Tags: map[string][]string{"p": {strangerPK}}}}, recipientPK)
	if len(exact) != 0 {
		t.Fatalf("a #p naming only someone else kept a protected filter: %+v", exact)
	}
}

// fakeCounter counts a fixed set of events with Filter.MatchesEvent.
func fakeCounter(evts []nostr.Event) func([]nostr.Filter) (int, bool, error) {
	return func(fs []nostr.Filter) (int, bool, error) {
		n := 0
		for _, e := range evts {
			if fs[0].MatchesEvent(e) {
				n++
			}
		}
		return n, false, nil
	}
}

func TestCountPrivately(t *testing.T) {
	note := func(kind int, p string) nostr.Event {
		return nostr.Event{Kind: kind, Tags: [][]string{{"p", p}}}
	}
	evts := []nostr.Event{
		note(1059, recipientPK), note(1059, recipientPK), note(1059, strangerPK),
		note(7, strangerPK), note(7, recipientPK),
	}
	count := fakeCounter(evts)
	cases := []struct {
		name   string
		f      nostr.Filter
		authed string
		want   int
	}{
		{"kindless, unauthenticated: open only", nostr.Filter{}, "", 2},
		{"kindless, recipient: open plus own", nostr.Filter{}, recipientPK, 4},
		{"kindless #p stranger, recipient: their reaction, not their wrap", nostr.Filter{Tags: map[string][]string{"p": {strangerPK}}}, recipientPK, 1},
		{"1059, stranger: own only", nostr.Filter{Kinds: []int{1059}}, strangerPK, 1},
		{"1059 #p recipient, stranger: none", nostr.Filter{Kinds: []int{1059}, Tags: map[string][]string{"p": {recipientPK}}}, strangerPK, 0},
		{"7+1059, recipient", nostr.Filter{Kinds: []int{7, 1059}}, recipientPK, 4},
	}
	for _, c := range cases {
		got, _, err := CountPrivately(count, []nostr.Filter{c.f}, c.authed)
		if err != nil || got != c.want {
			t.Errorf("%s: got %d (%v), want %d", c.name, got, err, c.want)
		}
	}
}
