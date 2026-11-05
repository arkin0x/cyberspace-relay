package handlers

import (
	"context"
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
)

// An event the relay already stores never reaches the admission gate: the
// duplicate check comes first, so re-sending a stored event costs no chain
// lookup and no proof check. A new event does reach it, and its refusal is
// the answer.
func TestDuplicateCheckRunsBeforeTheGate(t *testing.T) {
	evt := nostr.Event{ID: "ab", PubKey: "cd", Kind: 3333}
	var gated int
	gate := func(context.Context, nostr.Event) (bool, string) {
		gated++
		return false, "restricted: outside"
	}
	stored := func(nostr.Event) (bool, error) { return true, nil }
	fresh := func(nostr.Event) (bool, error) { return false, nil }

	ok, msg, notice := admitNew(evt, stored, gate)
	if ok || msg != "duplicate: already have this event" || notice == "" || gated != 0 {
		t.Fatalf("a stored event: got %v %q %q, gate asked %d times", ok, msg, notice, gated)
	}
	ok, msg, _ = admitNew(evt, fresh, gate)
	if ok || msg != "restricted: outside" || gated != 1 {
		t.Fatalf("a new event: got %v %q, gate asked %d times", ok, msg, gated)
	}
	if ok, _, _ := admitNew(evt, fresh, nil); !ok {
		t.Fatal("no gate: a new event is admitted")
	}
}
