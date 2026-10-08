package regiongate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// The gate judges a chain only when it holds all of it. Relays answer newest
// first, so a capped or broken-off answer drops the events right after the
// spawn, and a chain missing them resolves to a wrong position. Such a lookup
// is refused with "try again" and not cached.

// cappedGate is a structural gate over src whose sources return at most max
// events per question.
func cappedGate(t *testing.T, box Box, src Source, max int) *Gate {
	t.Helper()
	g := gateFor(t, ModeStructural, box, src)
	g.cfg.MaxChainEvents = max
	return g
}

// expectRefusedUncached asserts the gate refuses with reason and keeps no
// verdict, so the next lookup asks again.
func expectRefusedUncached(t *testing.T, g *Gate, evt nostr.Event, reason string) {
	t.Helper()
	if ok, msg := g.Admit(context.Background(), evt); ok || msg != reason {
		t.Fatalf("want refusal %q, got %v %q", reason, ok, msg)
	}
	g.mu.Lock()
	_, cached := g.cache[evt.PubKey]
	g.mu.Unlock()
	if cached {
		t.Fatal("an incomplete lookup must not be cached")
	}
}

// longChain is a chain of n hops that ends at `end`: the hops creep along X
// from the spawn and the last one jumps to end.
func longChain(t *testing.T, s *signer, n int, end string) (*chainBuilder, []nostr.Event) {
	b := newChain(t, s)
	events := []nostr.Event{b.spawn}
	for i := 1; i < n; i++ {
		events = append(events, b.move(ActHop, offset(t, s.pubkey, int64(i))))
	}
	return b, append(events, b.move(ActHop, end))
}

func TestGateRefusesAChainLongerThanTheCap(t *testing.T) {
	s := newSigner(t)
	inside := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, inside, 20)
	if box.Contains(mustCoord(t, s.pubkey)) {
		t.Skip("spawn happens to fall in the target box")
	}

	// A 32-event chain that ends inside the region, read with a cap of 20:
	// the newest 20 leave out the hops after the spawn.
	_, events := longChain(t, s, 31, inside)
	src := &fakeSource{events: events}
	expectRefusedUncached(t, cappedGate(t, box, src, 20), s.sign(t, 1, 1), errTooLong)
	// With the whole chain in reach it is admitted.
	if ok, msg := cappedGate(t, box, src, 100).Admit(context.Background(), s.sign(t, 1, 2)); !ok {
		t.Fatalf("the whole chain ends inside: %s", msg)
	}

	// The other way round: the spawn is inside and the chain has left. A
	// capped answer must not admit the identity at its spawn.
	home := cubeAround(t, s.pubkey, 20)
	_, events = longChain(t, s, 31, offset(t, s.pubkey, 1<<45))
	expectRefusedUncached(t, cappedGate(t, home, &fakeSource{events: events}, 20), s.sign(t, 1, 3), errTooLong)
}

// The identity's own junk counts: it is authentic and names the spawn. Junk
// that pushes the real events out of the answer gets the identity refused,
// never admitted at its spawn.
func TestGateRefusesWhenTheIdentitysOwnJunkFillsTheCap(t *testing.T) {
	s := newSigner(t)
	home := cubeAround(t, s.pubkey, 20)
	b := newChain(t, s)
	away := b.move(ActHop, offset(t, s.pubkey, 1<<45)) // the real move, out of the region
	events := []nostr.Event{b.spawn, away}
	for i := 0; i < 25; i++ {
		junk := *b
		junk.last, junk.at = b.spawn, b.at+int64(100+i)
		events = append(events, junk.raw("wave"))
	}
	expectRefusedUncached(t, cappedGate(t, home, &fakeSource{events: events}, 20), s.sign(t, 1, 1), errTooLong)
}

// Events a third party forged are dropped while reading, so they never count
// toward the cap and cannot push the real chain out of the answer.
func TestForgedJunkDoesNotCountTowardTheCap(t *testing.T) {
	s := newSigner(t)
	inside := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, inside, 20)
	_, events := longChain(t, s, 10, inside)
	for i := 0; i < 50; i++ {
		forged := events[1]
		forged.ID = fmt.Sprintf("%064x", i+1) // not its hash: anyone can publish these
		forged.CreatedAt += int64(1000 + i)
		events = append(events, forged)
	}
	if ok, msg := cappedGate(t, box, &fakeSource{events: events}, 20).Admit(context.Background(), s.sign(t, 1, 1)); !ok {
		t.Fatalf("forged junk filled the cap: %s", msg)
	}
}

func TestGateRefusesAPartialAnswer(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn, b.move(ActHop, offset(t, s.pubkey, 1))}, partial: true}
	expectRefusedUncached(t, cappedGate(t, box, src, 100), s.sign(t, 1, 1), errIncomplete)
}

// A relay that drops the connection part way through paging gives a Partial
// answer, not a complete one; a relay with more than Max kept events gives a
// Capped one; and Keep decides what counts while paging.
func TestRelaySourceReportsCoverage(t *testing.T) {
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
	ctx := context.Background()
	flaky := RelaySource{Relays: []string{authRelay(t, events, 10, 3)}, Timeout: 10 * time.Second, AuthKey: key}
	got, cov, err := flaky.Movement(ctx, s.pubkey, ChainQuery{Max: 5000})
	if err != nil || !cov.Partial || len(got) == 0 || len(got) >= len(events) {
		t.Fatalf("a relay failing on its third page: %d events, %+v, %v", len(got), cov, err)
	}

	whole := RelaySource{Relays: []string{authRelay(t, events, 10)}, Timeout: 10 * time.Second, AuthKey: key}
	if got, cov, err = whole.Movement(ctx, s.pubkey, ChainQuery{Max: 20}); err != nil || !cov.Capped || len(got) != 20 {
		t.Fatalf("more than Max: %d events, %+v, %v", len(got), cov, err)
	}
	if got, cov, err = whole.Movement(ctx, s.pubkey, ChainQuery{Max: len(events)}); err != nil || cov.Truncated() || len(got) != len(events) {
		t.Fatalf("exactly Max is complete: %d events, %+v, %v", len(got), cov, err)
	}
	hopsOnly := func(e nostr.Event) bool { m, _ := ParseMove(e); return m.Action == ActHop }
	if got, cov, err = whole.Movement(ctx, s.pubkey, ChainQuery{Max: 34, Keep: hopsOnly}); err != nil || cov.Truncated() || len(got) != 34 {
		t.Fatalf("dropped events must not count toward Max: %d events, %+v, %v", len(got), cov, err)
	}
}

// LocalSource reports Capped past Max, and when the store's own ceiling is
// what stopped the answer.
func TestLocalSourceReportsCapped(t *testing.T) {
	s := newSigner(t)
	_, events := longChain(t, s, 30, offset(t, s.pubkey, 99))
	store := func(_ []nostr.Filter, limit int) ([]nostr.Event, error) {
		if limit > 0 && limit < len(events) {
			return events[:limit], nil
		}
		return events, nil
	}
	ctx := context.Background()
	if _, cov, _ := (LocalSource{Query: store}).Movement(ctx, s.pubkey, ChainQuery{Max: 10}); !cov.Capped {
		t.Fatal("more than Max must be Capped")
	}
	if got, cov, _ := (LocalSource{Query: store}).Movement(ctx, s.pubkey, ChainQuery{Max: 100}); cov.Capped || len(got) != len(events) {
		t.Fatalf("under Max is complete: %d %+v", len(got), cov)
	}
	if _, cov, _ := (LocalSource{Query: store, MaxResults: 20}).Movement(ctx, s.pubkey, ChainQuery{Max: 100}); !cov.Capped {
		t.Fatal("an answer stopped by the store's ceiling must be Capped")
	}
}

// A chain event whose previous the tag query did not return is asked for by
// id, and the chain is judged whole.
func TestGateFillsAGapByID(t *testing.T) {
	s := newSigner(t)
	inside := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, inside, 20)
	_, events := longChain(t, s, 6, inside)
	src := &fakeSource{events: events, untagged: map[string]bool{events[2].ID: true, events[3].ID: true}}
	g := cappedGate(t, box, src, 100)
	if ok, msg := g.Admit(context.Background(), s.sign(t, 1, 1)); !ok {
		t.Fatalf("the gap was not filled: %s", msg)
	}
}

// A gap no source can fill is refused, not judged and cached.
func TestGateRefusesAnUnfilledGap(t *testing.T) {
	s := newSigner(t)
	home := cubeAround(t, s.pubkey, 20)
	_, events := longChain(t, s, 6, offset(t, s.pubkey, 1<<45))
	held := append(append([]nostr.Event{}, events[:2]...), events[3:]...) // nobody holds events[2]
	expectRefusedUncached(t, cappedGate(t, home, &fakeSource{events: held}, 100), s.sign(t, 1, 1), errIncomplete)
}

// A forgery borrowing a missing event's id does not close the gap: only the
// event whose id is the hash of its content can answer for that id.
// Otherwise anyone could cut another identity's chain short (§8.7.3).
func TestForgedCopyCannotCloseAGap(t *testing.T) {
	s := newSigner(t)
	home := cubeAround(t, s.pubkey, 20)
	_, events := longChain(t, s, 6, offset(t, s.pubkey, 1<<45))
	copyOf := events[2]
	copyOf.Tags = append([][]string{}, copyOf.Tags...)
	copyOf.Tags[4] = []string{"C", offset(t, s.pubkey, 777)} // same id, other content
	held := append(append([]nostr.Event{}, events[:2]...), copyOf)
	held = append(held, events[3:]...)
	expectRefusedUncached(t, cappedGate(t, home, &fakeSource{events: held}, 100), s.sign(t, 1, 1), errIncomplete)
}

// A gap whose event exists but resolution never follows (here genuinely
// inauthentic: its id is right, its sig is not) is a cut the spec defines:
// the chain ends before it and is judged, not refused (§8.7.3).
func TestGenuineDiscardedEventClosesItsGap(t *testing.T) {
	s := newSigner(t)
	home := cubeAround(t, s.pubkey, 20)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	unsigned := b.move(ActHop, offset(t, s.pubkey, 1<<45))
	unsigned.Sig = strings.Repeat("0", 128)
	after := b.move(ActHop, offset(t, s.pubkey, 1<<46)) // names the unsigned event
	src := &fakeSource{events: []nostr.Event{b.spawn, h1, unsigned, after}}
	g := cappedGate(t, home, src, 100)
	if ok, msg := g.Admit(context.Background(), s.sign(t, 1, 1)); !ok {
		t.Fatalf("the branch through the unsigned event is cut, and h1 is inside: %s", msg)
	}
}
