package regiongate

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// One test per ruling arkinox made on 2026-10-08 on the points the spec left
// open after #46.

// Rule 1: every chain event, recognized, skipped or virtual, carries exactly
// one e genesis and one e previous, and an exit exactly one e entry.
// Resolution follows the first copy; validity rejects the event.
func TestRuling1008ExactlyOneOfEachETag(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 8)
	dupPrevious := func(b *chainBuilder) []string { return []string{"e", b.spawn.ID, "", "previous"} }

	b := newChain(t, s)
	hop := b.move(ActHop, offset(t, s.pubkey, 1), dupPrevious(b))
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, hop}), ReasonMalformed, hop, s.pubkey)

	b = newChain(t, s)
	skipped := b.raw("wave", []string{"e", b.spawn.ID, "", "genesis"})
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, skipped}), ReasonMalformed, skipped, s.pubkey)

	b = newChain(t, s)
	skipped = b.raw("wave", []string{"e", "", "", "previous"}) // an empty second copy still counts
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, skipped}), ReasonMalformed, skipped, s.pubkey)

	b = newChain(t, s)
	enter := b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
	virtual := b.raw("shoot", dupPrevious(b))
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enter, virtual}), ReasonMalformed, virtual, s.pubkey)

	b = newChain(t, s)
	enter = b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
	exit := b.move(ActExitVirtual, s.pubkey, []string{"e", enter.ID, "", "entry"}, []string{"e", enter.ID, "", "entry"})
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enter, exit}), ReasonMalformed, exit, s.pubkey)

	// An e tag with no marker, or another marker, is not read and is free.
	b = newChain(t, s)
	free := b.move(ActHop, offset(t, s.pubkey, 1), []string{"e", b.spawn.ID}, []string{"e", b.spawn.ID, "", "root"})
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, free}), free, offset(t, s.pubkey, 1))
}

// Rule 2: the exit's optional c is never read. Rule 3: only kind 3333 takes
// part.
func TestRuling1008ExitCAndKind(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 8)
	for name, cs := range map[string][][]string{
		"missing":    nil,
		"garbled":    {{"c", "zz"}},
		"bare":       {{"c"}},
		"duplicated": {{"c", s.pubkey}, {"c", offset(t, s.pubkey, 5)}},
	} {
		b := newChain(t, s)
		enter := b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
		tags := append([][]string{{"e", enter.ID, "", "entry"}, {"C", s.pubkey}}, sectorTags(t, s.pubkey)...)
		exit := b.raw(ActExitVirtual, append(tags, cs...)...)
		vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enter, exit})
		if !vd.Valid() {
			t.Fatalf("exit with a %s c: %s", name, vd.Stopped)
		}
	}

	b := newChain(t, s)
	notMovement := s.sign(t, 1, b.at+100, append([][]string{{"A", ActSpawn}, {"C", offset(t, s.pubkey, 1)}}, sectorTags(t, s.pubkey)...)...)
	fork := b.move(ActHop, offset(t, s.pubkey, 1))
	kind1 := s.sign(t, 1, fork.CreatedAt-1, fork.Tags...) // would fork the chain if it counted
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, notMovement, fork, kind1}), fork, offset(t, s.pubkey, 1))
}

// Rule 4: any A tag equal to "spawn" makes the event a spawn for resolution,
// wherever it stands. With a second A tag it is an invalid newest spawn, and
// the identity stands at its pubkey's coordinate. It is never a link.
func TestRuling1008AnySpawnATagMakesASpawn(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	b := newChain(t, s)
	away := offset(t, s.pubkey, 1<<45)
	hop := b.move(ActHop, away)
	// Names hop as previous, so with only its first A read it would extend
	// the chain as a skipped action.
	second := b.raw("wave", []string{"A", ActSpawn}, []string{"C", s.pubkey})
	events := []nostr.Event{b.spawn, hop, second}

	vd := verifier().Verify(s.pubkey, events)
	if !slices.Equal(vd.Chain, []string{second.ID}) {
		t.Fatalf("the event with a spawn A tag is the newest spawn: %v", vd.Chain)
	}
	expectInvalid(t, vd, ReasonATag, second, s.pubkey)

	// The gate finds it by its spawn tag and judges the identity at its
	// pubkey's coordinate, not where the older chain left it.
	src := &fakeSource{events: events}
	if ok, msg := gateFor(t, ModeStructural, cubeAround(t, s.pubkey, 20), src).Admit(ctx, s.sign(t, 1, 1)); !ok {
		t.Fatalf("dead at its spawn coordinate, inside: %s", msg)
	}
	if ok, _ := gateFor(t, ModeStructural, cubeAround(t, away, 20), src).Admit(ctx, s.sign(t, 1, 2)); ok {
		t.Fatal("the older chain must not count")
	}
}

// Rule 5: a fork, two or more chain events naming the same previous, makes
// the whole chain dead at the pubkey's coordinate, whichever branch is valid
// or signed first. A forged event is never a branch.
func TestRuling1008ForkIsDead(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	fork := *b
	b.pos = offset(t, s.pubkey, 50)
	early := b.move(ActHop, offset(t, s.pubkey, 51)) // invalid, signed first
	fork.at = early.CreatedAt + 5
	late := fork.move(ActHop, offset(t, s.pubkey, 2)) // valid, signed later
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, late, early})
	// As the reference reports it: invalid from the spawn, the chain running
	// from the spawn to the event the branches name.
	expectInvalid(t, vd, ReasonFork, b.spawn, s.pubkey)
	want := []string{early.ID, late.ID}
	slices.Sort(want)
	if !slices.Equal(vd.Fork, want) || vd.InvalidIndex != 0 || !slices.Equal(vd.Chain, []string{b.spawn.ID, h1.ID}) {
		t.Fatalf("branches %v at index %d, chain %v", vd.Fork, vd.InvalidIndex, vd.Chain)
	}

	// Two valid branches, one of them a skipped action: dead as well.
	b = newChain(t, s)
	h1 = b.move(ActHop, offset(t, s.pubkey, 1))
	fork = *b
	next := b.move(ActHop, offset(t, s.pubkey, 2))
	wave := fork.raw("wave")
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, next, wave}), ReasonFork, b.spawn, s.pubkey)

	// Branches the walk never reaches (both name an event nobody holds) make
	// no fork (spec PR #48): the chain stays valid at h1.
	b = newChain(t, s)
	h1 = b.move(ActHop, offset(t, s.pubkey, 1))
	b.move(ActHop, offset(t, s.pubkey, 2)) // never handed over
	fork = *b
	o1 := b.move(ActHop, offset(t, s.pubkey, 3))
	o2 := fork.move(ActHop, offset(t, s.pubkey, 4))
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, o1, o2}), h1, offset(t, s.pubkey, 1))

	// A forged sibling is discarded before resolution and is not a branch.
	b = newChain(t, s)
	h1 = b.move(ActHop, offset(t, s.pubkey, 1))
	forged := h1
	forged.ID = strings.Repeat("0", 64)
	forged.CreatedAt--
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, forged}), h1, offset(t, s.pubkey, 1))
}

// Rule 5 closes the frozen-chain rewind the review found: an identity that
// left the region signs one invalid event, backdated to just after an old
// event inside the region, naming that event as previous. That is a fork, so
// the chain is dead at the spawn coordinate (here outside the region), not
// frozen inside it.
func TestRuling1008ForkClosesTheFrozenChainRewind(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	inside := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, inside, 20)
	if box.Contains(mustCoord(t, s.pubkey)) {
		t.Skip("spawn happens to fall in the target box")
	}
	b := newChain(t, s)
	in := b.move(ActHop, inside)
	rewind := *b
	out := b.move(ActHop, offset(t, inside, 1<<30)) // leaves the region
	rewind.pos = offset(t, inside, 7)               // breaks continuity: invalid
	rewind.at = in.CreatedAt + 1
	backdated := rewind.move(ActHop, inside)
	src := &fakeSource{events: []nostr.Event{b.spawn, in, out}}
	g := gateFor(t, ModeStructural, box, src)
	if ok, _ := g.Admit(ctx, s.sign(t, 1, 1)); ok {
		t.Fatal("the identity has left the region")
	}
	if ok, _ := g.Admit(ctx, backdated); ok {
		t.Fatal("a backdated fork must not earn admission")
	}
}

// A fork whose second branch the gate learns of later changes the verdict
// at the next lookup: at once for a movement event published here, and
// after cache_ttl_seconds for anything else.
func TestRuling1008LateBranchChangesTheVerdict(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	inside := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, inside, 20)
	if box.Contains(mustCoord(t, s.pubkey)) {
		t.Skip("spawn happens to fall in the target box")
	}
	b := newChain(t, s)
	h1 := b.move(ActHop, inside)
	fork := *b
	src := &fakeSource{events: []nostr.Event{b.spawn, h1}}
	g := gateFor(t, ModeStructural, box, src)
	now := time.Now()
	g.now = func() time.Time { return now }
	if ok, msg := g.Admit(ctx, s.sign(t, 1, 1)); !ok {
		t.Fatalf("inside: %s", msg)
	}

	// Two branches at h1 appear on a chain relay.
	src.mu.Lock()
	src.events = append(src.events, b.move(ActHop, offset(t, inside, 1)), fork.move(ActHop, offset(t, inside, 2)))
	src.mu.Unlock()
	if ok, _ := g.Admit(ctx, s.sign(t, 1, 2)); !ok {
		t.Fatal("within cache_ttl_seconds the cached admission still answers")
	}
	now = now.Add(601 * time.Second)
	if ok, _ := g.Admit(ctx, s.sign(t, 1, 3)); ok {
		t.Fatal("after the TTL the fork is seen: dead at the spawn coordinate, outside")
	}
	// A movement event published here is always judged afresh.
	g2 := gateFor(t, ModeStructural, box, src)
	if ok, _ := g2.Admit(ctx, b.move(ActHop, offset(t, inside, 3))); ok {
		t.Fatal("a movement event on a forked chain is judged at the spawn coordinate")
	}
}

// Rule 6: every tag a chain rule reads appears exactly once with a
// well-formed value. A tag with no value still counts and is malformed;
// duplicates are invalid; unread tags are free.
func TestRuling1008ExactlyOnceWithAValue(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 8)
	check := func(name string, want string, build func(b *chainBuilder) []nostr.Event) {
		t.Helper()
		b := newChain(t, s)
		evs := build(b)
		vd := verifier().Verify(s.pubkey, append([]nostr.Event{b.spawn}, evs...))
		last := evs[len(evs)-1]
		if want == "" {
			if !vd.Valid() {
				t.Errorf("%s: want valid, got %s", name, vd.Stopped)
			}
			return
		}
		if vd.Reason != want || vd.InvalidAt != last.ID {
			t.Errorf("%s: want %s at the last event, got %q: %s", name, want, vd.Reason, vd.Stopped)
		}
	}
	to := offset(t, s.pubkey, 1)
	check("bare A alone", ReasonATag, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.s.sign(t, KindMovement, b.at+10, append([][]string{{"A"}, {"e", b.spawn.ID, "", "genesis"}, {"e", b.spawn.ID, "", "previous"}, {"c", s.pubkey}, {"C", to}}, sectorTags(t, to)...)...)}
	})
	check("A plus a bare A", ReasonATag, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActHop, to, []string{"A"})}
	})
	check("bare A on a skipped action", ReasonATag, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.raw("wave", []string{"A"})}
	})
	check("bare second C", ReasonMalformed, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActHop, to, []string{"C"})}
	})
	check("empty c", ReasonMalformed, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.raw(ActHop, append([][]string{{"c", ""}, {"C", to}, {"proof", strings.Repeat("ab", 32)}}, sectorTags(t, to)...)...)}
	})
	check("bare second region", ReasonRegion, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), []string{"region"}, gameTag())}
	})
	check("bare second X", ReasonSectorTags, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActHop, to, []string{"X"})}
	})
	check("bare second proof", ReasonMalformed, func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActHop, to, []string{"proof"})}
	})

	ride := func(extra ...[]string) func(b *chainBuilder) []nostr.Event {
		return func(b *chainBuilder) []nostr.Event {
			board := b.move(ActEnterHyperspace, s.pubkey)
			tags := append([][]string{{"from_height", "2"}, {"B", "3"}, {"as_of", "3"}}, extra...)
			return []nostr.Event{board, b.move(ActHyperjump, offset(t, s.pubkey, 1<<40), tags...)}
		}
	}
	check("ride", "", ride())
	check("second B", ReasonMalformed, ride([]string{"B", "3"}))
	check("bare second from_height", ReasonMalformed, ride([]string{"from_height"}))
	check("second as_of on the first ride", ReasonMalformed, ride([]string{"as_of", "3"}))
	check("second mp", ReasonMalformed, ride([]string{"mp", "ab"}, []string{"mp", "cd"}))
	check("second mn", ReasonMalformed, ride([]string{"mn", strings.Repeat("1", 16)}))
	check("ride with no mp", ReasonMalformed, func(b *chainBuilder) []nostr.Event {
		board := b.move(ActEnterHyperspace, s.pubkey)
		to := offset(t, s.pubkey, 1<<40)
		tags := append([][]string{{"c", s.pubkey}, {"C", to}, {"from_height", "2"}, {"B", "3"}, {"as_of", "3"}, {"proof", strings.Repeat("ab", 32)}}, sectorTags(t, to)...)
		return []nostr.Event{board, b.raw(ActHyperjump, tags...)}
	})
	check("ride with no mn (DECK-0001 §5.8 lists some; the checker decides)", "", func(b *chainBuilder) []nostr.Event {
		board := b.move(ActEnterHyperspace, s.pubkey)
		to := offset(t, s.pubkey, 1<<40)
		tags := append([][]string{{"c", s.pubkey}, {"C", to}, {"from_height", "2"}, {"B", "3"}, {"as_of", "3"}, {"proof", strings.Repeat("ab", 32)}, {"mp", "ab"}}, sectorTags(t, to)...)
		return []nostr.Event{board, b.raw(ActHyperjump, tags...)}
	})

	// as_of is read on the first ride only: missing there it breaks
	// DECK-0001 §4.2; garbled it is malformed; on a later ride it is free.
	check("first ride with no as_of", ReasonHyperjumpAsOf, func(b *chainBuilder) []nostr.Event {
		board := b.move(ActEnterHyperspace, s.pubkey)
		return []nostr.Event{board, b.move(ActHyperjump, offset(t, s.pubkey, 1<<40), []string{"from_height", "2"}, []string{"B", "3"})}
	})
	check("garbled as_of", ReasonMalformed, ride([]string{"as_of", "x"}))
	check("as_of twice on a later ride", "", func(b *chainBuilder) []nostr.Event {
		evs := ride()(b)
		return append(evs, b.move(ActHyperjump, offset(t, s.pubkey, 1<<41), []string{"from_height", "3"}, []string{"B", "4"}, []string{"as_of", "x"}, []string{"as_of"}))
	})
	// The ride's heights come first, then DECK-0001 §5.6, then its other
	// tags: a zero-length ride with no proof tags is zero-length.
	check("zero-length ride with no proof tags", ReasonHyperjumpZeroLength, func(b *chainBuilder) []nostr.Event {
		board := b.move(ActEnterHyperspace, s.pubkey)
		to := offset(t, s.pubkey, 1<<40)
		tags := append([][]string{{"c", s.pubkey}, {"C", to}, {"from_height", "2"}, {"B", "2"}, {"as_of", "2"}}, sectorTags(t, to)...)
		return []nostr.Event{board, b.raw(ActHyperjump, tags...)}
	})
	check("ride with bad heights and no proof tags", ReasonMalformed, func(b *chainBuilder) []nostr.Event {
		board := b.move(ActEnterHyperspace, s.pubkey)
		to := offset(t, s.pubkey, 1<<40)
		tags := append([][]string{{"c", s.pubkey}, {"C", to}, {"from_height", "2"}, {"B", "x"}}, sectorTags(t, to)...)
		return []nostr.Event{board, b.raw(ActHyperjump, tags...)}
	})

	// A sidestep's mr, mp, hx, hy and hz appear exactly once in form; its mn
	// may be absent (§6.16 lists sidesteps without one) but not repeated.
	root := strings.Repeat("ef", 32)
	sidestep := func(drop string, extra ...[]string) func(b *chainBuilder) []nostr.Event {
		return func(b *chainBuilder) []nostr.Event {
			tags := [][]string{{"mr", root + ":" + root + ":" + root}, {"mp", "ab"}, {"hx", "1"}, {"hy", "1"}, {"hz", "1"}}
			tags = slices.DeleteFunc(tags, func(t []string) bool { return t[0] == drop })
			return []nostr.Event{b.move(ActSidestep, to, append(tags, extra...)...)}
		}
	}
	check("sidestep", "", sidestep(""))
	check("sidestep with mn", "", sidestep("", []string{"mn", strings.Repeat("1", 16)}))
	check("sidestep with two mn", ReasonMalformed, sidestep("", []string{"mn", strings.Repeat("1", 16)}, []string{"mn", strings.Repeat("1", 16)}))
	check("sidestep with a short mn", ReasonMalformed, sidestep("", []string{"mn", "12"}))
	check("sidestep with two roots in mr", ReasonMalformed, sidestep("mr", []string{"mr", root + ":" + root}))
	check("sidestep with no mp", ReasonMalformed, sidestep("mp"))
	check("sidestep with hx not decimal", ReasonMalformed, sidestep("hx", []string{"hx", "-1"}))
	check("sidestep with two hz", ReasonMalformed, sidestep("", []string{"hz", "1"}))

	// Unread tags are free: on a hop an unknown tag twice, on a skipped
	// action c and C twice and bare, inside a bracket anything but A and e.
	check("unread tags on a hop", "", func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActHop, to, []string{"net", "a"}, []string{"net"})}
	})
	check("c and C on a skipped action", "", func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.raw("wave", []string{"c"}, []string{"c", "x"}, []string{"C"}, []string{"C", "y"})}
	})
	check("tags inside a bracket", "", func(b *chainBuilder) []nostr.Event {
		e := b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
		return []nostr.Event{e, b.raw("shoot", []string{"C"}, []string{"C", "x"}, []string{"proof"}, []string{"region"})}
	})
}

// A spawn is never a link (arkinox, spec #48): an event any of whose A tags
// is "spawn" is never reached by the walk, whatever e tags it carries, so an
// older one never extends or forks the chain and is never skipped.
func TestRuling1008SpawnIsNeverALink(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	h2 := b.move(ActHop, offset(t, s.pubkey, 2))
	// Older than the spawn, so it is history, not the newest spawn; it names
	// h1 as previous under this chain's genesis.
	spawnLink := s.sign(t, KindMovement, b.spawn.CreatedAt-100, append([][]string{{"A", ActSpawn}, {"C", s.pubkey},
		{"e", b.spawn.ID, "", "genesis"}, {"e", h1.ID, "", "previous"}}, sectorTags(t, s.pubkey)...)...)
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, h2, spawnLink})
	expectValid(t, vd, h2, offset(t, s.pubkey, 2))
	if len(vd.Chain) != 3 || len(vd.Skipped) != 0 {
		t.Fatalf("chain %v skipped %v", vd.Chain, vd.Skipped)
	}

	// The same with the spawn tag second, behind another A tag.
	second := s.sign(t, KindMovement, b.spawn.CreatedAt-50, append([][]string{{"A", "wave"}, {"A", ActSpawn},
		{"e", b.spawn.ID, "", "genesis"}, {"e", h1.ID, "", "previous"}}, sectorTags(t, s.pubkey)...)...)
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, h2, second}), h2, offset(t, s.pubkey, 2))
}

// Always mainnet (arkinox, spec #48): a net tag is informational and never
// read by chain validity, whatever its value or count.
func TestRuling1008NetTagIsNeverRead(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	board := b.move(ActEnterHyperspace, s.pubkey, []string{"net", "testnet"}, []string{"net"})
	jump := b.move(ActHyperjump, offset(t, s.pubkey, 1<<40), []string{"from_height", "2"}, []string{"B", "3"}, []string{"as_of", "3"},
		[]string{"net", "signet"}, []string{"net", "regtest"})
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, board, jump}), jump, offset(t, s.pubkey, 1<<40))
}
