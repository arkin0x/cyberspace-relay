package regiongate

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
)

// One test per ruling of 2026-10-07 (Q1 to Q9) and per clarification of
// 2026-10-08, as merged into the spec by arkin0x/cyberspace #46 (912f3d7).

// expectInvalid asserts the chain is invalid at want with reason, and that
// the identity stands frozen at frozen (§8.7.3).
func expectInvalid(t *testing.T, vd Verdict, reason string, want nostr.Event, frozen string) {
	t.Helper()
	if vd.Reason != reason || vd.InvalidAt != want.ID {
		t.Fatalf("want %s at %s, got %q at %s: %s", reason, want.ID, vd.Reason, vd.InvalidAt, vd.Stopped)
	}
	if vd.Position == nil || vd.Position.Hex() != frozen {
		t.Fatalf("frozen position: got %v want %s", vd.Position, frozen)
	}
}

func expectValid(t *testing.T, vd Verdict, head nostr.Event, position string) {
	t.Helper()
	if !vd.Valid() || vd.Head != head.ID || vd.Position == nil || vd.Position.Hex() != position {
		t.Fatalf("want valid with head %s at %s, got %+v", head.ID, position, vd)
	}
}

// Q1: there is no zero-length ride, the first ride from the station
// included, and nothing is grandfathered (DECK-0001 §5.2, §5.6, §5.8).
func TestRulingQ1NoZeroLengthRide(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	board := b.move(ActEnterHyperspace, s.pubkey)
	start := b.pos
	zero := b.move(ActHyperjump, offset(t, s.pubkey, 1<<40), []string{"from_height", "2"}, []string{"B", "2"}, []string{"as_of", "2"})
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, board, zero})
	expectInvalid(t, vd, ReasonHyperjumpZeroLength, zero, start)

	// A later zero-length ride is invalid too; a ride of one block is not.
	b = newChain(t, s)
	board = b.move(ActEnterHyperspace, s.pubkey)
	first := b.move(ActHyperjump, offset(t, s.pubkey, 1<<40), []string{"from_height", "2"}, []string{"B", "3"}, []string{"as_of", "3"})
	at := b.pos
	later := b.move(ActHyperjump, offset(t, s.pubkey, 1<<41), []string{"from_height", "3"}, []string{"B", "3"})
	vd = verifier().Verify(s.pubkey, []nostr.Event{b.spawn, board, first, later})
	expectInvalid(t, vd, ReasonHyperjumpZeroLength, later, at)
}

// Q2 and the 2026-10-08 region clarification: a virtual bracket is opaque.
// Base checks the entry (continuity, C = c, sector tags, region and game for
// form), the links, the A tag and reserved names inside, and the exit's
// entry, C and sector tags. Nothing else inside, and not the exit's c.
func TestRulingQ2BracketIsOpaque(t *testing.T) {
	s := newSigner(t)
	// A region far from the identity: a game may be declared anywhere, and
	// the base position need not lie in or near it (§8.11.1).
	far := offset(t, s.pubkey, 1<<60)
	box := cubeAround(t, far, 8)
	if box.Contains(mustCoord(t, s.pubkey)) {
		t.Fatal("fixture: the region must not contain the base position")
	}
	b := newChain(t, s)
	hop := b.move(ActHop, offset(t, s.pubkey, 1))
	base := b.pos
	enter := b.move(ActEnterVirtual, base, regionTag(box, 8), gameTag())
	inside := []nostr.Event{
		b.raw("noop"), // no c, no C, no sector tags
		b.raw("teleport", []string{"c", "zz"}, []string{"C", offset(t, far, 1<<62)}), // malformed c, C far outside the region
		b.raw("move", []string{"c", offset(t, base, 7)}, []string{"C", s.pubkey}, []string{"X", "1"}, []string{"X", "2"}, []string{"S", "nowhere"}),
	}
	exit := b.move(ActExitVirtual, base, []string{"e", enter.ID, "", "entry"}) // c is the last C carried, never checked
	evs := append(append([]nostr.Event{b.spawn, hop, enter}, inside...), exit)
	expectValid(t, verifier().Verify(s.pubkey, evs), exit, base)

	// An exit with no c at all is valid (§8.11.3: c is optional).
	b2 := newChain(t, s)
	e2 := b2.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
	x2 := b2.raw(ActExitVirtual, append([][]string{{"e", e2.ID, "", "entry"}, {"C", s.pubkey}}, sectorTags(t, s.pubkey)...)...)
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b2.spawn, e2, x2}), x2, s.pubkey)

	// Continuity resumes after the exit from its C, the base position.
	b.pos = offset(t, base, 3)
	wrong := b.move(ActHop, offset(t, base, 4))
	expectInvalid(t, verifier().Verify(s.pubkey, append(evs, wrong)), ReasonCMismatch, wrong, base)

	// The entry itself is continuous with the chain.
	b3 := newChain(t, s)
	b3.pos = offset(t, s.pubkey, 9)
	bad := b3.move(ActEnterVirtual, b3.pos, regionTag(box, 8), gameTag())
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b3.spawn, bad}), ReasonCMismatch, bad, s.pubkey)
}

// Q3: an invalid chain is frozen at its last valid position. The gate judges
// the identity by that position: nothing published on the frozen chain moves
// it in or out of the region, and only a respawn does.
func TestRulingQ3FrozenChainInTheGate(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	target := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, target, 20)
	if box.Contains(mustCoord(t, s.pubkey)) {
		t.Skip("spawn happens to fall in the target box")
	}
	b := newChain(t, s)
	in := b.move(ActHop, target)
	b.pos = offset(t, target, 5) // breaks continuity: invalid from here
	broken := b.move(ActHop, offset(t, target, 6))
	src := &fakeSource{events: []nostr.Event{b.spawn, in, broken}}

	vd := verifier().Verify(s.pubkey, src.events)
	expectInvalid(t, vd, ReasonCMismatch, broken, target)
	if ok, msg := gateFor(t, ModeStructural, box, src).Admit(ctx, s.sign(t, 1, 1)); !ok {
		t.Fatalf("a frozen identity stands at its last valid position, inside the region: %s", msg)
	}
	// A move out published on the frozen chain does not move it, so it is
	// judged at the frozen position and admitted.
	out := b.move(ActHop, s.pubkey)
	if ok, msg := gateFor(t, ModeStructural, box, src).Admit(ctx, out); !ok {
		t.Fatalf("an event on a frozen chain cannot move the identity out: %s", msg)
	}
	// A respawn does: the identity is back at its spawn coordinate, outside.
	respawn := s.sign(t, KindMovement, b.at+100, append([][]string{{"A", ActSpawn}, {"C", s.pubkey}}, sectorTags(t, s.pubkey)...)...)
	if ok, _ := gateFor(t, ModeStructural, box, src).Admit(ctx, respawn); ok {
		t.Fatal("a respawn outside the region must be refused")
	}

	// Frozen outside the region, a move in on the frozen chain is refused.
	b = newChain(t, s)
	b.pos = offset(t, s.pubkey, 5)
	broken = b.move(ActHop, offset(t, s.pubkey, 6))
	b.pos = broken.Tags[4][1]
	into := b.move(ActHop, target)
	src = &fakeSource{events: []nostr.Event{b.spawn, broken}}
	if ok, _ := gateFor(t, ModeStructural, box, src).Admit(ctx, into); ok {
		t.Fatal("a move on a frozen chain must not bring the identity into the region")
	}
}

// Q4: inauthentic events are discarded before resolution. A branch through
// one is cut off, the head is the event before it, and the identity
// continues from that head without a fork. Erratum 2: there is no unsigned
// local chain, so a blank sig is discarded like any other bad one.
func TestRulingQ4InauthenticEventsCutTheirBranch(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	forged := b.move(ActHop, offset(t, s.pubkey, 2))
	forged.Tags[4] = []string{"C", offset(t, s.pubkey, 99)} // tampered: the id no longer matches
	after := b.move(ActHop, offset(t, s.pubkey, 3))         // authentic, but names the forged event
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, forged, after})
	expectValid(t, vd, h1, offset(t, s.pubkey, 1))
	if len(vd.Chain) != 2 {
		t.Fatalf("the branch through the forged event must be cut off: %v", vd.Chain)
	}

	// The identity continues from the head; that is not a fork.
	b.last, b.pos = h1, offset(t, s.pubkey, 1)
	next := b.move(ActHop, offset(t, s.pubkey, 4))
	expectValid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, forged, after, next}), next, offset(t, s.pubkey, 4))

	// A blank sig, and an event by another author naming this chain, are
	// discarded too.
	blank := next
	blank.Sig = ""
	other := newSigner(t)
	foreign := other.sign(t, KindMovement, next.CreatedAt-1, next.Tags...)
	vd = verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, blank, foreign})
	expectValid(t, vd, h1, offset(t, s.pubkey, 1))
}

// Q5: exactly one A tag on every event, recognized, skipped, inside a
// bracket or the spawn. Its own reason code, a-tag.
func TestRulingQ5ExactlyOneATag(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 8)

	b := newChain(t, s)
	two := b.move(ActHop, offset(t, s.pubkey, 1), []string{"A", ActHop})
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, two}), ReasonATag, two, s.pubkey)

	b = newChain(t, s)
	skipped := b.raw("wave", []string{"A", "wave"})
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, skipped}), ReasonATag, skipped, s.pubkey)

	b = newChain(t, s)
	enter := b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
	virtual := b.raw("shoot", []string{"A", "shoot"})
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enter, virtual}), ReasonATag, virtual, s.pubkey)

	spawn := s.sign(t, KindMovement, 1, append([][]string{{"A", ActSpawn}, {"A", ActSpawn}, {"C", s.pubkey}}, sectorTags(t, s.pubkey)...)...)
	expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{spawn}), ReasonATag, spawn, s.pubkey)
}

// Q6: a skipped action is checked only for being authentic, linked and
// carrying one A tag.
func TestRulingQ6SkippedActionChecksNothingElse(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	wave := b.raw("wave", []string{"X", "x"}, []string{"S", "a"}, []string{"S", "b"}, []string{"C", "not-a-coordinate"})
	hop := b.move(ActHop, offset(t, s.pubkey, 1))
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, wave, hop})
	expectValid(t, vd, hop, offset(t, s.pubkey, 1))
	if !slices.Equal(vd.Skipped, []string{wave.ID}) {
		t.Fatalf("skipped: %v", vd.Skipped)
	}
}

// Q7: the newest spawn wins even when it is invalid; there is no fallback.
// The identity stands at its spawn coordinate, and the gate judges it there.
func TestRulingQ7InvalidNewestSpawnNoFallback(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	b := newChain(t, s)
	away := offset(t, s.pubkey, 1<<45)
	hop := b.move(ActHop, away)
	bad := s.sign(t, KindMovement, b.at+100, append([][]string{{"A", ActSpawn}, {"C", offset(t, s.pubkey, 1)}}, sectorTags(t, s.pubkey)...)...)
	events := []nostr.Event{b.spawn, hop, bad}

	vd := verifier().Verify(s.pubkey, events)
	if !slices.Equal(vd.Chain, []string{bad.ID}) {
		t.Fatalf("the newest spawn starts the active chain, valid or not: %v", vd.Chain)
	}
	expectInvalid(t, vd, ReasonSpawnCoordinate, bad, s.pubkey)
	if vd.VerifiedPosition == nil || vd.VerifiedPosition.Hex() != s.pubkey {
		t.Fatalf("strict mode stands it at its spawn coordinate too: %v", vd.VerifiedPosition)
	}

	src := &fakeSource{events: events}
	home := cubeAround(t, s.pubkey, 20)
	for _, mode := range []Mode{ModeStructural, ModeStrict} {
		if ok, msg := gateFor(t, mode, home, src).Admit(ctx, s.sign(t, 1, 1)); !ok {
			t.Fatalf("%s: an identity with an invalid newest spawn stands at its spawn coordinate, inside: %s", mode, msg)
		}
	}
	if !home.Contains(mustCoord(t, away)) {
		if ok, _ := gateFor(t, ModeStructural, cubeAround(t, away, 20), src).Admit(ctx, s.sign(t, 1, 2)); ok {
			t.Fatal("the older spawn's chain must not be used as a fallback")
		}
	}
}

// Q8: rule 3 names a category. Every recognized action, which is every base
// and mandatory DECK action, is reserved inside a bracket, except the spawn
// (never inside one) and the exit that closes it.
func TestRulingQ8ReservedNamesAreACategory(t *testing.T) {
	want := map[string]bool{}
	for a := range recognizedActions {
		want[a] = true
	}
	delete(want, ActSpawn)
	delete(want, ActExitVirtual)
	if !maps.Equal(notInBracket, want) {
		t.Fatalf("reserved inside a bracket: %v, want %v", notInBracket, want)
	}
	for _, a := range []string{ActHop, ActSidestep, ActEnterHyperspace, ActHyperjump, ActEnterVirtual} {
		if !notInBracket[a] {
			t.Errorf("%s must be reserved inside a bracket", a)
		}
	}
}

// Q9 and the 2026-10-08 duplicate clarification: sector tags count toward
// the validity of every base and mandatory DECK action: each of X, Y, Z and
// S exactly once, equal to the values computed from C.
func TestRulingQ9SectorTags(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 8)
	right := sectorTags(t, s.pubkey)
	bads := map[string][][]string{
		"missing":      right[:3],
		"duplicated":   append(append([][]string{}, right...), right[0]),
		"wrong":        append([][]string{{"X", "1"}}, right[1:]...),
		"noncanonical": {{"X", "0" + right[0][1]}, right[1], right[2], {"S", "0" + right[3][1]}},
	}
	for name, sectors := range bads {
		t.Run(name, func(t *testing.T) {
			spawn := s.sign(t, KindMovement, 1, append([][]string{{"A", ActSpawn}, {"C", s.pubkey}}, sectors...)...)
			expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{spawn}), ReasonSectorTags, spawn, s.pubkey)

			for _, action := range []string{ActHop, ActSidestep, ActEnterHyperspace} {
				b := newChain(t, s)
				evt := b.moveTags(action, s.pubkey, sectors)
				expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, evt}), ReasonSectorTags, evt, s.pubkey)
			}

			b := newChain(t, s)
			enter := b.moveTags(ActEnterVirtual, s.pubkey, sectors, regionTag(box, 8), gameTag())
			expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enter}), ReasonSectorTags, enter, s.pubkey)

			b = newChain(t, s)
			enter = b.move(ActEnterVirtual, s.pubkey, regionTag(box, 8), gameTag())
			exit := b.moveTags(ActExitVirtual, s.pubkey, sectors, []string{"e", enter.ID, "", "entry"})
			expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enter, exit}), ReasonSectorTags, exit, s.pubkey)

			b = newChain(t, s)
			board := b.move(ActEnterHyperspace, s.pubkey)
			to := offset(t, s.pubkey, 1<<40)
			jumpSectors := sectors
			if name != "missing" { // the same defect, against the ride's own C
				jumpSectors = append([][]string{}, sectorTags(t, to)...)
				switch name {
				case "duplicated":
					jumpSectors = append(jumpSectors, jumpSectors[0])
				case "wrong":
					jumpSectors[0] = []string{"X", "1"}
				case "noncanonical":
					jumpSectors[0] = []string{"X", "0" + jumpSectors[0][1]}
				}
			} else {
				jumpSectors = sectorTags(t, to)[:3]
			}
			jump := b.moveTags(ActHyperjump, to, jumpSectors, []string{"from_height", "2"}, []string{"B", "3"}, []string{"as_of", "3"})
			expectInvalid(t, verifier().Verify(s.pubkey, []nostr.Event{b.spawn, board, jump}), ReasonSectorTags, jump, s.pubkey)
		})
	}
}

// The reason codes are the reference's (cyberspace-cli, regenerated against
// 912f3d7): outside-region is gone, a-tag, sector-tags and
// enter-virtual-moved are new.
func TestReasonCodesAfterRulings(t *testing.T) {
	for _, code := range []string{ReasonATag, ReasonSectorTags, ReasonEnterVirtualMoved} {
		if Reasons[code] == "" {
			t.Errorf("missing reason %s", code)
		}
	}
	if _, ok := Reasons["outside-region"]; ok {
		t.Error("outside-region must be gone: nothing has to lie inside a bracket's region")
	}
	for code, rule := range Reasons {
		if strings.Contains(rule, "inside a bracket not the C of the previous event") {
			t.Errorf("%s still describes in-bracket continuity", code)
		}
	}
}
