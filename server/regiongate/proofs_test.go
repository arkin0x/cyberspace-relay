package regiongate

import (
	"strings"
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"
)

// The checker's behavior that the golden vectors cannot show, because the
// vectors always run with a line and every proof checkable.

// scriptedProofs answers each proof-bearing action in turn from a script.
type scriptedProofs struct {
	answers []ProofResult
	asked   *int
}

func (s scriptedProofs) Check(prev, cur Move) (ProofResult, string) {
	i := *s.asked
	*s.asked++
	if i < len(s.answers) {
		if s.answers[i] == ProofInvalid {
			return ProofInvalid, ReasonHopProof + ": scripted"
		}
		return s.answers[i], "scripted"
	}
	return ProofVerified, ""
}

// A proof is judged on its own event and the id it names as previous, so a
// verifier that could not check one proof still checks every later one: an
// invalid hop after an unchecked ride makes the chain invalid. Before this
// revision of the gate, the walk stopped asking after the first unchecked
// proof, and a chain of forged hops behind one ride landed at its head in
// structural mode.
func TestProofsAfterAnUncheckedOneAreChecked(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	at1, at2 := offset(t, s.pubkey, 1), offset(t, s.pubkey, 2)
	h1 := b.move(ActHop, at1)
	h2 := b.move(ActHop, at2)
	h3 := b.move(ActHop, offset(t, s.pubkey, 3))
	asked := 0
	v := Verifier{Proofs: scriptedProofs{answers: []ProofResult{ProofUnchecked, ProofInvalid}, asked: &asked}, Signature: validation.CheckSignature}
	vd := v.Verify(s.pubkey, []nostr.Event{b.spawn, h1, h2, h3})
	expectInvalid(t, vd, ReasonHopProof, h2, at1)
	if asked != 2 {
		t.Fatalf("the checker was asked %d times, want 2", asked)
	}
	if vd.VerifiedEvent != b.spawn.ID {
		t.Fatalf("the verified prefix ends at %s, want the spawn", vd.VerifiedEvent)
	}
}

// hopEvent is an unsigned hop carrying the given tags after its links:
// enough for the checker, which never reads a signature.
func hopEvent(id, prev, from, to string, tags ...[]string) Move {
	evt := nostr.Event{ID: id, Kind: KindMovement, Tags: append([][]string{
		{"A", "hop"}, {"e", strings.Repeat("0", 64), "", "genesis"}, {"e", prev, "", "previous"},
		{"c", from}, {"C", to},
	}, tags...)}
	m, _ := ParseMove(evt)
	return m
}

// Above the ceiling, a hop that passes its form and its price is left
// unchecked, never judged: Level 1 would cost about 2^h_max per residue.
func TestHopAboveTheCeilingIsUnchecked(t *testing.T) {
	rv := loadResidueVectors(t)
	p := rv.Prover[0] // the §5.7 hop: h_max 13
	if p.HMax != 13 {
		t.Fatalf("expected the §5.7 hop first, got %s at h%d", p.Name, p.HMax)
	}
	m := hopEvent(strings.Repeat("1", 64), p.PreviousEventID, p.C1, p.C2,
		[]string{"proof", p.Tags.Proof}, []string{"mn", p.Tags.Mn}, []string{"mp", p.Tags.Mp})
	if res, why := (SpecProofs{}).Check(Move{}, m); res != ProofVerified {
		t.Fatalf("at the default ceiling: %v %s", res, why)
	}
	if res, why := (SpecProofs{MaxHopHeight: 12}).Check(Move{}, m); res != ProofUnchecked {
		t.Fatalf("above the ceiling: want unchecked, got %v %s", res, why)
	}
	// A wrong price is still judged above the ceiling: it costs one attempt.
	bad := hopEvent(strings.Repeat("1", 64), p.PreviousEventID, p.C1, p.C2,
		[]string{"proof", p.Tags.Proof}, []string{"mn", "0000000000000000"}, []string{"mp", p.Tags.Mp})
	if res, why := (SpecProofs{MaxHopHeight: 12}).Check(Move{}, bad); res != ProofInvalid || !strings.HasPrefix(why, ReasonHopProof) {
		t.Fatalf("a missed price above the ceiling: want invalid, got %v %s", res, why)
	}
}

// With no line, a ride is unchecked: the chain stays valid, strict mode
// places the identity where it boarded, structural mode at the ride's C.
func TestRideWithoutALineIsUnchecked(t *testing.T) {
	vf := loadVectors(t, vectorsFile)
	for _, vec := range vf.Vectors {
		if vec.Name != "ride-valid" {
			continue
		}
		vd := Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}.Verify(vf.TestKey.Pubkey, parseEvents(vec.Events))
		if !vd.Valid() || vd.Unchecked == 0 || vd.Position.Hex() != vec.Expected.Position {
			t.Fatalf("want valid at the ride's stop with the ride unchecked, got %+v", vd)
		}
		// The chain is spawn, hop, enter-hyperspace, two rides, then a hop:
		// the verified prefix ends at the boarding, and the hop after the
		// rides is still checked (it holds, so the chain stays valid).
		boarding := vd.Chain[2]
		if vd.VerifiedEvent != boarding || vd.VerifiedPosition.Equal(*vd.Position) {
			t.Fatalf("the verified prefix should end at the boarding %s, got %s", boarding, vd.VerifiedEvent)
		}
		return
	}
	t.Fatal("no ride-valid vector")
}

// The embedded exemption lists are the spec's, line for line.
func TestEmbeddedExemptionLists(t *testing.T) {
	for name, want := range map[string]struct {
		list map[string]bool
		n    int
		id   string
	}{
		"v1 hops":      {ListedV1Hops, 2658, "2bf6e3665f73b90d33f36d15e6e5188cc4978969e281b8620d22f24ba89af618"},
		"v2 sidesteps": {ListedV2Sidesteps, 36, "f6d6696585aaf660f868c7f184bf90500e2dcfae2aa5a8cc4d2584a08700302c"},
		"v1 rides":     {ListedV1Rides, 16, ""},
	} {
		if len(want.list) != want.n || want.id != "" && !want.list[want.id] {
			t.Errorf("%s: %d ids, want %d", name, len(want.list), want.n)
		}
	}
}
