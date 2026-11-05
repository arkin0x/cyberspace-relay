package regiongate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
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

// seededTree builds the seeded Merkle tree of one sidestep axis (§6.4, §6.5)
// over the leaves base .. base + 2^h - 1, levels from the leaves up, and
// returns its root and a function giving a leaf's path.
func seededTree(prefix []byte, base int64, h int) ([]byte, func(int) []string) {
	level := make([][]byte, 1<<h)
	for i := range level {
		level[i] = sidestepLeaf(prefix, big.NewInt(base+int64(i)))
	}
	levels := [][][]byte{level}
	for len(level) > 1 {
		next := make([][]byte, len(level)/2)
		for i := range next {
			s := sha256.Sum256(append(append([]byte{}, level[2*i]...), level[2*i+1]...))
			next[i] = s[:]
		}
		levels, level = append(levels, next), next
	}
	return level[0], func(i int) []string {
		var path []string
		for _, lv := range levels[:len(levels)-1] {
			path = append(path, hex.EncodeToString(lv[i^1]))
			i >>= 1
		}
		return path
	}
}

// A sidestep whose openings are true for the G its nonce gives, but whose G
// misses the re-roll price, is invalid (§6.10, §8.7.2 step 4): the price is
// what makes redrawing the samples cost work. The same sidestep with a
// nonce that pays is valid. Built here from scratch, z crossing one wall at
// height 4 (7 to 8), x and y still.
func TestSidestepThatMissesThePriceIsInvalid(t *testing.T) {
	prev := bytes.Repeat([]byte{0x5a}, 32)
	x, y := big.NewInt(1<<40), big.NewInt(3<<40)
	from := packCoord(x, y, big.NewInt(7), 0)
	to := packCoord(x, y, big.NewInt(8), 0)
	prefix := func(axis byte) []byte {
		return append(append(append(append([]byte{}, sidestepDomain...), prev...), axis), make([]byte, 9)...)
	}
	mx, my := sidestepLeaf(prefix(0), x), sidestepLeaf(prefix(1), y)
	mz, path := seededTree(prefix(2), 0, 4)
	price := big.NewInt(2) // ceil(16 leaves / 8)
	build := func(wantPaid bool) Move {
		for nonce := uint64(0); ; nonce++ {
			var nb [8]byte
			binary.BigEndian.PutUint64(nb[:], nonce)
			g := sha256.New()
			g.Write(sidestepGrindDomain)
			g.Write(nb[:])
			g.Write(prev)
			g.Write(mx)
			g.Write(my)
			g.Write(mz)
			G := g.Sum(nil)
			if meetsPrice(G, price) != wantPaid {
				continue
			}
			segment := strings.Join(path(8), "")
			for i := 0; i < sidestepSamples; i++ {
				var ib [4]byte
				binary.BigEndian.PutUint32(ib[:], uint32(i))
				s := sha256.Sum256(append(append(append(append([]byte{}, sidestepSampleDomain...), G...), 2), ib[:]...))
				segment += strings.Join(path(int(new(big.Int).Mod(new(big.Int).SetBytes(s[:]), big.NewInt(16)).Int64())), "")
			}
			m := [3]*big.Int{new(big.Int).SetBytes(mx), new(big.Int).SetBytes(my), new(big.Int).SetBytes(mz)}
			region := cantorPair(new(big.Int), cantorPair(new(big.Int), m[0], m[1]), m[2])
			toCoord, _ := ParseCoord(hex.EncodeToString(to[:]))
			proof := doubleSHA256Hex(cantorPair(new(big.Int), region, temporalCantor(prev, terrainK(toCoord))))
			evt := nostr.Event{ID: strings.Repeat("2", 64), Kind: KindMovement, Tags: [][]string{
				{"A", "sidestep"}, {"e", strings.Repeat("0", 64), "", "genesis"}, {"e", hex.EncodeToString(prev), "", "previous"},
				{"c", hex.EncodeToString(from[:])}, {"C", hex.EncodeToString(to[:])}, {"proof", proof},
				{"mr", hex.EncodeToString(mx) + ":" + hex.EncodeToString(my) + ":" + hex.EncodeToString(mz)},
				{"mp", "::" + segment}, {"mn", hex.EncodeToString(nb[:])}, {"hx", "0"}, {"hy", "0"}, {"hz", "4"},
			}}
			mv, _ := ParseMove(evt)
			return mv
		}
	}
	if why := verifySidestep(build(true)); why != "" {
		t.Fatalf("a sidestep that pays its price: %s", why)
	}
	if why := verifySidestep(build(false)); !strings.HasPrefix(why, "mn:") {
		t.Fatalf("a sidestep whose nonce misses the price: want an mn failure, got %q", why)
	}
}
