package regiongate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

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

func (s scriptedProofs) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
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
	if res, why := (SpecProofs{}).Check(context.Background(), Move{}, m); res != ProofVerified {
		t.Fatalf("at the default ceiling: %v %s", res, why)
	}
	if res, why := (SpecProofs{MaxHopHeight: 12}).Check(context.Background(), Move{}, m); res != ProofUnchecked {
		t.Fatalf("above the ceiling: want unchecked, got %v %s", res, why)
	}
	// Exactly at the ceiling is checked (the reviewer's mutation R5).
	if res, why := (SpecProofs{MaxHopHeight: 13}).Check(context.Background(), Move{}, m); res != ProofVerified {
		t.Fatalf("exactly at the ceiling: want verified, got %v %s", res, why)
	}
	// A wrong price is still judged above the ceiling: it costs one attempt.
	bad := hopEvent(strings.Repeat("1", 64), p.PreviousEventID, p.C1, p.C2,
		[]string{"proof", p.Tags.Proof}, []string{"mn", "0000000000000000"}, []string{"mp", p.Tags.Mp})
	if res, why := (SpecProofs{MaxHopHeight: 12}).Check(context.Background(), Move{}, bad); res != ProofInvalid || !strings.HasPrefix(why, ReasonHopProof) {
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

// sidestepCase is a sidestep built from scratch: z crosses one wall from
// zFrom to zTo, x and y stay still. Every value is computed honestly unless
// a field below spoils one, so each test breaks exactly one check.
type sidestepCase struct {
	zFrom, zTo     int64
	unpaid         bool   // a nonce whose G misses the re-roll price
	hz             string // the hz tag, when not the computed height
	badDestination bool   // the destination's path is another leaf's
	badSample      int    // 1 to 8: that sampled path is another leaf's
	badStillRoot   bool   // x's root is not its seeded leaf (§6.11, an axis that does not move)
}

func (o sidestepCase) build(t *testing.T) Move {
	t.Helper()
	prev := bytes.Repeat([]byte{0x5a}, 32)
	x, y := big.NewInt(1<<40), big.NewInt(3<<40)
	from := packCoord(x, y, big.NewInt(o.zFrom), 0)
	to := packCoord(x, y, big.NewInt(o.zTo), 0)
	prefix := func(axis byte) []byte {
		return append(append(append(append([]byte{}, sidestepDomain...), prev...), axis), make([]byte, 9)...)
	}
	h := lcaHeight(big.NewInt(o.zFrom), big.NewInt(o.zTo))
	mx, my := sidestepLeaf(prefix(0), x), sidestepLeaf(prefix(1), y)
	if o.badStillRoot {
		junk := sha256.Sum256([]byte("not the seeded leaf"))
		mx = junk[:]
	}
	mz, path := seededTree(prefix(2), 0, h)
	price := ceilDiv(new(big.Int).Lsh(bigOne, uint(h)), big.NewInt(sidestepSamples))
	other := func(i int) int { return i ^ 1 } // a sibling leaf's path differs at the first level
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
		if meetsPrice(G, price) == o.unpaid {
			continue
		}
		dest := int(o.zTo)
		if o.badDestination {
			dest = other(dest)
		}
		segment := strings.Join(path(dest), "")
		for i := 0; i < sidestepSamples; i++ {
			var ib [4]byte
			binary.BigEndian.PutUint32(ib[:], uint32(i))
			d := sha256.Sum256(append(append(append(append([]byte{}, sidestepSampleDomain...), G...), 2), ib[:]...))
			idx := int(new(big.Int).Mod(new(big.Int).SetBytes(d[:]), new(big.Int).Lsh(bigOne, uint(h))).Int64())
			if o.badSample == i+1 {
				idx = other(idx)
			}
			segment += strings.Join(path(idx), "")
		}
		m := [3]*big.Int{new(big.Int).SetBytes(mx), new(big.Int).SetBytes(my), new(big.Int).SetBytes(mz)}
		region := cantorPair(new(big.Int), cantorPair(new(big.Int), m[0], m[1]), m[2])
		toCoord, _ := ParseCoord(hex.EncodeToString(to[:]))
		proof := doubleSHA256Hex(cantorPair(new(big.Int), region, temporalCantor(prev, terrainK(toCoord))))
		hz := o.hz
		if hz == "" {
			hz = fmt.Sprint(h)
		}
		evt := nostr.Event{ID: strings.Repeat("2", 64), Kind: KindMovement, Tags: [][]string{
			{"A", "sidestep"}, {"e", strings.Repeat("0", 64), "", "genesis"}, {"e", hex.EncodeToString(prev), "", "previous"},
			{"c", hex.EncodeToString(from[:])}, {"C", hex.EncodeToString(to[:])}, {"proof", proof},
			{"mr", hex.EncodeToString(mx) + ":" + hex.EncodeToString(my) + ":" + hex.EncodeToString(mz)},
			{"mp", "::" + segment}, {"mn", hex.EncodeToString(nb[:])}, {"hx", "0"}, {"hy", "0"}, {"hz", hz},
		}}
		mv, _ := ParseMove(evt)
		return mv
	}
}

// Each spoiled sidestep fails Level 1 (§6.3, §6.10, §6.11, §8.7.2), and only
// at the check it spoils; the honest one passes. Each case fails if its
// check is skipped: the reviewer's mutations S1, S2, S3, S5 and S6, and the
// price.
func TestSidestepLevel1Checks(t *testing.T) {
	honest := sidestepCase{zFrom: 7, zTo: 8}
	if why := verifySidestep(honest.build(t)); why != "" {
		t.Fatalf("the honest sidestep: %s", why)
	}
	for _, c := range []struct {
		name   string
		o      sidestepCase
		prefix string
	}{
		{"misses the price", sidestepCase{zFrom: 7, zTo: 8, unpaid: true}, "mn:"},
		{"moves two gibsons (S5)", sidestepCase{zFrom: 7, zTo: 9}, "geometry:"},
		{"moves fifteen gibsons (S5)", sidestepCase{zFrom: 0, zTo: 15}, "geometry:"},
		{"hz names another height (S6)", sidestepCase{zFrom: 7, zTo: 8, hz: "5"}, "hz:"},
		{"hz with a leading zero (S6)", sidestepCase{zFrom: 7, zTo: 8, hz: "04"}, "hz:"},
		{"the destination's path is wrong (S2)", sidestepCase{zFrom: 7, zTo: 8, badDestination: true}, "merkle_z:"},
		{"the last sampled path is wrong (S1)", sidestepCase{zFrom: 7, zTo: 8, badSample: 8}, "merkle_z:"},
		{"the first sampled path is wrong", sidestepCase{zFrom: 7, zTo: 8, badSample: 1}, "merkle_z:"},
		{"a still axis's root is not its leaf (S3)", sidestepCase{zFrom: 7, zTo: 8, badStillRoot: true}, "merkle_x:"},
	} {
		if why := verifySidestep(c.o.build(t)); !strings.HasPrefix(why, c.prefix) {
			t.Errorf("%s: want a %s failure, got %q", c.name, c.prefix, why)
		}
	}
}

// smallHop is a hop short enough that its whole residue list is one block
// (h_max <= 4, so m = 8 and the seal is the one leaf) and its price is one
// attempt, so a test can seal any list it likes and choose, by the nonce,
// where the 16 samples fall.
type smallHop struct {
	prev     []byte
	from, to Coord
	g        hopGeometry
	residues []uint64 // the true residues r_0 .. r_7
}

func newSmallHop(t *testing.T) smallHop {
	t.Helper()
	prev := bytes.Repeat([]byte{0x3c}, 32)
	for y := int64(0); y < 4096; y++ {
		from := Coord{X: big.NewInt(1 << 30), Y: big.NewInt(y << 12), Z: big.NewInt(5 << 20)}
		to := Coord{X: big.NewInt(1<<30 + 9), Y: from.Y, Z: from.Z}
		g := newHopGeometry(prev, from, to)
		if g.hMax > 4 {
			continue
		}
		if g.m.Int64() != 8 || g.depth != 0 || g.price.Int64() != 1 {
			t.Fatalf("expected one block and a price of one attempt, got m %s depth %d A %s", g.m, g.depth, g.price)
		}
		h := smallHop{prev: prev, from: from, to: to, g: g}
		for j := uint64(0); j < 8; j++ {
			h.residues = append(h.residues, g.hopResidue(hopPrime(prev, j)))
		}
		return h
	}
	t.Fatal("no destination with terrain K <= 4 found")
	return smallHop{}
}

// tags seals list, then takes the first nonce whose samples satisfy want,
// and writes the 16 openings; edit, when set, changes opening i's copy of
// the block before it is written.
func (h smallHop) tags(t *testing.T, list []uint64, want func(idx []uint64) bool, edit func(i int, block []uint64)) (proof, mn, mp string) {
	t.Helper()
	seal := hopLeaf(h.prev, 0, list)
	for nonce := uint64(0); nonce < 1<<16; nonce++ {
		G := hopAttempt(h.prev, seal, nonce)
		idx := make([]uint64, hopSamples)
		for i := range idx {
			var ib [4]byte
			binary.BigEndian.PutUint32(ib[:], uint32(i))
			d := sha256.Sum256(append(append(append([]byte{}, hopSampleDomain...), G...), ib[:]...))
			idx[i] = new(big.Int).Mod(new(big.Int).SetBytes(d[:]), big.NewInt(8)).Uint64()
		}
		if !want(idx) {
			continue
		}
		var b strings.Builder
		for i := 0; i < hopSamples; i++ {
			block := append([]uint64{}, list...)
			if edit != nil {
				edit(i, block)
			}
			for _, r := range block {
				b.WriteString(fmt.Sprintf("%016x", r))
			}
		}
		var nb [8]byte
		binary.BigEndian.PutUint64(nb[:], nonce)
		return hex.EncodeToString(seal), hex.EncodeToString(nb[:]), b.String()
	}
	t.Fatal("no nonce draws the samples wanted")
	return
}

// Level 1 checks all 16 openings, the last included (§5.11 step 5): a
// residue that only the 16th sample reads, and a path that only the 16th
// opening spoils, each make the hop invalid. These fail if the check of the
// last sample is skipped (the reviewer's mutations R1 and R2).
func TestHopLevel1ChecksTheLastSample(t *testing.T) {
	h := newSmallHop(t)
	verify := func(proof, mn, mp string) string {
		why, err := verifyHopLevel1(context.Background(), h.prev, h.from, h.to, proof, mn, mp, 32)
		if err != nil {
			t.Fatal(err)
		}
		return why
	}
	any := func([]uint64) bool { return true }
	if why := verify(h.tags(t, h.residues, any, nil)); why != "" {
		t.Fatalf("the honest hop: %s", why)
	}
	// R1: residue j is wrong in the sealed list; only sample 15 reads it.
	const j = 5
	junk := append([]uint64{}, h.residues...)
	junk[j] = (junk[j] + 1) % hopPrime(h.prev, j)
	onlyLast := func(idx []uint64) bool {
		for i, x := range idx {
			if (x == j) != (i == hopSamples-1) {
				return false
			}
		}
		return true
	}
	if why := verify(h.tags(t, junk, onlyLast, nil)); !strings.Contains(why, "opening 15") || !strings.Contains(why, "residue") {
		t.Errorf("a wrong residue read only by sample 15: want a residue failure at opening 15, got %q", why)
	}
	// R2: the list is true, but opening 15's copy of the block differs at a
	// position sample 15 does not read, so its leaf does not climb to the seal.
	var last uint64
	pick := func(idx []uint64) bool { last = idx[hopSamples-1]; return true }
	proof, mn, _ := h.tags(t, h.residues, pick, nil)
	_, _, mp := h.tags(t, h.residues, func(idx []uint64) bool { return idx[hopSamples-1] == last }, func(i int, block []uint64) {
		if i == hopSamples-1 {
			k := (last + 1) % 8
			block[k] = (block[k] + 1) % hopPrime(h.prev, k)
		}
	})
	if why := verify(proof, mn, mp); !strings.Contains(why, "opening 15") || !strings.Contains(why, "path") {
		t.Errorf("opening 15's block altered off its sample: want a path failure at opening 15, got %q", why)
	}
}

// In strict mode the walk stops at the first proof the checker cannot judge:
// nothing after it can move a strict position, so nothing after it is
// checked, however expensive.
func TestStrictWalkStopsAtTheFirstUncheckedProof(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	h2 := b.move(ActHop, offset(t, s.pubkey, 2))
	h3 := b.move(ActHop, offset(t, s.pubkey, 3))
	asked := 0
	v := Verifier{Proofs: scriptedProofs{answers: []ProofResult{ProofUnchecked, ProofInvalid}, asked: &asked}, Signature: validation.CheckSignature, StopAtUnchecked: true}
	vd := v.Verify(s.pubkey, []nostr.Event{b.spawn, h1, h2, h3})
	if asked != 1 {
		t.Fatalf("the checker was asked %d times, want 1", asked)
	}
	if !vd.Valid() || vd.VerifiedEvent != b.spawn.ID || vd.VerifiedPosition.Hex() != s.pubkey || vd.Unchecked != 3 {
		t.Fatalf("want the walk stopped at h1 with the identity at its spawn, got %+v", vd)
	}
	cfg := &Config{Mode: ModeStrict}
	if !NewGate(cfg, verifier()).verifier.StopAtUnchecked || NewGate(&Config{Mode: ModeStructural}, verifier()).verifier.StopAtUnchecked {
		t.Fatal("NewGate must stop the walk in strict mode only")
	}
}

// blockingProofs answers only once its context ends, as a check too long for
// the lookup's deadline.
type blockingProofs struct{ entered chan struct{} }

func (b blockingProofs) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	close(b.entered)
	<-ctx.Done()
	return ProofVerified, "too late"
}

// A check that outlives its caller's deadline is abandoned: the verifier
// returns the context's error, the gate refuses with "try again" without
// caching it, and the lookup slot is free at once.
func TestCheckIsCanceledWithItsCaller(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	hop := b.move(ActHop, offset(t, s.pubkey, 1))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	v := Verifier{Proofs: blockingProofs{entered: make(chan struct{})}, Signature: validation.CheckSignature}
	if _, err := v.VerifyContext(ctx, s.pubkey, []nostr.Event{b.spawn, hop}); err == nil {
		t.Fatal("want the context's error")
	}

	cfg := &Config{Enabled: true, Mode: ModeStructural, CacheTTLSeconds: 600, NegativeCacheTTLSeconds: 60,
		MaxConcurrentLookups: 1, boxes: []Box{cubeAround(t, s.pubkey, 40)}, exempt: map[string]bool{}}
	g := NewGate(cfg, Verifier{Proofs: blockingProofs{entered: make(chan struct{})}, Signature: validation.CheckSignature}, &fakeSource{events: []nostr.Event{b.spawn, hop}})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	start := time.Now()
	ok, msg := g.Admit(ctx2, s.sign(t, 1, 1))
	if ok || msg != errTimeout || time.Since(start) > 2*time.Second {
		t.Fatalf("want a prompt %q, got %v %q after %v", errTimeout, ok, msg, time.Since(start))
	}
	if n := len(g.lookups); n != 0 {
		t.Fatalf("%d lookup slots still held after the caller timed out", n)
	}
	if _, hit := g.cache[s.pubkey]; hit {
		t.Fatal("a timed-out lookup was cached as a verdict")
	}
}

// A residue computation and an exact Cantor tree both give up once their
// context ends, so an abandoned tall hop or ride stops using the CPU.
func TestLongComputationsStopOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	residueRootCtx(ctx, big.NewInt(0), 32, hopPrime(make([]byte, 32), 0)) // seconds if it ran
	if subtreeCantorCtx(ctx, big.NewInt(0), 22) != nil {
		t.Fatal("a canceled exact tree returned a root")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("canceled computations ran for %v", d)
	}
}

// The ceiling defaults to 24 and is capped where the residue count stops
// fitting a machine word.
func TestHopCeilingSetting(t *testing.T) {
	base := "enabled: true\nchain_relays: [wss://a.example]\nregions:\n  - {sector: \"5-6-7\", plane: 1}\n"
	c, err := ParseConfig([]byte(base))
	if err != nil || c.MaxHopVerifyHeight != 24 {
		t.Fatalf("default: %v %v", c, err)
	}
	if c, err := ParseConfig([]byte(base + "max_hop_verify_height: 65\n")); err != nil || c.MaxHopVerifyHeight != 65 {
		t.Fatalf("65 should be allowed: %v", err)
	}
	if _, err := ParseConfig([]byte(base + "max_hop_verify_height: 66\n")); err == nil {
		t.Fatal("66 should be refused")
	}
	if !residueCount(MaxHopVerifyHeightLimit).IsUint64() || residueCount(MaxHopVerifyHeightLimit+1).IsUint64() {
		t.Fatal("the limit is not where m stops fitting 64 bits")
	}
}

// A version 1 sidestep is refused as one (§6.15), not as an unlisted
// version 2 sidestep: the three real chains frozen by one say so.
func TestVersion1SidestepIsNamed(t *testing.T) {
	vf := loadVectors(t, realVectorsFile)
	v := Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}
	n := 0
	for _, vec := range vf.Vectors {
		if vec.Expected.Reason != ReasonSidestepProof {
			continue
		}
		n++
		vd := v.Verify(vec.Identity, parseEvents(vec.Events))
		if !strings.Contains(vd.Stopped, "version 1 sidestep") || !strings.Contains(vd.Stopped, "invalid since 2026-09-07 (spec §6.15)") || strings.Contains(vd.Stopped, "version 2") {
			t.Errorf("%s: %s", vec.Name, vd.Stopped)
		}
	}
	if n != 3 {
		t.Fatalf("%d real chains frozen by a sidestep, want 3", n)
	}
}

// A check cut short by its context has judged nothing, so it answers
// ProofUnchecked, never a verdict: a forged hop is not Verified and a valid
// ride is not Invalid because the caller gave up (a verdict cache builds on
// these answers).
func TestCanceledCheckIsUnchecked(t *testing.T) {
	live := context.Background()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	// A forged hop: form and price hold, every residue in its sealed list is wrong.
	h := newSmallHop(t)
	junk := make([]uint64, 8)
	for j := range junk {
		junk[j] = (h.residues[j] + 1) % hopPrime(h.prev, uint64(j))
	}
	proof, mn, mp := h.tags(t, junk, func([]uint64) bool { return true }, nil)
	forged := hopEvent(strings.Repeat("4", 64), hex.EncodeToString(h.prev), h.from.Hex(), h.to.Hex(),
		[]string{"proof", proof}, []string{"mn", mn}, []string{"mp", mp})
	if res, why := (SpecProofs{}).Check(live, Move{}, forged); res != ProofInvalid {
		t.Fatalf("the forged hop, not canceled: want invalid, got %v %s", res, why)
	}
	if res, why := (SpecProofs{}).Check(canceled, Move{}, forged); res != ProofUnchecked {
		t.Fatalf("the forged hop, canceled: want unchecked, got %v %s", res, why)
	}

	// A valid ride from the spec's vectors, with its line.
	vf := loadVectors(t, vectorsFile)
	line, err := NewStaticLine(vf.Line.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	for _, vec := range vf.Vectors {
		if vec.Name != "ride-valid" {
			continue
		}
		byID := map[string]Move{}
		for _, e := range parseEvents(vec.Events) {
			m, _ := ParseMove(e)
			byID[e.ID] = m
		}
		board, ride := byID[vec.Expected.Chain[2]], byID[vec.Expected.Chain[3]]
		if board.Action != ActEnterHyperspace || ride.Action != ActHyperjump {
			t.Fatalf("unexpected ride-valid chain: %s then %s", board.Action, ride.Action)
		}
		checker := SpecProofs{Line: line}
		if res, why := checker.Check(live, board, ride); res != ProofVerified {
			t.Fatalf("the valid ride, not canceled: want verified, got %v %s", res, why)
		}
		if res, why := checker.Check(canceled, board, ride); res != ProofUnchecked {
			t.Fatalf("the valid ride, canceled: want unchecked, got %v %s", res, why)
		}
		return
	}
	t.Fatal("no ride-valid vector")
}
