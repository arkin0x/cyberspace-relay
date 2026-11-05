package regiongate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/bits"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// growingLine is the golden vectors' line as a line that lags: it holds
// heights up to tip only, and a height above is not known yet (it is not
// Complete), as an AnchorLine is.
type growingLine struct {
	inner *StaticLine
	mu    sync.Mutex
	tip   uint64
	epoch uint64
}

func (l *growingLine) Tip() (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tip, true
}
func (l *growingLine) grow(tip uint64) { l.mu.Lock(); l.tip = tip; l.mu.Unlock() }
func (l *growingLine) Name() string    { return "growing" }
func (l *growingLine) Epoch() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.epoch
}
func (l *growingLine) held(h uint64) bool { t, _ := l.Tip(); return h <= t }
func (l *growingLine) Stop(h uint64) (string, bool) {
	if !l.held(h) {
		return "", false
	}
	return l.inner.Stop(h)
}
func (l *growingLine) BlockHash(h uint64) ([]byte, bool) {
	if !l.held(h) {
		return nil, false
	}
	return l.inner.BlockHash(h)
}
func (l *growingLine) Station(c Coord, bound uint64) uint64 { return l.inner.Station(c, bound) }

// countedSpec is SpecProofs counting what it is asked, by event id.
type countedSpec struct {
	SpecProofs
	mu    sync.Mutex
	asked map[string]int
	// during, when set, runs on each ride asked about.
	during func()
}

func (c *countedSpec) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	c.mu.Lock()
	c.asked[cur.Event.ID]++
	c.mu.Unlock()
	if c.during != nil && cur.Action == ActHyperjump {
		c.during()
	}
	return c.SpecProofs.Check(ctx, prev, cur)
}

func (c *countedSpec) times(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asked[id]
}

// rideValid is the spec's ride-valid vector: its events, ids in chain
// order (spawn, hop, enter-hyperspace, ride from 2 to 4 with as_of 5, ride
// to 3, hop), its identity and its line.
func rideValid(t *testing.T) ([]nostr.Event, []string, string, *StaticLine) {
	t.Helper()
	vf := loadVectors(t, vectorsFile)
	line, err := NewStaticLine(vf.Line.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	for _, vec := range vf.Vectors {
		if vec.Name == "ride-valid" {
			return parseEvents(vec.Events), vec.Expected.Chain, vf.TestKey.Pubkey, line
		}
	}
	t.Fatal("no ride-valid vector")
	return nil, nil, "", nil
}

// TestRideWaitingForTheLineIsNeverAFailure is the owner's ruling of
// 2026-11-05: a ride whose as_of the line has not reached is not judged,
// so the identity stays where it boarded (strict), no failure point is
// kept, and once the line holds the height the chain is checked again at
// once, cache or not, and the ride lands.
func TestRideWaitingForTheLineIsNeverAFailure(t *testing.T) {
	ctx := context.Background()
	events, chain, pubkey, static := rideValid(t)
	var final string
	for _, e := range events {
		if e.ID == chain[len(chain)-1] {
			final = tagValues(e, "C")[0]
		}
	}
	box := cubeAround(t, final, 8)
	if box.Contains(mustCoord(t, pubkey)) {
		t.Fatal("the region holds the spawn")
	}
	line := &growingLine{inner: static, tip: 4} // the first ride's as_of is 5
	proofs := &countedSpec{SpecProofs: SpecProofs{Line: line, ListedV1Hops: map[string]bool{}}, asked: map[string]int{}}
	g, _ := cacheGate(t, ModeStrict, box, proofs, &fakeSource{events: events})

	if ok, why := g.AdmitPubkey(ctx, pubkey); ok {
		t.Fatalf("admitted before the line holds as_of: %s", why)
	}
	e := g.entry(pubkey)
	if e == nil || e.vd.Reason != "" || e.known.FailAt != "" || e.known.StopAt != chain[3] || e.known.LineWait != 5 {
		t.Fatalf("want a valid chain stopped at the first ride, waiting for block 5; got %+v %+v", e.vd, e.known)
	}
	if _, _, failed := g.failedEvent(chain[3]); failed {
		t.Fatal("the waiting ride is in the failed set")
	}
	if ok, _ := g.AdmitPubkey(ctx, pubkey); ok || proofs.times(chain[3]) != 1 {
		t.Fatalf("the line has not grown: the answer should stand from the cache (ride asked %d times)", proofs.times(chain[3]))
	}

	line.grow(7)
	if ok, why := g.AdmitPubkey(ctx, pubkey); !ok {
		t.Fatalf("not admitted once the line holds the rides' blocks: %s", why)
	}
	if e := g.entry(pubkey); e.vd.Unchecked != 0 || e.vd.VerifiedEvent != chain[len(chain)-1] || e.known.LineWait != 0 {
		t.Fatalf("want every proof verified to the head; got %+v %+v", e.vd, e.known)
	}
}

// TestStructuralWalkKeepsWaitingAcrossIncrementalChecks: in structural mode
// the walk goes on past a waiting ride; a later incremental check over new
// events keeps the wait, and the ride is checked once the line grows.
func TestStructuralWalkKeepsWaitingAcrossIncrementalChecks(t *testing.T) {
	ctx := context.Background()
	events, chain, pubkey, static := rideValid(t)
	line := &growingLine{inner: static, tip: 4}
	proofs := &countedSpec{SpecProofs: SpecProofs{Line: line, ListedV1Hops: map[string]bool{}}, asked: map[string]int{}}
	// The chain without its last hop, then that hop as a new event.
	var head, last nostr.Event
	var first []nostr.Event
	for _, e := range events {
		switch e.ID {
		case chain[len(chain)-1]:
			last = e
		default:
			first = append(first, e)
		}
		if e.ID == chain[len(chain)-2] {
			head = e
		}
	}
	src := &fakeSource{events: first}
	g, clock := cacheGate(t, ModeStructural, cubeAround(t, tagValues(head, "C")[0], 84), proofs, src)
	g.AdmitPubkey(ctx, pubkey)
	if e := g.entry(pubkey); e.known.LineWait != 5 || e.vd.Unchecked == 0 {
		t.Fatalf("want rides unchecked, waiting for block 5: %+v %+v", e.vd, e.known)
	}
	src.mu.Lock()
	src.events = append(src.events, last)
	src.mu.Unlock()
	clock.add(time.Hour) // past the cache's life: an incremental check
	g.AdmitPubkey(ctx, pubkey)
	if e := g.entry(pubkey); e.vd.Head != last.ID || e.known.LineWait != 5 {
		t.Fatalf("the incremental check lost the wait: head %s, %+v", e.vd.Head, e.known)
	}
	clock.add(resyncAfter) // the daily whole read, which answers from Known
	g.AdmitPubkey(ctx, pubkey)
	if e := g.entry(pubkey); e.known.LineWait != 5 || proofs.times(chain[3]) != 1 {
		t.Fatalf("the whole read lost the wait or asked the ride again: %+v, asked %d", e.known, proofs.times(chain[3]))
	}
	line.grow(7)
	g.AdmitPubkey(ctx, pubkey)
	if e := g.entry(pubkey); e.vd.Unchecked != 0 || proofs.times(chain[3]) != 2 {
		t.Fatalf("the ride was not checked again once the line grew: %+v, asked %d", e.vd, proofs.times(chain[3]))
	}
}

// TestALineReorganizingDuringACheckKeepsNothing: what a check read may
// come from both sides of a reorganization, so its result is not stored.
func TestALineReorganizingDuringACheckKeepsNothing(t *testing.T) {
	events, chain, pubkey, static := rideValid(t)
	line := &growingLine{inner: static, tip: 7}
	proofs := &countedSpec{SpecProofs: SpecProofs{Line: line, ListedV1Hops: map[string]bool{}}, asked: map[string]int{}}
	proofs.during = func() { line.mu.Lock(); line.epoch = 1; line.mu.Unlock(); proofs.during = nil }
	var final string
	for _, e := range events {
		if e.ID == chain[len(chain)-1] {
			final = tagValues(e, "C")[0]
		}
	}
	g, _ := cacheGate(t, ModeStrict, cubeAround(t, final, 8), proofs, &fakeSource{events: events})
	rules := g.rules()
	if ok, why := g.AdmitPubkey(context.Background(), pubkey); ok || why != errBusy {
		t.Fatalf("want try again, got %v %q", ok, why)
	}
	if g.rules() == rules || !strings.Contains(g.rules(), "line=growing@1") {
		t.Fatalf("rules %q do not carry the line's epoch", g.rules())
	}
	if g.entry(pubkey) != nil {
		t.Fatal("an entry was kept from a check the reorganization cut across")
	}
	if ok, why := g.AdmitPubkey(context.Background(), pubkey); !ok {
		t.Fatalf("the next check is not admitted: %s", why)
	}
}

// TestCheckpointKeepsTheEntrysLineWait: a checkpoint merged with the
// entry's Known keeps the height a ride waits for.
func TestCheckpointKeepsTheEntrysLineWait(t *testing.T) {
	g, _ := cacheGate(t, ModeStrict, cubeAround(t, strings.Repeat("0", 64), 8), SpecProofs{}, &fakeSource{})
	g.progress["pk"] = &Known{Genesis: "s", Passed: "a"}
	kn := g.knownFor("pk", &chainEntry{known: &Known{Genesis: "s", StopAt: "r", LineWait: 5}})
	if len(kn) == 0 || kn[0].LineWait != 5 || kn[0].StopAt != "r" {
		t.Fatalf("merged %+v", kn[0])
	}
}

// TestCheckpointFromAnotherLineIsNotUsed: a checkpoint made before a
// reorganization answers for nothing after it.
func TestCheckpointFromAnotherLineIsNotUsed(t *testing.T) {
	_, _, _, static := rideValid(t)
	line := &growingLine{inner: static, tip: 7}
	g, _ := cacheGate(t, ModeStrict, cubeAround(t, strings.Repeat("0", 64), 8), SpecProofs{Line: line}, &fakeSource{})
	g.saveProgress("pk", &walker{genesis: "s", passed: "a"})
	if kn := g.knownFor("pk", nil); len(kn) != 1 {
		t.Fatalf("the checkpoint is not used on its own line: %v", kn)
	}
	line.mu.Lock()
	line.epoch++
	line.mu.Unlock()
	if kn := g.knownFor("pk", nil); len(kn) != 0 {
		t.Fatalf("a checkpoint from before the reorganization is used: %+v", kn[0])
	}
}

func TestFailuresAreKeptWithTheirRules(t *testing.T) {
	f := newFailedSet()
	id := strings.Repeat("ab", 32)
	f.add(&Known{FailAt: id, FailReason: ReasonHyperjumpStop, Stopped: "x"}, "rules line=a@0")
	if _, ok := f.get(id, "rules line=a@0"); !ok {
		t.Fatal("not kept")
	}
	if _, ok := f.get(id, "rules line=a@1"); ok {
		t.Fatal("a failure found on another line is used")
	}
	f.add(&Known{FailAt: id, FailReason: ReasonHyperjumpStop, Stopped: "y"}, "rules line=a@1")
	if x, ok := f.get(id, "rules line=a@1"); !ok || x.stopped != "y" {
		t.Fatal("a failure found again on the new line is not kept")
	}
}

// ── the ride proof's work ────────────────────────────────────────────────

// leafLog records the blocks whose leaves are computed, in order.
func leafLog(t *testing.T, also func()) *[]uint64 {
	var got []uint64
	var mu sync.Mutex
	rideLeafHook = func(b uint64) {
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
		if also != nil {
			also()
		}
	}
	t.Cleanup(func() { rideLeafHook = nil })
	return &got
}

func rideMoves(t *testing.T) (Move, Move, *StaticLine) {
	events, chain, _, line := rideValid(t)
	byID := map[string]Move{}
	for _, e := range events {
		m, _ := ParseMove(e)
		byID[e.ID] = m
	}
	return byID[chain[2]], byID[chain[3]], line
}

// TestRideLeavesAreComputedOncePerBlock: the first ride of ride-valid
// passes 2 blocks, so its 32 samples hold 2 blocks, and 2 leaves are
// computed, not 32.
func TestRideLeavesAreComputedOncePerBlock(t *testing.T) {
	board, ride, line := rideMoves(t)
	kept := leafLog(t, nil)
	sp := SpecProofs{Line: line} // no progress kept: nothing but the dedupe saves work
	if res, why := sp.Check(context.Background(), board, ride); res != ProofVerified {
		t.Fatalf("%v %s", res, why)
	}
	if len(*kept) != 2 {
		t.Fatalf("%d leaves computed for a 2-block ride", len(*kept))
	}
}

// syntheticRide is a line of blocks with chosen leaf heights and a ride over
// them with a forged root: the samples, the heights and the line.
func syntheticRide(t *testing.T, heights []int) (Move, *StaticLine) {
	t.Helper()
	blocks := make([]LineBlock, len(heights))
	var n uint64
	for h, want := range heights {
		for ; ; n++ {
			var hash [32]byte
			hash[0], hash[1] = byte(h), 0xee
			for i := 0; i < 8; i++ {
				hash[2+i] = byte(n >> (8 * i))
			}
			if rideLeafHeight(hash[:]) == want {
				c := strings.Repeat("0", 63) + "1"
				blocks[h] = LineBlock{Height: uint64(h), BlockHash: hex.EncodeToString(hash[:]), MerkleRoot: c, Coord: c}
				n++
				break
			}
		}
	}
	line, err := NewStaticLine(blocks)
	if err != nil {
		t.Fatal(err)
	}
	depth := bits.Len64(uint64(len(heights) - 2))
	paths := make([]string, rideSamples)
	for i := range paths {
		paths[i] = strings.Repeat("11", 32*depth)
	}
	ev := nostr.Event{ID: strings.Repeat("cd", 32), Tags: [][]string{{"A", ActHyperjump}, {"e", strings.Repeat("ef", 32), "", "previous"},
		{"proof", strings.Repeat("22", 32)}, {"mn", "0000000000000001"}, {"mp", strings.Join(paths, ":")},
		{"from_height", "0"}, {"B", "0"}}}
	return Move{Event: ev, Action: ActHyperjump, Previous: strings.Repeat("ef", 32)}, line
}

// TestAForgedRideFailsOnItsCheapestSample: of the sampled blocks, the
// cheapest leaf is computed first, so a forged root costs that leaf only.
func TestAForgedRideFailsOnItsCheapestSample(t *testing.T) {
	// Block 0 is where the ride starts; blocks 1 to 8 are passed, one cheap
	// (h6) among tall ones (h17).
	heights := []int{6, 17, 17, 17, 6, 17, 17, 17, 17}
	m, line := syntheticRide(t, heights)
	kept := leafLog(t, nil)
	rp := NewRideProgress(8)
	why, err := verifyRideProof(context.Background(), line, m, 0, uint64(len(heights)-1), &rideKept{p: rp, id: m.Event.ID})
	if err != nil || !strings.Contains(why, "does not reach the root") {
		t.Fatalf("want a failed opening, got %q %v", why, err)
	}
	if len(*kept) != 1 || (*kept)[0] != 4 {
		t.Fatalf("leaves computed before the forged root failed: %v, want only the cheap block 4", *kept)
	}
}

// TestACutShortRideGoesOnFromItsLeaves: a check its deadline cuts short
// after one leaf keeps it; the next check computes only the others.
func TestACutShortRideGoesOnFromItsLeaves(t *testing.T) {
	board, ride, line := rideMoves(t)
	ctx, cancel := context.WithCancel(context.Background())
	kept := leafLog(t, cancel)
	sp := SpecProofs{Line: line, RideProgress: NewRideProgress(8)}
	if res, _ := sp.Check(ctx, board, ride); res != ProofUnchecked {
		t.Fatalf("a check cut short gave %v", res)
	}
	if len(*kept) != 1 {
		t.Fatalf("%d leaves before the cut", len(*kept))
	}
	rideLeafHook = func(b uint64) { *kept = append(*kept, b) }
	if res, why := sp.Check(context.Background(), board, ride); res != ProofVerified {
		t.Fatalf("%v %s", res, why)
	}
	if len(*kept) != 2 {
		t.Fatalf("%d leaves computed in all, want 2: the kept leaf was computed again", len(*kept))
	}
	if len(sp.RideProgress.byID) != 0 {
		t.Fatal("a judged ride's progress is kept")
	}
}

// stepCtx is a context that ends after its Err has been asked n times.
type stepCtx struct {
	context.Context
	left atomic.Int64
}

func (c *stepCtx) Err() error {
	if c.left.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

// TestCantorTreeResumes: a tree cut short at any point and run again gives
// the root an uninterrupted run gives.
func TestCantorTreeResumes(t *testing.T) {
	base := new(big.Int).Lsh(big.NewInt(12345), 40)
	// A tree checks ctx once every 1024 leaves, and after each pairing from
	// level 16 up: cut every 64 checks, an h17 tree stops inside settle.
	for _, c := range []struct {
		height int
		every  []int64
	}{{11, []int64{1}}, {17, []int64{1, 5, 40, 64}}} {
		height := c.height
		want := subtreeCantor(base, height)
		for _, every := range c.every {
			tree := newCantorTree(base, height)
			runs := 0
			for {
				runs++
				ctx := &stepCtx{Context: context.Background()}
				ctx.left.Store(every)
				if got, ok := tree.run(ctx); ok {
					if got.Cmp(want) != 0 {
						t.Fatalf("h%d cut every %d checks: wrong root after %d runs", height, every, runs)
					}
					break
				}
			}
			if runs < 2 {
				t.Fatalf("h%d: never cut short", height)
			}
		}
	}
}

// TestTallLeavesTakeTurns: while one tall leaf is computed, another waits,
// and gives up at its deadline without starting.
func TestTallLeavesTakeTurns(t *testing.T) {
	tallLeaves <- struct{}{}
	defer func() { <-tallLeaves }()
	rp := NewRideProgress(4)
	hash := make([]byte, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := rideLeafKept(ctx, make([]byte, 32), 7, hash, tallLeafHeight, &rideKept{p: rp, id: "x"})
	if err != errRideCut || rp.tree != nil || time.Since(start) > 2*time.Second {
		t.Fatalf("a tall leaf did not wait its turn: %v, tree kept %v", err, rp.tree != nil)
	}
}

// TestSquareByFFTIsExact: the FFT product is math/big's, at sizes around
// the switch.
func TestSquareByFFTIsExact(t *testing.T) {
	for _, words := range []int{fftWords - 1, fftWords, fftWords + 1, 3 * fftWords} {
		b := make([]byte, 8*words)
		for i := range b {
			b[i] = byte(i*131 + words)
		}
		s := new(big.Int).SetBytes(b)
		if square(s).Cmp(new(big.Int).Mul(s, s)) != 0 {
			t.Fatalf("square differs at %d words", words)
		}
	}
}

// TestLandfallMainnetSample: 1000 mainnet landfalls, as the reference
// derives them (the whole line is TestLandfallAgreesWithTheReferenceLine).
func TestLandfallMainnetSample(t *testing.T) {
	data, err := os.ReadFile("testdata/landfall-mainnet-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Landfalls []struct {
			Height    uint64
			BlockHash string `json:"block_hash"`
			Coord     string
		}
	}
	if err := json.Unmarshal(data, &f); err != nil || len(f.Landfalls) != 1000 {
		t.Fatalf("sample: %v, %d", err, len(f.Landfalls))
	}
	for _, l := range f.Landfalls {
		h, _ := hex.DecodeString(l.BlockHash)
		if got := LandfallCoord(h); hex.EncodeToString(got[:]) != l.Coord {
			t.Fatalf("block %d: %x, the reference %s", l.Height, got, l.Coord)
		}
	}
}
