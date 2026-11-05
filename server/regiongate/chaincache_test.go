package regiongate

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"
)

// ── fixtures ──────────────────────────────────────────────────────────

// countingProofs answers each proof from a table by event id (verified when
// absent) and counts how often each event is asked about. An event in block
// is answered only once the check's context ends.
type countingProofs struct {
	mu      sync.Mutex
	answers map[string]ProofResult
	asks    map[string]int
	block   map[string]bool
	entered chan struct{}
}

func newCountingProofs() *countingProofs {
	return &countingProofs{answers: map[string]ProofResult{}, asks: map[string]int{}, block: map[string]bool{}, entered: make(chan struct{}, 16)}
}

func (c *countingProofs) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	c.mu.Lock()
	c.asks[cur.Event.ID]++
	res, block := c.answers[cur.Event.ID], c.block[cur.Event.ID]
	c.mu.Unlock()
	if block {
		c.entered <- struct{}{}
		<-ctx.Done()
		return ProofVerified, "too late"
	}
	switch res {
	case ProofInvalid:
		return ProofInvalid, ReasonHopProof + ": forged"
	case ProofUnchecked:
		return ProofUnchecked, "too tall"
	}
	return ProofVerified, ""
}

func (c *countingProofs) asked(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asks[id]
}

func (c *countingProofs) set(id string, r ProofResult) {
	c.mu.Lock()
	c.answers[id] = r
	c.mu.Unlock()
}

// testClock is a clock the test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// cacheGate is a gate over src with a real signature check and proofs, on a
// clock the test moves.
func cacheGate(t *testing.T, mode Mode, box Box, proofs ProofChecker, src Source) (*Gate, *testClock) {
	t.Helper()
	cfg := &Config{Enabled: true, Mode: mode, AlwaysAllowKinds: []int{5}, CacheTTLSeconds: 600,
		NegativeCacheTTLSeconds: 60, FetchTimeoutSeconds: 8, CheckTimeoutSeconds: 5, boxes: []Box{box}, exempt: map[string]bool{}}
	g := NewGate(cfg, Verifier{Proofs: proofs, Signature: validation.CheckSignature}, src)
	clock := &testClock{t: time.Now()}
	g.now = clock.now
	return g, clock
}

func (g *Gate) entry(pubkey string) *chainEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.chains.get(pubkey, g.rules)
}

// insideTarget is a signer, a target coordinate away from its spawn and a
// region around the target that does not hold the spawn.
func insideTarget(t *testing.T) (*signer, string, Box) {
	t.Helper()
	for {
		s := newSigner(t)
		target := offset(t, s.pubkey, 1<<45)
		box := cubeAround(t, target, 20)
		if !box.Contains(mustCoord(t, s.pubkey)) {
			return s, target, box
		}
	}
}

// ── the re-send DoS (cyberspace-relay #11 review) ─────────────────────

// N sends of one forged proof cost one check in total: re-sent one after
// another, all at once, after the entry has expired, and when the chain is
// read whole again a day later. Within the TTL a re-send asks no source at
// all. The forgery may be backdated before the look-back window; it is
// still the chain's failure point and answered from the entry.
func TestResentForgeryCostsOneCheck(t *testing.T) {
	for _, backdated := range []bool{false, true} {
		t.Run(fmt.Sprintf("backdated=%v", backdated), func(t *testing.T) {
			ctx := context.Background()
			s, target, box := insideTarget(t)
			b := newChain(t, s)
			in := b.move(ActHop, target)
			if backdated {
				b.at = in.CreatedAt - 2*lookbackSeconds
			}
			forged := b.move(ActHop, offset(t, target, 1<<30))
			proofs := newCountingProofs()
			proofs.set(forged.ID, ProofInvalid)
			src := &fakeSource{events: []nostr.Event{b.spawn, in}}
			g, clock := cacheGate(t, ModeStructural, box, proofs, src)

			// Frozen at `in`, inside the region: admitted, and frozen there.
			if ok, msg := g.Admit(ctx, forged); !ok {
				t.Fatalf("a forged hop freezes the chain at its last valid position, inside: %s", msg)
			}
			if e := g.entry(s.pubkey); e == nil || e.known == nil || e.known.FailAt != forged.ID {
				t.Fatalf("want the failure point cached at the forged hop, got %+v", e)
			}
			calls := src.calls.Load()
			for i := 0; i < 50; i++ {
				if ok, _ := g.Admit(ctx, forged); !ok {
					t.Fatal("a re-send changed the verdict")
				}
			}
			if n := src.calls.Load() - calls; n != 0 {
				t.Fatalf("re-sends within the TTL asked the sources %d times, want 0", n)
			}
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); g.Admit(ctx, forged) }()
			}
			wg.Wait()
			clock.add(601 * time.Second)
			g.Admit(ctx, forged)
			clock.add(25 * time.Hour) // read whole again
			if ok, _ := g.Admit(ctx, forged); !ok {
				t.Fatal("the whole re-read changed the verdict")
			}
			if e := g.entry(s.pubkey); !g.now().Equal(e.wholeAt) {
				t.Fatal("the chain was not read whole again after a day")
			}
			if n := proofs.asked(forged.ID); n != 1 {
				t.Fatalf("the forged hop was checked %d times, want 1", n)
			}
			if n := proofs.asked(in.ID); n != 1 {
				t.Fatalf("the valid hop before it was checked %d times, want 1", n)
			}
		})
	}
}

// A valid proof is checked once: sent again, read by readers, and with the
// chain extended after it, only the new events are checked.
func TestValidHopIsCheckedOnce(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	proofs := newCountingProofs()
	g, clock := cacheGate(t, ModeStructural, box, proofs, src)
	tall := b.move(ActHop, target)
	if ok, msg := g.Admit(ctx, tall); !ok {
		t.Fatalf("the move in: %s", msg)
	}
	src.mu.Lock()
	src.events = append(src.events, tall)
	src.mu.Unlock()
	for i := 0; i < 10; i++ {
		g.Admit(ctx, tall)
		g.AdmitPubkey(ctx, s.pubkey)
	}
	clock.add(601 * time.Second)
	g.AdmitPubkey(ctx, s.pubkey)
	next := b.move(ActHop, offset(t, target, 1))
	if ok, msg := g.Admit(ctx, next); !ok {
		t.Fatalf("the next hop: %s", msg)
	}
	if n, m := proofs.asked(tall.ID), proofs.asked(next.ID); n != 1 || m != 1 {
		t.Fatalf("checks: tall hop %d, next hop %d; want 1 each", n, m)
	}
	if e := g.entry(s.pubkey); e.vd.Head != next.ID || e.vd.PositionEvent != next.ID || e.walk == nil {
		t.Fatalf("the head was not walked on to: %+v", e.vd)
	}
}

// ── the incremental check ─────────────────────────────────────────────

// A newer spawn starts a new chain: the entry is flushed and the new chain
// checked from scratch, so the old chain's frozen position no longer counts.
func TestGenesisChangeFlushesTheEntry(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	in := b.move(ActHop, target)
	forged := b.move(ActHop, offset(t, target, 1<<30))
	proofs := newCountingProofs()
	proofs.set(forged.ID, ProofInvalid)
	src := &fakeSource{events: []nostr.Event{b.spawn, in, forged}}
	g, clock := cacheGate(t, ModeStructural, box, proofs, src)
	if ok, msg := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatalf("frozen inside: %s", msg)
	}

	// A respawn, published elsewhere: the identity is back at its spawn
	// coordinate, outside the region.
	respawn := s.sign(t, KindMovement, b.at+100, append([][]string{{"A", ActSpawn}, {"C", s.pubkey}}, sectorTags(t, s.pubkey)...)...)
	src.mu.Lock()
	src.events = append(src.events, respawn)
	src.mu.Unlock()
	clock.add(601 * time.Second)
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); ok {
		t.Fatal("the old chain's frozen position still admits after a respawn")
	}
	e := g.entry(s.pubkey)
	if e.genesis != respawn.ID || e.vd.Head != respawn.ID || e.known == nil || e.known.FailAt != "" || e.walk == nil {
		t.Fatalf("want a fresh entry for the new chain, got genesis %s head %s known %+v", e.genesis, e.vd.Head, e.known)
	}
	// The new chain is walked on from its own head.
	b2 := &chainBuilder{t: t, s: s, at: respawn.CreatedAt, spawn: respawn, last: respawn, pos: s.pubkey}
	if ok, msg := g.Admit(ctx, b2.move(ActHop, target)); !ok {
		t.Fatalf("a move in on the new chain: %s", msg)
	}
}

// An event that names anything but the cached head as previous is not
// walked on from the head: a fork, or a gap the look-back did not fill,
// reads the chain whole.
func TestForkOrGapReadsTheChainWhole(t *testing.T) {
	ctx := context.Background()
	t.Run("fork", func(t *testing.T) {
		s, target, box := insideTarget(t)
		b := newChain(t, s)
		h1 := b.move(ActHop, target)
		branch := *b
		h2 := b.move(ActHop, offset(t, target, 1))
		src := &fakeSource{events: []nostr.Event{b.spawn, h1, h2}}
		g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
		if ok, msg := g.AdmitPubkey(ctx, s.pubkey); !ok {
			t.Fatalf("inside: %s", msg)
		}
		// A second child of h1, behind the head: the chain is dead.
		src.mu.Lock()
		src.events = append(src.events, branch.move(ActHop, offset(t, target, 2)))
		src.mu.Unlock()
		clock.add(601 * time.Second)
		if ok, _ := g.AdmitPubkey(ctx, s.pubkey); ok {
			t.Fatal("a fork behind the head must kill the chain (spawn coordinate, outside)")
		}
		if e := g.entry(s.pubkey); e.vd.Reason != ReasonFork {
			t.Fatalf("want a fork verdict, got %q", e.vd.Reason)
		}
	})
	t.Run("gap", func(t *testing.T) {
		s, target, box := insideTarget(t)
		b := newChain(t, s)
		h1 := b.move(ActHop, target)
		src := &fakeSource{events: []nostr.Event{b.spawn, h1}}
		g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
		if ok, msg := g.AdmitPubkey(ctx, s.pubkey); !ok {
			t.Fatalf("inside: %s", msg)
		}
		// n1 is signed long before the head's time (outside the look-back),
		// n2 after it; only n2 is new to an incremental question.
		b.at = h1.CreatedAt - 2*lookbackSeconds
		n1 := b.move(ActHop, offset(t, target, 1<<30))
		b.at = h1.CreatedAt + 100
		n2 := b.move(ActHop, offset(t, target, 1<<31))
		src.mu.Lock()
		src.events = append(src.events, n1, n2)
		src.mu.Unlock()
		clock.add(601 * time.Second)
		if ok, _ := g.AdmitPubkey(ctx, s.pubkey); ok {
			t.Fatal("the identity has moved out through n1 and n2")
		}
		if e := g.entry(s.pubkey); e.vd.Head != n2.ID {
			t.Fatalf("want the head at n2 after reading whole, got %s", e.vd.Head)
		}
	})
}

// An event signed before the highest created_at the cache holds, and
// published after the cache read it, is caught by the look-back.
func TestLookBackCatchesALatePublishedEvent(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, target)
	b.at = h1.CreatedAt + 1000
	h2 := b.move(ActHop, offset(t, target, 1))
	src := &fakeSource{events: []nostr.Event{b.spawn, h1, h2}}
	g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	if ok, msg := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatalf("inside: %s", msg)
	}
	// Signed with a clock ten minutes slow, published later elsewhere: it
	// leaves the region.
	b.at = h2.CreatedAt - 600
	late := b.move(ActHop, offset(t, target, 1<<30))
	src.mu.Lock()
	src.events = append(src.events, late)
	src.mu.Unlock()
	clock.add(601 * time.Second)
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); ok {
		t.Fatal("the late-published move out was missed")
	}
	if e := g.entry(s.pubkey); e.vd.Head != late.ID || e.highest != h2.CreatedAt {
		t.Fatalf("want the head at the late event and the highest created_at kept, got %s %d", e.vd.Head, e.highest)
	}
}

// A check cut short by its deadline keeps nothing: the entry stays as it
// was, the event is not accounted for, and the next try checks it again.
func TestTimedOutCheckCachesNothing(t *testing.T) {
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	proofs := newCountingProofs()
	g, _ := cacheGate(t, ModeStructural, box, proofs, src)
	g.queue.timeout = 300 * time.Millisecond
	if ok, _ := g.AdmitPubkey(context.Background(), s.pubkey); ok {
		t.Fatal("the spawn is outside")
	}
	before := g.entry(s.pubkey)
	in := b.move(ActHop, target)
	proofs.mu.Lock()
	proofs.block[in.ID] = true
	proofs.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if ok, msg := g.Admit(ctx, in); ok || msg != errTimeout {
		t.Fatalf("want %q, got %v %q", errTimeout, ok, msg)
	}
	<-proofs.entered
	waitFor(t, func() bool { return !g.queue.pending(s.pubkey) })
	if e := g.entry(s.pubkey); e != before || e.accounted(in.ID) {
		t.Fatal("a check cut short by its deadline changed the entry")
	}
	proofs.mu.Lock()
	proofs.block[in.ID] = false
	proofs.mu.Unlock()
	if ok, msg := g.Admit(context.Background(), in); !ok || proofs.asked(in.ID) != 2 {
		t.Fatalf("the retry must check again and admit: %v %q, asked %d", ok, msg, proofs.asked(in.ID))
	}
}

// In strict mode the position comes from the cached proof-verified head:
// past a proof the checker cannot judge, nothing moves it, and nothing
// after it is checked.
func TestStrictPositionComesFromTheCachedHead(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	proofs := newCountingProofs()
	g, _ := cacheGate(t, ModeStrict, box, proofs, src)
	in := b.move(ActHop, target)
	if ok, msg := g.Admit(ctx, in); !ok {
		t.Fatalf("a verified move in: %s", msg)
	}
	tall := b.move(ActHop, offset(t, target, 1<<30))
	proofs.set(tall.ID, ProofUnchecked)
	if ok, msg := g.Admit(ctx, tall); !ok {
		t.Fatalf("strict mode stands before a proof it cannot judge, inside: %s", msg)
	}
	after := b.move(ActHop, offset(t, target, 1<<31))
	if ok, msg := g.Admit(ctx, after); !ok {
		t.Fatalf("nothing after the stop moves a strict position: %s", msg)
	}
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatal("a reader is placed at the cached verified head")
	}
	if n := proofs.asked(after.ID); n != 0 {
		t.Fatalf("an event after the strict stop was checked %d times", n)
	}
	e := g.entry(s.pubkey)
	if e.vd.VerifiedEvent != in.ID || e.vd.Head != after.ID || e.known.StopAt != tall.ID {
		t.Fatalf("want verified head %s, head %s, stop %s; got %s %s %s", in.ID, after.ID, tall.ID, e.vd.VerifiedEvent, e.vd.Head, e.known.StopAt)
	}
}

// ── the work queue ────────────────────────────────────────────────────

// blockedRun is a queue's run function that records the pubkeys it is
// called for and waits for release before answering.
type blockedRun struct {
	mu      sync.Mutex
	order   []string
	release chan struct{}
	started chan string
}

func newBlockedRun() *blockedRun {
	return &blockedRun{release: make(chan struct{}), started: make(chan string, 64)}
}

func (r *blockedRun) run(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string) {
	r.mu.Lock()
	r.order = append(r.order, pubkey)
	r.mu.Unlock()
	r.started <- pubkey
	<-r.release
	return true, ""
}

func eventWithID(id string) *nostr.Event { return &nostr.Event{ID: id, Kind: KindMovement} }

// When full the queue refuses at once with "busy, try again": in total,
// per client address, and per pubkey (distinct movement events). A reader,
// or an event already waiting, joins its job and adds no work.
func TestQueueRefusesWhenFull(t *testing.T) {
	prompt := func(t *testing.T, q *workQueue, ip, pubkey string, incoming *nostr.Event) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		start := time.Now()
		if ok, msg := q.submit(ctx, ip, pubkey, incoming); ok || msg != errBusy || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("want a prompt %q, got %v %q after %v", errBusy, ok, msg, time.Since(start))
		}
	}
	waiting := func(q *workQueue, ip, pubkey string, incoming *nostr.Event) {
		go q.submit(context.Background(), ip, pubkey, incoming)
	}
	units := func(q *workQueue) int {
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.queued
	}

	t.Run("total", func(t *testing.T) {
		r := newBlockedRun()
		defer close(r.release)
		q := newWorkQueue(1, 3, 8, 4, time.Second, r.run)
		waiting(q, "a", "p0", nil)
		<-r.started
		waiting(q, "b", "p1", nil)
		waiting(q, "c", "p2", nil)
		waitFor(t, func() bool { return units(q) == 3 })
		prompt(t, q, "d", "p3", nil)
		waiting(q, "d", "p1", nil) // a reader joins p1's job
		waitFor(t, func() bool {
			q.mu.Lock()
			defer q.mu.Unlock()
			return len(q.jobs["p1"].waiters) == 2
		})
	})
	t.Run("per address", func(t *testing.T) {
		r := newBlockedRun()
		defer close(r.release)
		q := newWorkQueue(1, 100, 2, 4, time.Second, r.run)
		waiting(q, "a", "p0", nil)
		<-r.started
		waiting(q, "a", "p1", nil)
		waitFor(t, func() bool { return units(q) == 2 })
		prompt(t, q, "a", "p2", nil)
		waiting(q, "b", "p3", nil)
		waitFor(t, func() bool { return units(q) == 3 })
	})
	t.Run("per pubkey", func(t *testing.T) {
		r := newBlockedRun()
		defer close(r.release)
		q := newWorkQueue(1, 100, 100, 4, time.Second, r.run)
		waiting(q, "a", "p0", nil)
		<-r.started
		for i := 0; i < 4; i++ {
			waiting(q, "a", "p1", eventWithID(fmt.Sprint(i)))
			waitFor(t, func() bool { return units(q) == 2+i })
		}
		prompt(t, q, "b", "p1", eventWithID("4"))
		waiting(q, "b", "p1", eventWithID("0")) // already waiting: no new work
		waiting(q, "b", "p1", nil)
		waitFor(t, func() bool {
			q.mu.Lock()
			defer q.mu.Unlock()
			return len(q.jobs["p1"].waiters) == 6 && q.queued == 5
		})
	})
}

// Jobs are taken in turn across client addresses: one address with many
// jobs queued delays its own, not another address's.
func TestQueueIsFairAcrossAddresses(t *testing.T) {
	r := newBlockedRun()
	q := newWorkQueue(1, 100, 100, 4, time.Second, r.run)
	go q.submit(context.Background(), "z", "z0", nil)
	<-r.started
	for i := 0; i < 4; i++ {
		go q.submit(context.Background(), "a", fmt.Sprintf("a%d", i), nil)
		waitFor(t, func() bool { return q.pending(fmt.Sprintf("a%d", i)) })
	}
	go q.submit(context.Background(), "b", "b0", nil)
	waitFor(t, func() bool { return q.pending("b0") })
	close(r.release)
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.order) == 6
	})
	want := []string{"z0", "a0", "b0", "a1", "a2", "a3"}
	if got := strings.Join(r.order, " "); got != strings.Join(want, " ") {
		t.Fatalf("order %q, want %q", got, strings.Join(want, " "))
	}
}

// Concurrent requests for one pubkey share one check: readers share one
// lookup, and one movement event sent many times at once is checked once.
func TestConcurrentRequestsForOnePubkeyShareOneCheck(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}, delay: 50 * time.Millisecond}
	proofs := newCountingProofs()
	g, _ := cacheGate(t, ModeStructural, box, proofs, src)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.AdmitPubkey(ctx, s.pubkey) }()
	}
	wg.Wait()
	if n := src.calls.Load(); n != 2 { // spawns and chain, once
		t.Fatalf("20 concurrent readers made %d source calls, want 2", n)
	}
	in := b.move(ActHop, target)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, msg := g.Admit(ctx, in); !ok {
				t.Errorf("refused: %s", msg)
			}
		}()
	}
	wg.Wait()
	if n := proofs.asked(in.ID); n != 1 {
		t.Fatalf("one event sent 20 times at once was checked %d times", n)
	}
	if n := src.calls.Load(); n != 3 { // one incremental question
		t.Fatalf("one event sent 20 times at once made %d source calls, want 3 in all", n)
	}
}

// ── measurement: a real forged tall hop ───────────────────────────────

// forgeTallHop signs a hop whose c and C are h apart on every axis, with a
// seal over a junk residue list that meets the re-roll price and whose 16
// sampled openings climb to the seal: it passes every cheap check and fails
// only once Level 1 has computed its 16 residues, which is the full price of
// checking a hop of that height (§5.11).
func forgeTallHop(t *testing.T, b *chainBuilder, h int) nostr.Event {
	t.Helper()
	from := mustCoord(t, b.pos)
	flip := new(big.Int).Lsh(bigOne, uint(h-1))
	to := Coord{X: new(big.Int).Xor(from.X, flip), Y: new(big.Int).Xor(from.Y, flip), Z: new(big.Int).Xor(from.Z, flip), Plane: from.Plane}
	prev, _ := hex.DecodeString(b.last.ID)
	g := newHopGeometry(prev, from, to)
	zeros := make([]uint64, residueBlock)
	level := make([][]byte, 1<<g.depth)
	for i := range level {
		level[i] = hopLeaf(prev, uint64(i), zeros)
	}
	levels := [][][]byte{level}
	for len(level) > 1 {
		up := make([][]byte, len(level)/2)
		for i := range up {
			s := sha256.Sum256(append(append([]byte{}, level[2*i]...), level[2*i+1]...))
			up[i] = s[:]
		}
		levels, level = append(levels, up), up
	}
	seal := level[0]
	var nonce uint64
	var G []byte
	for nonce = 0; ; nonce++ {
		if G = hopAttempt(prev, seal, nonce); meetsPrice(G, g.price) {
			break
		}
	}
	var mp strings.Builder
	for i := 0; i < hopSamples; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		d := sha256.Sum256(append(append(append([]byte{}, hopSampleDomain...), G...), ib[:]...))
		idx := new(big.Int).Mod(new(big.Int).SetBytes(d[:]), g.m).Uint64()
		block := idx / residueBlock
		mp.WriteString(strings.Repeat("0", 16*residueBlock))
		for lv := 0; lv < g.depth; lv++ {
			mp.WriteString(hex.EncodeToString(levels[lv][(block>>uint(lv))^1]))
		}
	}
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	t.Logf("forged an h%d hop (h_max %d, m %s, depth %d, price %s) after %d attempts", h, g.hMax, g.m, g.depth, g.price, nonce+1)
	return b.move(ActHop, to.Hex(), []string{"proof", hex.EncodeToString(seal)}, []string{"mn", hex.EncodeToString(nb[:])}, []string{"mp", mp.String()})
}

// timedProofs is the real checker, timed and counted.
type timedProofs struct {
	inner SpecProofs
	mu    sync.Mutex
	n     int
	total time.Duration
}

func (p *timedProofs) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	start := time.Now()
	res, why := p.inner.Check(ctx, prev, cur)
	p.mu.Lock()
	p.n++
	p.total += time.Since(start)
	p.mu.Unlock()
	return res, why
}

// TestMeasureResentTallForgery sends one real forged h20 hop (the machine's
// ceiling for hop proofs) many times through a gate running the real
// checker, and logs what the sends cost. Run with REGIONGATE_MEASURE=1.
func TestMeasureResentTallForgery(t *testing.T) {
	if os.Getenv("REGIONGATE_MEASURE") == "" {
		t.Skip("set REGIONGATE_MEASURE=1 to measure")
	}
	ctx := context.Background()
	s := newSigner(t)
	b := newChain(t, s)
	start := time.Now()
	forged := forgeTallHop(t, b, 20)
	t.Logf("forging took %v", time.Since(start))
	tag := func(name string) string { return tagValues(forged, name)[0] }
	why, err := verifyHopLevel1(ctx, mustHexBytes(t, b.spawn.ID), mustCoord(t, s.pubkey), mustCoord(t, tag("C")),
		tag("proof"), tag("mn"), tag("mp"), DefaultMaxHopHeight)
	if err != nil || !strings.Contains(why, "residue") {
		t.Fatalf("the forgery must fail only at its residues: %q %v", why, err)
	}
	proofs := &timedProofs{inner: SpecProofs{}}
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g, clock := cacheGate(t, ModeStructural, cubeAround(t, s.pubkey, 40), proofs, src)
	const sends = 1000
	start = time.Now()
	g.Admit(ctx, forged)
	first := time.Since(start)
	start = time.Now()
	for i := 1; i < sends; i++ {
		g.Admit(ctx, forged)
	}
	rest := time.Since(start)
	var wg sync.WaitGroup
	start = time.Now()
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.Admit(ctx, forged) }()
	}
	wg.Wait()
	concurrent := time.Since(start)
	clock.add(25 * time.Hour)
	start = time.Now()
	g.Admit(ctx, forged)
	whole := time.Since(start)
	t.Logf("first send %v (Level 1 %v); %d re-sends %v (%v each); 64 at once %v; whole re-read a day later %v; Level 1 checks in all: %d",
		first, proofs.total, sends-1, rest, rest/time.Duration(sends-1), concurrent, whole, proofs.n)
	if proofs.n != 1 {
		t.Fatalf("%d Level 1 checks for one forged hop, want 1", proofs.n)
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMeasureRealChainIncremental logs, for each real history in
// REGIONGATE_REAL_CHAINS (the jsonl TestRealChainCost reads), what a gate
// with the real checker pays: the chain read and checked whole with no
// entry, the head then arriving as a new movement event (incremental), and
// the chain read whole again a day later (Known: no proof checked again).
func TestMeasureRealChainIncremental(t *testing.T) {
	path := os.Getenv("REGIONGATE_REAL_CHAINS")
	if path == "" {
		t.Skip("REGIONGATE_REAL_CHAINS not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string][]nostr.Event{}
	var order []string
	for _, line := range splitLines(data) {
		var e nostr.Event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		if by[e.PubKey] == nil {
			order = append(order, e.PubKey)
		}
		by[e.PubKey] = append(by[e.PubKey], e)
	}
	ctx := context.Background()
	for _, pk := range order {
		vd := Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}.Verify(pk, by[pk])
		if vd.Length < 2 {
			continue
		}
		var held []nostr.Event
		var head nostr.Event
		for _, e := range by[pk] {
			if e.ID == vd.Head {
				head = e
			} else {
				held = append(held, e)
			}
		}
		proofs := &timedProofs{inner: SpecProofs{}}
		src := &fakeSource{events: held}
		g, clock := cacheGate(t, ModeStructural, cubeAround(t, pk, 85), proofs, src)
		g.cfg.MaxChainEvents = 100000
		start := time.Now()
		_, coldMsg := g.AdmitPubkey(ctx, pk)
		cold, coldN := time.Since(start), proofs.n
		start = time.Now()
		_, incMsg := g.Admit(ctx, head)
		inc, incN := time.Since(start), proofs.n-coldN
		src.mu.Lock()
		src.events = append(src.events, head)
		src.mu.Unlock()
		clock.add(25 * time.Hour)
		start = time.Now()
		g.AdmitPubkey(ctx, pk)
		whole, wholeN := time.Since(start), proofs.n-coldN-incN
		e := g.entry(pk)
		if e == nil {
			if coldMsg != errIncomplete {
				t.Errorf("%s: no entry (cold %q, incremental %q)", pk[:8], coldMsg, incMsg)
			}
			t.Logf("%s: %d held: refused uncached as incomplete (a previous no source holds), as before the cache", pk[:8], len(by[pk]))
			continue
		}
		t.Logf("%s: %d held, chain %d (%s): cold %v (%d proofs); new head %v (%d); whole a day later %v (%d); entry seen %d",
			pk[:8], len(by[pk]), vd.Length, map[bool]string{true: "valid", false: "invalid " + vd.Reason}[vd.Valid()], cold, coldN, inc, incN, whole, wholeN, len(e.seen))
		if e.vd.Head != vd.Head || e.vd.Reason != vd.Reason || e.vd.PositionEvent != vd.PositionEvent {
			t.Errorf("%s: the cache's verdict differs from a whole walk: head %s/%s reason %q/%q position %s/%s",
				pk[:8], e.vd.Head, vd.Head, e.vd.Reason, vd.Reason, e.vd.PositionEvent, vd.PositionEvent)
		}
	}
}

// The chain cache walks on from a cached head over new events alone, with
// the head's state slimmed (kept). Walked that way one event at a time, every
// golden vector and every real chain reaches the verdict the whole walk
// reaches, in both modes: positions, head, open bracket, length, unchecked
// count and failure point. After a failure or a strict stop the cache only
// moves the head on, as here.
func TestResumedWalkAgreesWithTheWholeWalk(t *testing.T) {
	ctx := context.Background()
	golden := loadVectors(t, vectorsFile)
	real := loadVectors(t, realVectorsFile)
	type set struct {
		vf     vectorFile
		v      Verifier
		pubkey func(vector) string
	}
	sets := []set{
		{golden, vectorVerifier(t, golden), func(vector) string { return golden.TestKey.Pubkey }},
		{real, Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}, func(vec vector) string { return vec.Identity }},
	}
	key := verdictKey
	walked := 0
	for _, st := range sets {
		for _, strict := range []bool{false, true} {
			v := st.v
			v.StopAtUnchecked = strict
			for _, vec := range st.vf.Vectors {
				pk := st.pubkey(vec)
				whole, _, chain, err := v.verify(ctx, pk, parseEvents(vec.Events), nil)
				if err != nil {
					t.Fatal(err)
				}
				if !whole.HasChain || whole.Reason == ReasonFork || whole.InvalidIndex == 0 {
					continue // nothing is walked: the cache keeps no walk
				}
				_, k, _, err := v.verify(ctx, pk, []nostr.Event{chain[0].Event}, nil)
				if err != nil || k == nil {
					t.Fatalf("%s: the spawn alone: %v", vec.Name, err)
				}
				got := summary(k.vd)
				for _, m := range chain[1:] {
					if !k.atHead() {
						got.Head, got.Length = m.Event.ID, got.Length+1
						if k.stopAt != "" {
							got.Unchecked++
						}
						continue
					}
					k = k.kept()
					if err := k.resume(ctx, []Move{m}); err != nil {
						t.Fatal(err)
					}
					got = summary(k.vd)
				}
				if a, b := key(got), key(summary(whole)); a != b {
					t.Errorf("%s (strict %v):\n resumed %s\n whole   %s", vec.Name, strict, a, b)
				}
				walked++
			}
		}
	}
	t.Logf("%d chains walked on one event at a time, in both modes", walked)
}

// countedChecker counts the questions a ProofChecker is asked.
type countedChecker struct {
	inner ProofChecker
	n     int
}

func (c *countedChecker) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	c.n++
	return c.inner.Check(ctx, prev, cur)
}

// A chain read whole again with what an earlier walk of it established
// (Known) reaches the same verdict and asks the checker nothing: every
// golden vector and real chain, in both modes.
func TestKnownWalkAgreesAndChecksNothingAgain(t *testing.T) {
	ctx := context.Background()
	golden := loadVectors(t, vectorsFile)
	real := loadVectors(t, realVectorsFile)
	type set struct {
		vf     vectorFile
		v      Verifier
		pubkey func(vector) string
	}
	sets := []set{
		{golden, vectorVerifier(t, golden), func(vector) string { return golden.TestKey.Pubkey }},
		{real, Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}, func(vec vector) string { return vec.Identity }},
	}
	again := 0
	for _, st := range sets {
		for _, strict := range []bool{false, true} {
			for _, vec := range st.vf.Vectors {
				events := parseEvents(vec.Events)
				v := st.v
				v.StopAtUnchecked = strict
				first, k, _, err := v.verify(ctx, st.pubkey(vec), events, nil)
				if err != nil {
					t.Fatal(err)
				}
				if k == nil {
					continue
				}
				counted := &countedChecker{inner: st.v.Proofs}
				v.Proofs = counted
				second, _, _, err := v.verify(ctx, st.pubkey(vec), events, k.knowledge())
				if err != nil {
					t.Fatal(err)
				}
				if counted.n != 0 {
					t.Errorf("%s (strict %v): the checker was asked %d times again", vec.Name, strict, counted.n)
				}
				if a, b := verdictKey(second)+fmt.Sprint(second.Chain, second.Skipped), verdictKey(first)+fmt.Sprint(first.Chain, first.Skipped); a != b {
					t.Errorf("%s (strict %v): the verdict with Known differs:\n %s\n %s", vec.Name, strict, a, b)
				}
				again++
			}
		}
	}
	t.Logf("%d chains read whole again with Known", again)
}

// verdictKey is a verdict's fields as one comparable string.
func verdictKey(vd Verdict) string {
	pos := func(c *Coord) string {
		if c == nil {
			return "nil"
		}
		return c.Hex()
	}
	return fmt.Sprintf("pos %s verified %s at %s/%s head %s bracket %q length %d unchecked %d reason %q at %s index %d stopped %q",
		pos(vd.Position), pos(vd.VerifiedPosition), vd.PositionEvent, vd.VerifiedEvent, vd.Head, vd.OpenBracket,
		vd.Length, vd.Unchecked, vd.Reason, vd.InvalidAt, vd.InvalidIndex, vd.Stopped)
}
