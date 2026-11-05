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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	return g.chains.get(pubkey, g.rules())
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
	// Spawn and hop both inside: a cut-short walk stored by mistake would be
	// admitted and kept, so the test sees it.
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	proofs := newCountingProofs()
	g, _ := cacheGate(t, ModeStructural, box, proofs, src)
	g.queue.timeout = 300 * time.Millisecond
	if ok, _ := g.AdmitPubkey(context.Background(), s.pubkey); !ok {
		t.Fatal("the spawn is inside")
	}
	before := g.entry(s.pubkey)
	in := b.move(ActHop, offset(t, s.pubkey, 1))
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
	if e := g.entry(s.pubkey); e == nil || e.accounted(in.ID) || e.vd.Head != before.vd.Head || e.vd.PositionEvent != before.vd.PositionEvent {
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
	// The event after the stop was answered from the entry (it changes
	// nothing), so the head is still the stop; the relay stores it, and the
	// next check finds it in the sources.
	if e.vd.VerifiedEvent != in.ID || e.vd.Head != tall.ID || e.known.StopAt != tall.ID {
		t.Fatalf("want verified head %s, head %s, stop %s; got %s %s %s", in.ID, tall.ID, tall.ID, e.vd.VerifiedEvent, e.vd.Head, e.known.StopAt)
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

// ── review round 2 ────────────────────────────────────────────────────

// slowProofs costs per proof a fixed time, giving up when its context ends.
type slowProofs struct {
	per  time.Duration
	mu   sync.Mutex
	asks int
}

func (p *slowProofs) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	p.mu.Lock()
	p.asks++
	p.mu.Unlock()
	select {
	case <-time.After(p.per):
	case <-ctx.Done():
	}
	return ProofVerified, ""
}

// A chain costlier than one check's deadline is paid for once across
// retries: each check cut short keeps a checkpoint, and the next walks on
// from it, read whole or walked on from a cached head alike. Without it the
// chain never finishes and every retry burns a whole deadline.
func TestChainCostlierThanOneDeadlineIsPaidForOnce(t *testing.T) {
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	events := []nostr.Event{b.spawn}
	for i := 0; i < 10; i++ {
		events = append(events, b.move(ActHop, offset(t, target, int64(i))))
	}
	proofs := &slowProofs{per: 60 * time.Millisecond}
	src := &fakeSource{events: events}
	g, clock := cacheGate(t, ModeStructural, box, proofs, src)
	g.queue.timeout = 250 * time.Millisecond
	settle := func(what string, events int) {
		t.Helper()
		before := proofs.asks
		for tries := 1; ; tries++ {
			ok, msg := g.AdmitPubkey(context.Background(), s.pubkey)
			if msg != errTimeout {
				if !ok {
					t.Fatalf("%s: %q", what, msg)
				}
				asked := proofs.asks - before
				t.Logf("%s: %d events checked in %d tries, %d proofs asked", what, events, tries, asked)
				if asked > events+tries {
					t.Fatalf("%s: %d proofs asked for %d events in %d tries: work was redone", what, asked, events, tries)
				}
				return
			}
			if tries == 12 {
				t.Fatalf("%s: never finished in %d tries", what, tries)
			}
		}
	}
	settle("read whole", 10)
	// Ten more events, walked on from the cached head.
	for i := 10; i < 20; i++ {
		src.mu.Lock()
		src.events = append(src.events, b.move(ActHop, offset(t, target, int64(i))))
		src.mu.Unlock()
	}
	clock.add(601 * time.Second)
	settle("walked on from the head", 10)
}

// A single tall hop costlier than one deadline is paid for once too: the
// residues a check computed before its deadline are kept, and the next check
// of that hop computes only the rest. Once judged, the hop's are dropped.
func TestTallHopResiduesSurviveTheDeadline(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	hop := forgeTallHop(t, b, 12)
	cur, _ := ParseMove(hop)
	n := 0
	defer func() { residueKept = nil }()

	full := SpecProofs{Progress: NewHopProgress(8)}
	residueKept = func() { n++ }
	if res, _ := full.Check(context.Background(), Move{}, cur); res != ProofInvalid {
		t.Fatal("the forgery must fail at its residues")
	}
	whole := n

	progress := NewHopProgress(8)
	sp := SpecProofs{Progress: progress}
	ctx, cancel := context.WithCancel(context.Background())
	n = 0
	residueKept = func() {
		if n++; n == 2 {
			cancel()
		}
	}
	if res, _ := sp.Check(ctx, Move{}, cur); res != ProofUnchecked {
		t.Fatal("a check cut short judges nothing")
	}
	first := n
	n = 0
	residueKept = func() { n++ }
	if res, _ := sp.Check(context.Background(), Move{}, cur); res != ProofInvalid {
		t.Fatal("the resumed check must reach the verdict")
	}
	if first+n != whole || first < 2 {
		t.Fatalf("residues computed: %d before the deadline + %d after, want %d in all", first, n, whole)
	}
	if len(progress.byID) != 0 {
		t.Fatal("a judged hop's residues must be dropped")
	}
}

// Checks run about one per core the process may use by default (a check is
// CPU-bound once its events are fetched).
func TestDefaultLookupsFollowTheCores(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(3))
	c, err := ParseConfig([]byte("enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxConcurrentLookups != 3 {
		t.Fatalf("with 3 cores max_concurrent_lookups defaults to %d, want 3", c.MaxConcurrentLookups)
	}
	if NewGate(&Config{}, verifier()).queue.workers != 3 {
		t.Fatal("a gate with no setting runs one check per core")
	}
}

// Fresh keys cost an attacker nothing, so they must not evict members:
// refusals and pubkeys with no chain have a cache of their own.
func TestFreshKeysDoNotEvictMembers(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	src := &fakeSource{events: []nostr.Event{newChain(t, s).spawn}}
	g, _ := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	g.chains = newChainCache(8)
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatal("member refused")
	}
	for i := 0; i < 50; i++ {
		g.AdmitPubkey(ctx, newSigner(t).pubkey)
	}
	if g.entry(s.pubkey) == nil {
		t.Fatal("50 fresh keys evicted a member")
	}
}

// An event a walk found invalid stays known invalid after its pubkey's
// entry is evicted: re-sent, its proof is not checked again.
func TestFailedEventSurvivesEviction(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	forged := b.move(ActHop, target) // would move in; invalid, so frozen at the spawn, outside
	proofs := newCountingProofs()
	proofs.set(forged.ID, ProofInvalid)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g, _ := cacheGate(t, ModeStructural, box, proofs, src)
	g.chains = newChainCache(8)
	if ok, _ := g.Admit(ctx, forged); ok {
		t.Fatal("a forged move in must be refused")
	}
	for i := 0; i < 20; i++ {
		g.AdmitPubkey(ctx, newSigner(t).pubkey)
	}
	if g.entry(s.pubkey) != nil {
		t.Fatal("the refusal should have been evicted for this test")
	}
	if ok, _ := g.Admit(ctx, forged); ok {
		t.Fatal("still refused")
	}
	if n := proofs.asked(forged.ID); n != 1 {
		t.Fatalf("after eviction the forged hop was checked %d times, want 1", n)
	}
}

// A refused forgery sent again costs nothing either: no proof check, and
// within the TTL no source is asked.
func TestResentRefusedForgeryCostsNothing(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	forged := b.move(ActHop, target)
	proofs := newCountingProofs()
	proofs.set(forged.ID, ProofInvalid)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g, clock := cacheGate(t, ModeStructural, box, proofs, src)
	g.AdmitPubkey(ctx, s.pubkey)
	if ok, _ := g.Admit(ctx, forged); ok {
		t.Fatal("refused")
	}
	calls := src.calls.Load()
	for i := 0; i < 50; i++ {
		if ok, _ := g.Admit(ctx, forged); ok {
			t.Fatal("a re-send changed the verdict")
		}
	}
	if n := src.calls.Load() - calls; n != 0 {
		t.Fatalf("re-sends of a refused forgery asked the sources %d times within the TTL", n)
	}
	clock.add(61 * time.Second)
	g.Admit(ctx, forged)
	if n := proofs.asked(forged.ID); n != 1 {
		t.Fatalf("the refused forgery was checked %d times, want 1", n)
	}
}

// A refused movement event is stored nowhere, so it must not move the
// cached identity: a member who tried to move out and was refused is still
// where the sources place them.
func TestRefusedMoveIsNotKept(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	in := b.move(ActHop, target)
	src := &fakeSource{events: []nostr.Event{b.spawn, in}}
	g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatal("inside")
	}
	if ok, _ := g.Admit(ctx, b.move(ActHop, offset(t, target, 1<<41))); ok {
		t.Fatal("a move out is refused")
	}
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatal("within the TTL the refused move must not lock the member out")
	}
	clock.add(601 * time.Second)
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatal("after the TTL the refused move must not lock the member out")
	}
	if e := g.entry(s.pubkey); e.vd.Head != in.ID {
		t.Fatalf("the entry's head moved to a refused event: %s", e.vd.Head)
	}
}

// The seen window holds at most maxSeen ids, however many events share one
// created_at, and the next incremental check still asks one question.
func TestSeenBoundHoldsWithEqualTimestamps(t *testing.T) {
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	evs := []nostr.Event{b.spawn}
	for i := 0; i < 3*maxSeen; i++ {
		b.at = b.spawn.CreatedAt + 100
		evs = append(evs, b.move(ActHop, offset(t, target, int64(i%2))))
	}
	src := &fakeSource{events: evs}
	g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	g.cfg.MaxChainEvents = 5000
	g.queue.timeout = 2 * time.Minute // 3,072 signatures, slow under -race
	if ok, msg := g.AdmitPubkey(context.Background(), s.pubkey); !ok {
		t.Fatal(msg)
	}
	if n := len(g.entry(s.pubkey).seen); n > maxSeen {
		t.Fatalf("seen holds %d ids, above %d", n, maxSeen)
	}
	b.at = b.spawn.CreatedAt + 200
	next := b.move(ActHop, target)
	src.mu.Lock()
	src.events = append(src.events, next)
	src.mu.Unlock()
	clock.add(601 * time.Second)
	calls := src.calls.Load()
	g.AdmitPubkey(context.Background(), s.pubkey)
	if n, e := src.calls.Load()-calls, g.entry(s.pubkey); n != 1 || e.vd.Head != next.ID {
		t.Fatalf("the next check made %d source calls (want 1) and has head %s", n, e.vd.Head)
	}
}

// Junk movement events (naming a previous nobody holds) cannot make the gate
// read the chain whole on each one: at most once every wholeEvery.
func TestJunkEventsAreRateLimited(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	evs := []nostr.Event{b.spawn, b.move(ActHop, target)}
	src := &fakeSource{events: evs}
	g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	g.AdmitPubkey(ctx, s.pubkey)
	calls := src.calls.Load()
	for i := 0; i < 10; i++ {
		junk := s.sign(t, KindMovement, b.at+5, []string{"A", ActHop}, []string{"e", b.spawn.ID, "", "genesis"},
			[]string{"e", fmt.Sprintf("%064x", i+1), "", "previous"})
		if ok, msg := g.Admit(ctx, junk); ok || msg != errBusy {
			t.Fatalf("junk %d: %v %q, want %q", i, ok, msg, errBusy)
		}
	}
	if n := src.calls.Load() - calls; n != 10 {
		t.Fatalf("10 junk events made %d source calls, want 10 (one incremental question each)", n)
	}
	clock.add(wholeEvery)
	calls = src.calls.Load()
	junk := s.sign(t, KindMovement, b.at+6, []string{"A", ActHop}, []string{"e", b.spawn.ID, "", "genesis"},
		[]string{"e", strings.Repeat("ee", 32), "", "previous"})
	if ok, msg := g.Admit(ctx, junk); ok || msg != errIncomplete {
		t.Fatalf("after wholeEvery the chain is read whole: %v %q", ok, msg)
	}
}

// LiveAllowed's background checks queue under an address of their own, so
// they count against the per-address limit like any client's.
func TestLiveRefreshesCountAgainstALimit(t *testing.T) {
	s := newSigner(t)
	cfg := &Config{Enabled: true, Mode: ModeStructural, CacheTTLSeconds: 600, NegativeCacheTTLSeconds: 60, FetchTimeoutSeconds: 8,
		MaxConcurrentLookups: 1, MaxQueuedLookups: 100, MaxQueuedPerIP: 2, boxes: []Box{cubeAround(t, s.pubkey, 40)}, exempt: map[string]bool{}}
	g := NewGate(cfg, verifier(), &fakeSource{delay: time.Second})
	for i := 0; i < 10; i++ {
		g.LiveAllowed(newSigner(t).pubkey)
	}
	time.Sleep(100 * time.Millisecond)
	g.queue.mu.Lock()
	queued, live := g.queue.queued, g.queue.ipUnits[liveBucket]
	g.queue.mu.Unlock()
	if queued > 2 || live > 2 {
		t.Fatalf("background checks queued %d units (%d under the live bucket), want at most 2", queued, live)
	}
}

// One host's IPv6 /64 is one address for the per-address limit.
func TestIPv6AddressesShareTheirSlash64(t *testing.T) {
	r := newBlockedRun()
	defer close(r.release)
	q := newWorkQueue(1, 100, 2, 4, time.Second, r.run)
	go q.submit(context.Background(), "2001:db8:1:2::1", "p0", nil)
	<-r.started
	go q.submit(context.Background(), "2001:db8:1:2:aaaa::2", "p1", nil)
	waitFor(t, func() bool { return q.pending("p1") })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if ok, msg := q.submit(ctx, "2001:db8:1:2:ffff::3", "p2", nil); ok || msg != errBusy || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("a third address in the same /64: %v %q after %v, want a prompt %q", ok, msg, time.Since(start), errBusy)
	}
	go q.submit(context.Background(), "2001:db8:1:3::1", "p3", nil)
	waitFor(t, func() bool { return q.pending("p3") })
	if got := addressBucket("192.0.2.7"); got != "192.0.2.7" {
		t.Fatalf("an IPv4 address is its own bucket, got %q", got)
	}
	if got := addressBucket("::ffff:192.0.2.7"); got != "192.0.2.7" {
		t.Fatalf("an IPv4-mapped IPv6 address counts as its IPv4 one, got %q", got)
	}
}

// ── review round 3 ────────────────────────────────────────────────────

// Anyone can replay an identity's old, public chain events. Dated before
// the window and not extending the head, they are answered from the entry
// (the daily whole read covers them, as for events the sources return), so
// replays cost no source call within the TTL and no whole read after it.
// On first contact, the whole read that already holds the event answers
// for it without reading again.
func TestReplayedOldEventsCostNothing(t *testing.T) {
	ctx := context.Background()
	s, target, box := insideTarget(t)
	b := newChain(t, s)
	evs := []nostr.Event{b.spawn}
	for i := 0; i < 200; i++ {
		evs = append(evs, b.move(ActHop, offset(t, target, int64(i%2))))
	}
	b.at += 2 * lookbackSeconds // the head is well after the old events
	evs = append(evs, b.move(ActHop, target))
	src := &fakeSource{events: evs}

	first, _ := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	if ok, msg := first.Admit(ctx, evs[5]); !ok {
		t.Fatalf("first contact with a replayed old event: %s", msg)
	}
	if n := src.calls.Load(); n != 2 {
		t.Fatalf("first contact with a replayed old event made %d source calls, want 2 (one whole read)", n)
	}

	g, clock := cacheGate(t, ModeStructural, box, newCountingProofs(), src)
	g.AdmitPubkey(ctx, s.pubkey)
	calls := src.calls.Load()
	for i := 0; i < 20; i++ {
		clock.add(16 * time.Second) // past wholeEvery each time, within the TTL
		if ok, msg := g.Admit(ctx, evs[1+i]); !ok {
			t.Fatalf("replay %d: %s", i, msg)
		}
	}
	for i := 0; i < 20; i++ {
		g.Admit(ctx, evs[30+i])
	}
	if n := src.calls.Load() - calls; n != 0 {
		t.Fatalf("40 replays within the TTL made %d source calls, want 0", n)
	}
	clock.add(601 * time.Second)
	calls = src.calls.Load()
	for i := 0; i < 20; i++ {
		clock.add(16 * time.Second)
		g.Admit(ctx, evs[60+i])
	}
	if n := src.calls.Load() - calls; n > 1 {
		t.Fatalf("20 replays after the TTL made %d source calls, want at most 1 (one incremental question)", n)
	}
}

// Only proof failures go into the failed set: structural junk is cheap to
// find again and must not push a forged proof out.
func TestOnlyProofFailuresAreKept(t *testing.T) {
	f := newFailedSet()
	junk, forged := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	f.add(&Known{FailAt: junk, FailReason: ReasonCMismatch, Stopped: "c-mismatch"}, "r")
	f.add(&Known{FailAt: forged, FailReason: ReasonHopProof, Stopped: "hop-proof"}, "r")
	if _, in := f.get(junk, "r"); in {
		t.Fatal("a structural failure was kept")
	}
	if _, in := f.get(forged, "r"); !in {
		t.Fatal("a proof failure was not kept")
	}
}

// Known members' jobs are taken before anyone else's: fresh keys building
// costly chains cannot starve players.
func TestQueueServesKnownMembersFirst(t *testing.T) {
	r := newBlockedRun()
	q := newWorkQueue(1, 100, 100, 4, time.Second, r.run)
	q.member = func(pubkey string) bool { return strings.HasPrefix(pubkey, "m") }
	go q.submit(context.Background(), "z", "z0", nil)
	<-r.started
	for _, pk := range []string{"u0", "u1", "u2", "m0", "u3", "m1"} {
		go q.submit(context.Background(), "a", pk, nil)
		waitFor(t, func() bool { return q.pending(pk) })
	}
	close(r.release)
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.order) == 7
	})
	want := "z0 m0 m1 u0 u1 u2 u3"
	if got := strings.Join(r.order, " "); got != want {
		t.Fatalf("order %q, want %q", got, want)
	}
}

// The gate tells its queue who its members are: a member whose entry has
// expired is checked ahead of a flood of unknown keys.
func TestGateServesKnownMembersFirst(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	src := &fakeSource{events: []nostr.Event{newChain(t, s).spawn}}
	cfg := &Config{Enabled: true, Mode: ModeStructural, CacheTTLSeconds: 600, NegativeCacheTTLSeconds: 60, FetchTimeoutSeconds: 8,
		MaxConcurrentLookups: 1, MaxQueuedLookups: 100, MaxQueuedPerIP: 100, boxes: []Box{box}, exempt: map[string]bool{}}
	g := NewGate(cfg, verifier(), src)
	clock := &testClock{t: time.Now()}
	g.now = clock.now
	if ok, _ := g.AdmitPubkey(ctx, s.pubkey); !ok {
		t.Fatal("member refused")
	}
	clock.add(601 * time.Second)
	src.mu.Lock()
	src.delay = 50 * time.Millisecond
	src.mu.Unlock()
	for i := 0; i < 10; i++ {
		go g.AdmitPubkey(WithClientIP(ctx, "198.51.100.9"), newSigner(t).pubkey)
	}
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	if ok, msg := g.AdmitPubkey(WithClientIP(ctx, "198.51.100.9"), s.pubkey); !ok {
		t.Fatal(msg)
	}
	if took := time.Since(start); took > 300*time.Millisecond {
		t.Fatalf("the member waited %v behind 10 unknown keys (about 50 ms each)", took)
	}
}

// Members first never starves anyone: an unknown key behind members who
// keep the only worker busy is still served, well within its deadline.
func TestQueueMembersFirstDoesNotStarveUnknownKeys(t *testing.T) {
	run := func(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string) {
		time.Sleep(5 * time.Millisecond)
		return true, ""
	}
	q := newWorkQueue(1, 100, 100, 4, time.Second, run)
	q.member = func(pk string) bool { return pk[0] == 'm' }
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, pk := range []string{"m0", "m1", "m2"} {
		wg.Add(1)
		go func(pk string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				q.submit(context.Background(), "members", pk, nil)
			}
		}(pk)
	}
	defer func() { close(stop); wg.Wait() }()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	ok, msg := q.submit(ctx, "newcomer", "u0", nil)
	if took := time.Since(start); !ok || took > 200*time.Millisecond {
		t.Fatalf("an unknown key behind always-busy members: %v %q after %v, want served within 200 ms", ok, msg, took)
	}
}

// ── review round 5: the door ──────────────────────────────────────────

// queuedCount is the units waiting in q.
func queuedCount(q *workQueue) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queued
}

// A member is never refused at a full door while anyone else holds work:
// it takes the place of the newest job of the address holding the most
// (whose waiter is told "busy, try again"), or, when all of theirs is
// running already, goes over the cap by that much.
func TestMembersAreNeverRefusedAtAFullDoor(t *testing.T) {
	r := newBlockedRun()
	defer close(r.release)
	q := newWorkQueue(1, 4, 100, 4, time.Second, r.run)
	q.member = func(pk string) bool { return pk[0] == 'm' }
	go q.submit(context.Background(), "192.0.2.1", "z0", nil)
	<-r.started
	evicted := make(chan string, 4)
	for _, pk := range []string{"u1", "u2", "u3"} {
		go func(pk string) {
			if _, msg := q.submit(context.Background(), "198.51.100.1", pk, nil); msg == errBusy {
				evicted <- pk
			}
		}(pk)
		waitFor(t, func() bool { return q.pending(pk) })
	}
	if n := queuedCount(q); n != 4 {
		t.Fatalf("want the queue full at 4 units, got %d", n)
	}
	go q.submit(context.Background(), "203.0.113.1", "m0", nil)
	waitFor(t, func() bool { return q.pending("m0") })
	select {
	case pk := <-evicted:
		if pk != "u3" {
			t.Fatalf("evicted %s, want the newest job, u3", pk)
		}
	case <-time.After(time.Second):
		t.Fatal("no job made room for the member")
	}

	// All of the non-members' work is running: the member goes over the cap.
	r2 := newBlockedRun()
	defer close(r2.release)
	q2 := newWorkQueue(1, 1, 100, 4, time.Second, r2.run)
	q2.member = q.member
	go q2.submit(context.Background(), "192.0.2.1", "z0", nil)
	<-r2.started
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go q2.submit(ctx, "203.0.113.1", "m0", nil)
	waitFor(t, func() bool { return q2.pending("m0") })
}

// At a full door an address with nothing waiting takes the place of the
// newest job of the network holding the most, so every address gets in; an
// address that already has work waiting is refused, at once.
func TestEveryAddressGetsInAtAFullDoor(t *testing.T) {
	r := newBlockedRun()
	defer close(r.release)
	q := newWorkQueue(1, 4, 8, 4, time.Second, r.run)
	go q.submit(context.Background(), "192.0.2.1", "z0", nil)
	<-r.started
	for _, pk := range []string{"a1", "a2", "a3"} {
		go q.submit(context.Background(), "198.51.100.1", pk, nil)
		waitFor(t, func() bool { return q.pending(pk) })
	}
	go q.submit(context.Background(), "203.0.113.7", "c1", nil)
	waitFor(t, func() bool { return q.pending("c1") })
	if q.pending("a3") || !q.pending("a2") {
		t.Fatal("want the newest job of the fullest network (a3) to make room, and a2 kept")
	}
	for _, try := range []struct{ ip, pk string }{{"203.0.113.7", "c2"}, {"198.51.100.1", "a4"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		ok, msg := q.submit(ctx, try.ip, try.pk, nil)
		cancel()
		if ok || msg != errBusy || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("%s from %s at a full door: %v %q after %v, want a prompt refusal", try.pk, try.ip, ok, msg, time.Since(start))
		}
	}
}

// One network (IPv4 /24, IPv6 /48) holds at most networkShare times the
// per-address limit, so many addresses of one host cannot fill the queue.
func TestNetworkLimitBluntsAddressSybils(t *testing.T) {
	for _, nets := range [][2]string{{"10.0.0.%d", "10.0.1.1"}, {"2001:db8:0:1%02x::1", "2001:db8:1::1"}} {
		r := newBlockedRun()
		q := newWorkQueue(1, 1000, 2, 4, time.Second, r.run)
		go q.submit(context.Background(), "192.0.2.1", "z0", nil)
		<-r.started
		n := 0
		for a := 1; a <= networkShare; a++ {
			for k := 0; k < 2; k++ {
				pk := fmt.Sprintf("s%d", n)
				n++
				go q.submit(context.Background(), fmt.Sprintf(nets[0], a), pk, nil)
				waitFor(t, func() bool { return q.pending(pk) })
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		ok, msg := q.submit(ctx, fmt.Sprintf(nets[0], networkShare+1), "over", nil)
		cancel()
		if ok || msg != errBusy || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("%s: another address of a full network: %v %q after %v, want a prompt refusal", nets[0], ok, msg, time.Since(start))
		}
		go q.submit(context.Background(), nets[1], "elsewhere", nil)
		waitFor(t, func() bool { return q.pending("elsewhere") })
		close(r.release)
	}
}

// The reviewer's flood (cyberspace-relay #15, round 4): unknown keys from
// 16 addresses keep a 64-unit queue full; a newcomer from another address
// still gets in every time, and is served well within its deadline.
func TestNewcomerGetsInAmongAFlood(t *testing.T) {
	run := func(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string) {
		time.Sleep(2 * time.Millisecond)
		return true, ""
	}
	const workers, capQ, perIP, addrs = 2, 64, 8, 16
	q := newWorkQueue(workers, capQ, perIP, 4, time.Second, run)
	stop, wg := make(chan struct{}), &sync.WaitGroup{}
	var n atomic.Int64
	for a := 0; a < addrs; a++ {
		for k := 0; k < perIP; k++ {
			wg.Add(1)
			go func(a int) {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					q.submit(context.Background(), fmt.Sprintf("10.%d.0.1", a), fmt.Sprintf("f%d", n.Add(1)), nil)
				}
			}(a)
		}
	}
	defer func() { close(stop); wg.Wait() }()
	time.Sleep(100 * time.Millisecond)
	tries, refused := 0, 0
	var worst time.Duration
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		tries++
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		ok, _ := q.submit(ctx, "203.0.113.9", fmt.Sprintf("u%d", tries), nil)
		cancel()
		if !ok {
			refused++
		} else {
			worst = max(worst, time.Since(start))
		}
	}
	t.Logf("newcomer among %d flooding addresses: %d tries, %d refused, worst wait %v", addrs, tries, refused, worst)
	if refused > 0 || worst > 500*time.Millisecond {
		t.Fatalf("a newcomer was refused %d of %d times (worst wait %v)", refused, tries, worst)
	}
}

// Over the cap, members go only as far as the non-members' work already
// running: the reviewer's probe (one slow unknown job holds the only
// worker; 200 members from fresh /24s) stays within cap + that work.
func TestMembersPastTheCapAreBounded(t *testing.T) {
	release := make(chan struct{})
	run := func(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string) {
		if pubkey[0] == 'u' {
			<-release
		}
		return true, ""
	}
	const capQ = 8
	q := newWorkQueue(1, capQ, 8, 4, 30*time.Second, run)
	q.member = func(pk string) bool { return pk[0] == 'm' }
	defer close(release)
	go q.submit(context.Background(), "198.51.100.1", "u0", nil)
	waitFor(t, func() bool { q.mu.Lock(); defer q.mu.Unlock(); return q.running == 1 && len(q.rings[1]) == 0 })
	admitted := 0
	for i := 0; i < 200; i++ {
		if w, refusal := q.enqueue(fmt.Sprintf("10.%d.%d.1", i/200, i%200), fmt.Sprintf("m%d", i), nil, nil); refusal == "" && w != nil {
			admitted++
		}
	}
	q.mu.Lock()
	queued, running := q.queued, q.classUnits[1]
	q.mu.Unlock()
	if queued > capQ+running || admitted != capQ {
		t.Fatalf("cap %d with %d unknown unit running: %d members admitted, %d units queued; want %d and at most %d", capQ, running, admitted, queued, capQ, capQ+running)
	}
}

// The job that makes room comes from the network holding the most queued
// work, not the address: three one-unit addresses of one /24 outweigh one
// address with two units elsewhere.
func TestEvictionChoosesTheFullestNetwork(t *testing.T) {
	r := newBlockedRun()
	defer close(r.release)
	q := newWorkQueue(1, 6, 8, 4, time.Second, r.run)
	go q.submit(context.Background(), "192.0.2.1", "z0", nil)
	<-r.started
	for _, x := range []struct{ ip, pk string }{{"198.51.100.1", "b1"}, {"198.51.100.1", "b2"},
		{"10.0.0.1", "n1"}, {"10.0.0.2", "n2"}, {"10.0.0.3", "n3"}} {
		go q.submit(context.Background(), x.ip, x.pk, nil)
		waitFor(t, func() bool { return q.pending(x.pk) })
	}
	go q.submit(context.Background(), "203.0.113.7", "c1", nil)
	waitFor(t, func() bool { return q.pending("c1") })
	if q.pending("n3") || !q.pending("b2") {
		t.Fatalf("want the newest job of the fullest network (n3) to make room, b2 kept: n3 %v b2 %v", q.pending("n3"), q.pending("b2"))
	}
}
