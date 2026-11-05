package regiongate

import (
	"context"
	"strings"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// sharedGate is a gate for many region sets (the speakeasies) over src.
func sharedGate(t *testing.T, src Source) *Gate {
	t.Helper()
	cfg := &Config{Enabled: true, Mode: ModeStructural, AlwaysAllowKinds: []int{5}, CacheTTLSeconds: 600,
		NegativeCacheTTLSeconds: 60, MaxConcurrentLookups: 1, exempt: map[string]bool{}}
	return NewSharedGate(cfg, verifier(), src)
}

// One shared gate judges each speakeasy in its own region, from one check of
// the chain: the cache is shared, the verdict is not.
func TestSharedGateJudgesEachRegionApart(t *testing.T) {
	ctx := context.Background()
	in := newSigner(t)
	b := newChain(t, in)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g := sharedGate(t, src)
	here := NewRegions(cubeAround(t, in.pubkey, 40))
	there := NewRegions(cubeAround(t, offset(t, in.pubkey, 1<<41), 40))
	g.SetMemberRegions(func(c Coord) bool { return here.Contains(c) || there.Contains(c) })

	if ok, msg := g.AdmitPubkeyIn(ctx, in.pubkey, here); !ok {
		t.Fatalf("refused in its own region: %s", msg)
	}
	calls := src.calls.Load()
	if ok, msg := g.AdmitPubkeyIn(ctx, in.pubkey, there); ok || !strings.Contains(msg, "outside") {
		t.Fatalf("admitted in another region (%v, %q)", ok, msg)
	}
	if ok, _ := g.AdmitPubkeyIn(ctx, in.pubkey, here); !ok {
		t.Fatal("refused in its own region after being judged elsewhere")
	}
	if src.calls.Load() != calls {
		t.Fatalf("the second region asked the sources again (%d calls, want %d): the chain cache must be shared", src.calls.Load(), calls)
	}
	// Inside a served region, so a member for the queue and the cache,
	// whatever region asked last.
	if !g.isMember(in.pubkey) {
		t.Fatal("an identity inside a served region is not a member of the shared gate")
	}
	if g.LiveAllowedIn(in.pubkey, there) || !g.LiveAllowedIn(in.pubkey, here) {
		t.Fatal("live events must follow each region's own verdict")
	}
	if g.AdmitPubkeyIn(ctx, in.pubkey, NewRegions()); g.LiveAllowed(in.pubkey) {
		t.Fatal("a shared gate's own region set is empty: nobody is inside it")
	}
}

// An entry refused in one region expires there at the negative TTL, while
// the same entry, admitted elsewhere, stays fresh there for the positive one:
// an identity that moves in is checked again soon.
func TestSharedGateFreshnessIsPerRegion(t *testing.T) {
	ctx := context.Background()
	in := newSigner(t)
	b := newChain(t, in)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g := sharedGate(t, src)
	clock := time.Now()
	g.now = func() time.Time { return clock }
	here := NewRegions(cubeAround(t, in.pubkey, 40))
	there := NewRegions(cubeAround(t, offset(t, in.pubkey, 1<<41), 40))

	g.AdmitPubkeyIn(ctx, in.pubkey, here)
	clock = clock.Add(61 * time.Second)
	calls := src.calls.Load()
	if ok, _ := g.AdmitPubkeyIn(ctx, in.pubkey, here); !ok || src.calls.Load() != calls {
		t.Fatal("an admitted entry went stale before cache_ttl_seconds")
	}
	if ok, _ := g.AdmitPubkeyIn(ctx, in.pubkey, there); ok || src.calls.Load() == calls {
		t.Fatal("a refusal was answered from an entry older than negative_cache_ttl_seconds")
	}
}

// The same movement event sent to two speakeasies at once joins one job,
// and each is answered in its own region: moving into one is moving out of
// the other.
func TestSharedQueueAnswersEachRegion(t *testing.T) {
	in := newSigner(t)
	b := newChain(t, in)
	there := offset(t, in.pubkey, 1<<41)
	hop := b.move(ActHop, there)
	src := &fakeSource{events: []nostr.Event{b.spawn}, delay: 50 * time.Millisecond}
	g := sharedGate(t, src)
	from := NewRegions(cubeAround(t, in.pubkey, 40))
	to := NewRegions(cubeAround(t, there, 40))

	// Keep the one worker busy so both requests wait in the same job.
	other := newSigner(t)
	go g.AdmitPubkeyIn(context.Background(), other.pubkey, from)
	time.Sleep(20 * time.Millisecond)

	type answer struct {
		ok  bool
		msg string
	}
	toCh, fromCh := make(chan answer, 1), make(chan answer, 1)
	go func() { ok, msg := g.AdmitIn(context.Background(), hop, to); toCh <- answer{ok, msg} }()
	time.Sleep(5 * time.Millisecond)
	go func() { ok, msg := g.AdmitIn(context.Background(), hop, from); fromCh <- answer{ok, msg} }()
	a, f := <-toCh, <-fromCh
	if !a.ok {
		t.Fatalf("the move into the region was refused there: %s", a.msg)
	}
	if f.ok || !strings.Contains(f.msg, "outside") {
		t.Fatalf("the move out of a region was admitted there (%v, %q): an answer for one region was handed to another", f.ok, f.msg)
	}
}

// On a shared gate a member is an identity placed inside any region the gate
// serves, whichever region asked: one judged where it is outside is still a
// player, kept with the members and served first by the queue. A key placed
// outside every region is not.
func TestSharedGateMemberIsInsideAServedRegion(t *testing.T) {
	in := newSigner(t)
	src := &fakeSource{events: []nostr.Event{newChain(t, in).spawn}}
	g := sharedGate(t, src)
	here := NewRegions(cubeAround(t, in.pubkey, 40))
	there := NewRegions(cubeAround(t, offset(t, in.pubkey, 1<<41), 40))
	g.SetMemberRegions(here.Contains)
	if ok, _ := g.AdmitPubkeyIn(context.Background(), in.pubkey, there); ok {
		t.Fatal("admitted outside")
	}
	if !g.isMember(in.pubkey) {
		t.Fatal("an identity inside a served region, refused in another, is not a member")
	}
	elsewhere := newSigner(t)
	src.mu.Lock()
	src.events = append(src.events, newChain(t, elsewhere).spawn)
	src.mu.Unlock()
	g.AdmitPubkeyIn(context.Background(), elsewhere.pubkey, there)
	if g.isMember(elsewhere.pubkey) {
		t.Fatal("an identity placed outside every served region is a member")
	}
}

// Fresh keys spawned outside every served region (free for an attacker) are
// never members, so they cannot evict a real member's entry from the chain
// cache (the #15 eviction rule, on a shared gate).
func TestSharedGateFreshSpawnsNeverEvictMembers(t *testing.T) {
	ctx := context.Background()
	member := newSigner(t)
	src := &fakeSource{events: []nostr.Event{newChain(t, member).spawn}}
	cfg := &Config{Enabled: true, Mode: ModeStructural, AlwaysAllowKinds: []int{5}, CacheTTLSeconds: 600,
		NegativeCacheTTLSeconds: 60, MaxConcurrentLookups: 1, MaxCachedChains: 8, exempt: map[string]bool{}}
	g := NewSharedGate(cfg, verifier(), src)
	room := NewRegions(cubeAround(t, member.pubkey, 40))
	g.SetMemberRegions(room.Contains)
	if ok, msg := g.AdmitPubkeyIn(ctx, member.pubkey, room); !ok {
		t.Fatal(msg)
	}
	for i := 0; i < 20; i++ {
		k := newSigner(t)
		src.mu.Lock()
		src.events = append(src.events, newChain(t, k).spawn)
		src.mu.Unlock()
		if room.Contains(mustCoord(t, k.pubkey)) {
			continue
		}
		if ok, _ := g.AdmitPubkeyIn(ctx, k.pubkey, room); ok {
			t.Fatal("a fresh key outside was admitted")
		}
	}
	g.mu.Lock()
	kept := g.chains.get(member.pubkey, g.rules()) != nil
	g.mu.Unlock()
	if !kept || !g.isMember(member.pubkey) {
		t.Fatal("fresh spawned keys outside every region evicted a member's cache entry")
	}
}
