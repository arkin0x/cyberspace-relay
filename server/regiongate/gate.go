package regiongate

import (
	"context"
	"sync"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils/log"
)

// Source returns a pubkey's movement events (kind 3333) that carry the given
// tag values (NIP-01 tag filters, keys without "#"). The gate asks two such
// questions: {"A": ["spawn"]} for the spawns, then {"e": [spawn_id]} for the
// events of the newest spawn's chain (they all name it as genesis, §8.7.3
// step 2). Both are indexed tag queries, so an identity with a long history
// of old chains costs two small answers instead of all of it.
type Source interface {
	Movement(ctx context.Context, pubkey string, tags map[string][]string, max int) ([]nostr.Event, error)
}

// LocalSource reads movement events from this relay's store.
type LocalSource struct {
	Query func(filters []nostr.Filter, limit int) ([]nostr.Event, error)
}

// Movement implements Source.
func (s LocalSource) Movement(_ context.Context, pubkey string, tags map[string][]string, max int) ([]nostr.Event, error) {
	return s.Query([]nostr.Filter{{Authors: []string{pubkey}, Kinds: []int{KindMovement}, Tags: tags}}, max)
}

// Gate decides whether an event's author may publish here.
type Gate struct {
	cfg      *Config
	sources  []Source
	verifier Verifier
	now      func() time.Time

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]*call
}

type cached struct {
	ok      bool
	reason  string
	expires time.Time
}

type call struct {
	done   chan struct{}
	ok     bool
	reason string
}

// NewGate builds a gate. Sources are read in order and merged.
func NewGate(cfg *Config, verifier Verifier, sources ...Source) *Gate {
	return &Gate{
		cfg: cfg, sources: sources, verifier: verifier, now: time.Now,
		cache: map[string]cached{}, inflight: map[string]*call{},
	}
}

// Admit reports whether evt may be stored, and the NIP-01 OK message when
// not. A movement event by its author is judged by the position it leaves
// the author in, so moving into the region is admitted with the move itself
// and moving out is refused.
func (g *Gate) Admit(ctx context.Context, evt nostr.Event) (bool, string) {
	if g.cfg.exempt[evt.PubKey] {
		return true, ""
	}
	for _, k := range g.cfg.AlwaysAllowKinds {
		if evt.Kind == k {
			return true, ""
		}
	}
	if evt.Kind == KindMovement {
		ok, reason := g.decide(ctx, evt.PubKey, &evt)
		g.remember(evt.PubKey, ok, reason)
		return ok, reason
	}

	g.mu.Lock()
	if c, hit := g.cache[evt.PubKey]; hit && g.now().Before(c.expires) {
		g.mu.Unlock()
		return c.ok, c.reason
	}
	if c := g.inflight[evt.PubKey]; c != nil {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.ok, c.reason
		case <-ctx.Done():
			return false, "restricted: cyberspace chain lookup timed out, try again"
		}
	}
	c := &call{done: make(chan struct{})}
	g.inflight[evt.PubKey] = c
	g.mu.Unlock()

	c.ok, c.reason = g.decide(ctx, evt.PubKey, nil)
	g.mu.Lock()
	delete(g.inflight, evt.PubKey)
	g.mu.Unlock()
	g.remember(evt.PubKey, c.ok, c.reason)
	close(c.done)
	return c.ok, c.reason
}

func (g *Gate) remember(pubkey string, ok bool, reason string) {
	if reason == errFetch {
		return // a failed lookup is not a verdict
	}
	g.mu.Lock()
	g.cache[pubkey] = cached{ok: ok, reason: reason, expires: g.now().Add(g.cfg.cacheTTL(ok))}
	g.mu.Unlock()
}

const errFetch = "restricted: could not fetch your cyberspace chain, try again"

// decide fetches and verifies a pubkey's chain, with an optional new
// movement event appended, and checks the resulting position.
func (g *Gate) decide(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string) {
	// 1. The spawns. Signatures are checked before choosing, so a forged
	// "newer" spawn cannot redirect the lookup.
	spawns, ok := g.gather(ctx, pubkey, map[string][]string{"A": {ActSpawn}})
	if !ok {
		return false, errFetch
	}
	if incoming != nil {
		spawns = append(spawns, *incoming)
	}
	var newest *nostr.Event
	for i := range spawns {
		e := &spawns[i]
		if m, isMove := ParseMove(*e); !isMove || m.Action != ActSpawn || e.PubKey != pubkey {
			continue
		}
		if g.verifier.Signature != nil && !g.verifier.Signature(*e) {
			continue
		}
		if newest == nil || newer(*e, *newest) {
			newest = e
		}
	}
	events := spawns
	// 2. The newest spawn's chain: every event naming it.
	if newest != nil {
		chain, ok := g.gather(ctx, pubkey, map[string][]string{"e": {newest.ID}})
		if !ok {
			return false, errFetch
		}
		events = append(events, chain...)
	}

	vd := g.verifier.Verify(pubkey, events)
	pos := vd.Position
	if g.cfg.Mode == ModeStrict {
		pos = vd.VerifiedPosition
	}
	log.RegionGate().Debug("Chain verdict", "pubkey", pubkey, "has_chain", vd.HasChain,
		"length", vd.Length, "unchecked", vd.Unchecked, "position_event", vd.PositionEvent, "stopped", vd.Stopped)
	switch {
	case !vd.HasChain:
		return false, "restricted: this relay only accepts events from cyberspace identities inside its region; no movement chain found for your pubkey"
	case pos == nil:
		return false, "restricted: your cyberspace chain could not be verified: " + vd.Stopped
	case !g.cfg.Contains(*pos):
		return false, "restricted: your cyberspace position is outside this relay's region"
	}
	return true, ""
}

// gather asks every source one question and merges the answers. It fails
// only when every source fails.
func (g *Gate) gather(ctx context.Context, pubkey string, tags map[string][]string) ([]nostr.Event, bool) {
	var events []nostr.Event
	failures := 0
	for _, s := range g.sources {
		evs, err := s.Movement(ctx, pubkey, tags, g.cfg.MaxChainEvents)
		if err != nil {
			failures++
			log.RegionGate().Warn("Chain source failed", "pubkey", pubkey, "error", err)
			continue
		}
		events = append(events, evs...)
	}
	return events, failures < len(g.sources) || len(g.sources) == 0
}
