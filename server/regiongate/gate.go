package regiongate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/0ceanslim/grain/client/core"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils/log"
)

// ChainQuery is one question the gate asks a Source about one pubkey's
// movement events (kind 3333).
type ChainQuery struct {
	// Tags are NIP-01 tag filters, keys without "#". The gate asks
	// {"A": ["spawn"]} for the spawns, then {"e": [spawn_id]} for the events
	// of the newest spawn's chain (they all name it as genesis, §8.7.3
	// rule 2). Both are indexed tag queries, so an identity with a long
	// history of old chains costs two small answers instead of all of it.
	Tags map[string][]string
	// IDs asks for these events by id, to fill a gap in a chain.
	IDs []string
	// Max is how many kept events the source returns at most; 0 is no cap.
	// A source holding more reports the answer Capped.
	Max int
	// Keep, when set, says which events count: the others are dropped while
	// the source reads and never count toward Max, so events a third party
	// forged cannot push the identity's real events out of the answer.
	Keep func(nostr.Event) bool
}

// Coverage says how much of what a source holds an answer covers.
type Coverage struct {
	// Capped: the answer stopped at Max, so it may leave events out.
	// Relays answer newest first, so a capped answer drops the oldest
	// events, the ones right after the spawn.
	Capped bool
	// Partial: the source failed part way, after answering some of it.
	Partial bool
}

// Truncated reports whether the answer may leave out events the source
// holds.
func (c Coverage) Truncated() bool { return c.Capped || c.Partial }

func (c *Coverage) add(o Coverage) {
	c.Capped, c.Partial = c.Capped || o.Capped, c.Partial || o.Partial
}

// Source answers chain queries. It returns an error only when it could not
// answer at all.
type Source interface {
	Movement(ctx context.Context, pubkey string, q ChainQuery) ([]nostr.Event, Coverage, error)
}

// LocalSource reads movement events from this relay's store.
type LocalSource struct {
	Query func(filters []nostr.Filter, limit int) ([]nostr.Event, error)
	// MaxResults is the most events one Query call returns, whatever limit
	// it is given (nostrdb.MaxQueryResults), or 0 when it honors any limit.
	// An answer that fills it is Capped, since the store may hold more.
	MaxResults int
}

// Movement implements Source. It asks the store for one event more than
// Max, so that an answer over the cap is reported Capped.
func (s LocalSource) Movement(_ context.Context, pubkey string, q ChainQuery) ([]nostr.Event, Coverage, error) {
	limit := q.Max + 1
	if q.Max <= 0 {
		limit = s.MaxResults
	}
	if s.MaxResults > 0 && limit > s.MaxResults {
		limit = s.MaxResults
	}
	f := nostr.Filter{Authors: []string{pubkey}, Kinds: []int{KindMovement}, Tags: q.Tags, IDs: q.IDs}
	raw, err := s.Query([]nostr.Filter{f}, limit)
	if err != nil {
		return nil, Coverage{}, err
	}
	var out []nostr.Event
	for _, e := range raw {
		if q.Keep == nil || q.Keep(e) {
			out = append(out, e)
		}
	}
	capped := limit > 0 && len(raw) >= limit
	if q.Max > 0 && len(out) > q.Max {
		out, capped = out[:q.Max], true
	}
	return out, Coverage{Capped: capped}, nil
}

// Gate decides whether an event's author may publish here.
type Gate struct {
	cfg      *Config
	sources  []Source
	verifier Verifier
	now      func() time.Time

	lookups chan struct{} // semaphore: chain lookups in flight

	mu        sync.Mutex
	cache     map[string]cached
	inflight  map[string]*call
	lastSweep time.Time
}

// sweepAbove is the cache size past which expired entries are dropped.
const sweepAbove = 4096

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
	n := cfg.MaxConcurrentLookups
	if n <= 0 {
		n = 16
	}
	return &Gate{
		cfg: cfg, sources: sources, verifier: verifier, now: time.Now,
		lookups: make(chan struct{}, n),
		cache:   map[string]cached{}, inflight: map[string]*call{},
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
	return g.AdmitPubkey(ctx, evt.PubKey)
}

// AdmitPubkey reports whether a pubkey is inside the region right now: from
// the cache when fresh, otherwise by one shared lookup. Readers are judged
// with it (by the pubkey they authenticated as), and so are writers of
// anything but movement events.
func (g *Gate) AdmitPubkey(ctx context.Context, pubkey string) (bool, string) {
	if g.cfg.exempt[pubkey] {
		return true, ""
	}
	g.mu.Lock()
	if c, hit := g.cache[pubkey]; hit && g.now().Before(c.expires) {
		g.mu.Unlock()
		return c.ok, c.reason
	}
	if c := g.inflight[pubkey]; c != nil {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.ok, c.reason
		case <-ctx.Done():
			return false, "restricted: cyberspace chain lookup timed out, try again"
		}
	}
	c := &call{done: make(chan struct{})}
	g.inflight[pubkey] = c
	g.mu.Unlock()

	c.ok, c.reason = g.decide(ctx, pubkey, nil)
	g.mu.Lock()
	delete(g.inflight, pubkey)
	g.mu.Unlock()
	g.remember(pubkey, c.ok, c.reason)
	close(c.done)
	return c.ok, c.reason
}

// LiveAllowed decides, without blocking, whether a live event may be pushed
// to a connection authenticated as pubkey. It answers from the cache; an
// expired verdict keeps answering until a background lookup replaces it
// (so someone who leaves the region stops receiving events within one
// cache_ttl_seconds plus one lookup), and an unknown pubkey gets nothing
// until its lookup completes.
func (g *Gate) LiveAllowed(pubkey string) bool {
	if pubkey == "" {
		return false
	}
	if g.cfg.exempt[pubkey] {
		return true
	}
	g.mu.Lock()
	c, hit := g.cache[pubkey]
	fresh := hit && g.now().Before(c.expires)
	busy := g.inflight[pubkey] != nil
	g.mu.Unlock()
	if !fresh && !busy {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), g.lookupTimeout())
			defer cancel()
			g.AdmitPubkey(ctx, pubkey)
		}()
	}
	return hit && c.ok
}

func (g *Gate) lookupTimeout() time.Duration {
	return time.Duration(g.cfg.FetchTimeoutSeconds+2) * time.Second
}

func (g *Gate) remember(pubkey string, ok bool, reason string) {
	if reason == errFetch || reason == errBusy || reason == errIncomplete || reason == errTooLong {
		return // a failed or incomplete lookup is not a verdict
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.cache[pubkey] = cached{ok: ok, reason: reason, expires: now.Add(g.cfg.cacheTTL(ok))}
	// Refusals for random pubkeys would otherwise pile up forever.
	if len(g.cache) > sweepAbove && now.Sub(g.lastSweep) > time.Minute {
		g.lastSweep = now
		for pk, c := range g.cache {
			if !now.Before(c.expires) {
				delete(g.cache, pk)
			}
		}
	}
}

const (
	errFetch      = "restricted: could not fetch your cyberspace chain, try again"
	errBusy       = "restricted: relay busy verifying chains, try again"
	errIncomplete = "restricted: could not fetch your whole cyberspace chain, so it cannot be verified yet, try again"
	errTooLong    = "restricted: your cyberspace chain has more events than this relay reads (max_chain_events), so it cannot be verified, try again"
)

// maxGapRounds bounds how many times one lookup asks for missing events.
const maxGapRounds = 8

// decide fetches and verifies a pubkey's chain, with an optional new
// movement event appended, and checks the resulting position.
func (g *Gate) decide(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string) {
	select {
	case g.lookups <- struct{}{}:
		defer func() { <-g.lookups }()
	case <-ctx.Done():
		return false, errBusy
	}
	// 1. The spawns. Authenticity is checked before choosing, so a forged
	// "newer" spawn cannot redirect the lookup (§8.7.3). Validity is not:
	// the newest authentic spawn is the one whose chain is fetched even when
	// it is invalid, because the newest spawn wins with no fallback (§3.2).
	authentic := func(e nostr.Event) bool {
		return e.PubKey == pubkey && e.Kind == KindMovement && (g.verifier.Signature == nil || g.verifier.Signature(e))
	}
	isSpawn := func(e nostr.Event) bool {
		m, _ := ParseMove(e)
		return m.Action == ActSpawn && authentic(e)
	}
	spawns, cov, ok := g.gather(ctx, pubkey, ChainQuery{Tags: map[string][]string{"A": {ActSpawn}}, Keep: isSpawn})
	if !ok {
		return false, errFetch
	}
	if incoming != nil && isSpawn(*incoming) {
		spawns = append(spawns, *incoming)
	}
	var newest *nostr.Event
	for i := range spawns {
		if newest == nil || newer(spawns[i], *newest) {
			newest = &spawns[i]
		}
	}
	events := spawns
	// 2. The newest spawn's chain: every authentic event naming it as
	// genesis. Nothing else counts toward the cap.
	if newest != nil {
		spawnID := newest.ID
		onChain := func(e nostr.Event) bool {
			m, _ := ParseMove(e)
			return m.Action != ActSpawn && m.Genesis == spawnID && authentic(e)
		}
		chain, chainCov, ok := g.gather(ctx, pubkey, ChainQuery{Tags: map[string][]string{"e": {spawnID}}, Keep: onChain})
		if !ok {
			return false, errFetch
		}
		cov.add(chainCov)
		if incoming != nil && onChain(*incoming) {
			chain = append(chain, *incoming)
		}
		// 3. The gaps. A held event whose previous is neither the spawn nor
		// held means the answers left something out, unless that event
		// turns out to be one resolution never follows: inauthentic, by
		// another author or kind, or on another chain (§8.7.3).
		chain, gapCov, gap, ok := g.fillGaps(ctx, pubkey, spawnID, chain, onChain)
		if !ok {
			return false, errFetch
		}
		cov.add(gapCov)
		if gap != "" && !cov.Truncated() {
			log.RegionGate().Debug("Chain gap", "pubkey", pubkey, "missing", gap)
			return false, errIncomplete
		}
		events = append(events, chain...)
	}
	// Whatever a truncated answer left out could change the verdict: an
	// older branch at a fork, or the events right after the spawn. Refuse
	// without caching rather than judge a part of the chain.
	switch {
	case cov.Capped:
		return false, errTooLong
	case cov.Partial:
		return false, errIncomplete
	}

	// The verdict's position is where the identity stands, valid chain or
	// not. An invalid chain is frozen at its last valid position (§3.2,
	// §8.7.3), and an invalid newest spawn leaves the identity at its spawn
	// coordinate, so the gate judges both by that position: a frozen
	// identity inside the region stays admitted until it respawns, and no
	// event published on a frozen chain, the incoming one included, can move
	// it in or out. Only a respawn changes its position.
	vd := g.verifier.Verify(pubkey, events)
	pos := vd.Position
	if g.cfg.Mode == ModeStrict {
		pos = vd.VerifiedPosition
	}
	log.RegionGate().Debug("Chain verdict", "pubkey", pubkey, "has_chain", vd.HasChain,
		"length", vd.Length, "unchecked", vd.Unchecked, "skipped", len(vd.Skipped), "position_event", vd.PositionEvent,
		"reason", vd.Reason, "stopped", vd.Stopped)
	switch {
	case !vd.HasChain:
		return false, "restricted: this relay is only for cyberspace identities inside its region; no movement chain found for your pubkey"
	case pos == nil:
		return false, "restricted: your cyberspace chain could not be verified: " + vd.Stopped
	case !g.cfg.Contains(*pos):
		return false, "restricted: your cyberspace position is outside this relay's region"
	}
	return true, ""
}

// gather asks every source one question and merges the answers, with
// MaxChainEvents as each source's cap. It fails only when every source
// fails. A source that fails outright is left out, as a relay that does not
// hold the events would be; one that answers part of it is Partial.
func (g *Gate) gather(ctx context.Context, pubkey string, q ChainQuery) ([]nostr.Event, Coverage, bool) {
	q.Max = g.cfg.MaxChainEvents
	var events []nostr.Event
	var cov Coverage
	failures := 0
	for _, s := range g.sources {
		evs, c, err := s.Movement(ctx, pubkey, q)
		if err != nil {
			failures++
			log.RegionGate().Warn("Chain source failed", "pubkey", pubkey, "error", err)
			continue
		}
		cov.add(c)
		events = append(events, evs...)
	}
	return events, cov, failures < len(g.sources) || len(g.sources) == 0
}

// fillGaps asks for the events that held chain events name as previous but
// that nobody has handed over yet, by id, until there are none or
// maxGapRounds is spent. An event that comes back and counts (onChain) joins
// the chain and may reveal the next gap. One that comes back but does not
// count closes its gap, because resolution never follows it: an event naming
// it is cut off (§8.7.3). It returns the chain events, the coverage of those
// answers, and the id of a missing event no source returned, or "".
func (g *Gate) fillGaps(ctx context.Context, pubkey, spawnID string, chain []nostr.Event, onChain func(nostr.Event) bool) ([]nostr.Event, Coverage, string, bool) {
	held := map[string]bool{spawnID: true}
	for _, e := range chain {
		held[e.ID] = true
	}
	var cov Coverage
	for round := 0; ; round++ {
		var missing []string
		asked := map[string]bool{}
		for _, e := range chain {
			m, _ := ParseMove(e)
			if m.Previous != "" && !held[m.Previous] && !asked[m.Previous] {
				asked[m.Previous] = true
				missing = append(missing, m.Previous)
			}
		}
		if len(missing) == 0 {
			return chain, cov, "", true
		}
		if round == maxGapRounds {
			return chain, cov, missing[0], true
		}
		found, c, ok := g.gather(ctx, pubkey, ChainQuery{IDs: missing})
		if !ok {
			return chain, cov, "", false
		}
		cov.add(c)
		// Only the event that really has the asked id can answer for it: an
		// event whose id is not the hash of its content is a forgery
		// borrowing the id, and must not close the gap, or anyone could cut
		// another identity's chain short by publishing one (§8.7.3).
		progress := false
		for _, e := range found {
			if !asked[e.ID] || held[e.ID] || !idMatches(e) {
				continue
			}
			held[e.ID], progress = true, true
			if onChain(e) {
				chain = append(chain, e)
			}
		}
		if !progress {
			return chain, cov, missing[0], true
		}
	}
}

// idMatches reports whether the event's id is the NIP-01 hash of its
// content, so that it is the one event that can carry that id, whatever its
// signature says.
func idMatches(e nostr.Event) bool {
	sum := sha256.Sum256([]byte(core.SerializeEvent(e)))
	return hex.EncodeToString(sum[:]) == e.ID
}
