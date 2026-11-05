package regiongate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
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
	// Since, when above 0, asks only for events whose created_at is at
	// least this: the chain cache's incremental check.
	Since int64
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
	if q.Since > 0 {
		since := time.Unix(q.Since, 0)
		f.Since = &since
	}
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
	// rulesBase names the chain rules and the checker settings verdicts
	// rest on; rules adds the line's state. A cache entry or failure made
	// under other rules is not used.
	rulesBase string

	queue *workQueue
	// home is the region set of the gate's own config, the one Admit,
	// AdmitPubkey and LiveAllowed judge in. shared marks a gate that judges
	// in the region set each request names (NewSharedGate): one chain cache
	// and one queue serve every speakeasy, since a chain's head is the same
	// whatever region asks.
	home   *Regions
	shared bool
	// memberIn, on a shared gate, reports whether a position lies in any
	// region the gate serves (SetMemberRegions); nil: none.
	memberIn func(Coord) bool

	mu     sync.Mutex
	chains *chainCache
	// failed holds the events walks found invalid, beyond any entry's life;
	// progress the checkpoints of checks cut short (see saveProgress).
	failed        *failedSet
	progress      map[string]*Known
	progressOrder []string
}

// NewGate builds a gate. Sources are read in order and merged.
func NewGate(cfg *Config, verifier Verifier, sources ...Source) *Gate {
	orDefault := func(v, d int) int {
		if v <= 0 {
			return d
		}
		return v
	}
	// Strict mode stops each walk at the first proof it cannot judge:
	// nothing after it can move a strict position.
	verifier.StopAtUnchecked = cfg.Mode == ModeStrict
	g := &Gate{
		cfg: cfg, sources: sources, verifier: verifier, now: time.Now,
		rulesBase: fmt.Sprintf("%s mode=%s max_hop_verify_height=%d", ChainRulesRevision, cfg.Mode, orDefault(cfg.MaxHopVerifyHeight, DefaultMaxHopHeight)),
		chains:    newChainCache(orDefault(cfg.MaxCachedChains, 4096)),
		failed:    newFailedSet(), progress: map[string]*Known{},
		home: NewRegions(cfg.boxes...),
	}
	g.verifier.failed = g.failedEvent
	g.queue = newWorkQueue(orDefault(cfg.MaxConcurrentLookups, defaultLookups()), orDefault(cfg.MaxQueuedLookups, 256),
		orDefault(cfg.MaxQueuedPerIP, 8), maxQueuedPerPubkey, time.Duration(orDefault(cfg.CheckTimeoutSeconds, 30))*time.Second, nil)
	g.queue.runIn = g.run
	g.queue.member = g.isMember
	return g
}

// NewSharedGate builds a gate for many region sets at once (the
// speakeasies): every request names the Regions it is judged in (AdmitIn,
// AdmitPubkeyIn, LiveAllowedIn), and the chain cache, the failed set and the
// work queue are shared by all of them. The config's regions are not used.
// A known member, for the queue and the cache's eviction, is an identity
// whose position lies in any region the gate serves (SetMemberRegions),
// whichever region asked: fresh keys spawned elsewhere cost an attacker
// nothing and must never evict a player.
func NewSharedGate(cfg *Config, verifier Verifier, sources ...Source) *Gate {
	g := NewGate(cfg, verifier, sources...)
	g.home, g.shared = NewRegions(), true
	return g
}

// rules is rulesBase with the state of the line rides are checked against
// (SpecProofs.LineState): its source, and how often it has reorganized.
func (g *Gate) rules() string {
	if la, ok := g.verifier.Proofs.(lineAware); ok {
		return g.rulesBase + " line=" + la.LineState()
	}
	return g.rulesBase
}

// defaultLookups is how many checks run at once by default: about one per
// core the process may use, since a check is CPU-bound once its events are
// fetched.
func defaultLookups() int { return max(2, runtime.GOMAXPROCS(0)) }

type clientIPKey struct{}

// isMember reports whether pubkey has an admitted entry in the chain cache,
// fresh or not: the work queue serves known members first.
func (g *Gate) isMember(pubkey string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.chains.members.byPub[pubkey]
	return e != nil && e.Value.(*cacheItem).entry.rules == g.rules()
}

// IsMember reports whether pubkey is a known member: kept with the members
// in the chain cache and served first by the work queue.
func (g *Gate) IsMember(pubkey string) bool { return g.isMember(pubkey) }

// WithClientIP returns ctx carrying the address of the client a request
// came from, which the gate's work queue limits per address.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func clientIP(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}

// Admit reports whether evt may be stored, and the NIP-01 OK message when
// not. A movement event by its author is judged by the position it leaves
// the author in, so moving into the region is admitted with the move itself
// and moving out is refused.
func (g *Gate) Admit(ctx context.Context, evt nostr.Event) (bool, string) {
	return g.AdmitIn(ctx, evt, g.home)
}

// AdmitIn is Admit judged in the region set in instead of the gate's own.
func (g *Gate) AdmitIn(ctx context.Context, evt nostr.Event, in *Regions) (bool, string) {
	for _, k := range g.cfg.AlwaysAllowKinds {
		if evt.Kind == k {
			return true, ""
		}
	}
	return g.AdmitAuthorIn(ctx, evt, in)
}

// AdmitAuthorIn is AdmitIn without always_allow_kinds: the event is admitted
// only when its author is exempt or inside in (with the event itself, for a
// movement event). A speakeasy judges with it, since a kind admitted from
// anyone would let anyone write into a private room.
func (g *Gate) AdmitAuthorIn(ctx context.Context, evt nostr.Event, in *Regions) (bool, string) {
	if g.cfg.exempt[evt.PubKey] {
		return true, ""
	}
	if evt.Kind == KindMovement {
		return g.check(ctx, evt.PubKey, &evt, in)
	}
	return g.AdmitPubkeyIn(ctx, evt.PubKey, in)
}

// AdmitPubkey reports whether a pubkey is inside the region right now: from
// the chain cache when fresh, otherwise by one shared check. Readers are
// judged with it (by the pubkey they authenticated as), and so are writers
// of anything but movement events.
func (g *Gate) AdmitPubkey(ctx context.Context, pubkey string) (bool, string) {
	return g.AdmitPubkeyIn(ctx, pubkey, g.home)
}

// AdmitPubkeyIn is AdmitPubkey judged in the region set in.
func (g *Gate) AdmitPubkeyIn(ctx context.Context, pubkey string, in *Regions) (bool, string) {
	if g.cfg.exempt[pubkey] {
		return true, ""
	}
	return g.check(ctx, pubkey, nil, in)
}

// check answers from the chain cache when that needs no new work, and
// otherwise queues a check of the pubkey, with the incoming movement event
// or none.
func (g *Gate) check(ctx context.Context, pubkey string, incoming *nostr.Event, in *Regions) (bool, string) {
	if ok, reason, hit := g.cached(pubkey, incoming, in); hit {
		return ok, reason
	}
	return g.queue.submitIn(ctx, clientIP(ctx), pubkey, incoming, in)
}

// cached is the verdict of pubkey's entry when it is fresh and, for a
// movement event, already accounts for it or would answer the same with it
// (sameVerdictWith): a re-sent event costs nothing, refused or not.
func (g *Gate) cached(pubkey string, incoming *nostr.Event, in *Regions) (bool, string, bool) {
	g.mu.Lock()
	e := g.chains.get(pubkey, g.rules())
	g.mu.Unlock()
	if e == nil || !g.fresh(e, in) {
		return false, "", false
	}
	if incoming != nil && !e.accounted(incoming.ID) {
		m, _ := ParseMove(*incoming)
		_, _, failed := g.failedEvent(incoming.ID)
		if !g.authentic(pubkey)(*incoming) || !e.sameVerdictWith(m, failed) {
			return false, "", false
		}
	}
	ok, reason := g.judge(e.vd, in)
	return ok, reason, true
}

// fresh reports whether an entry is recent enough to answer without
// asking the sources: for cache_ttl_seconds when it admits in the region
// set asked about, for negative_cache_ttl_seconds when it refuses there. One
// entry can be fresh for one speakeasy and stale for another: an identity
// refused here is checked again sooner, in case it has moved in. An entry
// that left a ride waiting for a height the line now holds is never fresh.
func (g *Gate) fresh(e *chainEntry, in *Regions) bool {
	if lineReached(g.verifier.Proofs, e.known) {
		return false // a ride it left unchecked can be judged now
	}
	ok, _ := g.judge(e.vd, in)
	return g.now().Before(e.checkedAt.Add(g.cfg.cacheTTL(ok)))
}

// SetMemberRegions tells a shared gate which positions make a member: those
// in any region it serves (the union of the registered speakeasies). It is
// called before the gate serves.
func (g *Gate) SetMemberRegions(inAny func(Coord) bool) { g.memberIn = inAny }

// memberClass reports whether an entry belongs with the members in the
// cache and the queue: admitted in the gate's own region, or, on a shared
// gate, placed inside any region it serves.
func (g *Gate) memberClass(vd Verdict, in *Regions) bool {
	if g.shared {
		pos := g.position(vd)
		return pos != nil && g.memberIn != nil && g.memberIn(*pos)
	}
	ok, _ := g.judge(vd, in)
	return ok
}

// run is one queued check, on a worker: it brings the pubkey's entry up to
// date and stores it, unless the check was cut short. An incoming movement
// event is judged in the region set its request named.
func (g *Gate) run(ctx context.Context, pubkey string, incoming *nostr.Event, in *Regions) (bool, string) {
	// An earlier check of this job may have answered it already.
	if ok, reason, hit := g.cached(pubkey, incoming, in); hit {
		return ok, reason
	}
	rules := g.rules()
	g.mu.Lock()
	e := g.chains.get(pubkey, rules)
	g.mu.Unlock()
	o := g.refresh(ctx, pubkey, e, incoming)
	if g.rules() != rules {
		// The line reorganized while the check ran: what it read may be
		// from both sides, so none of it is kept.
		return false, errBusy
	}
	// The incoming event enters the entry only when it is admitted, and so
	// stored here: a refused one is stored nowhere, and no reader would see
	// the identity where it puts it.
	keep := o.base
	ok, reason := false, o.refusal
	if o.refusal == "" && o.with != nil {
		if ok, reason = g.judge(o.with.vd, in); ok {
			keep = o.with
		}
	}
	g.mu.Lock()
	for _, x := range []*chainEntry{o.base, o.with} {
		if x != nil {
			g.failed.add(x.known, rules)
		}
	}
	if keep != nil {
		g.chains.put(pubkey, keep, g.memberClass(keep.vd, in))
		delete(g.progress, pubkey)
	}
	g.mu.Unlock()
	if o.refusal != "" {
		return false, o.refusal // a failed, incomplete or cut-short lookup is not a verdict
	}
	return ok, reason
}

// LiveAllowed decides, without blocking, whether a live event may be pushed
// to a connection authenticated as pubkey. It answers from the chain cache;
// an expired entry keeps answering until a background check replaces it
// (so someone who leaves the region stops receiving events within one
// cache_ttl_seconds plus one check), and an unknown pubkey gets nothing
// until its check completes.
func (g *Gate) LiveAllowed(pubkey string) bool {
	return g.LiveAllowedIn(pubkey, g.home)
}

// LiveAllowedIn is LiveAllowed judged in the region set in.
func (g *Gate) LiveAllowedIn(pubkey string, in *Regions) bool {
	if pubkey == "" {
		return false
	}
	if g.cfg.exempt[pubkey] {
		return true
	}
	g.mu.Lock()
	e := g.chains.get(pubkey, g.rules())
	g.mu.Unlock()
	if (e == nil || !g.fresh(e, in)) && !g.queue.pending(pubkey) {
		go func() {
			ctx, cancel := context.WithTimeout(WithClientIP(context.Background(), liveBucket), g.lookupTimeout())
			defer cancel()
			g.AdmitPubkeyIn(ctx, pubkey, in)
		}()
	}
	if e == nil {
		return false
	}
	ok, _ := g.judge(e.vd, in)
	return ok
}

func (g *Gate) lookupTimeout() time.Duration {
	return time.Duration(g.cfg.FetchTimeoutSeconds+2) * time.Second
}

const (
	errFetch      = "restricted: could not fetch your cyberspace chain, try again"
	errBusy       = "restricted: relay busy verifying chains, try again"
	errIncomplete = "restricted: could not fetch your whole cyberspace chain, so it cannot be verified yet, try again"
	errTooLong    = "restricted: your cyberspace chain has more events than this relay reads (max_chain_events), so it cannot be verified, try again"
	errTimeout    = "restricted: cyberspace chain lookup timed out, try again"
)

// maxGapRounds bounds how many times one lookup asks for missing events.
const maxGapRounds = 8

// judge turns a verdict into the gate's answer. The verdict's position is
// where the identity stands, valid chain or not. An invalid chain is frozen
// at its last valid position (§3.2, §8.7.3), and an invalid newest spawn
// leaves the identity at its spawn coordinate, so the gate judges both by
// that position: a frozen identity inside the region stays admitted until
// it respawns, and no event published on a frozen chain, the incoming one
// included, can move it in or out. Only a respawn changes its position.
// Strict mode takes the position from the proof-verified prefix.
// Each request is judged in the region set it names (in).
func (g *Gate) judge(vd Verdict, in *Regions) (bool, string) {
	pos := g.position(vd)
	switch {
	case !vd.HasChain:
		return false, "restricted: this relay is only for cyberspace identities inside its region; no movement chain found for your pubkey"
	case pos == nil:
		return false, "restricted: your cyberspace chain could not be verified: " + vd.Stopped
	case !in.Contains(*pos):
		return false, "restricted: your cyberspace position is outside this relay's region"
	}
	return true, ""
}

// position is where the gate places the identity a verdict is about: the
// proof-verified position in strict mode, the chain's otherwise; nil when
// there is none.
func (g *Gate) position(vd Verdict) *Coord {
	if !vd.HasChain {
		return nil
	}
	if g.cfg.Mode == ModeStrict {
		return vd.VerifiedPosition
	}
	return vd.Position
}

// authentic reports whether an event counts for pubkey's chain at all: by
// that pubkey, of the movement kind, and signed.
func (g *Gate) authentic(pubkey string) func(nostr.Event) bool {
	return func(e nostr.Event) bool {
		return e.PubKey == pubkey && e.Kind == KindMovement && (g.verifier.Signature == nil || g.verifier.Signature(e))
	}
}

// read reads a pubkey's chain whole and verifies it, with an optional new
// movement event and other new events (extra) appended, and what earlier
// walks established (known; the one about this chain is used). It returns
// the entry, or why there is no verdict; a walk its deadline cuts short
// leaves a checkpoint.
func (g *Gate) read(ctx context.Context, pubkey string, incoming *nostr.Event, extra []nostr.Event, known []*Known) (*chainEntry, string) {
	added := extra
	if incoming != nil {
		added = append(added[:len(added):len(added)], *incoming)
	}
	// 1. The spawns. Authenticity is checked before choosing, so a forged
	// "newer" spawn cannot redirect the lookup (§8.7.3). Validity is not:
	// the newest authentic spawn is the one whose chain is fetched even when
	// it is invalid, because the newest spawn wins with no fallback (§3.2).
	authentic := g.authentic(pubkey)
	isSpawn := func(e nostr.Event) bool {
		m, _ := ParseMove(e)
		return m.IsSpawn && authentic(e)
	}
	spawns, cov, ok := g.gather(ctx, pubkey, ChainQuery{Tags: map[string][]string{"A": {ActSpawn}}, Keep: isSpawn})
	if !ok {
		return nil, errFetch
	}
	for _, e := range added {
		if isSpawn(e) {
			spawns = append(spawns, e)
		}
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
			return !m.IsSpawn && m.Genesis == spawnID && authentic(e)
		}
		chain, chainCov, ok := g.gather(ctx, pubkey, ChainQuery{Tags: map[string][]string{"e": {spawnID}}, Keep: onChain})
		if !ok {
			return nil, errFetch
		}
		cov.add(chainCov)
		for _, e := range added {
			if onChain(e) {
				chain = append(chain, e)
			}
		}
		// 3. The gaps. A held event whose previous is neither the spawn nor
		// held means the answers left something out, unless that event
		// turns out to be one resolution never follows: inauthentic, by
		// another author or kind, or on another chain (§8.7.3).
		chain, gapCov, gap, ok := g.fillGaps(ctx, pubkey, spawnID, chain, onChain)
		if !ok {
			return nil, errFetch
		}
		cov.add(gapCov)
		if gap != "" && !cov.Truncated() {
			log.RegionGate().Debug("Chain gap", "pubkey", pubkey, "missing", gap)
			return nil, errIncomplete
		}
		events = append(events, chain...)
	}
	// Whatever a truncated answer left out could change the verdict: a
	// second branch, which makes the chain dead, or the events right after
	// the spawn. Refuse without caching rather than judge a part of the
	// chain.
	switch {
	case cov.Capped:
		return nil, errTooLong
	case cov.Partial:
		return nil, errIncomplete
	}

	// The check ends with ctx: nothing reached after it is cached.
	vd, k, chain, err := g.verifier.verify(ctx, pubkey, events, known...)
	if err != nil {
		g.saveProgress(pubkey, k)
		return nil, errTimeout
	}
	log.RegionGate().Debug("Chain verdict", "pubkey", pubkey, "has_chain", vd.HasChain,
		"length", vd.Length, "unchecked", vd.Unchecked, "skipped", len(vd.Skipped), "position_event", vd.PositionEvent,
		"reason", vd.Reason, "stopped", vd.Stopped)
	// Every event handed in counts as accounted for, those resolution does
	// not read included, so the next incremental check skips them.
	return g.newEntry(vd, k, chain, append(events, added...)), ""
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
