package regiongate

import (
	"container/list"
	"context"
	"encoding/hex"
	"sort"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// The chain cache (speakeasy design, section 4, the owner's design): per
// pubkey, the chain genesis id, the highest created_at validated, the head
// event and the position it leaves the identity at, the rules it was checked
// under, and the point where the chain stopped being valid, if it did. The
// next check asks the sources only for events newer than that created_at,
// less a look-back, and walks on from the head over them alone.
//
// It is also the fix for the re-sent forgery (cyberspace-relay #11 review):
// an event the entry has accounted for is answered from it, and a chain
// invalid at an event is invalid there again on any later walk without its
// proof being checked (Known, and the failed set, which outlives the
// entry), so one forged proof costs one check however often it is sent.
//
// Only what the sources hold, and an incoming event that is admitted (and so
// stored here), enter an entry. A refused incoming event is judged but not
// kept: it is stored nowhere, and keeping it would leave the identity where
// that event put it, which no other reader sees.

const (
	// lookbackSeconds is how far before the highest validated created_at an
	// incremental check starts: an event can be signed earlier than it is
	// published (ONOSENDAI's TV census does the same with READ_OVERLAP_S).
	// Ids already accounted for are skipped.
	lookbackSeconds = 60 * 60
	// resyncAfter is how often a chain is read whole again, for an event
	// published elsewhere and signed more than lookbackSeconds before the
	// head (ONOSENDAI's READ_WHOLE_S is the same day). The re-read asks the
	// checker about no proof it already judged (Known).
	resyncAfter = 24 * time.Hour
	// wholeEvery is the least time between two whole reads of one pubkey's
	// chain that new events force (a fork, a gap, another genesis): junk
	// events naming an unknown previous cannot make the gate read the chain
	// whole on each one. A newer spawn is never held back.
	wholeEvery = 15 * time.Second
	// maxSeen bounds the ids an entry remembers in its look-back window.
	maxSeen = 1024
	// maxQueuedPerPubkey bounds the distinct movement events one pubkey can
	// have waiting.
	maxQueuedPerPubkey = 4
	// refusalShare: the cache of refusals and pubkeys with no chain holds
	// max_cached_chains / refusalShare entries, apart from admitted members,
	// so a flood of fresh keys never evicts a member.
	refusalShare = 4
	// maxFailed bounds the failed set, and maxProgress the checkpoints.
	maxFailed   = 16384
	maxProgress = 1024
)

// eventKey is an event id as 32 bytes, or false when it is not 64 hex
// characters (no authentic event has such an id).
func eventKey(id string) ([32]byte, bool) {
	var k [32]byte
	if len(id) != 64 {
		return k, false
	}
	if _, err := hex.Decode(k[:], []byte(id)); err != nil {
		return k, false
	}
	return k, true
}

// chainEntry is one pubkey's cached chain. Once stored it is never changed;
// a check stores a new one.
type chainEntry struct {
	// rules names the chain rules and checker settings it was checked under
	// (Gate.rules); under others it is not used.
	rules string
	// checkedAt is when it was last brought up to date, and wholeAt when its
	// chain was last read whole.
	checkedAt, wholeAt time.Time
	// vd is the verdict, without the Chain, Skipped and Fork lists: the
	// head (Head), the position for each mode (Position, VerifiedPosition)
	// and the failure point (Reason, InvalidAt, Stopped).
	vd Verdict
	// genesis is the active chain's spawn and genesisAt its created_at;
	// highest is the highest created_at on the active chain.
	genesis            string
	genesisAt, highest int64
	// seen holds the ids, with their created_at, of every event accounted
	// for in the look-back window; the window starts at floor when maxSeen
	// cut it short.
	seen  map[[32]byte]int64
	floor int64
	// walk is the walk at the head, when the chain is valid there and can be
	// walked on; nil for a chain that is invalid or where strict mode
	// stopped.
	walk *walker
	// known is what the walks of this chain established, for a whole
	// re-read of it.
	known *Known
	// held is every event id the whole read that made the entry held,
	// while that check runs; it is dropped before the entry is stored.
	held map[[32]byte]bool
}

// windowStart is the oldest created_at an incremental check asks for.
func (e *chainEntry) windowStart() int64 { return max(e.highest-lookbackSeconds, e.floor) }

// accounted reports whether the event id is already part of the entry: in
// its look-back window, or its spawn, head, failure point or strict stop
// point, whatever their created_at (a forgery backdated before the window is
// still answered from the entry when it is sent again).
func (e *chainEntry) accounted(id string) bool {
	if k, ok := eventKey(id); ok {
		if _, in := e.seen[k]; in {
			return true
		}
	}
	if id == "" {
		return false
	}
	return id == e.genesis || id == e.vd.Head || e.known != nil && (id == e.known.FailAt || id == e.known.StopAt)
}

// sameVerdictWith reports whether the entry's answer stands with m added,
// whatever m's proof says: an older spawn, an event on a chain dead by a
// fork, and an event extending the head of a chain that is frozen (invalid,
// or stopped in strict mode) or with an event the failed set already holds
// (the chain is then invalid at m, frozen where the head left it). An event
// dated before the window that does not extend the head is answered from
// the entry too, as the incremental check leaves such events to the daily
// whole read: otherwise replaying an identity's old, public chain events
// would make the gate read its whole chain again on each one.
func (e *chainEntry) sameVerdictWith(m Move, failed bool) bool {
	if m.IsSpawn {
		return !newer(m.Event, nostr.Event{ID: e.genesis, CreatedAt: e.genesisAt})
	}
	if e.vd.HasChain && m.Event.CreatedAt < e.windowStart() && m.Previous != e.vd.Head {
		return true
	}
	if !e.vd.HasChain || m.Genesis != e.genesis {
		return false
	}
	return e.vd.Reason == ReasonFork || m.Previous == e.vd.Head && (e.walk == nil || failed)
}

// lru is a least recently used set of entries.
type lru struct {
	max   int
	order *list.List // front: most recently used
	byPub map[string]*list.Element
}

type cacheItem struct {
	pubkey string
	entry  *chainEntry
}

func newLRU(max int) *lru {
	return &lru{max: max, order: list.New(), byPub: map[string]*list.Element{}}
}

func (c *lru) get(pubkey string) *chainEntry {
	el := c.byPub[pubkey]
	if el == nil {
		return nil
	}
	c.order.MoveToFront(el)
	return el.Value.(*cacheItem).entry
}

func (c *lru) put(pubkey string, e *chainEntry) {
	if el := c.byPub[pubkey]; el != nil {
		el.Value.(*cacheItem).entry = e
		c.order.MoveToFront(el)
		return
	}
	c.byPub[pubkey] = c.order.PushFront(&cacheItem{pubkey, e})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.byPub, last.Value.(*cacheItem).pubkey)
	}
}

func (c *lru) remove(pubkey string) {
	if el := c.byPub[pubkey]; el != nil {
		c.order.Remove(el)
		delete(c.byPub, pubkey)
	}
}

// chainCache keeps admitted members apart from refusals and pubkeys with no
// chain, each least recently used out first, so fresh keys (which cost an
// attacker nothing) only ever evict other refusals.
type chainCache struct {
	members, others *lru
}

func newChainCache(size int) *chainCache {
	return &chainCache{members: newLRU(size), others: newLRU(max(1, size/refusalShare))}
}

// get returns the entry for pubkey checked under rules, or nil.
func (c *chainCache) get(pubkey, rules string) *chainEntry {
	e := c.members.get(pubkey)
	if e == nil {
		e = c.others.get(pubkey)
	}
	if e == nil || e.rules != rules {
		return nil
	}
	return e
}

// put stores an entry with the cache of its kind: admitted or not.
func (c *chainCache) put(pubkey string, e *chainEntry, admitted bool) {
	if admitted {
		c.others.remove(pubkey)
		c.members.put(pubkey, e)
	} else {
		c.members.remove(pubkey)
		c.others.put(pubkey, e)
	}
}

func (c *chainCache) len() int { return c.members.order.Len() + c.others.order.Len() }

// failedSet holds events a walk found invalid, by id, oldest out first. An
// event id commits to the e previous it names, so the walk reaches it from
// the same state every time, and it is invalid for the same reason: the set
// outlives any entry, so evicting a pubkey does not make its forged proof
// worth checking again. A fork is never kept (resolution decides it anew).
type failedSet struct {
	byID  map[[32]byte]failure
	order [][32]byte
}

type failure struct{ reason, stopped string }

func newFailedSet() *failedSet { return &failedSet{byID: map[[32]byte]failure{}} }

// Only proof failures are kept: they are what costs a check, and a flood
// of structural junk (cheap to find again) cannot push them out.
func (f *failedSet) add(kn *Known) {
	if kn == nil || kn.FailAt == "" || !proofReasons[kn.FailReason] {
		return
	}
	k, ok := eventKey(kn.FailAt)
	if !ok {
		return
	}
	if _, in := f.byID[k]; in {
		return
	}
	f.byID[k] = failure{kn.FailReason, kn.Stopped}
	f.order = append(f.order, k)
	if len(f.order) > maxFailed {
		delete(f.byID, f.order[0])
		f.order = f.order[1:]
	}
}

func (f *failedSet) get(id string) (failure, bool) {
	k, ok := eventKey(id)
	if !ok {
		return failure{}, false
	}
	x, in := f.byID[k]
	return x, in
}

// failedEvent is the failed set's lookup, for walks.
func (g *Gate) failedEvent(id string) (string, string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f, ok := g.failed.get(id)
	return f.reason, f.stopped, ok
}

// A checkpoint is the progress of a check its deadline cut short: what the
// walk established up to the last event it passed. It is never an answer;
// the next check of the pubkey walks on from it, so a chain costlier than
// one deadline is paid for once across retries instead of never finishing.
// A tall hop cut short keeps its computed residues the same way
// (HopProgress).
func (g *Gate) saveProgress(pubkey string, k *walker) {
	if k == nil || k.genesis == "" {
		return
	}
	kn := k.knowledge()
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, in := g.progress[pubkey]; !in {
		g.progressOrder = append(g.progressOrder, pubkey)
		if len(g.progressOrder) > maxProgress {
			delete(g.progress, g.progressOrder[0])
			g.progressOrder = g.progressOrder[1:]
		}
	}
	g.progress[pubkey] = kn
}

// knownFor is what earlier walks of pubkey's chain established: a
// checkpoint, then the entry's own. A walk uses the one about its chain.
func (g *Gate) knownFor(pubkey string, e *chainEntry) []*Known {
	g.mu.Lock()
	p := g.progress[pubkey]
	g.mu.Unlock()
	var out []*Known
	if p != nil {
		if e != nil && e.known != nil && e.known.Genesis == p.Genesis {
			merged := *p
			if merged.FailAt == "" {
				merged.FailAt, merged.FailReason, merged.Stopped = e.known.FailAt, e.known.FailReason, e.known.Stopped
			}
			if merged.StopAt == "" {
				merged.StopAt, merged.StopWhy = e.known.StopAt, e.known.StopWhy
			}
			p = &merged
		}
		out = append(out, p)
	}
	if e != nil && e.known != nil {
		out = append(out, e.known)
	}
	return out
}

// newEntry builds the entry for a verdict reached by reading the chain
// whole: vd, the walk (nil when it ended before walking), the active chain,
// and every event the check held.
func (g *Gate) newEntry(vd Verdict, k *walker, chain []Move, held []nostr.Event) *chainEntry {
	now := g.now()
	e := &chainEntry{rules: g.rules, checkedAt: now, wholeAt: now, vd: summary(vd), seen: map[[32]byte]int64{}}
	if !vd.HasChain {
		return e
	}
	e.genesis, e.genesisAt = chain[0].Event.ID, chain[0].Event.CreatedAt
	for _, m := range chain {
		e.highest = max(e.highest, m.Event.CreatedAt)
	}
	for _, ev := range held {
		if k, ok := eventKey(ev.ID); ok && ev.CreatedAt >= e.highest-lookbackSeconds {
			e.seen[k] = ev.CreatedAt
		}
	}
	e.prune()
	e.held = map[[32]byte]bool{}
	for _, ev := range held {
		if k, ok := eventKey(ev.ID); ok {
			e.held[k] = true
		}
	}
	if k != nil {
		e.known = k.knowledge()
		if k.atHead() {
			e.walk = k.kept()
		}
	}
	return e
}

// summary is vd without its lists, which an entry does not need and which
// grow with the chain.
func summary(vd Verdict) Verdict {
	vd.Chain, vd.Skipped, vd.Fork = nil, nil, nil
	return vd
}

// kept is a copy of the walk to keep in an entry: without its lists, and
// with the look-back action and the open bracket's entry holding only what
// a later rule reads from them (slim).
func (k *walker) kept() *walker {
	c := *k
	c.vd = summary(k.vd)
	c.known = nil
	c.w.lookback = slim(k.w.lookback)
	if k.w.bracket != nil {
		c.w.bracket = &openBracket{entry: slim(k.w.bracket.entry)}
	}
	return &c
}

// slimTags are the tags a rule that looks back reads from the action it
// looks back to (ride, checkRide) or from an open bracket's entry (inside):
// its links and position, and a ride's heights. A tall hop's mp, the bulk of
// it, is never read again once the hop is passed.
var slimTags = map[string]bool{"A": true, "e": true, "c": true, "C": true, "B": true, "from_height": true, "as_of": true}

func slim(m Move) Move {
	ev := m.Event
	ev.Tags = nil
	for _, t := range m.Event.Tags {
		if len(t) > 0 && slimTags[t[0]] {
			ev.Tags = append(ev.Tags, t)
		}
	}
	ev.Content, ev.Sig = "", ""
	m.Event = ev
	return m
}

// prune drops the ids older than the look-back window, then, past maxSeen,
// the oldest seconds: the window then starts after the newest second it had
// to cut into, so it holds at most maxSeen ids however many share a
// created_at, and an event of a second it dropped is not fetched again (the
// daily whole read covers one published late into it). Two cases put the
// window's start past the head's second, both only for an identity with
// more than maxSeen of its own events (nobody else can sign them) in one
// second or dated after its head: an event dated within the head's second,
// or between the head and that start, published later elsewhere, is then
// seen at the daily whole read, or at once when published here. Holding
// the start at the head instead would refetch the dropped ids of that
// second on every check and send each check to a whole read.
func (e *chainEntry) prune() {
	from := max(e.highest-lookbackSeconds, e.floor)
	for id, at := range e.seen {
		if at < from {
			delete(e.seen, id)
		}
	}
	if len(e.seen) <= maxSeen {
		return
	}
	ats := make([]int64, 0, len(e.seen))
	for _, at := range e.seen {
		ats = append(ats, at)
	}
	sort.Slice(ats, func(i, j int) bool { return ats[i] > ats[j] })
	e.floor = ats[maxSeen] + 1 // the newest second not kept whole
	for id, at := range e.seen {
		if at < e.floor {
			delete(e.seen, id)
		}
	}
}

// outcome is what one check found: base, the entry from what the sources
// hold, which is stored; with, the entry with the incoming event as well,
// which is the answer for it and is stored instead of base only when it is
// admitted (the relay then stores the event, so the sources hold it too);
// and refusal, why there is no answer (base may still be stored).
type outcome struct {
	base, with *chainEntry
	refusal    string
}

// refresh brings pubkey's entry up to date, with an incoming movement event
// or none. It reads the chain whole when there is no entry, when the entry
// holds no chain, or once a day; otherwise it checks only what is new.
func (g *Gate) refresh(ctx context.Context, pubkey string, e *chainEntry, incoming *nostr.Event) outcome {
	if e == nil || !e.vd.HasChain || g.now().Sub(e.wholeAt) >= resyncAfter {
		return g.whole(ctx, pubkey, incoming, nil, g.knownFor(pubkey, e), e)
	}
	return g.extend(ctx, pubkey, e, incoming)
}

// wholeAllowed reports whether new events may make the chain be read whole
// now (wholeEvery).
func (g *Gate) wholeAllowed(e *chainEntry) bool {
	return g.now().Sub(e.wholeAt) >= wholeEvery
}

// extend is the incremental check: one question per source, for the
// pubkey's movement events since the look-back, skipping the ids the entry
// accounted for. With nothing new the entry stands. New events that extend
// the chain from its head, one after another, are walked on from the head:
// only their proofs are checked, and on a chain already invalid, or stopped
// in strict mode, none is, since nothing published after that point can
// move the identity. Anything else is read whole: a newer spawn or an event
// naming another genesis (the chain may have changed: checked from scratch),
// and an event that names anything but the head as previous (a fork or a
// gap); but for a newer spawn, not twice within wholeEvery. A chain dead by
// a fork stays dead whatever is added to it, until a newer spawn.
func (g *Gate) extend(ctx context.Context, pubkey string, e *chainEntry, incoming *nostr.Event) outcome {
	authentic := g.authentic(pubkey)
	since := max(e.highest-lookbackSeconds, e.floor, 1)
	evs, cov, ok := g.gather(ctx, pubkey, ChainQuery{Since: since, Keep: func(ev nostr.Event) bool {
		return !e.accounted(ev.ID) && authentic(ev)
	}})
	if !ok {
		return outcome{refusal: errFetch}
	}
	switch {
	case cov.Capped:
		return outcome{refusal: errTooLong}
	case cov.Partial:
		return outcome{refusal: errIncomplete}
	}
	var fresh []nostr.Event
	dup := map[string]bool{}
	for _, ev := range evs {
		if !dup[ev.ID] {
			dup[ev.ID] = true
			fresh = append(fresh, ev)
		}
	}
	if err := ctx.Err(); err != nil {
		return outcome{refusal: errTimeout}
	}
	next := *e
	next.checkedAt = g.now()

	genesis := nostr.Event{ID: e.genesis, CreatedAt: e.genesisAt}
	var links []Move
	respawn, other := false, false
	for _, ev := range fresh {
		m, _ := ParseMove(ev)
		switch {
		case m.IsSpawn && newer(ev, genesis):
			respawn = true
		case !m.IsSpawn && m.Genesis != e.genesis:
			other = true
		case !m.IsSpawn:
			links = append(links, m)
		}
		// An older spawn is history resolution never reads (§8.7.3 rule 1).
	}
	var base *chainEntry
	switch {
	case respawn || other:
	case e.vd.Reason == ReasonFork:
		next.account(fresh, nil)
		base = &next
	default:
		if order, linear := extension(e.vd.Head, links); linear {
			var refusal string
			if base, refusal = g.extendLocal(ctx, pubkey, &next, order, fresh); refusal != "" {
				return outcome{refusal: refusal}
			}
		}
	}
	if base == nil {
		if !respawn && !g.wholeAllowed(e) {
			return outcome{refusal: errBusy}
		}
		return g.whole(ctx, pubkey, incoming, fresh, g.knownFor(pubkey, e), e)
	}
	return g.withIncoming(ctx, pubkey, base, incoming, fresh, g.wholeAllowed(e))
}

// extendLocal walks e on over order, events that extend its head one after
// another, and accounts for fresh, the new events held. A walk its deadline
// cuts short leaves a checkpoint and no entry.
func (g *Gate) extendLocal(ctx context.Context, pubkey string, e *chainEntry, order []Move, fresh []nostr.Event) (*chainEntry, string) {
	next := *e
	next.checkedAt = g.now()
	if len(order) > 0 {
		if e.walk == nil {
			next.vd.Head = order[len(order)-1].Event.ID
			next.vd.Length += len(order)
			if e.known != nil && e.known.StopAt != "" {
				next.vd.Unchecked += len(order)
			}
		} else {
			k := *e.walk
			for _, kn := range g.knownFor(pubkey, nil) {
				if kn.Genesis == e.genesis {
					k.useKnown(kn, order)
				}
			}
			if err := k.resume(ctx, order); err != nil {
				g.saveProgress(pubkey, &k)
				return nil, errTimeout
			}
			next.vd, next.known, next.walk = summary(k.vd), k.knowledge(), nil
			if k.atHead() {
				next.walk = k.kept()
			}
		}
	}
	next.account(fresh, order)
	return &next, ""
}

// withIncoming is the answer for the incoming event, on top of base: base
// itself when the event changes nothing, base walked on by it when it
// extends the head, or else the chain read whole with it (not twice within
// wholeEvery, unless it is a newer spawn).
func (g *Gate) withIncoming(ctx context.Context, pubkey string, base *chainEntry, incoming *nostr.Event, fresh []nostr.Event, allowWhole bool) outcome {
	o := outcome{base: base, with: base}
	if incoming == nil || base.accounted(incoming.ID) || !g.authentic(pubkey)(*incoming) {
		return o
	}
	m, _ := ParseMove(*incoming)
	_, _, failed := g.failedEvent(incoming.ID)
	switch {
	case base.sameVerdictWith(m, failed):
		return o
	case !m.IsSpawn && base.vd.HasChain && m.Genesis == base.genesis && m.Previous == base.vd.Head:
		o.with, o.refusal = g.extendLocal(ctx, pubkey, base, []Move{m}, []nostr.Event{*incoming})
		return o
	case m.IsSpawn || allowWhole:
		w := g.whole(ctx, pubkey, incoming, fresh, []*Known{base.known}, base)
		if w.base != nil {
			o.base = w.base
		}
		o.with, o.refusal = w.with, w.refusal
		return o
	}
	o.with, o.refusal = nil, errBusy
	return o
}

// whole reads the chain whole: base from what the sources hold (and extra,
// new events they returned), and with, the same with the incoming event.
// When the incoming event extends base's head it is walked on from there;
// otherwise the chain is read again with it, since it may fill a gap the
// sources leave, fork the chain or start a new one. The ids prev (the entry
// it replaces, or nil) accounted for stay accounted: the whole read weighed
// every event the sources hold, events of older chains included, so they
// must not send the next incremental check back to a whole read.
func (g *Gate) whole(ctx context.Context, pubkey string, incoming *nostr.Event, extra []nostr.Event, known []*Known, prev *chainEntry) outcome {
	o := g.wholeRead(ctx, pubkey, incoming, extra, known)
	for _, x := range []*chainEntry{o.base, o.with} {
		if x != nil {
			x.held = nil
		}
	}
	if prev != nil {
		for _, x := range []*chainEntry{o.base, o.with} {
			if x != nil {
				x.carry(prev)
			}
		}
	}
	return o
}

// carry adds the ids prev accounted for to a new entry's window.
func (e *chainEntry) carry(prev *chainEntry) {
	if prev.seen == nil || e.seen == nil {
		return
	}
	for id, at := range prev.seen {
		if _, in := e.seen[id]; !in {
			e.seen[id] = at
		}
	}
	e.prune()
}

func (g *Gate) wholeRead(ctx context.Context, pubkey string, incoming *nostr.Event, extra []nostr.Event, known []*Known) outcome {
	base, refusal := g.read(ctx, pubkey, nil, extra, known)
	if incoming == nil {
		return outcome{base: base, with: base, refusal: refusal}
	}
	if base != nil {
		// The read held the incoming event already: the sources have it, and
		// base is the answer with it. Reading again would read the same.
		if k, ok := eventKey(incoming.ID); ok && base.held[k] || base.accounted(incoming.ID) {
			return outcome{base: base, with: base}
		}
		m, _ := ParseMove(*incoming)
		if base.sameVerdictWith(m, false) {
			return outcome{base: base, with: base}
		}
		if !m.IsSpawn && base.vd.HasChain && m.Genesis == base.genesis && m.Previous == base.vd.Head {
			with, refusal := g.extendLocal(ctx, pubkey, base, []Move{m}, []nostr.Event{*incoming})
			return outcome{base: base, with: with, refusal: refusal}
		}
		known = append([]*Known{base.known}, known...)
	} else if refusal != errIncomplete {
		return outcome{refusal: refusal} // the incoming event cannot help
	}
	with, refusal := g.read(ctx, pubkey, incoming, extra, known)
	return outcome{base: base, with: with, refusal: refusal}
}

// account adds the new events to the entry's window, raising the highest
// created_at by the chain events among them.
func (e *chainEntry) account(fresh []nostr.Event, chain []Move) {
	seen := make(map[[32]byte]int64, len(e.seen)+len(fresh))
	for id, at := range e.seen {
		seen[id] = at
	}
	for _, ev := range fresh {
		if k, ok := eventKey(ev.ID); ok {
			seen[k] = ev.CreatedAt
		}
	}
	for _, m := range chain {
		e.highest = max(e.highest, m.Event.CreatedAt)
	}
	e.seen = seen
	e.prune()
}

// extension orders links into the run that extends the chain from head, one
// after another. linear is false when any link is not on that run (it names
// another event as previous, a fork or a gap) or two name the same event.
func extension(head string, links []Move) (order []Move, linear bool) {
	children := map[string][]Move{}
	for _, m := range links {
		children[m.Previous] = append(children[m.Previous], m)
	}
	for cur := head; len(order) <= len(links); {
		kids := children[cur]
		if len(kids) > 1 {
			return nil, false
		}
		if len(kids) == 0 {
			break
		}
		order = append(order, kids[0])
		cur = kids[0].Event.ID
	}
	return order, len(order) == len(links)
}
