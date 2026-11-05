package regiongate

import (
	"container/list"
	"context"
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
// proof being checked, so one forged proof costs one check however often it
// is sent.

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
	// maxSeen bounds the ids an entry remembers in its look-back window. Past
	// it the oldest are dropped and the window starts after them.
	maxSeen = 1024
	// maxQueuedPerPubkey bounds the distinct movement events one pubkey can
	// have waiting.
	maxQueuedPerPubkey = 4
)

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
	// for in the look-back window, and floor is where the window starts when
	// maxSeen cut it short.
	seen  map[string]int64
	floor int64
	// walk is the walk at the head, when the chain is valid there and can be
	// walked on; nil for a chain that is invalid or where strict mode
	// stopped.
	walk *walker
	// known is what the walks of this chain established, for a whole
	// re-read of it.
	known *Known
}

// accounted reports whether the event id is already part of the entry: in
// its look-back window, or its spawn, head, failure point or strict stop
// point, whatever their created_at (a forgery backdated before the window is
// still answered from the entry when it is sent again).
func (e *chainEntry) accounted(id string) bool {
	if _, ok := e.seen[id]; ok {
		return true
	}
	if id == "" {
		return false
	}
	return id == e.genesis || id == e.vd.Head || e.known != nil && (id == e.known.FailAt || id == e.known.StopAt)
}

// chainCache is a least recently used cache of chain entries.
type chainCache struct {
	max   int
	order *list.List // front: most recently used
	byPub map[string]*list.Element
}

type cacheItem struct {
	pubkey string
	entry  *chainEntry
}

func newChainCache(max int) *chainCache {
	return &chainCache{max: max, order: list.New(), byPub: map[string]*list.Element{}}
}

// get returns the entry for pubkey checked under rules, or nil.
func (c *chainCache) get(pubkey, rules string) *chainEntry {
	el := c.byPub[pubkey]
	if el == nil {
		return nil
	}
	e := el.Value.(*cacheItem).entry
	if e.rules != rules {
		return nil
	}
	c.order.MoveToFront(el)
	return e
}

func (c *chainCache) put(pubkey string, e *chainEntry) {
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

func (c *chainCache) len() int { return c.order.Len() }

// newEntry builds the entry for a verdict reached by reading the chain
// whole: vd, the walk (nil when it ended before walking), the active chain,
// and every event the check held.
func (g *Gate) newEntry(vd Verdict, k *walker, chain []Move, held []nostr.Event) *chainEntry {
	now := g.now()
	e := &chainEntry{rules: g.rules, checkedAt: now, wholeAt: now, vd: summary(vd), seen: map[string]int64{}}
	if !vd.HasChain {
		return e
	}
	e.genesis, e.genesisAt = chain[0].Event.ID, chain[0].Event.CreatedAt
	for _, m := range chain {
		e.highest = max(e.highest, m.Event.CreatedAt)
	}
	for _, ev := range held {
		if ev.CreatedAt >= e.highest-lookbackSeconds {
			e.seen[ev.ID] = ev.CreatedAt
		}
	}
	e.prune()
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
// the oldest, starting the window after them.
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
	e.floor = ats[maxSeen-1]
	for id, at := range e.seen {
		if at < e.floor {
			delete(e.seen, id)
		}
	}
}

// refresh brings pubkey's entry up to date, with an incoming movement event
// or none. It reads the chain whole when there is no entry, when the entry
// holds no chain, or once a day; otherwise it checks only what is new. A
// refusal that is not a verdict (a failed or incomplete lookup, a deadline)
// is returned as the reason, and nothing is to be stored.
func (g *Gate) refresh(ctx context.Context, pubkey string, e *chainEntry, incoming *nostr.Event) (*chainEntry, string) {
	if e == nil || !e.vd.HasChain || g.now().Sub(e.wholeAt) >= resyncAfter {
		var kn *Known
		if e != nil {
			kn = e.known
		}
		return g.whole(ctx, pubkey, incoming, nil, kn)
	}
	return g.extend(ctx, pubkey, e, incoming)
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
// gap). A chain dead by a fork stays dead whatever is added to it, until a
// newer spawn.
func (g *Gate) extend(ctx context.Context, pubkey string, e *chainEntry, incoming *nostr.Event) (*chainEntry, string) {
	authentic := g.authentic(pubkey)
	since := max(e.highest-lookbackSeconds, e.floor, 1)
	evs, cov, ok := g.gather(ctx, pubkey, ChainQuery{Since: since, Keep: func(ev nostr.Event) bool {
		return !e.accounted(ev.ID) && authentic(ev)
	}})
	if !ok {
		return nil, errFetch
	}
	switch {
	case cov.Capped:
		return nil, errTooLong
	case cov.Partial:
		return nil, errIncomplete
	}
	if incoming != nil && !e.accounted(incoming.ID) && authentic(*incoming) {
		evs = append(evs, *incoming)
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
		return nil, errTimeout
	}
	next := *e
	next.checkedAt = g.now()
	if len(fresh) == 0 {
		return &next, ""
	}

	genesis := nostr.Event{ID: e.genesis, CreatedAt: e.genesisAt}
	var links []Move
	for _, ev := range fresh {
		m, _ := ParseMove(ev)
		switch {
		case m.IsSpawn && newer(ev, genesis), !m.IsSpawn && m.Genesis != e.genesis:
			return g.whole(ctx, pubkey, incoming, fresh, e.known)
		case !m.IsSpawn:
			links = append(links, m)
		}
		// An older spawn is history resolution never reads (§8.7.3 rule 1).
	}
	if e.vd.Reason == ReasonFork {
		next.account(fresh, nil)
		return &next, ""
	}
	order, linear := extension(e.vd.Head, links)
	if !linear {
		return g.whole(ctx, pubkey, incoming, fresh, e.known)
	}
	if len(order) > 0 {
		if e.walk == nil {
			next.vd.Head = order[len(order)-1].Event.ID
			next.vd.Length += len(order)
			if e.known != nil && e.known.StopAt != "" {
				next.vd.Unchecked += len(order)
			}
		} else {
			k := *e.walk
			if err := k.resume(ctx, order); err != nil {
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

// account adds the new events to the entry's window, raising the highest
// created_at by the chain events among them.
func (e *chainEntry) account(fresh []nostr.Event, chain []Move) {
	seen := make(map[string]int64, len(e.seen)+len(fresh))
	for id, at := range e.seen {
		seen[id] = at
	}
	for _, ev := range fresh {
		seen[ev.ID] = ev.CreatedAt
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
