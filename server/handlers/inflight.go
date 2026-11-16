package handlers

import (
	"container/list"
	"sync"
	"time"
)

// The duplicate check reads nostrdb, and nostrdb indexes an event a moment
// after StoreEvent returns (and the OK goes out). Copies of one event sent at
// the same moment, on one connection or several, all pass that check: each
// would be stored again (nostrdb drops the copy), broadcast live again, and
// charged to its author's per-author budget again, so anyone holding a
// signed event could spend its author's budget by fanning it out.
//
// recentEvents closes that window. An event is claimed before the duplicate
// check; while it is in flight, or for recentStoredTTL after it was stored,
// another copy for the same database is answered as a duplicate. A copy of an
// event that was refused is not: the claim is released.

const (
	// recentStoredTTL covers nostrdb's indexing delay many times over.
	recentStoredTTL = 30 * time.Second
	// recentInFlightTTL bounds a claim whose holder never finishes (a
	// panic); the slowest step, the region gate, times out at 30 s.
	recentInFlightTTL = 2 * time.Minute
	// maxRecentEvents caps the table (about 200 B an entry, so about 20 MB).
	// Full of live claims, a new event is let through untracked: the
	// duplicate check and the per-connection limits still apply.
	maxRecentEvents = 100000
)

type recentEntry struct {
	key     string
	expires time.Time
	stored  bool
}

type recentEventSet struct {
	mu      sync.Mutex
	entries map[string]*list.Element // Value is *recentEntry
	order   *list.List               // by expiry, soonest at the front
	max     int
	now     func() time.Time
}

func newRecentEventSet(max int, now func() time.Time) *recentEventSet {
	return &recentEventSet{entries: map[string]*list.Element{}, order: list.New(), max: max, now: now}
}

var recentEvents = newRecentEventSet(maxRecentEvents, time.Now)

// recentKey is the event's key for one database: the root's ("") or a
// speakeasy's path, so the same event may be stored in each.
func recentKey(scopePath, id string) string { return scopePath + "\x00" + id }

// expire drops entries past their time from the front. Expiry times are in
// the order entries were pushed to the back (claims get recentInFlightTTL,
// stored entries are re-pushed with recentStoredTTL, both from now), up to
// the gap between the two TTLs, so a stale entry can wait behind a newer
// claim for at most that long. Caller holds s.mu.
func (s *recentEventSet) expire(now time.Time) {
	for e := s.order.Front(); e != nil; e = s.order.Front() {
		if now.Before(e.Value.(*recentEntry).expires) {
			return
		}
		delete(s.entries, e.Value.(*recentEntry).key)
		s.order.Remove(e)
	}
}

// claim takes the event for this database. It returns false, with a NIP-01
// OK message, when another copy is in flight or was just stored. When it
// returns true, call done exactly once: done(true) once the event is stored,
// done(false) if it was refused.
func (s *recentEventSet) claim(key string) (ok bool, msg string, done func(stored bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expire(now)
	if e, found := s.entries[key]; found {
		if e.Value.(*recentEntry).stored {
			return false, "duplicate: already have this event", nil
		}
		return false, "duplicate: this event is already being stored", nil
	}
	if s.order.Len() >= s.max {
		return true, "", func(bool) {}
	}
	ent := &recentEntry{key: key, expires: now.Add(recentInFlightTTL)}
	el := s.order.PushBack(ent)
	s.entries[key] = el
	return true, "", func(stored bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if cur, found := s.entries[key]; !found || cur != el {
			return
		}
		if !stored {
			delete(s.entries, key)
			s.order.Remove(el)
			return
		}
		ent.stored = true
		ent.expires = s.now().Add(recentStoredTTL)
		s.order.MoveToBack(el)
	}
}
