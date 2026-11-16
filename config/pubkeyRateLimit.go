package config

import (
	"container/list"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	cfgType "github.com/0ceanslim/grain/config/types"
	"github.com/0ceanslim/grain/server/utils/log"
)

// Per-author rate limits (rate_limit.pubkey_kind_limits).
//
// grain's other rate limits live on the connection, so they start over when
// a client reconnects. These are keyed by (event pubkey, kind) and live in
// the process: one bucket per author and limited kind, shared by every
// connection, kept across reconnects and across config reloads that do not
// change that kind's numbers.
//
// Memory is bounded two ways. A bucket that has refilled to its burst holds
// nothing a fresh one would not, so it is dropped as soon as it is seen idle
// (lossless). And the table never holds more than maxPubkeyKindBuckets: at
// the cap the least recently used bucket goes, which can only hand that
// author a fresh burst early. The cap is far above honest use (an author
// keeps a bucket only until it refills, 30 minutes at 12 an hour with a burst
// of 6). This limits what one key can do; new keys are free, so many keys
// are past what a per-key limit can stop, and are left to the
// per-connection and per-IP limits.

// maxPubkeyKindBuckets caps the table. Each bucket costs about 250 bytes
// (the pubkey, the bucket, its list element and map slot), so the cap is
// about 12 MB.
const maxPubkeyKindBuckets = 50000

// maxWaitSeconds caps the wait a refusal names (a year), far below where
// seconds overflow a time.Duration.
const maxWaitSeconds = 365 * 24 * 3600

// idleSweepPerCall bounds how many refilled buckets one call may drop from
// the cold end of the table. More than one, so idle buckets drain faster
// than new ones arrive.
const idleSweepPerCall = 8

type pubkeyKindRule struct {
	perHour   float64
	perSecond float64
	burst     float64
	label     string
}

type pubkeyKindKey struct {
	pubkey string
	kind   int
}

type pubkeyKindBucket struct {
	key    pubkeyKindKey
	tokens float64
	last   time.Time
}

// pubkeyKindLimiter is safe for concurrent use. The rules are an immutable
// map behind an atomic pointer, so an event of a kind with no rule takes no
// lock; the mutex guards the buckets (and orders rule swaps with them).
type pubkeyKindLimiter struct {
	rules   atomic.Pointer[map[int]pubkeyKindRule]
	mu      sync.Mutex
	buckets map[pubkeyKindKey]*list.Element // Value is *pubkeyKindBucket
	lru     *list.List                      // front = most recently used
	max     int
	now     func() time.Time
}

func newPubkeyKindLimiter(max int, now func() time.Time) *pubkeyKindLimiter {
	l := &pubkeyKindLimiter{
		buckets: map[pubkeyKindKey]*list.Element{},
		lru:     list.New(),
		max:     max,
		now:     now,
	}
	l.rules.Store(&map[int]pubkeyKindRule{})
	return l
}

// rulesNow is the current rule map. Never modified after it is stored.
func (l *pubkeyKindLimiter) rulesNow() map[int]pubkeyKindRule { return *l.rules.Load() }

// pubkeyLimiter is the process-wide table. It outlives server instance
// restarts (config reloads): SetRateLimit reconfigures it in place.
var pubkeyLimiter = newPubkeyKindLimiter(maxPubkeyKindBuckets, time.Now)

// configure installs a new set of rules. Buckets of a kind whose per_hour or
// burst is unchanged are kept, so a reload does not hand everyone a fresh
// burst; buckets of a kind that changed or was removed are dropped. Entries
// that fail validation (ValidateAndApplyDefaults refuses them at load) are
// skipped here too, so a bad admin write cannot install a rule that divides
// by zero.
func (l *pubkeyKindLimiter) configure(limits []cfgType.PubkeyKindLimitConfig) {
	rules := make(map[int]pubkeyKindRule, len(limits))
	for _, c := range limits {
		if !(c.PerHour >= minPubkeyPerHour) || c.Burst < 1 {
			continue
		}
		rules[c.Kind] = pubkeyKindRule{
			perHour:   c.PerHour,
			perSecond: c.PerHour / 3600,
			burst:     float64(c.Burst),
			label:     c.Label,
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	stale := map[int]bool{}
	for kind, old := range l.rulesNow() {
		nr, ok := rules[kind]
		if !ok || nr.perHour != old.perHour || nr.burst != old.burst {
			stale[kind] = true
		}
	}
	if len(stale) > 0 {
		for e := l.lru.Front(); e != nil; {
			next := e.Next()
			if b := e.Value.(*pubkeyKindBucket); stale[b.key.kind] {
				l.remove(e)
			}
			e = next
		}
	}
	l.rules.Store(&rules)
}

// remove drops one bucket. Caller holds l.mu.
func (l *pubkeyKindLimiter) remove(e *list.Element) {
	delete(l.buckets, e.Value.(*pubkeyKindBucket).key)
	l.lru.Remove(e)
}

// tokensAt is the bucket's balance at now, refilled at the rule's rate and
// capped at its burst. A clock that steps back refills nothing.
func (b *pubkeyKindBucket) tokensAt(r pubkeyKindRule, now time.Time) float64 {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return math.Min(r.burst, b.tokens+elapsed*r.perSecond)
}

// sweepIdle drops up to idleSweepPerCall buckets from the cold end that have
// refilled to their burst, stopping at the first that has not. Caller holds
// l.mu.
func (l *pubkeyKindLimiter) sweepIdle(now time.Time) {
	for i := 0; i < idleSweepPerCall; i++ {
		e := l.lru.Back()
		if e == nil {
			return
		}
		b := e.Value.(*pubkeyKindBucket)
		r, ok := l.rulesNow()[b.key.kind]
		if ok && b.tokensAt(r, now) < r.burst {
			return
		}
		l.remove(e)
	}
}

// allow takes one event from the author's bucket for this kind. It returns
// true for a kind with no rule. When it refuses, msg is a NIP-01 OK message
// ("rate-limited: ..."). When it allows, refund puts the event back: call it
// if the relay then refuses the event.
func (l *pubkeyKindLimiter) allow(pubkey string, kind int) (ok bool, msg string, refund func()) {
	if _, limited := l.rulesNow()[kind]; !limited {
		return true, "", func() {}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Again under the lock: configure swaps rules and drops stale buckets
	// while holding it.
	r, limited := l.rulesNow()[kind]
	if !limited {
		return true, "", func() {}
	}
	now := l.now()
	key := pubkeyKindKey{pubkey: pubkey, kind: kind}

	var b *pubkeyKindBucket
	if e, found := l.buckets[key]; found {
		b = e.Value.(*pubkeyKindBucket)
		b.tokens = b.tokensAt(r, now)
		b.last = now
		l.lru.MoveToFront(e)
	} else {
		l.sweepIdle(now)
		for l.lru.Len() >= l.max && l.lru.Len() > 0 {
			l.remove(l.lru.Back())
		}
		b = &pubkeyKindBucket{key: key, tokens: r.burst, last: now}
		l.buckets[key] = l.lru.PushFront(b)
	}

	if b.tokens < 1 {
		// Capped before the conversion, so a tiny per_hour cannot overflow it.
		secs := math.Min(math.Ceil((1-b.tokens)/r.perSecond), maxWaitSeconds)
		wait := time.Duration(secs) * time.Second
		return false, pubkeyLimitMessage(kind, r, wait), nil
	}
	b.tokens--
	return true, "", func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		// Only the same bucket, still in the table: one evicted or
		// replaced since started over at a full burst already.
		if e, found := l.buckets[key]; found && e.Value.(*pubkeyKindBucket) == b {
			b.tokens = math.Min(r.burst, b.tokens+1)
		}
	}
}

// pubkeyLimitMessage is the refusal a person reads, e.g. "rate-limited:
// avatars are limited to 12 an hour per key; try again in 5 minutes". The
// count follows the label, so the label stays plural whatever the number.
func pubkeyLimitMessage(kind int, r pubkeyKindRule, wait time.Duration) string {
	what := r.label
	if what == "" {
		what = fmt.Sprintf("kind %d events", kind)
	}
	return fmt.Sprintf("rate-limited: %s are limited to %s an hour per key; try again in %s",
		what, strconv.FormatFloat(r.perHour, 'f', -1, 64), humanWait(wait))
}

// humanWait rounds up: "1 second", "40 seconds", "5 minutes", "2 hours".
func humanWait(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	secs := int64(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	if secs < 60 {
		return plural(secs, "second")
	}
	mins := (secs + 59) / 60
	if mins <= 90 {
		return plural(mins, "minute")
	}
	return plural((mins+59)/60, "hour")
}

// AllowPubkeyEvent applies rate_limit.pubkey_kind_limits to an event whose
// signature has been verified (so evt.PubKey is its real author). See
// pubkeyKindLimiter.allow for the results; refund is never nil when ok.
func AllowPubkeyEvent(pubkey string, kind int) (ok bool, msg string, refund func()) {
	ok, msg, refund = pubkeyLimiter.allow(pubkey, kind)
	if !ok {
		log.Config().Debug("Per-author rate limit exceeded", "kind", kind, "pubkey", pubkey)
	}
	return ok, msg, refund
}

// PubkeyKindLimited reports whether rate_limit.pubkey_kind_limits lists kind.
func PubkeyKindLimited(kind int) bool {
	_, ok := pubkeyLimiter.rulesNow()[kind]
	return ok
}

// configurePubkeyLimits is SetRateLimit's half for the per-author table.
func configurePubkeyLimits(limits []cfgType.PubkeyKindLimitConfig) {
	pubkeyLimiter.configure(limits)
	for _, c := range limits {
		log.Config().Info("Per-author rate limit configured",
			"kind", c.Kind, "per_hour", c.PerHour, "burst", c.Burst)
	}
}

// ResetPubkeyLimiterForTest empties the per-author table and its rules.
func ResetPubkeyLimiterForTest() {
	l := pubkeyLimiter
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rules.Store(&map[int]pubkeyKindRule{})
	l.buckets = map[pubkeyKindKey]*list.Element{}
	l.lru.Init()
}
