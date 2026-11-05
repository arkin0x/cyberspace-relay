package nostrdb

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// untilT is the second the until tests are built around.
const untilT = int64(1710000000)

type untilKey struct {
	priv *btcec.PrivateKey
	pub  string
}

func newUntilKey(t *testing.T) untilKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return untilKey{priv, hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))}
}

// storeInOrder stores events one at a time, waiting for each, so nostrdb's
// note keys follow the slice order.
func storeInOrder(t *testing.T, db *NDB, evts []nostr.Event) {
	t.Helper()
	for _, e := range evts {
		if err := db.StoreEvent(context.Background(), e); err != nil {
			t.Fatalf("store: %v", err)
		}
		waitForIngest(t, db, e.ID, true)
	}
}

// pagingFixture is 3 events at T+1, 3 at T and 2 at T-1: with a page of 4,
// every page boundary falls inside a second, and no second holds a full page.
func pagingFixture(t *testing.T, k untilKey, kind int, content string, tags [][]string) []nostr.Event {
	t.Helper()
	var evts []nostr.Event
	for i, at := range []int64{untilT - 1, untilT - 1, untilT, untilT, untilT, untilT + 1, untilT + 1, untilT + 1} {
		evts = append(evts, signEvent(t, k.priv, k.pub, kind, fmt.Sprintf("%s %d", content, i), tags, at))
	}
	return evts
}

func timeAt(s int64) *time.Time {
	u := time.Unix(s, 0)
	return &u
}

// NIP-01: since <= created_at <= until. nostrdb's index seeks used to step
// back past every event at created_at == until, on every query plan that
// grain reaches (kinds, authors, author_kinds, tags, created_at, ids).
func TestQueryUntilIsInclusive(t *testing.T) {
	db := openTempDB(t)
	k := newUntilKey(t)
	tag := [][]string{{"t", "until"}}

	var evts []nostr.Event
	for i, at := range []int64{untilT - 1, untilT - 1, untilT, untilT, untilT, untilT, untilT, untilT + 1, untilT + 1} {
		evts = append(evts, signEvent(t, k.priv, k.pub, 1, fmt.Sprintf("until %d", i), tag, at))
	}
	storeInOrder(t, db, evts)

	plans := []struct {
		name string
		f    nostr.Filter
	}{
		{"kinds", nostr.Filter{Kinds: []int{1}}},
		{"authors", nostr.Filter{Authors: []string{k.pub}}},
		{"author_kinds", nostr.Filter{Authors: []string{k.pub}, Kinds: []int{1}}},
		{"tags", nostr.Filter{Tags: map[string][]string{"t": {"until"}}}},
		{"created_at", nostr.Filter{}},
	}
	count := func(f nostr.Filter) int {
		t.Helper()
		got, err := db.Query([]nostr.Filter{f}, 100)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		for _, e := range got {
			if e.CreatedAt > untilT {
				t.Fatalf("event at %d returned for until %d", e.CreatedAt, untilT)
			}
		}
		return len(got)
	}
	for _, p := range plans {
		f := p.f
		f.Until = timeAt(untilT)
		if got := count(f); got != 7 {
			t.Errorf("%s until=T: got %d events, want 7 (2 at T-1, 5 at T)", p.name, got)
		}
		f.Since = timeAt(untilT)
		if got := count(f); got != 5 {
			t.Errorf("%s since=until=T: got %d events, want the 5 at T", p.name, got)
		}
	}

	if got := count(nostr.Filter{IDs: []string{evts[4].ID}, Until: timeAt(untilT)}); got != 1 {
		t.Errorf("ids until=T: an event at T came back %d times, want 1", got)
	}
	if got := count(nostr.Filter{IDs: []string{evts[8].ID}, Until: timeAt(untilT)}); got != 0 {
		t.Errorf("ids until=T: an event at T+1 came back %d times, want 0", got)
	}
}

func withPageSize(t *testing.T, v *int, n int) {
	t.Helper()
	old := *v
	*v = n
	t.Cleanup(func() { *v = old })
}

// COUNT used to page with until = oldest-1, losing the rest of the oldest
// second at every page boundary while reporting the count as exact.
func TestCountExactAcrossPageBoundaries(t *testing.T) {
	db := openTempDB(t)
	withPageSize(t, &countPageSize, 4)
	k := newUntilKey(t)
	storeInOrder(t, db, pagingFixture(t, k, 1, "count", nil))

	cases := []struct {
		name string
		f    nostr.Filter
		want int
	}{
		{"kinds", nostr.Filter{Kinds: []int{1}}, 8},
		{"kinds until=T+1", nostr.Filter{Kinds: []int{1}, Until: timeAt(untilT + 1)}, 8},
		{"kinds until=T", nostr.Filter{Kinds: []int{1}, Until: timeAt(untilT)}, 5},
		{"authors since=T-1 until=T", nostr.Filter{Authors: []string{k.pub}, Since: timeAt(untilT - 1), Until: timeAt(untilT)}, 5},
	}
	for _, c := range cases {
		got, approx, err := db.CountFiltered([]nostr.Filter{c.f})
		if err != nil {
			t.Fatalf("%s: count: %v", c.name, err)
		}
		if got != c.want || approx {
			t.Errorf("%s: COUNT = %d (approximate %v), want exactly %d", c.name, got, approx, c.want)
		}
	}
}

// A second with more events than a page can't be paged through by
// created_at alone: COUNT must then say it is approximate.
func TestCountCrowdedSecondIsApproximate(t *testing.T) {
	db := openTempDB(t)
	withPageSize(t, &countPageSize, 3)
	k := newUntilKey(t)
	var evts []nostr.Event
	for i, at := range []int64{untilT - 1, untilT - 1, untilT, untilT, untilT, untilT, untilT} {
		evts = append(evts, signEvent(t, k.priv, k.pub, 1, fmt.Sprintf("crowd %d", i), nil, at))
	}
	storeInOrder(t, db, evts)

	got, approx, err := db.CountFiltered([]nostr.Filter{{Kinds: []int{1}}})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if !approx {
		t.Errorf("COUNT = %d reported as exact; a second held 5 events against a page of 3", got)
	}
	if got < 5 || got > 7 {
		t.Errorf("COUNT = %d, want the 3 of the crowded second it saw plus the 2 older (5), at most 7", got)
	}
}

// The expiration bootstrap paged with until = oldest-1 too, so expiring
// events in the rest of a boundary second were never tracked.
func TestBootstrapExpirationsAcrossPageBoundaries(t *testing.T) {
	db := openTempDB(t)
	withPageSize(t, &bootstrapPageSize, 4)
	k := newUntilKey(t)
	future := fmt.Sprint(time.Now().Add(24 * time.Hour).Unix())
	storeInOrder(t, db, pagingFixture(t, k, 1, "expiring", [][]string{{"expiration", future}}))

	db.expiration = newExpirationTracker() // forget what ingest tracked
	if err := db.BootstrapExpirations(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := db.expiration.Len(); got != 8 {
		t.Errorf("bootstrap tracked %d expirations, want all 8", got)
	}
}

// purgeKind used to step to oldest-1 after a page it deleted nothing from,
// skipping the rest of that page's oldest second: a page of whitelisted
// events hid the purgeable ones that shared its last second.
func TestPurgeKindReachesSameSecondRemainder(t *testing.T) {
	db := openTempDB(t)
	withPageSize(t, &purgePageSize, 4)
	member, other := newUntilKey(t), newUntilKey(t)

	// Non-members first, so members get the higher note keys and lead each
	// second in the kind index: the first page is members only.
	purge := []nostr.Event{
		signEvent(t, other.priv, other.pub, 1, "old", nil, untilT-1),
		signEvent(t, other.priv, other.pub, 1, "same second a", nil, untilT),
		signEvent(t, other.priv, other.pub, 1, "same second b", nil, untilT),
	}
	keep := []nostr.Event{
		signEvent(t, member.priv, member.pub, 1, "member a", nil, untilT),
		signEvent(t, member.priv, member.pub, 1, "member b", nil, untilT),
		signEvent(t, member.priv, member.pub, 1, "member c", nil, untilT+1),
		signEvent(t, member.priv, member.pub, 1, "member d", nil, untilT+1),
	}
	storeInOrder(t, db, append(append([]nostr.Event{}, purge...), keep...))

	db.purgeKind(1, untilT+1, map[string]bool{member.pub: true}, true, 100)

	for _, e := range purge {
		waitForIngest(t, db, e.ID, false)
	}
	for _, e := range keep {
		waitForIngest(t, db, e.ID, true)
	}
}

// PageCursor on its own, against an in-memory store that honours until
// inclusively: every event comes out exactly once whatever the page size,
// and a second that fills a whole page is reported as Crowded.
func TestPageCursorHandsOutEveryEventOnce(t *testing.T) {
	var all []nostr.Event // newest first, like nostrdb
	for s, n := range []int{3, 1, 4, 2, 2, 3} {
		for i := 0; i < n; i++ {
			all = append(all, nostr.Event{ID: fmt.Sprintf("%d-%d", s, i), CreatedAt: 100 - int64(s)})
		}
	}
	query := func(until *time.Time, limit int) []nostr.Event {
		var page []nostr.Event
		for _, e := range all {
			if until != nil && e.CreatedAt > until.Unix() {
				continue
			}
			if len(page) == limit {
				break
			}
			page = append(page, e)
		}
		return page
	}
	for pageSize := 1; pageSize <= 8; pageSize++ {
		c := NewPageCursor(nil)
		seen := map[string]int{}
		for guard := 0; guard < 100; guard++ {
			fresh, more := c.Next(query(c.Until(), pageSize), pageSize)
			for _, e := range fresh {
				seen[e.ID]++
			}
			if !more {
				break
			}
		}
		crowded := pageSize <= 4 // the largest second holds 4
		if c.Crowded != crowded {
			t.Errorf("page %d: Crowded = %v, want %v", pageSize, c.Crowded, crowded)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("page %d: %s handed out %d times", pageSize, id, n)
			}
		}
		if !crowded && len(seen) != len(all) {
			t.Errorf("page %d: handed out %d of %d events", pageSize, len(seen), len(all))
		}
	}
}
