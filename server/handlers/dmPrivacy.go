package handlers

import (
	"sort"
	"strconv"

	"github.com/0ceanslim/grain/config"
	"github.com/0ceanslim/grain/server/db/nostrdb"
	nostr "github.com/0ceanslim/grain/server/types"
)

// NIP-17 gift-wrap metadata privacy (#73). A protected-kind event (kind:1059)
// is served only to a client AUTHed as a pubkey p-tagged on it. These helpers
// are shared by the historical REQ path, the COUNT path, and the live-broadcast
// path (server/client.go), so the gate is identical everywhere.

// CanServeProtectedEvent reports whether evt may be served to a client that has
// AUTHed as authedPubkey ("" if unauthenticated). Non-protected events always
// pass; a protected event passes only when the authed pubkey appears in one of
// its p tags.
func CanServeProtectedEvent(evt nostr.Event, authedPubkey string) bool {
	if !config.IsDMProtectedKind(evt.Kind) {
		return true
	}
	if authedPubkey == "" {
		return false
	}
	return eventHasPTag(evt, authedPubkey)
}

// FilterRequestsProtectedKind reports whether the filter explicitly asks for a
// protected kind. Used to decide when an unauthenticated REQ/COUNT should be
// told to AUTH (vs. a broad filter where we just silently omit the events).
func FilterRequestsProtectedKind(f nostr.Filter) bool {
	for _, k := range f.Kinds {
		if config.IsDMProtectedKind(k) {
			return true
		}
	}
	return false
}

// eventHasPTag reports whether evt carries a `p` tag whose value equals pubkey.
func eventHasPTag(evt nostr.Event, pubkey string) bool {
	for _, tag := range evt.Tags {
		if len(tag) >= 2 && tag[0] == "p" && tag[1] == pubkey {
			return true
		}
	}
	return false
}

// ownPTagFilter narrows f to the protected kinds and to the caller's own p
// tag: the only protected events the caller may see. ok is false when the
// caller may see none of them (unauthenticated, or f's own #p list leaves the
// caller out). The returned filter has its own Tags map, so f is untouched.
func ownPTagFilter(f nostr.Filter, kinds []int, authedPubkey string) (nostr.Filter, bool) {
	if authedPubkey == "" || len(kinds) == 0 {
		return nostr.Filter{}, false
	}
	if want, has := f.Tags["p"]; has {
		found := false
		for _, v := range want {
			if v == authedPubkey {
				found = true
				break
			}
		}
		if !found {
			return nostr.Filter{}, false
		}
	}
	own := f
	own.Kinds = kinds
	own.Tags = make(map[string][]string, len(f.Tags)+1)
	for k, v := range f.Tags {
		own.Tags[k] = v
	}
	own.Tags["p"] = []string{authedPubkey}
	return own, true
}

// splitKinds separates a filter's explicit kinds into the open ones and the
// protected ones.
func splitKinds(kinds []int) (open, protected []int) {
	for _, k := range kinds {
		if config.IsDMProtectedKind(k) {
			protected = append(protected, k)
		} else {
			open = append(open, k)
		}
	}
	return open, protected
}

// RootOpenKinds returns the kinds a kindless filter can stand for on the
// root relay: the kind whitelist minus the protected kinds. It is nil when the
// whitelist is off (any kind may be stored, so no list covers them all); the
// filters are then gated instead (GatedQuery, CountPrivately's subtraction).
// A speakeasy takes any kind (ruling D6), so its callers pass nil.
func RootOpenKinds() []int {
	wl := config.GetWhitelistConfig()
	if wl == nil || !wl.KindWhitelist.Enabled {
		return nil
	}
	open := []int{}
	seen := map[int]bool{}
	for _, s := range wl.KindWhitelist.Kinds {
		k, err := strconv.Atoi(s)
		if err != nil || seen[k] || config.IsDMProtectedKind(k) {
			continue
		}
		seen[k] = true
		open = append(open, k)
	}
	return open
}

// PrivateFilters rewrites a REQ's filters so the database itself never hands
// back a protected event the caller may not see. Withheld events then never
// take a slot under a filter's limit, so the number of events delivered (or
// which ones, under an ids or authors prefix scan) reveals nothing about them.
//
//   - A filter with explicit kinds: its open kinds as they are, and its
//     protected kinds only with #p narrowed to the caller (dropped when the
//     caller is unauthenticated or its #p leaves them out).
//   - A filter with no kinds, when openKinds is not nil (RootOpenKinds): the
//     same, as if it had named openKinds and the protected kinds. Only kinds
//     the relay accepts are stored, so it matches what it matched before.
//   - A filter with no kinds and openKinds nil: the database cannot exclude
//     a kind, so it is returned in gated, to be run through GatedQuery.
//
// Each part keeps the filter's limit, so a filter split in two may return up
// to that limit per part.
func PrivateFilters(filters []nostr.Filter, authedPubkey string, openKinds []int) (exact, gated []nostr.Filter) {
	protectedKinds := config.DMProtectedKinds()
	for _, f := range filters {
		var open, protected []int
		switch {
		case len(f.Kinds) > 0:
			open, protected = splitKinds(f.Kinds)
			if len(protected) == 0 {
				exact = append(exact, f)
				continue
			}
		case openKinds != nil:
			open, protected = openKinds, protectedKinds
		default:
			gated = append(gated, f)
			continue
		}
		if len(open) > 0 {
			o := f
			o.Kinds = open
			exact = append(exact, o)
		}
		if own, ok := ownPTagFilter(f, protected, authedPubkey); ok {
			exact = append(exact, own)
		}
	}
	return exact, gated
}

// gatedScanCap bounds how many events GatedQuery reads for a single filter.
// Past it a shortfall could show that thousands of protected events sit in
// the filter's range; reaching it takes a filter whose matches are almost all
// gift wraps the caller may not see.
var gatedScanCap = 10000

// gatedMinPage is the smallest page GatedQuery asks for, so a small limit
// does not turn into many one-event queries when it has to page.
var gatedMinPage = 50

// MaxGatedFilters caps the kindless filters one REQ may run through
// GatedQuery: each is its own query (or several), unlike the filters nostrdb
// answers in one call.
const MaxGatedFilters = 32

// GatedQuery runs one kindless filter where the kinds cannot be listed
// (PrivateFilters' gated) and returns up to its limit (or effectiveLimit) of
// the events the caller may see, newest first.
//
// nostrdb fills a limit newest first from its created_at-ordered indexes, so
// when withheld gift wraps fill part of a page it pages on past them (by
// created_at, with nostrdb.PageCursor) and the caller still gets a full limit.
// An ids or authors prefix is scanned in id order instead, where withheld
// events take slots anywhere in the page; that filter is read in one query of
// up to gatedScanCap events, gated, then sorted and cut to the limit.
func GatedQuery(query func([]nostr.Filter, int) ([]nostr.Event, error), f nostr.Filter, effectiveLimit int, authedPubkey string) ([]nostr.Event, error) {
	want := effectiveLimit
	if f.Limit != nil && *f.Limit < want {
		want = *f.Limit
	}
	if want <= 0 {
		return nil, nil
	}

	if f.HasPrefixMatch() {
		page := f
		lim := gatedScanCap
		page.Limit = &lim
		events, err := query([]nostr.Filter{page}, gatedScanCap)
		if err != nil {
			return nil, err
		}
		out := make([]nostr.Event, 0, want)
		for _, evt := range events {
			if CanServeProtectedEvent(evt, authedPubkey) {
				out = append(out, evt)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
		if len(out) > want {
			out = out[:want]
		}
		return out, nil
	}

	pageSize := want
	if pageSize < gatedMinPage {
		pageSize = gatedMinPage
	}
	if pageSize > nostrdb.MaxQueryResults {
		pageSize = nostrdb.MaxQueryResults
	}

	var out []nostr.Event
	scanned := 0
	cursor := nostrdb.NewPageCursor(f.Until)
	for len(out) < want {
		page := f
		lim := pageSize
		page.Limit = &lim
		page.Until = cursor.Until()
		events, err := query([]nostr.Filter{page}, pageSize)
		if err != nil {
			return nil, err
		}
		fresh, more := cursor.Next(events, pageSize)
		for _, evt := range fresh {
			if !CanServeProtectedEvent(evt, authedPubkey) {
				continue
			}
			out = append(out, evt)
			if len(out) == want {
				break
			}
		}
		scanned += len(fresh)
		if !more || scanned >= gatedScanCap {
			break
		}
	}
	return out, nil
}

// CountPrivately counts filters so a protected event is counted only for the
// caller it may be served to: the caller's own p-tagged gift wraps, never
// anyone else's. count is the database's per-filter count (CountFiltered);
// openKinds is RootOpenKinds (nil when the kinds cannot be listed).
//
//   - Explicit kinds, or no kinds with openKinds: the open kinds are counted
//     as they are, the protected kinds only narrowed to the caller's p tag
//     (see ownPTagFilter). The parts never overlap.
//   - No kinds, openKinds nil: the database cannot exclude a kind, so the
//     filter is counted whole, minus its protected-kind matches, plus the
//     caller's own. A whole count at nostrdb.CountHardCap is reported as the
//     cap, approximate, with nothing subtracted: the cap minus the protected
//     count would be the protected count.
//
// A single filter stays exact unless a part is approximate; several filters
// are approximate already.
func CountPrivately(count func([]nostr.Filter) (int, bool, error), filters []nostr.Filter, authedPubkey string, openKinds []int) (int, bool, error) {
	total := 0
	approximate := len(filters) > 1
	one := func(f nostr.Filter) (int, error) {
		n, approx, err := count([]nostr.Filter{f})
		approximate = approximate || approx
		return n, err
	}
	protectedKinds := config.DMProtectedKinds()
	for _, f := range filters {
		var open, protected []int
		switch {
		case len(f.Kinds) > 0:
			open, protected = splitKinds(f.Kinds)
		case openKinds != nil:
			open, protected = openKinds, protectedKinds
		default:
			whole, err := one(f)
			if err != nil {
				return 0, false, err
			}
			if whole >= nostrdb.CountHardCap {
				total += whole
				approximate = true
				continue
			}
			p := f
			p.Kinds = protectedKinds
			theirs, err := one(p)
			if err != nil {
				return 0, false, err
			}
			if d := whole - theirs; d > 0 {
				total += d
			}
			protected = protectedKinds
		}
		if len(open) > 0 {
			o := f
			o.Kinds = open
			n, err := one(o)
			if err != nil {
				return 0, false, err
			}
			total += n
		}
		if len(protected) > 0 {
			if own, ok := ownPTagFilter(f, protected, authedPubkey); ok {
				n, err := one(own)
				if err != nil {
					return 0, false, err
				}
				total += n
			}
		}
	}
	if total > nostrdb.CountHardCap {
		total = nostrdb.CountHardCap
		approximate = true
	}
	return total, approximate, nil
}
