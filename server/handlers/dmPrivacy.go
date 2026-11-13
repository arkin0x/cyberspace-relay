package handlers

import (
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

// PrivateFilters rewrites a REQ's filters so the database itself never hands
// back a protected event the caller may not see, which keeps the number of
// events delivered from revealing how many were withheld.
//
//   - A filter with explicit kinds is answered exactly: its open kinds as
//     they are, and its protected kinds only with #p narrowed to the caller
//     (dropped when the caller is unauthenticated or its #p leaves them out).
//     Each part keeps the filter's limit, so a filter that mixes a protected
//     kind with open kinds may return up to that limit per part.
//   - A filter with no kinds can match a protected event and the database
//     cannot exclude a kind, so it is returned in gated, to be run through
//     GatedQuery.
func PrivateFilters(filters []nostr.Filter, authedPubkey string) (exact, gated []nostr.Filter) {
	for _, f := range filters {
		if len(f.Kinds) == 0 {
			gated = append(gated, f)
			continue
		}
		open, protected := splitKinds(f.Kinds)
		if len(protected) == 0 {
			exact = append(exact, f)
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

// gatedScanCap bounds how many events GatedQuery reads past withheld ones for
// a single filter. Past it the shortfall could show that thousands of
// protected events sit in the filter's range; reaching it takes a filter whose
// matches are almost all gift wraps the caller may not see.
var gatedScanCap = 10000

// gatedMinPage is the smallest page GatedQuery asks for, so a small limit
// does not turn into many one-event queries when it has to page.
var gatedMinPage = 50

// GatedQuery runs one kindless filter and returns up to its limit (or
// effectiveLimit) of the events the caller may see, newest first. When
// protected events it may not see fill part of a page, it pages on past them
// (by created_at, with nostrdb.PageCursor) so the caller still gets a full
// limit and cannot count the withheld ones by the shortfall.
func GatedQuery(query func([]nostr.Filter, int) ([]nostr.Event, error), f nostr.Filter, effectiveLimit int, authedPubkey string) ([]nostr.Event, error) {
	want := effectiveLimit
	if f.Limit != nil && *f.Limit < want {
		want = *f.Limit
	}
	if want <= 0 {
		return nil, nil
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
// anyone else's. count is the database's per-filter count (CountFiltered).
//
//   - Explicit kinds: the open kinds are counted as they are, the protected
//     kinds only narrowed to the caller's p tag (see ownPTagFilter).
//   - No kinds: the database cannot exclude a kind, so the filter is counted
//     whole, minus its protected-kind matches, plus the caller's own.
//
// The parts of one filter never overlap, so a single filter stays exact
// unless a part is approximate; several filters are approximate already.
func CountPrivately(count func([]nostr.Filter) (int, bool, error), filters []nostr.Filter, authedPubkey string) (int, bool, error) {
	total := 0
	approximate := len(filters) > 1
	add := func(f nostr.Filter, sign int) error {
		n, approx, err := count([]nostr.Filter{f})
		if err != nil {
			return err
		}
		total += sign * n
		approximate = approximate || approx
		return nil
	}
	protectedKinds := config.DMProtectedKinds()
	for _, f := range filters {
		var open, protected []int
		if len(f.Kinds) == 0 {
			if err := add(f, 1); err != nil {
				return 0, false, err
			}
			p := f
			p.Kinds = protectedKinds
			if err := add(p, -1); err != nil {
				return 0, false, err
			}
			protected = protectedKinds
		} else {
			open, protected = splitKinds(f.Kinds)
			if len(open) > 0 {
				o := f
				o.Kinds = open
				if err := add(o, 1); err != nil {
					return 0, false, err
				}
			}
		}
		if len(protected) > 0 {
			if own, ok := ownPTagFilter(f, protected, authedPubkey); ok {
				if err := add(own, 1); err != nil {
					return 0, false, err
				}
			}
		}
	}
	if total < 0 {
		total = 0
	}
	return total, approximate, nil
}
