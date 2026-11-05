package nostrdb

import (
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// PageCursor walks a newest-first query backwards through created_at, one
// page at a time, without skipping or repeating events that share a second
// across a page boundary.
//
// NIP-01 makes until inclusive (since <= created_at <= until), so each page
// after the first asks again for the oldest second of the page before it, and
// Next drops the events of that second it has already handed out. Stepping to
// oldest-1 instead, as COUNT, NIP-50 search paging, purge and the expiration
// bootstrap used to, skipped every event of that second that did not fit on
// the page.
//
// One second can fill a whole page. Asking for it again then returns the same
// full page, and created_at alone cannot tell whether the second holds exactly
// a page or more, so the cursor steps past it and sets Crowded: events of that
// second beyond the page may never have been seen.
type PageCursor struct {
	until    *time.Time
	boundary int64
	seen     map[string]struct{}

	// Crowded is set once a single second filled a whole page, so some of
	// its events may have been missed.
	Crowded bool
}

// NewPageCursor starts a cursor at until (nil: no upper bound).
func NewPageCursor(until *time.Time) *PageCursor {
	return &PageCursor{until: until}
}

// Until is the until bound for the next page; nil means no bound.
func (c *PageCursor) Until() *time.Time {
	return c.until
}

// Next takes the page a query returned for Until(), asked for with limit
// pageSize, and returns its events that were not handed out before, in page
// order. more is false once a page came back short, so nothing older is left.
func (c *PageCursor) Next(page []nostr.Event, pageSize int) (fresh []nostr.Event, more bool) {
	fresh = make([]nostr.Event, 0, len(page))
	for _, e := range page {
		if c.seen != nil && e.CreatedAt == c.boundary {
			if _, dup := c.seen[e.ID]; dup {
				continue
			}
		}
		fresh = append(fresh, e)
	}
	if len(page) == 0 || len(page) < pageSize {
		return fresh, false
	}

	oldest := page[0].CreatedAt
	for _, e := range page {
		if e.CreatedAt < oldest {
			oldest = e.CreatedAt
		}
	}

	if len(fresh) == 0 {
		// A full page of events already handed out can only be one
		// second filling the page: asking again would return the same
		// page. Step past it.
		c.Crowded = true
		if oldest <= 0 {
			// nothing is older than created_at 0, and a negative until
			// is no bound nostrdb can take
			return fresh, false
		}
		next := time.Unix(oldest-1, 0)
		c.until, c.seen = &next, nil
		return fresh, true
	}

	if c.seen == nil || oldest != c.boundary {
		c.boundary, c.seen = oldest, make(map[string]struct{})
	}
	for _, e := range page {
		if e.CreatedAt == oldest {
			c.seen[e.ID] = struct{}{}
		}
	}
	next := time.Unix(oldest, 0)
	c.until = &next
	return fresh, true
}
