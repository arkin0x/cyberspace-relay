package nostrdb

import (
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils/log"
)

// countHardCap bounds the worst-case work for a single COUNT request.
// Above this we return the cap and report `approximate: true` per NIP-45.
const countHardCap = 1_000_000

// countPageSize is how many events one COUNT page asks nostrdb for. A
// variable only so tests can cross page boundaries with a few events.
var countPageSize = maxQueryResults

// CountFiltered returns the number of events matching `filters`. The
// nostrdb query API is capped at maxQueryResults per call, so we page
// backwards through created_at with a PageCursor, which neither skips nor
// double-counts events that share a second across a page boundary. The bool
// return is true when the result is approximate:
//
//   - hardCap reached, or
//   - multiple filters supplied (we sum per-filter counts; a multi-filter
//     union that overlaps in event ids would double-count, and dedupe
//     would require buffering all matched ids, defeating the purpose
//     of COUNT vs REQ), or
//   - one second filled a whole page (PageCursor.Crowded), so matches of
//     that second beyond the page may have gone uncounted.
//
// Otherwise a single-filter count is exact.
func (db *NDB) CountFiltered(filters []nostr.Filter) (int, bool, error) {
	if len(filters) == 0 {
		return 0, false, nil
	}

	logger := log.DBQuery()
	approximate := len(filters) > 1
	total := 0

	for _, base := range filters {
		filterTotal, hitCap, err := countSingleFilter(db, base)
		if err != nil {
			return 0, false, err
		}
		total += filterTotal
		if hitCap {
			approximate = true
		}
		if total >= countHardCap {
			total = countHardCap
			approximate = true
			break
		}
	}

	logger.Debug("Count completed",
		"filter_count", len(filters),
		"total", total,
		"approximate", approximate)
	return total, approximate, nil
}

// countSingleFilter pages through one filter and returns its match count
// plus a flag that is true when the count is approximate: the hard cap was
// reached, or a second filled a whole page.
func countSingleFilter(db *NDB, base nostr.Filter) (int, bool, error) {
	pageSize := countPageSize
	cursor := NewPageCursor(base.Until)
	total := 0

	for {
		limit := pageSize
		page := base
		page.Limit = &limit
		page.Until = cursor.Until()

		events, err := db.Query([]nostr.Filter{page}, pageSize)
		if err != nil {
			return 0, false, err
		}
		fresh, more := cursor.Next(events, pageSize)
		total += len(fresh)
		if total >= countHardCap {
			return countHardCap, true, nil
		}
		if !more {
			break
		}
	}
	return total, cursor.Crowded, nil
}
