package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/0ceanslim/grain/server/db/nostrdb"
	nostr "github.com/0ceanslim/grain/server/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// pagedTextSearch used to page with until = oldest-1, so a NIP-50 search
// lost the rest of the oldest second at every page boundary.
func TestPagedTextSearchAcrossPageBoundaries(t *testing.T) {
	db, err := nostrdb.Open(t.TempDir(), 32, 1)
	if err != nil {
		t.Fatalf("open nostrdb: %v", err)
	}
	t.Cleanup(db.Close)

	old := textSearchPageSize
	textSearchPageSize = 4
	t.Cleanup(func() { textSearchPageSize = old })

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))

	// 3 events at T+1, 3 at T, 2 at T-1: with a page of 4 every boundary
	// falls inside a second, and no second fills a page
	const at = int64(1710000000)
	want := map[string]bool{}
	for i, ts := range []int64{at - 1, at - 1, at, at, at, at + 1, at + 1, at + 1} {
		raw, _ := json.Marshal([]interface{}{0, pub, ts, 1, [][]string{}, fmt.Sprintf("lattice note %d", i)})
		h := sha256.Sum256(raw)
		sig, err := schnorr.Sign(priv, h[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		e := nostr.Event{ID: hex.EncodeToString(h[:]), PubKey: pub, CreatedAt: ts, Kind: 1,
			Tags: [][]string{}, Content: fmt.Sprintf("lattice note %d", i), Sig: hex.EncodeToString(sig.Serialize())}
		if err := db.StoreEvent(context.Background(), e); err != nil {
			t.Fatalf("store: %v", err)
		}
		want[e.ID] = true
	}

	// ingest is asynchronous: wait until the search index has all of them
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := db.TextSearch("lattice", nostr.Filter{}, 100)
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(got) == len(want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("search index holds %d of %d events", len(got), len(want))
		}
		time.Sleep(20 * time.Millisecond)
	}

	got, err := pagedTextSearch(db, nostr.Filter{Search: "lattice"}, 500)
	if err != nil {
		t.Fatalf("paged search: %v", err)
	}
	seen := map[string]int{}
	for _, e := range got {
		seen[e.ID]++
	}
	for id := range want {
		if seen[id] != 1 {
			t.Errorf("event %s returned %d times, want once", id[:8], seen[id])
		}
	}
	if len(got) != len(want) {
		t.Errorf("paged search returned %d events, want %d", len(got), len(want))
	}

	// a client limit still caps the result
	lim := 5
	got, err = pagedTextSearch(db, nostr.Filter{Search: "lattice", Limit: &lim}, 500)
	if err != nil {
		t.Fatalf("paged search with limit: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("paged search with limit 5 returned %d events", len(got))
	}
}
