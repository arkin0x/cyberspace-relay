package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/0ceanslim/grain/server/db/nostrdb"
	nostr "github.com/0ceanslim/grain/server/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// GatedQuery pages past gift wraps the caller may not see, so a broad filter
// with a limit still returns that many: a shortfall would count them.
func TestGatedQueryPagesPastWithheldGiftWraps(t *testing.T) {
	db, err := nostrdb.Open(t.TempDir(), 32, 1)
	if err != nil {
		t.Fatalf("open nostrdb: %v", err)
	}
	t.Cleanup(db.Close)

	oldPage := gatedMinPage
	gatedMinPage = 2
	t.Cleanup(func() { gatedMinPage = oldPage })

	sign := func(at int64, kind int, p string) nostr.Event {
		priv, _ := btcec.NewPrivateKey()
		pub := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
		tags := [][]string{{"p", p}}
		raw, _ := json.Marshal([]interface{}{0, pub, at, kind, tags, ""})
		h := sha256.Sum256(raw)
		sig, _ := schnorr.Sign(priv, h[:])
		return nostr.Event{ID: hex.EncodeToString(h[:]), PubKey: pub, CreatedAt: at, Kind: kind,
			Tags: tags, Content: "", Sig: hex.EncodeToString(sig.Serialize())}
	}
	const at = int64(1710000000)
	var evts []nostr.Event
	// Seven gift wraps to the recipient are the newest; three reactions are
	// older. A page of 2 has to walk four pages of gift wraps.
	for i := 0; i < 7; i++ {
		evts = append(evts, sign(at-int64(i), 1059, recipientPK))
	}
	for i := 0; i < 3; i++ {
		evts = append(evts, sign(at-100-int64(i), 7, recipientPK))
	}
	for _, e := range evts {
		if err := db.StoreEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := db.Query([]nostr.Filter{{}}, 100)
		if len(got) == len(evts) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("indexed %d of %d", len(got), len(evts))
		}
		time.Sleep(20 * time.Millisecond)
	}

	limit := 2
	f := nostr.Filter{Tags: map[string][]string{"p": {recipientPK}}, Limit: &limit}

	got, err := GatedQuery(db.Query, f, 500, strangerPK)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Kind != 7 || got[1].Kind != 7 {
		t.Fatalf("stranger: want 2 reactions, got %d %+v", len(got), got)
	}
	got, _ = GatedQuery(db.Query, f, 500, recipientPK)
	if len(got) != 2 || got[0].Kind != 1059 {
		t.Fatalf("recipient: want their 2 newest gift wraps, got %+v", got)
	}
	// No limit: every reaction, and the scan stops when the filter runs out.
	got, _ = GatedQuery(db.Query, nostr.Filter{Tags: map[string][]string{"p": {recipientPK}}}, 500, "")
	if len(got) != 3 {
		t.Fatalf("unauthenticated, no limit: want 3 reactions, got %d", len(got))
	}
}
