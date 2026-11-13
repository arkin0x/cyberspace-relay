package api

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

// The public stats must not count gift wraps: total minus an unauthenticated
// COUNT {} (which never counts them) would otherwise be the relay's number of
// DMs, and polling it would time each one.
func TestRelayStatsLeaveOutGiftWraps(t *testing.T) {
	db, err := nostrdb.Open(t.TempDir(), 32, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	sign := func(kind int) nostr.Event {
		priv, _ := btcec.NewPrivateKey()
		pub := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
		tags := [][]string{{"p", pub}}
		at := time.Now().Unix()
		raw, _ := json.Marshal([]interface{}{0, pub, at, kind, tags, "x"})
		h := sha256.Sum256(raw)
		sig, _ := schnorr.Sign(priv, h[:])
		return nostr.Event{ID: hex.EncodeToString(h[:]), PubKey: pub, CreatedAt: at, Kind: kind, Tags: tags, Content: "x", Sig: hex.EncodeToString(sig.Serialize())}
	}
	evts := []nostr.Event{sign(1059), sign(1059), sign(1059), sign(3333), sign(7)}
	for _, e := range evts {
		if err := db.StoreEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, _ := db.Query([]nostr.Filter{{}}, 100); len(got) == len(evts) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not indexed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	total, byKind, err := db.EventStats()
	if err != nil {
		t.Fatal(err)
	}
	total, byKind, err = withoutProtectedKinds(db, total, byKind)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2 (gift wraps left out)", total)
	}
	var sum uint64
	for _, k := range byKind {
		sum += k.Count
	}
	if sum != 2 {
		t.Errorf("by_kind counts sum to %d, want 2: %+v", sum, byKind)
	}
}
