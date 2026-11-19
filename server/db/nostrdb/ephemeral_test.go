package nostrdb

import (
	"context"
	"testing"
)

// Nostr Connect (24133, NIP-46) and the other ephemeral kinds (20000-29999)
// are accepted and never stored: the ONOSENDAI relay delivers a signer's
// request live and keeps no copy, so a REQ made later does not return it.
func TestEphemeralKindsAreNotStored(t *testing.T) {
	db := openTempDB(t)
	k := newUntilKey(t)
	ctx := context.Background()

	ephemeral := signEvent(t, k.priv, k.pub, 24133, "nip44 payload", [][]string{{"p", k.pub}}, untilT)
	if err := db.StoreEvent(ctx, ephemeral); err != nil {
		t.Fatalf("store 24133: %v", err)
	}
	// nostrdb ingests in order on one writer: once a regular event stored
	// after it is in, the ephemeral one would be too, had it been kept.
	regular := signEvent(t, k.priv, k.pub, 3333, "after", nil, untilT+1)
	if err := db.StoreEvent(ctx, regular); err != nil {
		t.Fatalf("store 3333: %v", err)
	}
	waitForIngest(t, db, regular.ID, true)

	txn, err := db.BeginQuery()
	if err != nil {
		t.Fatalf("begin query: %v", err)
	}
	got, err := txn.GetNoteByID(ephemeral.ID)
	txn.EndQuery()
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got != nil {
		t.Fatal("kind 24133 was stored; ephemeral events must never be")
	}
}
