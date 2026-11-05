package speakeasy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0ceanslim/grain/server/db/nostrdb"
	nostr "github.com/0ceanslim/grain/server/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func testPool(t *testing.T, max int, idle time.Duration) *Pool {
	t.Helper()
	p := NewPool(t.TempDir(), nostrdb.Options{MapSizeMB: 32}, max, idle)
	t.Cleanup(p.CloseAll)
	return p
}

func note(t *testing.T, content string) nostr.Event {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	at := time.Now().Unix()
	raw, _ := json.Marshal([]any{0, pub, at, 1, [][]string{}, content})
	h := sha256.Sum256(raw)
	sig, err := schnorr.Sign(priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return nostr.Event{ID: hex.EncodeToString(h[:]), PubKey: pub, CreatedAt: at, Kind: 1, Tags: [][]string{}, Content: content, Sig: hex.EncodeToString(sig.Serialize())}
}

// stored waits for nostrdb's asynchronous ingest to make id queryable, or
// reports that it never did.
func stored(t *testing.T, db *nostrdb.NDB, id string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := db.Query([]nostr.Filter{{IDs: []string{id}}}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 1 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// At the cap, opening another database closes the idlest one nothing uses;
// with every open one in use, the request is refused busy.
func TestPoolCapEvictsIdleAndRefusesWhenAllInUse(t *testing.T) {
	p := testPool(t, 2, time.Hour)
	_, relA, err := p.Acquire("aa")
	if err != nil {
		t.Fatal(err)
	}
	_, relB, err := p.Acquire("bb")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Acquire("cc"); !errors.Is(err, ErrBusy) {
		t.Fatalf("third database while two are in use: want ErrBusy, got %v", err)
	}
	if p.Open() != 2 {
		t.Fatalf("open databases: want 2, got %d", p.Open())
	}
	relA()
	_, relC, err := p.Acquire("cc")
	if err != nil {
		t.Fatalf("after one is released: %v", err)
	}
	if p.IsOpen("aa") || !p.IsOpen("bb") || !p.IsOpen("cc") || p.Open() != 2 || p.Closed() != 1 {
		t.Fatalf("want aa closed, bb and cc open: aa %v bb %v cc %v open %d closed %d",
			p.IsOpen("aa"), p.IsOpen("bb"), p.IsOpen("cc"), p.Open(), p.Closed())
	}
	relB()
	relC()
}

// A database nothing has used for the idle time is closed; one in use is
// not, however long it is held; and what was stored survives the reopen.
func TestPoolIdleCloseKeepsDataAndNeverClosesInUse(t *testing.T) {
	p := testPool(t, 4, time.Minute)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	db, rel, err := p.Acquire("aa")
	if err != nil {
		t.Fatal(err)
	}
	evt := note(t, "kept across a close")
	if err := db.StoreEvent(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if !stored(t, db, evt.ID) {
		t.Fatal("event never became queryable")
	}
	clock = clock.Add(2 * time.Minute)
	if n := p.CloseIdle(); n != 0 || !p.IsOpen("aa") {
		t.Fatalf("a database in use was closed (closed %d)", n)
	}
	rel()
	clock = clock.Add(30 * time.Second)
	if n := p.CloseIdle(); n != 0 {
		t.Fatalf("closed %d before the idle time", n)
	}
	clock = clock.Add(31 * time.Second)
	if n := p.CloseIdle(); n != 1 || p.IsOpen("aa") {
		t.Fatalf("idle database not closed (closed %d, open %v)", n, p.IsOpen("aa"))
	}
	db, rel, err = p.Acquire("aa")
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	if !stored(t, db, evt.ID) {
		t.Fatal("event lost when the database was closed and reopened")
	}
}

// Many requests for one database at once open it once (LMDB forbids two
// opens of one environment in a process).
func TestPoolOpensOnce(t *testing.T) {
	p := testPool(t, 4, time.Hour)
	var wg sync.WaitGroup
	dbs := make([]*nostrdb.NDB, 16)
	for i := range dbs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db, rel, err := p.Acquire("aa")
			if err != nil {
				t.Error(err)
				return
			}
			dbs[i] = db
			rel()
		}(i)
	}
	wg.Wait()
	for _, db := range dbs {
		if db != dbs[0] {
			t.Fatal("two handles for one database")
		}
	}
	if p.Opened() != 1 {
		t.Fatalf("opened %d times, want 1", p.Opened())
	}
}

// After CloseAll nothing opens again: a connection left over from a server
// instance that stopped must not open a database the next instance opens.
func TestPoolClosedRefusesAcquire(t *testing.T) {
	p := testPool(t, 4, time.Hour)
	_, rel, err := p.Acquire("aa")
	if err != nil {
		t.Fatal(err)
	}
	rel()
	p.CloseAll()
	if p.Open() != 0 {
		t.Fatalf("open after CloseAll: %d", p.Open())
	}
	if _, _, err := p.Acquire("aa"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Acquire after CloseAll: want ErrClosed, got %v", err)
	}
}

// Each speakeasy is its own database in its own directory: what one stores
// the other never holds.
func TestPoolDatabasesAreApart(t *testing.T) {
	p := testPool(t, 4, time.Hour)
	a, relA, err := p.Acquire("aa")
	if err != nil {
		t.Fatal(err)
	}
	defer relA()
	b, relB, err := p.Acquire("bb")
	if err != nil {
		t.Fatal(err)
	}
	defer relB()
	evt := note(t, "only in aa")
	if err := a.StoreEvent(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if !stored(t, a, evt.ID) {
		t.Fatal("not stored in aa")
	}
	if got, err := b.Query([]nostr.Filter{{}}, 100); err != nil || len(got) != 0 {
		t.Fatalf("bb holds %d events (err %v), want none", len(got), err)
	}
	for _, id := range []string{"aa", "bb"} {
		if _, err := os.Stat(filepath.Join(p.Dir(id), "data.mdb")); err != nil {
			t.Fatalf("%s has no database file of its own: %v", id, err)
		}
	}
	if _, _, err := p.Acquire("../x"); err == nil {
		t.Fatal("an id that is not hex must never become a directory")
	}
}
