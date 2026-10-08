package regiongate

import (
	"context"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0ceanslim/grain/server/validation"
)

// TestLiveChain verifies a real identity's chain from real relays. It is
// skipped unless REGIONGATE_LIVE_PUBKEY is set, e.g.
//
//	REGIONGATE_LIVE_PUBKEY=<hex> go test -run TestLiveChain -v ./server/regiongate/
//
// REGIONGATE_LIVE_RELAYS overrides the relays (comma separated).
func TestLiveChain(t *testing.T) {
	pk := os.Getenv("REGIONGATE_LIVE_PUBKEY")
	if pk == "" {
		t.Skip("set REGIONGATE_LIVE_PUBKEY to run against live relays")
	}
	relays := []string{"wss://cyberspace.nostr1.com", "wss://nos.lol", "wss://relay.damus.io", "wss://relay.primal.net"}
	if r := os.Getenv("REGIONGATE_LIVE_RELAYS"); r != "" {
		relays = strings.Split(r, ",")
	}
	key, _ := AuthKey("")
	src := RelaySource{Relays: relays, Timeout: 30 * time.Second, AuthKey: key}
	cfg := &Config{Enabled: true, MaxChainEvents: 20000, AlwaysAllowKinds: []int{5},
		CacheTTLSeconds: 1, NegativeCacheTTLSeconds: 1, exempt: map[string]bool{}}
	ver := Verifier{Proofs: PendingSpec{}, Signature: validation.CheckSignature}
	g := NewGate(cfg, ver, src)

	// The gate's two indexed questions: spawns, then the newest spawn's chain.
	start := time.Now()
	spawns, _, ok := g.gather(context.Background(), pk, ChainQuery{Tags: map[string][]string{"A": {ActSpawn}}})
	if !ok {
		t.Fatal("spawn query failed on every relay")
	}
	vd0 := ver.Verify(pk, spawns)
	chain, cov, _ := g.gather(context.Background(), pk, ChainQuery{Tags: map[string][]string{"e": {vd0.Head}}})
	fetched := time.Since(start)
	start = time.Now()
	vd := ver.Verify(pk, append(spawns, chain...))
	t.Logf("fetched %d spawns + %d chain events in %s, verified in %s", len(spawns), len(chain),
		fetched.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	t.Logf("chain answer coverage %+v", cov)
	t.Logf("has_chain=%v length=%d unchecked=%d head=%s", vd.HasChain, vd.Length, vd.Unchecked, vd.Head)
	t.Logf("position_event=%s stopped=%q", vd.PositionEvent, vd.Stopped)
	if vd.Position != nil {
		p := *vd.Position
		sec := func(v *big.Int) string { return new(big.Int).Rsh(v, SectorBits).String() }
		t.Logf("position %s = (x=%s, y=%s, z=%s, plane=%d), sector %s-%s-%s",
			p.Hex(), p.X, p.Y, p.Z, p.Plane, sec(p.X), sec(p.Y), sec(p.Z))
	}
}
