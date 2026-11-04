package regiongate

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"
)

// realProofsFile holds real proof-bearing events read from
// wss://cyberspace.nostr1.com on 2026-11-04 (version 2 hops at every h_max
// seen, every sidestep with mn and every enter-hyperspace), each with the
// verdict of the reference verifier (cyberspace-cli 5103c62:
// verify_hop_event, verify_sidestep_event, verify_enter_hyperspace_event).
// REGIONGATE_REAL_PROOFS=<path> runs a file of the same shape in its place,
// such as the full set this sample was drawn from.
const realProofsFile = "testdata/real-proofs-2026-11-04.json"

type realProof struct {
	Action   string
	OK       bool
	Failures []string
	HMax     int `json:"h_max"`
	Event    nostr.Event
}

func TestRealProofs(t *testing.T) {
	path := realProofsFile
	if p := os.Getenv("REGIONGATE_REAL_PROOFS"); p != "" {
		path = p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []realProof
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatal(err)
	}
	type cost struct {
		action string
		hMax   int
		d      time.Duration
	}
	var costs []cost
	checker := SpecProofs{}
	for _, r := range recs {
		if !validation.CheckSignature(r.Event) {
			t.Fatalf("%s: not authentic", r.Event.ID)
		}
		m, _ := ParseMove(r.Event)
		start := time.Now()
		res, why := checker.Check(Move{}, m)
		costs = append(costs, cost{r.Action, r.HMax, time.Since(start)})
		if got := res == ProofVerified; got != r.OK {
			t.Errorf("%s %s: gate says %v (%s), the reference %v %v", r.Action, r.Event.ID, got, why, r.OK, r.Failures)
		}
	}
	// The cost of each, by action, for the PR's measurements.
	by := map[string][]time.Duration{}
	for _, c := range costs {
		by[c.action] = append(by[c.action], c.d)
	}
	for action, ds := range by {
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		var sum time.Duration
		for _, d := range ds {
			sum += d
		}
		t.Logf("%s: %d events, median %v, max %v, total %v", action, len(ds), ds[len(ds)/2], ds[len(ds)-1], sum)
	}
}

// TestRealChainCost verifies every identity's whole history in
// REGIONGATE_REAL_CHAINS (one kind 3333 event per line, as a relay gives
// them) with the production checker, and logs what each costs. It is a
// measurement, skipped unless the variable is set.
func TestRealChainCost(t *testing.T) {
	path := os.Getenv("REGIONGATE_REAL_CHAINS")
	if path == "" {
		t.Skip("REGIONGATE_REAL_CHAINS not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string][]nostr.Event{}
	var order []string
	for _, line := range splitLines(data) {
		var e nostr.Event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		if by[e.PubKey] == nil {
			order = append(order, e.PubKey)
		}
		by[e.PubKey] = append(by[e.PubKey], e)
	}
	v := Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}
	for _, pk := range order {
		start := time.Now()
		vd := v.Verify(pk, by[pk])
		hops := 0
		for _, id := range vd.Chain {
			for _, e := range by[pk] {
				if e.ID == id {
					if m, _ := ParseMove(e); m.Action == ActHop {
						hops++
					}
					break
				}
			}
		}
		t.Logf("%s: %d events held, chain %d (%d hops), valid %v %s at %d, unchecked %d: %v", pk[:8], len(by[pk]), vd.Length, hops, vd.Valid(), vd.Reason, vd.InvalidIndex, vd.Unchecked, time.Since(start))
		if vd.Reason != "" {
			t.Logf("  %s", vd.Stopped)
		}
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := 0
		for i < len(b) && b[i] != '\n' {
			i++
		}
		if i > 0 {
			out = append(out, b[:i])
		}
		if i == len(b) {
			break
		}
		b = b[i+1:]
	}
	return out
}
