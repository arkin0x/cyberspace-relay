package regiongate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"
)

// realRidesFile holds the whole chains of every identity whose active chain
// boards or rides, read from wss://relay.onosendai.tech on 2026-11-05, each
// with the verdict of the reference verifier (cyberspace-cli af6eee8) under
// the real exemption lists and Bitcoin mainnet's line from 0 to 974,696; and
// every real ride judged alone (verify_ride_event). Its line is sparse: the
// blocks the reference read, and every stop as near each boarding as its
// station (testdata/tools/build-ride-vectors.py says how it was made).
// REGIONGATE_REF_LINE=<line.tsv> also runs them against the whole line.
const realRidesFile = "testdata/chain-rules-2026-10-08-residue-openings-real-rides.json"

type realRidesFileT struct {
	Revision string `json:"chain_rules_revision"`
	Line     struct {
		Tip    uint64      `json:"tip"`
		Blocks []LineBlock `json:"blocks"`
	} `json:"line"`
	Vectors []vector
	Proofs  []struct {
		OK       bool
		Failures []string
		Ms       float64 `json:"reference_ms"`
		Length   uint64
		Event    nostr.Event
	}
}

// sparseLine is mainnet's line as far as the vectors read it: the blocks it
// holds and mainnet's tip. Like the reference's line it is the whole line
// (a height above the tip does not exist). A block at or below the tip that
// it lacks was not read by the reference, so asking for one is a
// disagreement, and is reported.
type sparseLine struct {
	tip    uint64
	blocks map[uint64]LineBlock
	stops  map[uint64]Coord
	mu     sync.Mutex
	missed []uint64
}

func newSparseLine(t *testing.T, tip uint64, blocks []LineBlock) *sparseLine {
	l := &sparseLine{tip: tip, blocks: map[uint64]LineBlock{}, stops: map[uint64]Coord{}}
	for _, b := range blocks {
		c, err := ParseCoord(b.Coord)
		if err != nil {
			t.Fatal(err)
		}
		l.blocks[b.Height], l.stops[b.Height] = b, c
	}
	return l
}

func (l *sparseLine) Complete() bool      { return true }
func (l *sparseLine) Tip() (uint64, bool) { return l.tip, true }

func (l *sparseLine) get(h uint64) (LineBlock, bool) {
	b, ok := l.blocks[h]
	if !ok && h <= l.tip {
		l.mu.Lock()
		l.missed = append(l.missed, h)
		l.mu.Unlock()
	}
	return b, ok
}

func (l *sparseLine) Stop(h uint64) (string, bool) {
	b, ok := l.get(h)
	return b.Coord, ok
}

func (l *sparseLine) BlockHash(h uint64) ([]byte, bool) {
	b, ok := l.get(h)
	if !ok {
		return nil, false
	}
	raw, _ := hex.DecodeString(b.BlockHash)
	return raw, true
}

func (l *sparseLine) Station(c Coord, bound uint64) uint64 {
	best, bestD := uint64(0), -1
	for h, s := range l.stops {
		if h > bound {
			continue
		}
		d := max(lcaHeight(c.X, s.X), lcaHeight(c.Y, s.Y), lcaHeight(c.Z, s.Z))
		if bestD < 0 || d < bestD || d == bestD && h < best {
			best, bestD = h, d
		}
	}
	return best
}

func loadRealRides(t *testing.T) realRidesFileT {
	t.Helper()
	data, err := os.ReadFile(realRidesFile)
	if err != nil {
		t.Fatal(err)
	}
	var f realRidesFileT
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Revision != ChainRulesRevision || len(f.Vectors) == 0 || len(f.Proofs) == 0 {
		t.Fatalf("real ride vectors lock revision %q, the verifier implements %q", f.Revision, ChainRulesRevision)
	}
	return f
}

// runRealRides checks every vector and every ride proof against line.
func runRealRides(t *testing.T, f realRidesFileT, line Line) {
	v := Verifier{Proofs: SpecProofs{Line: line}, Signature: validation.CheckSignature}
	// The rides a chain vector judges: each of its chain up to the event
	// that breaks it. A ride's own proof agreeing is then part of the
	// chain's verdict agreeing, so the rides judged alone below are the
	// others (all of them with REGIONGATE_ALL_RIDES=1).
	inChain := map[string]bool{}
	for _, vec := range f.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			vd := v.Verify(vec.Identity, parseEvents(vec.Events))
			if why := checkVector(vec, vd); why != "" {
				t.Fatal(why)
			}
			upto := len(vd.Chain)
			if vd.InvalidIndex >= 0 {
				upto = vd.InvalidIndex + 1
			}
			for _, id := range vd.Chain[:upto] {
				inChain[id] = true
			}
		})
	}
	all := os.Getenv("REGIONGATE_ALL_RIDES") != ""
	rides, judged := 0, 0
	type cost struct {
		id     string
		length uint64
		ref    float64
		d      time.Duration
	}
	var costs []cost
	for _, p := range f.Proofs {
		if !validation.CheckSignature(p.Event) {
			t.Fatalf("%s: not authentic", p.Event.ID)
		}
		if inChain[p.Event.ID] {
			rides++
			if !all {
				continue
			}
		}
		m, _ := ParseMove(p.Event)
		from, _ := onlyDecimal(p.Event, "from_height")
		to, _ := onlyDecimal(p.Event, "B")
		start := time.Now()
		ok := false
		why := "B equals from_height (5.6)"
		if from.Cmp(to) != 0 {
			w, err := verifyRideProof(context.Background(), line, m, from.Uint64(), to.Uint64(), nil)
			if err != nil {
				t.Fatal(err)
			}
			ok, why = w == "", w
		}
		costs = append(costs, cost{p.Event.ID[:8], p.Length, p.Ms, time.Since(start)})
		judged++
		if ok != p.OK {
			t.Errorf("ride %s: gate says %v (%s), the reference %v %v", p.Event.ID, ok, why, p.OK, p.Failures)
		}
	}
	sort.Slice(costs, func(i, j int) bool { return costs[i].d > costs[j].d })
	for _, c := range costs[:min(6, len(costs))] {
		t.Logf("ride %s, %d blocks: %v here, %.0f ms in the reference", c.id, c.length, c.d.Round(time.Millisecond), c.ref)
	}
	t.Logf("%d chains (%d rides judged on them), %d rides judged alone", len(f.Vectors), rides, judged)
}

func TestRealRideVectors(t *testing.T) {
	f := loadRealRides(t)
	line := newSparseLine(t, f.Line.Tip, f.Line.Blocks)
	runRealRides(t, f, line)
	if len(line.missed) > 0 {
		t.Fatalf("the gate read blocks the reference did not: %v", line.missed[:min(10, len(line.missed))])
	}
}

// TestRealRideVectorsOnTheWholeLine runs the same against an AnchorLine of
// mainnet's whole line, station index included (REGIONGATE_REF_LINE, the TSV
// of TestLandfallAgreesWithTheReferenceLine).
func TestRealRideVectorsOnTheWholeLine(t *testing.T) {
	path := os.Getenv("REGIONGATE_REF_LINE")
	if path == "" {
		t.Skip("REGIONGATE_REF_LINE not set")
	}
	f := loadRealRides(t)
	line := anchorLineFromRows(t, readRefLine(t, path))
	if tip, _ := line.Tip(); tip != f.Line.Tip {
		t.Fatalf("whole line tip %d, the vectors' %d", tip, f.Line.Tip)
	}
	runRealRides(t, f, line)
}

// anchorLineFromRows builds an AnchorLine from a line's rows directly, as
// Load would from anchors (each block names the one below as previous).
func anchorLineFromRows(t *testing.T, rows []refLineRow) *AnchorLine {
	t.Helper()
	l := NewAnchorLine(AnchorLineConfig{Publisher: "test"})
	blocks := make([]anchorBlock, len(rows))
	for i, r := range rows {
		var b anchorBlock
		b.height = r.height
		hex.Decode(b.hash[:], []byte(r.hash))
		hex.Decode(b.coord[:], []byte(r.coord))
		if i > 0 {
			b.prev = blocks[i-1].hash
		}
		blocks[i] = b
	}
	l.add(blocks)
	l.mu.Lock()
	l.reindex(true)
	l.mu.Unlock()
	if tip, ok := l.Tip(); !ok || tip+1 != uint64(len(rows)) {
		t.Fatal(fmt.Sprintf("line built to %d of %d rows", tip, len(rows)))
	}
	return l
}
