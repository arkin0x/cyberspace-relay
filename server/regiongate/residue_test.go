package regiongate

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// The golden vectors of residue openings, hop proof version 2
// (CYBERSPACE_V2 §5.9 to §5.13), copied unchanged from the spec:
//
//	arkin0x/cyberspace 9210d6d, hop-residue-vectors.json
//	(written by hop-residue-vectors.py from hop-residue-reference.py, spec 8b45430)
const residueVectorsFile = "testdata/hop-residue-vectors.json"

type residueVectors struct {
	Single []struct {
		Function  string
		Arguments map[string]json.RawMessage
		Value     string
	}
	Prover []struct {
		Name            string
		PreviousEventID string `json:"previous_event_id"`
		C1              string `json:"c"`
		C2              string `json:"C"`
		Axes            []struct {
			Base   string
			Height int
		}
		K            int
		TBase        string `json:"t_base"`
		HMax         int    `json:"h_max"`
		M            int64
		Depth        int
		A            string
		PrimesFirst8 []string `json:"primes_first_8"`
		RootsModP0   struct {
			X, Y, Z, T string
			HopN       string `json:"hop_n"`
		} `json:"roots_mod_p0"`
		ResiduesFirst8 []string `json:"residues_first_8"`
		Nonce          uint64
		G              string
		Indices        []uint64
		Tags           struct{ Proof, Mn, Mp string }
	}
	Verifier []struct {
		Name            string
		PreviousEventID string `json:"previous_event_id"`
		C1              string `json:"c"`
		C2              string `json:"C"`
		Tags            map[string]string
		Expected        string
	}
	Prices struct {
		Budgets []struct {
			H int
			B string
		}
	}
	Sizes []struct {
		HMax     int   `json:"h_max"`
		M        int64 `json:"m"`
		Depth    int
		MpLength int `json:"mp_length"`
	}
}

func loadResidueVectors(t *testing.T) residueVectors {
	t.Helper()
	data, err := os.ReadFile(residueVectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var rv residueVectors
	if err := json.Unmarshal(data, &rv); err != nil {
		t.Fatal(err)
	}
	return rv
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decimal(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("not a decimal: %q", s)
	}
	return n
}

func TestResidueSingleValues(t *testing.T) {
	rv := loadResidueVectors(t)
	if len(rv.Single) == 0 {
		t.Fatal("no single vectors")
	}
	for _, s := range rv.Single {
		str := func(k string) string {
			var v string
			if err := json.Unmarshal(s.Arguments[k], &v); err != nil {
				t.Fatalf("%s: %s: %v", s.Function, k, err)
			}
			return v
		}
		num := func(k string) uint64 {
			var v uint64
			if err := json.Unmarshal(s.Arguments[k], &v); err != nil {
				t.Fatalf("%s: %s: %v", s.Function, k, err)
			}
			return v
		}
		var got string
		prev := mustHex(t, str("previous_event_id"))
		switch s.Function {
		case "hop_prime":
			got = new(big.Int).SetUint64(hopPrime(prev, num("j"))).String()
		case "compute_subtree_cantor mod p_0":
			got = new(big.Int).SetUint64(residueRoot(decimal(t, str("base")), int(num("height")), hopPrime(prev, 0))).String()
		case "leaf_hash":
			var rs []string
			json.Unmarshal(s.Arguments["residues"], &rs)
			var residues []uint64
			for _, r := range rs {
				residues = append(residues, decimal(t, r).Uint64())
			}
			got = hex.EncodeToString(hopLeaf(prev, num("block"), residues))
		case "attempt":
			got = hex.EncodeToString(hopAttempt(prev, mustHex(t, str("seal")), num("nonce")))
		default:
			t.Fatalf("unknown single function %q", s.Function)
		}
		if got != s.Value {
			t.Errorf("%s %s: got %s want %s", s.Function, string(s.Arguments["j"]), got, s.Value)
		}
	}
}

func TestResidueProverValues(t *testing.T) {
	rv := loadResidueVectors(t)
	for _, p := range rv.Prover {
		prev := mustHex(t, p.PreviousEventID)
		from, to := mustCoord(t, p.C1), mustCoord(t, p.C2)
		g := newHopGeometry(prev, from, to)
		for i, ax := range p.Axes {
			if g.heights[i] != ax.Height || g.bases[i].String() != ax.Base {
				t.Errorf("%s axis %d: got base %s height %d, want %s %d", p.Name, i, g.bases[i], g.heights[i], ax.Base, ax.Height)
			}
		}
		if g.heights[3] != p.K || g.bases[3].String() != p.TBase || g.hMax != p.HMax || g.m.Int64() != p.M || g.depth != p.Depth || g.price.String() != p.A {
			t.Errorf("%s: got K %d t_base %s h_max %d m %s depth %d A %s", p.Name, g.heights[3], g.bases[3], g.hMax, g.m, g.depth, g.price)
		}
		for j, want := range p.PrimesFirst8 {
			if got := hopPrime(prev, uint64(j)); new(big.Int).SetUint64(got).String() != want {
				t.Errorf("%s p_%d: got %d want %s", p.Name, j, got, want)
			}
		}
		p0 := hopPrime(prev, 0)
		for i, want := range []string{p.RootsModP0.X, p.RootsModP0.Y, p.RootsModP0.Z, p.RootsModP0.T} {
			if got := residueRoot(g.bases[i], g.heights[i], p0); new(big.Int).SetUint64(got).String() != want {
				t.Errorf("%s root %d mod p_0: got %d want %s", p.Name, i, got, want)
			}
		}
		for j, want := range p.ResiduesFirst8 {
			if got := g.hopResidue(hopPrime(prev, uint64(j))); new(big.Int).SetUint64(got).String() != want {
				t.Errorf("%s r_%d: got %d want %s", p.Name, j, got, want)
			}
		}
		if G := hopAttempt(prev, mustHex(t, p.Tags.Proof), p.Nonce); hex.EncodeToString(G) != p.G || !meetsPrice(G, g.price) {
			t.Errorf("%s: G %x, want %s meeting the price", p.Name, G, p.G)
		}
		why, err := verifyHopLevel1(prev, from, to, p.Tags.Proof, p.Tags.Mn, p.Tags.Mp, 32)
		if why != "" || err != nil {
			t.Errorf("%s: Level 1 rejects the prover's own tags: %s %v", p.Name, why, err)
		}
	}
}

func TestResidueVerifierVerdicts(t *testing.T) {
	rv := loadResidueVectors(t)
	for _, v := range rv.Verifier {
		prev := mustHex(t, v.PreviousEventID)
		why, err := verifyHopLevel1(prev, mustCoord(t, v.C1), mustCoord(t, v.C2), v.Tags["proof"], v.Tags["mn"], v.Tags["mp"], 32)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got := map[bool]string{true: "accept", false: "reject"}[why == ""]; got != v.Expected {
			t.Errorf("%s: got %s (%s), want %s", v.Name, got, why, v.Expected)
		}
	}
}

func TestResiduePricesAndSizes(t *testing.T) {
	rv := loadResidueVectors(t)
	for _, b := range rv.Prices.Budgets {
		if got := rerollBudget(b.H); got.String() != b.B {
			t.Errorf("B(%d): got %s want %s", b.H, got, b.B)
		}
	}
	for _, s := range rv.Sizes {
		m := residueCount(s.HMax)
		if m.Int64() != s.M || merkleDepth(m) != s.Depth || mpLength(s.Depth) != s.MpLength {
			t.Errorf("h_max %d: got m %s depth %d", s.HMax, m, merkleDepth(m))
		}
	}
}

// The method of differences must equal the tree carried modulo p at every
// height and level, aligned bases far from zero included.
func TestResidueRootMatchesTree(t *testing.T) {
	prev := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	base := new(big.Int).Lsh(decimal(t, "19342813113834066795298816"), 0)
	for h := 0; h <= 16; h++ {
		p := hopPrime(prev, uint64(h))
		b := aligned(base, h)
		if got, want := residueRoot(b, h, p), residueTree(modBig(b, p), h, p); got != want {
			t.Errorf("h%d: differences %d, tree %d", h, got, want)
		}
	}
}
