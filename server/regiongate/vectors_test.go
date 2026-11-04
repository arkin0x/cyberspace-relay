package regiongate

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"
)

// The golden vectors of the chain rules at revision
// 2026-10-08-residue-openings (CYBERSPACE_V2 §8.12), copied unchanged from
// the spec, where they are normative:
//
//	arkin0x/cyberspace 9210d6d (added by #84, 3ffa275),
//	chain-rules-2026-10-08-residue-openings.json
//	sha256 3c56a77dda23e81dcfd52ef6a4e07a1920eab93c43d3f1457c88f137a95b1218
//
// The same file is vectors/chain-rules-2026-10-08-residue-openings.json in
// arkin0x/cyberspace-cli (5103c62), whose scripts/gen_chain_vectors.py
// generated it. Replace the file, never edit it: a vector that disagrees
// with this verifier is a finding about one implementation or the other.
// REGIONGATE_VECTORS=<path> runs another vectors file of this revision in
// place of this one, without copying it in.
//
// §8.12: "A port runs every vector in full and skips none." Every vector runs
// with the real proof checker, the file's synthetic block line in place of
// Bitcoin mainnet, and the file's own list of version 1 hops in place of
// grandfathered-v1-hops.txt, and at no other time.
const vectorsFile = "testdata/chain-rules-2026-10-08-residue-openings.json"

type vectorFile struct {
	Revision   string `json:"chain_rules_revision"`
	VerifyWith struct {
		Identity string `json:"identity"` // every event is checked for authenticity (§8.7.3)
	} `json:"verify_with"`
	TestKey struct{ Pubkey string } `json:"test_key"`
	Line    struct {
		Blocks []LineBlock `json:"blocks"`
	} `json:"line"`
	GrandfatheredV1Hops struct {
		IDs []string `json:"ids"`
	} `json:"grandfathered_v1_hops"`
	Reasons map[string]string `json:"reasons"`
	Vectors []vector
}

type vector struct {
	Name string
	// Identity is the vector's own identity, in a file of real chains,
	// which come from many; "" means the file's verify_with.identity.
	Identity     string `json:"identity"`
	Description  string
	OpenQuestion string `json:"open_question"`
	Events       []json.RawMessage
	Expected     struct {
		Valid        bool
		Chain        []string
		Position     string
		Head         string
		OpenBracket  *string `json:"open_bracket"`
		Skipped      []string
		Reason       string
		InvalidAt    *string `json:"invalid_at"`
		InvalidIndex *int    `json:"invalid_index"`
	}
}

func loadVectors(t *testing.T, path string) vectorFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}
	return vf
}

// vectorVerifier is the verifier the vectors run under: the real checker,
// with the file's line and test list.
func vectorVerifier(t *testing.T, vf vectorFile) Verifier {
	t.Helper()
	line, err := NewStaticLine(vf.Line.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, id := range vf.GrandfatheredV1Hops.IDs {
		listed[id] = true
	}
	return Verifier{Proofs: SpecProofs{Line: line, ListedV1Hops: listed}, Signature: validation.CheckSignature}
}

// checkVector compares one verdict with the vector's, field by field: the
// active chain; for a valid chain its position, head, open bracket and
// skipped actions; for an invalid one the reason, the event that breaks it
// and the frozen position. It returns "" when they agree.
func checkVector(vec vector, vd Verdict) string {
	ex := vec.Expected
	if ex.Reason == ReasonNoSpawn {
		if vd.HasChain || vd.Reason != ReasonNoSpawn || len(vd.Chain) != 0 || vd.InvalidIndex != -1 {
			return "want no-spawn, got " + vd.Stopped
		}
		return ""
	}
	if !slices.Equal(vd.Chain, ex.Chain) {
		return "active chain differs"
	}
	pos := ""
	if vd.Position != nil {
		pos = vd.Position.Hex()
	}
	if ex.Valid {
		openBracket := ""
		if ex.OpenBracket != nil {
			openBracket = *ex.OpenBracket
		}
		switch {
		case !vd.Valid():
			return "want valid, got " + vd.Stopped
		case vd.Unchecked != 0:
			return "valid, but with proofs left unchecked"
		case pos != ex.Position || vd.Head != ex.Head || vd.OpenBracket != openBracket || !slices.Equal(vd.Skipped, ex.Skipped):
			return "valid, but the position, head, open bracket or skipped actions differ"
		}
		return ""
	}
	if vd.Reason != ex.Reason || vd.InvalidAt != *ex.InvalidAt || vd.InvalidIndex != *ex.InvalidIndex {
		return "want " + ex.Reason + ", got " + vd.Reason + ": " + vd.Stopped
	}
	// An invalid verdict names where the identity stands: frozen at its
	// last valid position (§3.2, §8.7.3).
	if pos != ex.Position {
		return "frozen position differs"
	}
	return ""
}

func TestChainRulesGoldenVectors(t *testing.T) {
	path := vectorsFile
	if p := os.Getenv("REGIONGATE_VECTORS"); p != "" {
		path = p
	}
	vf := loadVectors(t, path)
	if vf.Revision != ChainRulesRevision {
		t.Fatalf("vectors lock revision %q, the verifier implements %q", vf.Revision, ChainRulesRevision)
	}
	for code := range vf.Reasons {
		if _, ok := Reasons[code]; !ok {
			t.Errorf("vector reason code %q is unknown to the verifier", code)
		}
	}
	for code := range Reasons {
		if _, ok := vf.Reasons[code]; !ok {
			t.Errorf("verifier reason code %q is not in the vectors", code)
		}
	}
	if vf.TestKey.Pubkey == "" || vf.VerifyWith.Identity != vf.TestKey.Pubkey || len(vf.Vectors) == 0 || len(vf.Line.Blocks) == 0 {
		t.Fatal("vectors file is not the expected format")
	}
	v := vectorVerifier(t, vf)
	for _, vec := range vf.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			if vec.OpenQuestion != "" {
				t.Logf("open question, literal reading implemented: %s", vec.OpenQuestion)
			}
			if why := checkVector(vec, v.Verify(vf.TestKey.Pubkey, parseEvents(vec.Events))); why != "" {
				t.Fatal(why)
			}
		})
	}
	t.Logf("%d vectors, every one run in full", len(vf.Vectors))
}

// realVectorsFile holds real chains read from wss://cyberspace.nostr1.com on
// 2026-11-04, each with the verdict of the reference verifier
// (cyberspace-cli 5103c62) under the real exemption lists and no block line;
// a chain that rides is cut before its first ride. Its "description" field
// says how it was made. Every vector must reach the reference's verdict with
// the checker the gate runs in production.
const realVectorsFile = "testdata/chain-rules-2026-10-08-residue-openings-real.json"

func TestRealChainVectors(t *testing.T) {
	vf := loadVectors(t, realVectorsFile)
	if vf.Revision != ChainRulesRevision || len(vf.Vectors) == 0 {
		t.Fatalf("real vectors lock revision %q, the verifier implements %q", vf.Revision, ChainRulesRevision)
	}
	v := Verifier{Proofs: SpecProofs{}, Signature: validation.CheckSignature}
	valid := 0
	for _, vec := range vf.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			if why := checkVector(vec, v.Verify(vec.Identity, parseEvents(vec.Events))); why != "" {
				t.Fatal(why)
			}
		})
		if vec.Expected.Valid {
			valid++
		}
	}
	t.Logf("%d real chains, %d valid", len(vf.Vectors), valid)
}

// parseEvents decodes a vector's events one by one. An event that does not
// have NIP-01's shape (a created_at that is a string, a tag holding a
// number) cannot be decoded, just as a relay could not accept it, so it is
// left out: it is not a valid NIP-01 event, and a reader discards it before
// resolution (§8.7.3).
func parseEvents(raw []json.RawMessage) []nostr.Event {
	var out []nostr.Event
	for _, r := range raw {
		var e nostr.Event
		if json.Unmarshal(r, &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
