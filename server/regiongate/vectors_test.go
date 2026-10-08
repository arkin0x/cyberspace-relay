package regiongate

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
)

// The golden vectors of the chain rules at revision
// 2026-09-28-virtual-brackets (CYBERSPACE_V2 §8.12), with the rulings of
// 2026-10-07 and 2026-10-08 folded in (arkin0x/cyberspace #46, 912f3d7, and
// spec PR #48 in review), copied unchanged from the reference
// implementation:
//
//	arkin0x/cyberspace-cli PR #24, commit 80ab1456f24a94a51bb024e798ffe02d07cadd34,
//	vectors/chain-rules-2026-09-28-virtual-brackets.json
//	sha256 735886e151237ac198b126bc5e1df0fc8f3c98f96c139668d5ec76b4d6b7c990
//
// The format is described in that repository's vectors/README.md. Replace the
// file, never edit it: a vector that disagrees with this verifier is a
// finding about one implementation or the other. REGIONGATE_VECTORS=<path>
// runs another vectors file in place of this one, without copying it in.
const vectorsFile = "testdata/chain-rules-2026-09-28-virtual-brackets.json"

type vectorFile struct {
	Revision   string `json:"chain_rules_revision"`
	VerifyWith struct {
		Identity string `json:"identity"` // every event is checked for authenticity (§8.7.3)
	} `json:"verify_with"`
	TestKey struct{ Pubkey string } `json:"test_key"`
	Reasons map[string]string       `json:"reasons"`
	Vectors []struct {
		Name         string
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
}

// pendingReasons are the rules this relay leaves to the ProofChecker. A
// vector whose verdict rests on one of them is checked as far as the gate
// can check it today: the chain is structurally valid up to the event that
// breaks the rule, and that event's proof is reported unchecked, never
// verified. These assertions change to the vector's own verdict once a real
// checker replaces PendingSpec (rollout step 4).
var pendingReasons = map[string]bool{
	ReasonHopProof: true, ReasonSidestepProof: true, ReasonEnterHyperspaceProof: true,
	ReasonHyperjumpStation: true, ReasonHyperjumpStop: true, ReasonHyperjumpProof: true,
}

// needsBlockData are vectors whose rule the verifier decides from tags in
// some cases and needs Bitcoin's block data for in others: an as_of above the
// line's tip is not a height on the line (DECK-0001 §4.2), and only the line
// knows its tip.
var needsBlockData = map[string]bool{"ride-as-of-beyond-tip": true}

func TestChainRulesGoldenVectors(t *testing.T) {
	path := vectorsFile
	if p := os.Getenv("REGIONGATE_VECTORS"); p != "" {
		path = p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}
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
	if vf.TestKey.Pubkey == "" || vf.VerifyWith.Identity != vf.TestKey.Pubkey || len(vf.Vectors) == 0 {
		t.Fatal("vectors file is not the expected format")
	}

	var structural, structuralOnUnchecked, pending int
	for _, vec := range vf.Vectors {
		vec := vec
		ex := vec.Expected
		proofPending := !ex.Valid && (pendingReasons[ex.Reason] || needsBlockData[vec.Name])
		onUnchecked := false
		t.Run(vec.Name, func(t *testing.T) {
			if vec.OpenQuestion != "" {
				t.Logf("open question, literal reading implemented: %s", vec.OpenQuestion)
			}
			vd := verifier().Verify(vf.TestKey.Pubkey, parseEvents(vec.Events))
			if ex.Reason == ReasonNoSpawn {
				if vd.HasChain || vd.Reason != ReasonNoSpawn || len(vd.Chain) != 0 || vd.InvalidIndex != -1 {
					t.Fatalf("want no-spawn, got %+v", vd)
				}
				return
			}
			if !slices.Equal(vd.Chain, ex.Chain) {
				t.Fatalf("active chain:\n got %v\nwant %v", vd.Chain, ex.Chain)
			}
			switch {
			case ex.Valid:
				if !vd.Valid() {
					t.Fatalf("want valid, got %s", vd.Stopped)
				}
				if vd.Position == nil || vd.Position.Hex() != ex.Position {
					t.Fatalf("position: got %v want %s", vd.Position, ex.Position)
				}
				openBracket := ""
				if ex.OpenBracket != nil {
					openBracket = *ex.OpenBracket
				}
				if vd.Head != ex.Head || vd.OpenBracket != openBracket || !slices.Equal(vd.Skipped, ex.Skipped) {
					t.Fatalf("head %s open bracket %q skipped %v; want %s %q %v", vd.Head, vd.OpenBracket, vd.Skipped, ex.Head, openBracket, ex.Skipped)
				}
				onUnchecked = vd.Unchecked > 0
			case proofPending:
				// The vector breaks exactly one rule, and it is a rule the
				// checker owns: structurally the chain passes, and the
				// breaking event is past the proof-verified prefix.
				if !vd.Valid() {
					t.Fatalf("want structurally valid (the vector breaks %s only), got %s", ex.Reason, vd.Stopped)
				}
				if at := slices.Index(vd.Chain, vd.VerifiedEvent); at < 0 || at >= *ex.InvalidIndex || vd.Unchecked == 0 {
					t.Fatalf("event %d breaks %s, but the verified prefix reaches index %d (unchecked %d)", *ex.InvalidIndex, ex.Reason, at, vd.Unchecked)
				}
			default:
				if vd.Reason != ex.Reason || vd.InvalidAt != *ex.InvalidAt || vd.InvalidIndex != *ex.InvalidIndex {
					t.Fatalf("want %s at %d (%s), got %q at %d: %s", ex.Reason, *ex.InvalidIndex, *ex.InvalidAt, vd.Reason, vd.InvalidIndex, vd.Stopped)
				}
				// An invalid verdict names where the identity stands: frozen
				// at its last valid position (§3.2, §8.7.3).
				if vd.Position == nil || vd.Position.Hex() != ex.Position {
					t.Fatalf("frozen position: got %v want %s", vd.Position, ex.Position)
				}
			}
		})
		switch {
		case proofPending:
			pending++
		case onUnchecked:
			structuralOnUnchecked++
			structural++
		default:
			structural++
		}
	}
	t.Logf("%d vectors: %d checked to their verdict (%d of them valid chains whose proofs are unchecked), %d pending the proof checker",
		len(vf.Vectors), structural, structuralOnUnchecked, pending)
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
