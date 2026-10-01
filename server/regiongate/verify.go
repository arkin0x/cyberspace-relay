package regiongate

import (
	"fmt"

	nostr "github.com/0ceanslim/grain/server/types"
)

// ProofResult is a ProofChecker's answer for one event.
type ProofResult int

const (
	// ProofVerified: the event's work proof (or its absence, for actions
	// that carry none) checks out.
	ProofVerified ProofResult = iota
	// ProofUnchecked: the checker cannot verify this event's proof. Per
	// §8.9 this is "unverifiable, never invalid": the chain is not broken,
	// but nothing from here on counts as proof-verified.
	ProofUnchecked
	// ProofInvalid: the proof is wrong; the chain is invalid from here.
	ProofInvalid
)

// ProofChecker verifies the work proof of one chain event, given the event
// before it. It is the seam where the ratified chain-verification spec plugs
// in; structural rules (links, coordinates, brackets) are checked by the
// verifier itself and never reach the checker.
type ProofChecker interface {
	Check(prev, cur Move) (ProofResult, string)
}

// Verdict is the outcome of verifying one pubkey's chain.
type Verdict struct {
	Pubkey string
	// HasChain is false when the pubkey has no spawn at all.
	HasChain bool
	// Position is the identity's position after the last structurally
	// valid event of its active chain (inside an open bracket, the
	// bracket's base position, §8.11.4 rules 1 and 7).
	Position *Coord
	// PositionEvent is the id of the event that Position comes from.
	PositionEvent string
	// VerifiedPosition is the position after the longest prefix of the
	// chain whose every proof the checker verified. With PendingSpec this
	// is the spawn point.
	VerifiedPosition *Coord
	// Head is the id of the active chain's last event, valid or not.
	Head string
	// Length is the active chain's length; Unchecked counts the
	// structurally valid events past the proof-verified prefix.
	Length, Unchecked int
	// Stopped explains why the walk ended before the head, if it did.
	Stopped string
}

// Verifier walks chains with a proof checker and a signature check.
type Verifier struct {
	Proofs    ProofChecker
	Signature func(nostr.Event) bool
}

// Verify resolves and checks a pubkey's chain from the events held for it.
func (v Verifier) Verify(pubkey string, events []nostr.Event) Verdict {
	// Signatures first: a forged event must not take part in fork
	// resolution, or anyone could cut a chain off by publishing an
	// "older" branch in someone else's name.
	signed := events[:0:0]
	for _, e := range events {
		if e.PubKey == pubkey && e.Kind == KindMovement && (v.Signature == nil || v.Signature(e)) {
			signed = append(signed, e)
		}
	}
	chain := ActiveChain(pubkey, signed)
	vd := Verdict{Pubkey: pubkey, Length: len(chain)}
	if len(chain) == 0 {
		vd.Stopped = "no spawn event"
		return vd
	}
	vd.HasChain = true
	vd.Head = chain[len(chain)-1].Event.ID

	spawn := chain[0]
	if spawn.To != pubkey {
		vd.Stopped = "spawn C does not equal the pubkey (§8.3)"
		return vd
	}
	pos, err := ParseCoord(spawn.To)
	if err != nil {
		vd.Stopped = "spawn C: " + err.Error()
		return vd
	}
	vd.Position, vd.PositionEvent = &pos, spawn.Event.ID
	verified := pos
	vd.VerifiedPosition = &verified
	proofsHold := true

	var bracket *Move // the open enter-virtual, if any
	var bracketBox Box
	lastBase := ActSpawn // last action outside any bracket (§8.11.4 rule 8)
	prev := spawn
	for _, cur := range chain[1:] {
		reason := structural(prev, cur, bracket, bracketBox, lastBase)
		if reason != "" {
			vd.Stopped = fmt.Sprintf("event %s invalid: %s", cur.Event.ID, reason)
			return vd
		}
		to, _ := ParseCoord(cur.To) // checked by structural

		inBracket := bracket != nil
		switch {
		case cur.Action == ActEnterVirtual:
			box, _ := parseRegion(cur.Region)
			c := cur
			bracket, bracketBox = &c, box
		case cur.Action == ActExitVirtual:
			bracket = nil
		case !inBracket && !knownBase(cur.Action):
			// §8.9: an action this verifier does not implement is
			// unverifiable, never invalid. Report what was verified.
			vd.Stopped = fmt.Sprintf("event %s: action %q is not implemented here (unverifiable, §8.9)", cur.Event.ID, cur.Action)
			return vd
		case !inBracket:
			lastBase = cur.Action
		}

		// Virtual actions and brackets carry no base proof (§8.11.2).
		if proofsHold && !inBracket && cur.Action != ActEnterVirtual && cur.Action != ActExitVirtual && v.Proofs != nil {
			res, why := v.Proofs.Check(prev, cur)
			switch res {
			case ProofInvalid:
				vd.Stopped = fmt.Sprintf("event %s invalid: proof: %s", cur.Event.ID, why)
				return vd
			case ProofUnchecked:
				proofsHold = false
			}
		}
		if !proofsHold {
			vd.Unchecked++
		}

		// Position: inside a bracket it is the bracket's base position,
		// the enter-virtual's c (§8.11.4 rules 1 and 7).
		p := to
		if bracket != nil {
			p, _ = ParseCoord(bracket.From)
		}
		vd.Position, vd.PositionEvent = &p, cur.Event.ID
		if proofsHold {
			vp := p
			vd.VerifiedPosition = &vp
		}
		prev = cur
	}
	return vd
}

func knownBase(action string) bool { return baseActions[action] || action == ActExitVirtual }

// structural checks one event against the one before it: links (by
// construction of ActiveChain), coordinate continuity, and the bracket rules
// of §8.11.4. It returns "" when the event is structurally valid.
func structural(prev, cur Move, bracket *Move, box Box, lastBase string) string {
	if cur.Action == ActSpawn {
		return "spawn inside a chain"
	}
	if cur.From != prev.To {
		return "c does not equal the previous event's C"
	}
	to, err := ParseCoord(cur.To)
	if err != nil {
		return "C: " + err.Error()
	}
	if bracket != nil {
		switch {
		case cur.Action == ActExitVirtual:
			if cur.Entry != bracket.Event.ID {
				return "exit-virtual entry does not name the open enter-virtual (§8.11.4 rule 6)"
			}
			if cur.To != bracket.From {
				return "exit-virtual C does not restore the base position (§8.11.4 rule 2)"
			}
		case baseActions[cur.Action]:
			return "base action inside a virtual bracket (§8.11.4 rule 3)"
		default:
			if !box.Contains(to) {
				return "virtual action outside the bracket's region (§8.11.4 rule 4)"
			}
		}
		return ""
	}
	switch cur.Action {
	case ActExitVirtual:
		return "exit-virtual with no open bracket (§8.11.4 rule 6)"
	case ActEnterVirtual:
		box, ok := parseRegion(cur.Region)
		if !ok {
			return "enter-virtual region tag malformed or not aligned (§8.11.1)"
		}
		if !box.Contains(to) {
			return "enter-virtual C outside its region (§8.11.4 rule 4)"
		}
	case ActEnterHyperspace:
		if cur.To != cur.From {
			return "enter-hyperspace must not move (C must equal c)"
		}
	case ActHyperjump:
		// DECK-0001 §4.3; a bracket stands for the action before it
		// (§8.11.4 rule 8), so lastBase skips brackets.
		if lastBase != ActEnterHyperspace && lastBase != ActHyperjump {
			return "hyperjump must follow enter-hyperspace or hyperjump (DECK-0001 §4.3)"
		}
	}
	return ""
}

// PendingSpec is the placeholder ProofChecker used until the chain
// verification spec is ratified. It verifies no work proofs: every hop,
// sidestep, enter-hyperspace and hyperjump comes back ProofUnchecked.
//
// What this means for the gate: in "structural" mode an identity is placed at
// its chain head (links, signatures, coordinates and brackets are checked,
// proofs are trusted); in "strict" mode it is placed at its last
// proof-verified position, which with this checker is its spawn point.
//
// Replace it with a checker implementing the ratified rules (hop proofs
// §8.7.1 or their successor, sidestep Level 1 §8.7.2 with the mn re-roll
// price and the grandfathered lists, DECK-0001 ride openings).
type PendingSpec struct{}

// Check implements ProofChecker.
func (PendingSpec) Check(prev, cur Move) (ProofResult, string) {
	return ProofUnchecked, "awaiting the ratified chain-verification spec"
}
