package regiongate

import (
	"fmt"
	"math/big"
	"strings"

	nostr "github.com/0ceanslim/grain/server/types"
)

// ProofResult is a ProofChecker's answer for one event.
type ProofResult int

const (
	// ProofVerified: the event's work proof (or its absence, for actions
	// that carry none) checks out.
	ProofVerified ProofResult = iota
	// ProofUnchecked: the checker cannot verify this event's proof, because
	// it does not implement the check yet or lacks the data for it (Bitcoin
	// block data for a ride). The chain is not broken, but no event from
	// here on counts as proof-verified, so strict mode places the identity
	// at the last proof-verified position.
	ProofUnchecked
	// ProofInvalid: the proof is wrong; the chain is invalid from here.
	ProofInvalid
)

// ProofChecker verifies the work proof of one chain event: a hop (§8.7.1), a
// sidestep (§8.7.2), an enter-hyperspace (DECK-0001 §3.2) or a hyperjump
// (DECK-0001 §5.5), together with the ride rules that need Bitcoin's block
// data (DECK-0001 §4.2 and §4.3: as_of is a height on the line, from_height
// is the station; §5.5: C is the stop of B). It is the seam where the
// ratified chain verification rules plug in. The structural rules (links,
// coordinates, skipped actions, brackets, and the ride rules that read only
// tags) are checked by the verifier itself before the checker is asked.
//
// prev is the action a rule that looks back sees (§8.9 step 4, §8.11.4 rule
// 8): the nearest recognized action before cur, with a closed bracket
// standing for the action before its enter-virtual. The verifier has already
// checked that cur's c equals prev's C. The work is seeded by the event that
// cur's e previous tag names, cur.Previous, which can be a skipped action or
// an exit-virtual and is then not prev (§8.9 step 3, §8.11.4 rule 8).
//
// With ProofInvalid, the string starts with the code of the rule broken, one
// of the proof codes in Reasons, optionally followed by ": " and a detail. A
// string with no proof code is reported under the action's proof code.
type ProofChecker interface {
	Check(prev, cur Move) (ProofResult, string)
}

// Reason codes name the rule that makes a chain invalid. They are the codes
// of the golden vectors for this revision (arkin0x/cyberspace-cli,
// vectors/chain-rules-2026-09-28-virtual-brackets.json), so a verdict here
// can be compared with the reference implementation's, rule for rule.
const (
	ReasonNoSpawn              = "no-spawn"
	ReasonMalformed            = "malformed"
	ReasonSpawnCoordinate      = "spawn-coordinate"
	ReasonCMismatch            = "c-mismatch"
	ReasonHopProof             = "hop-proof"
	ReasonSidestepProof        = "sidestep-proof"
	ReasonEnterHyperspaceMoved = "enter-hyperspace-moved"
	ReasonEnterHyperspaceProof = "enter-hyperspace-proof"
	ReasonHyperjumpPredecessor = "hyperjump-predecessor"
	ReasonHyperjumpAsOf        = "hyperjump-as-of"
	ReasonHyperjumpStation     = "hyperjump-station"
	ReasonHyperjumpFromHeight  = "hyperjump-from-height"
	ReasonHyperjumpZeroLength  = "hyperjump-zero-length"
	ReasonHyperjumpStop        = "hyperjump-stop"
	ReasonHyperjumpProof       = "hyperjump-proof"
	ReasonRegion               = "region"
	ReasonGameTag              = "game-tag"
	ReasonOutsideRegion        = "outside-region"
	ReasonBaseActionInBracket  = "base-action-in-bracket"
	ReasonExitWithoutBracket   = "exit-without-bracket"
	ReasonExitWrongEntry       = "exit-wrong-entry"
	ReasonExitPosition         = "exit-position"
)

// Reasons maps every reason code to the rule it names.
var Reasons = map[string]string{
	ReasonNoSpawn:              "no spawn event for this pubkey, so there is no chain (§8.7.3 step 1)",
	ReasonMalformed:            "a tag the chain rules read is missing, repeated or ill-formed: A, e genesis, e previous, e entry, c, C, from_height, B",
	ReasonSpawnCoordinate:      "the spawn's C is not its pubkey (§8.3)",
	ReasonCMismatch:            "c is not the C of the nearest recognized action before it (§8.9 step 2), or inside a bracket not the C of the previous event (§8.11.5)",
	ReasonHopProof:             "the hop's proof does not verify (§8.7.1)",
	ReasonSidestepProof:        "the sidestep does not verify at Level 1 (§8.7.2)",
	ReasonEnterHyperspaceMoved: "an enter-hyperspace's C is not its c (DECK-0001 §3.1)",
	ReasonEnterHyperspaceProof: "the entry proof does not verify (DECK-0001 §3.2)",
	ReasonHyperjumpPredecessor: "the action a hyperjump looks back to is neither enter-hyperspace nor hyperjump (DECK-0001 §4.3)",
	ReasonHyperjumpAsOf:        "the first ride after boarding has no as_of tag, or as_of is not a height on the line, or is below B (DECK-0001 §4.2, §4.3)",
	ReasonHyperjumpStation:     "the first ride after boarding does not depart from the station (DECK-0001 §4.2, §4.3)",
	ReasonHyperjumpFromHeight:  "a later ride does not depart from the previous ride's B (DECK-0001 §4.3)",
	ReasonHyperjumpZeroLength:  "a ride with from_height equal to B that is not a first ride from the station (DECK-0001 §5.2, §5.6)",
	ReasonHyperjumpStop:        "the ride's C is not the stop coordinate of B, or B is not a height on the line (DECK-0001 §5.5 Level 1 step 2)",
	ReasonHyperjumpProof:       "the ride's proof does not verify at Level 1 (DECK-0001 §5.5, §5.8)",
	ReasonRegion:               "the enter-virtual's region tag is missing, repeated or ill-formed: H not canonical in [0, 85], or the base not aligned (§8.11.1)",
	ReasonGameTag:              "the enter-virtual does not carry exactly one p tag marked game holding a 32-byte lowercase hex pubkey (§8.11.1)",
	ReasonOutsideRegion:        "the C of an enter-virtual or a virtual action lies outside the declared region (§8.11.4 rule 4)",
	ReasonBaseActionInBracket:  "hop, sidestep, enter-hyperspace, hyperjump or enter-virtual inside an open bracket (§8.11.4 rule 3)",
	ReasonExitWithoutBracket:   "an exit-virtual when no bracket is open (§8.11.4 rule 6)",
	ReasonExitWrongEntry:       "an exit-virtual whose e entry names anything but the open enter-virtual (§8.11.4 rule 6)",
	ReasonExitPosition:         "an exit-virtual whose C is not the c of its enter-virtual (§8.11.4 rule 2)",
}

// proofReasons are the codes a ProofChecker reports. Each names a rule the
// verifier cannot decide from the tags alone.
var proofReasons = map[string]bool{
	ReasonHopProof: true, ReasonSidestepProof: true, ReasonEnterHyperspaceProof: true,
	ReasonHyperjumpAsOf: true, ReasonHyperjumpStation: true, ReasonHyperjumpStop: true, ReasonHyperjumpProof: true,
}

// proofOf is the proof code of each action that carries a work proof; the
// checker is asked about exactly these actions.
var proofOf = map[string]string{
	ActHop: ReasonHopProof, ActSidestep: ReasonSidestepProof,
	ActEnterHyperspace: ReasonEnterHyperspaceProof, ActHyperjump: ReasonHyperjumpProof,
}

// Verdict is the outcome of verifying one pubkey's chain.
type Verdict struct {
	Pubkey string
	// HasChain is false when the pubkey has no spawn at all.
	HasChain bool
	// Chain lists the ids of the active chain (§8.7.3), the spawn first.
	Chain []string
	// Position is the identity's position after the last event the walk
	// accepted: the C of the last recognized action (§8.9 step 5), or,
	// inside an open bracket, the bracket's base position (§8.11.4 rules 1
	// and 7). When the chain is invalid it is the position carried up to the
	// invalid event; the spec does not say whether an identity with an
	// invalid chain stands there or at its spawn (§3.2).
	Position *Coord
	// PositionEvent is the id of the last event the walk accepted that is
	// not a skipped action.
	PositionEvent string
	// VerifiedPosition is the position after the longest prefix of the
	// chain whose every proof the checker verified, and VerifiedEvent the id
	// of that prefix's last event. With PendingSpec this is the spawn point,
	// unless the chain carries no proof-bearing action at all.
	VerifiedPosition *Coord
	VerifiedEvent    string
	// Head is the id of the active chain's last event, valid or not, which
	// can be a skipped action.
	Head string
	// OpenBracket is the id of the enter-virtual still open at the end of
	// the walk, or "".
	OpenBracket string
	// Skipped lists the actions skipped under §8.9, in chain order. Names
	// inside a bracket are virtual actions and are never listed here.
	Skipped []string
	// Length is the active chain's length; Unchecked counts the events the
	// walk accepted past the proof-verified prefix, skipped actions aside.
	Length, Unchecked int
	// Reason is the code (Reasons) of the rule the chain breaks, or "" when
	// every event of the active chain passed. InvalidAt and InvalidIndex
	// name the first event that breaks it, the spawn at index 0; with no
	// spawn, or a valid chain, InvalidIndex is -1.
	Reason       string
	InvalidAt    string
	InvalidIndex int
	// Stopped explains, in words, why the walk ended before the head.
	Stopped string
}

// Valid reports whether the pubkey has a chain whose every event passed the
// structural rules and the proof checker. With a checker that leaves proofs
// unchecked, Valid means structurally valid; Unchecked says how much of it
// rests on proofs nobody verified.
func (vd Verdict) Valid() bool { return vd.HasChain && vd.Reason == "" }

// Verifier walks chains with a proof checker and a signature check.
type Verifier struct {
	Proofs    ProofChecker
	Signature func(nostr.Event) bool
}

// Verify resolves and checks a pubkey's chain from the events held for it,
// under the chain rules of ChainRulesRevision.
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
	vd := Verdict{Pubkey: pubkey, Length: len(chain), InvalidIndex: -1}
	if len(chain) == 0 {
		vd.Reason, vd.Stopped = ReasonNoSpawn, "no spawn event"
		return vd
	}
	vd.HasChain = true
	vd.Chain = make([]string, len(chain))
	for i, m := range chain {
		vd.Chain[i] = m.Event.ID
	}
	vd.Head = vd.Chain[len(chain)-1]
	invalid := func(i int, reason, detail string) Verdict {
		vd.Reason, vd.InvalidAt, vd.InvalidIndex = reason, chain[i].Event.ID, i
		vd.Stopped = fmt.Sprintf("event %s invalid (%s): %s", chain[i].Event.ID, reason, detail)
		return vd
	}

	spawn := chain[0]
	if reason, detail := checkSpawn(spawn, pubkey); reason != "" {
		return invalid(0, reason, detail)
	}
	pos, _ := ParseCoord(spawn.To) // checked by checkSpawn
	vd.Position, vd.PositionEvent = &pos, spawn.Event.ID
	verified := pos
	vd.VerifiedPosition, vd.VerifiedEvent = &verified, spawn.Event.ID
	proofsHold := true

	w := walk{carried: spawn.To, lookback: spawn}
	for i := 1; i < len(chain); i++ {
		cur := chain[i]
		if n := countTags(cur.Event, "A", ""); n != 1 {
			return invalid(i, ReasonMalformed, fmt.Sprintf("expected exactly one A tag, found %d", n))
		}
		if w.bracket == nil && !recognizedActions[cur.Action] {
			// §8.9: an action this verifier does not recognize is skipped.
			// Its links were followed when the chain was resolved (step 1);
			// it neither moves the identity (step 2) nor stands before the
			// next action for rules that look back (step 4), so the walk
			// leaves its state untouched. Its id still seeds the work of the
			// action after it, which the checker reads from that action's
			// e previous tag (step 3).
			vd.Skipped = append(vd.Skipped, cur.Event.ID)
			continue
		}
		prev := w.lookback
		if reason, detail := w.step(cur); reason != "" {
			return invalid(i, reason, detail)
		}

		// Only base and DECK-0001 actions outside a bracket carry a work
		// proof; brackets and virtual actions carry none (§8.11.2), and a
		// proof-bearing action inside a bracket was refused by step.
		if code, bearing := proofOf[cur.Action]; bearing && proofsHold && v.Proofs != nil {
			res, why := v.Proofs.Check(prev, cur)
			switch res {
			case ProofInvalid:
				if c, _, _ := strings.Cut(why, ":"); proofReasons[c] {
					code = c
				}
				return invalid(i, code, "proof: "+why)
			case ProofUnchecked:
				proofsHold = false
			}
		}
		if !proofsHold {
			vd.Unchecked++
		}

		p := w.position()
		vd.Position, vd.PositionEvent = &p, cur.Event.ID
		if proofsHold {
			vp := p
			vd.VerifiedPosition, vd.VerifiedEvent = &vp, cur.Event.ID
		}
	}
	if w.bracket != nil {
		vd.OpenBracket = w.bracket.entry.Event.ID
	}
	return vd
}

// checkSpawn checks the first event of the active chain: exactly one A tag,
// and exactly one C, which is the pubkey (§8.3).
func checkSpawn(spawn Move, pubkey string) (string, string) {
	if n := countTags(spawn.Event, "A", ""); n != 1 {
		return ReasonMalformed, fmt.Sprintf("expected exactly one A tag, found %d", n)
	}
	if countTags(spawn.Event, "C", "") != 1 || !isHex32(spawn.To) {
		return ReasonMalformed, "C: expected exactly one 32-byte lowercase hex coordinate"
	}
	if spawn.To != pubkey {
		return ReasonSpawnCoordinate, "the spawn's C is not its pubkey (§8.3)"
	}
	return "", ""
}

// walk is the state carried from one recognized action to the next.
type walk struct {
	// carried is the C of the nearest recognized action, where the next
	// recognized action starts (§8.9 step 2). A closed bracket leaves it
	// where it was, since the exit restores the entry's c (§8.11.4 rule 2).
	carried string
	// lookback is the action a rule that looks back sees (§8.9 step 4,
	// §8.11.4 rule 8): skipped actions are passed over, and a bracket stands
	// for the action before its enter-virtual. Its C is always carried.
	lookback Move
	bracket  *openBracket
}

// openBracket is a virtual bracket the walk is inside (§8.11).
type openBracket struct {
	entry Move // the enter-virtual; its c is the base position (rule 1)
	box   Box
	// game is the C of the last event inside the bracket, where the next
	// one starts (§8.11.5 step 2).
	game string
}

// position is the identity's position in cyberspace at this point of the
// walk: the base position inside a bracket (§8.11.4 rules 1 and 7), else the
// C of the nearest recognized action.
func (w *walk) position() Coord {
	p, _ := ParseCoord(w.carried) // every carried C was checked
	return p
}

// step checks one recognized action, or any action inside a bracket, and
// advances the walk past it. It returns the reason code and a detail when
// the event breaks a rule, or "" when the event is structurally valid.
func (w *walk) step(cur Move) (string, string) {
	for _, marker := range []string{"genesis", "previous"} {
		if n := countTags(cur.Event, "e", marker); n != 1 {
			return ReasonMalformed, fmt.Sprintf("e %s: expected exactly one, found %d", marker, n)
		}
	}
	if w.bracket != nil {
		return w.inside(cur)
	}
	return w.outside(cur)
}

// coords checks that the event has exactly one c and one C, each a 32-byte
// lowercase hex coordinate, and returns C decoded.
func coords(cur Move) (Coord, string, string) {
	if countTags(cur.Event, "c", "") != 1 || !isHex32(cur.From) {
		return Coord{}, ReasonMalformed, "c: expected exactly one 32-byte lowercase hex coordinate"
	}
	to, err := ParseCoord(cur.To)
	if countTags(cur.Event, "C", "") != 1 || err != nil {
		return Coord{}, ReasonMalformed, "C: expected exactly one 32-byte lowercase hex coordinate"
	}
	return to, "", ""
}

// inside checks an event inside an open bracket: a virtual action or the
// exit-virtual that closes it (§8.11.4, §8.11.5 steps 2 and 3).
func (w *walk) inside(cur Move) (string, string) {
	b := w.bracket
	if notInBracket[cur.Action] {
		return ReasonBaseActionInBracket, fmt.Sprintf("%s inside the bracket opened by %s (§8.11.4 rule 3)", cur.Action, b.entry.Event.ID)
	}
	to, reason, detail := coords(cur)
	if reason != "" {
		return reason, detail
	}
	if cur.Action == ActExitVirtual {
		if n := countTags(cur.Event, "e", "entry"); n != 1 {
			return ReasonMalformed, fmt.Sprintf("e entry: expected exactly one, found %d", n)
		}
		if cur.Entry != b.entry.Event.ID {
			return ReasonExitWrongEntry, fmt.Sprintf("e entry names %s, the open bracket is %s (§8.11.4 rule 6)", cur.Entry, b.entry.Event.ID)
		}
		// §8.11.3 defines the exit's c as the C of the previous event, the
		// last position inside the game. §8.11.5 step 3 does not list the
		// check; it is applied here as a rule, as the reference does.
		if cur.From != b.game {
			return ReasonCMismatch, "the exit's c is not the C of the previous event (§8.11.3)"
		}
		if cur.To != b.entry.From {
			return ReasonExitPosition, "the exit's C is not the c of its enter-virtual (§8.11.4 rule 2)"
		}
		// The base position is restored (rule 2), and it is carried
		// already. The look-back action is still the one before the entry,
		// which the exit stands for (rule 8).
		w.bracket = nil
		return "", ""
	}
	if cur.From != b.game {
		return ReasonCMismatch, "the virtual action's c is not the C of the previous event (§8.11.5 step 2)"
	}
	if !b.box.Contains(to) {
		return ReasonOutsideRegion, "the virtual action's C is outside the declared region (§8.11.4 rule 4)"
	}
	b.game = cur.To
	return "", ""
}

// outside checks a recognized action outside any bracket.
func (w *walk) outside(cur Move) (string, string) {
	if cur.Action == ActExitVirtual {
		return ReasonExitWithoutBracket, "no bracket is open (§8.11.4 rule 6)"
	}
	to, reason, detail := coords(cur)
	if reason != "" {
		return reason, detail
	}
	if cur.Action == ActEnterVirtual {
		box, why := parseRegion(cur.Event)
		if why != "" {
			return ReasonRegion, why + " (§8.11.1)"
		}
		// A check of form only: the game is never contacted (§8.11.5).
		if countTags(cur.Event, "p", "game") != 1 || !isHex32(cur.Game) {
			return ReasonGameTag, "expected exactly one p tag marked game holding a 32-byte lowercase hex pubkey (§8.11.1)"
		}
		if cur.From != w.carried {
			return ReasonCMismatch, "the entry's c is not the position the chain carries (§8.11.5 step 1)"
		}
		if !box.Contains(to) {
			return ReasonOutsideRegion, "the entry's C is outside the declared region (§8.11.4 rule 4)"
		}
		// The position is held at c (rule 1): carried and the look-back
		// action stay as they are until the exit.
		w.bracket = &openBracket{entry: cur, box: box, game: cur.To}
		return "", ""
	}
	if cur.From != w.carried {
		return ReasonCMismatch, "c is not the C of the nearest recognized action before it (§8.9 step 2)"
	}
	switch cur.Action {
	case ActEnterHyperspace:
		if cur.To != cur.From {
			return ReasonEnterHyperspaceMoved, "C is not c; boarding does not move the identity (DECK-0001 §3.1)"
		}
	case ActHyperjump:
		if reason, detail := ride(w.lookback, cur); reason != "" {
			return reason, detail
		}
	}
	w.carried, w.lookback = cur.To, cur
	return "", ""
}

// ride checks the rules of DECK-0001 §4.3 and §5.2 that read only tags: what
// a hyperjump looks back to, its heights, and where it departs from. The
// rules that need Bitcoin's block data (as_of is a height on the line,
// from_height is the station within as_of, C is the stop of B) and the ride's
// proof are the ProofChecker's.
func ride(look, cur Move) (string, string) {
	if look.Action != ActEnterHyperspace && look.Action != ActHyperjump {
		return ReasonHyperjumpPredecessor, fmt.Sprintf("the action before this ride is %s (DECK-0001 §4.3)", look.Action)
	}
	from, okFrom := firstDecimal(cur.Event, "from_height")
	to, okTo := firstDecimal(cur.Event, "B")
	if !okFrom || !okTo {
		return ReasonMalformed, "from_height and B: expected base-10 block heights (DECK-0001 §5.2)"
	}
	if look.Action == ActEnterHyperspace {
		// The first ride after boarding declares the station set bound,
		// and the bound is at least the destination (DECK-0001 §4.2).
		asOf, ok := firstDecimal(cur.Event, "as_of")
		if !ok || asOf.Cmp(to) < 0 {
			return ReasonHyperjumpAsOf, "the first ride needs an as_of of at least B (DECK-0001 §4.2, §4.3)"
		}
		return "", ""
	}
	prevB, _ := firstDecimal(look.Event, "B") // checked when that ride was walked
	if from.Cmp(prevB) != 0 {
		return ReasonHyperjumpFromHeight, fmt.Sprintf("from_height %s but the previous ride ended at %s (DECK-0001 §4.3)", from, prevB)
	}
	// B may equal from_height only on a first ride from the station
	// (DECK-0001 §5.2, §5.6), read literally.
	if from.Cmp(to) == 0 {
		return ReasonHyperjumpZeroLength, "only the first ride from the station may have from_height equal to B (DECK-0001 §5.2, §5.6)"
	}
	return "", ""
}

// firstDecimal reads the first tag named name as a base-10 height, which may
// carry leading zeros, as the reference reads it.
func firstDecimal(evt nostr.Event, name string) (*big.Int, bool) {
	vs := tagValues(evt, name)
	if len(vs) == 0 || !isDecimal(vs[0]) {
		return nil, false
	}
	n, ok := new(big.Int).SetString(vs[0], 10)
	return n, ok
}

// PendingSpec is the placeholder ProofChecker used until the chain
// verification rules are implemented here. It verifies no work proofs: every
// hop, sidestep, enter-hyperspace and hyperjump comes back ProofUnchecked.
//
// What this means for the gate: in "structural" mode an identity is placed at
// its chain head (signatures, links, coordinates, skipped actions, brackets
// and the ride rules that read only tags are checked; proofs are trusted); in
// "strict" mode it is placed at its last proof-verified position, which with
// this checker is its spawn point.
//
// Replace it with a checker implementing the rules of ChainRulesRevision:
// hop proofs (§8.7.1), sidestep Level 1 (§8.7.2) with the mn re-roll price
// and grandfathered-v2-sidesteps.txt (§6.16), entry proofs (DECK-0001 §3.2),
// and rides at Level 1 (DECK-0001 §5.5, §5.8) with the line's block data and
// grandfathered-v1-hyperjumps.txt.
type PendingSpec struct{}

// Check implements ProofChecker.
func (PendingSpec) Check(prev, cur Move) (ProofResult, string) {
	return ProofUnchecked, "awaiting the chain verification proof checker"
}
