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
	ReasonFork                 = "fork"
	ReasonATag                 = "a-tag"
	ReasonMalformed            = "malformed"
	ReasonSectorTags           = "sector-tags"
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
	ReasonEnterVirtualMoved    = "enter-virtual-moved"
	ReasonRegion               = "region"
	ReasonGameTag              = "game-tag"
	ReasonBaseActionInBracket  = "base-action-in-bracket"
	ReasonExitWithoutBracket   = "exit-without-bracket"
	ReasonExitWrongEntry       = "exit-wrong-entry"
	ReasonExitPosition         = "exit-position"
)

// Reasons maps every reason code to the rule it names.
var Reasons = map[string]string{
	ReasonNoSpawn:              "no authentic spawn event for this pubkey, so there is no chain (§8.7.3 rule 1)",
	ReasonFork:                 "two or more events whose e genesis names the newest spawn name the same event as e previous (each event's first e previous tag), where the walk from the spawn reaches it; the chain is invalid from the spawn, and the identity stands at its spawn coordinate (§8.7.3)",
	ReasonATag:                 "the event carries no A tag, more than one, or one with no value (§8.8)",
	ReasonMalformed:            "a tag a chain rule reads is missing, repeated, valueless or ill-formed: e genesis and e previous on every event but the spawn, e entry on an exit, C on every recognized action, c on every recognized action but the exit, proof on a proof-bearing action, mr, mp, hx, hy and hz on a sidestep, from_height, B and mp on a ride, as_of on the first ride when present; mn may be absent on a sidestep or ride but not repeated",
	ReasonSectorTags:           "a recognized action's X, Y, Z or S tag is missing, repeated, or not the value computed from its C (§10)",
	ReasonSpawnCoordinate:      "the spawn's C is not its pubkey (§8.3)",
	ReasonCMismatch:            "c is not the C of the nearest recognized action before it (§8.9 item 2, continuity)",
	ReasonHopProof:             "the hop's proof does not verify (§8.7.1)",
	ReasonSidestepProof:        "the sidestep does not verify at Level 1 (§8.7.2)",
	ReasonEnterHyperspaceMoved: "an enter-hyperspace's C is not its c (DECK-0001 §3.1)",
	ReasonEnterHyperspaceProof: "the entry proof does not verify (DECK-0001 §3.2)",
	ReasonHyperjumpPredecessor: "the action a hyperjump looks back to is neither enter-hyperspace nor hyperjump (DECK-0001 §4.3)",
	ReasonHyperjumpAsOf:        "the first ride after boarding has no as_of tag, or as_of is not a height on the line, or is below B (DECK-0001 §4.2, §4.3)",
	ReasonHyperjumpStation:     "the first ride after boarding does not depart from the station (DECK-0001 §4.2, §4.3)",
	ReasonHyperjumpFromHeight:  "a later ride does not depart from the previous ride's B (DECK-0001 §4.3)",
	ReasonHyperjumpZeroLength:  "a ride whose B equals its from_height; there is no zero-length ride (DECK-0001 §5.2, §5.6)",
	ReasonHyperjumpStop:        "the ride's C is not the stop coordinate of B, or B is not a height on the line (DECK-0001 §5.5 Level 1 step 2)",
	ReasonHyperjumpProof:       "the ride's proof does not verify at Level 1 (DECK-0001 §5.5, §5.8)",
	ReasonEnterVirtualMoved:    "an enter-virtual's C is not its c; entering a game does not move the identity (§8.11.1)",
	ReasonRegion:               "the enter-virtual's region tag is missing, repeated or ill-formed: H not canonical in [0, 85], or the base not aligned (§8.11.1)",
	ReasonGameTag:              "the enter-virtual does not carry exactly one p tag marked game holding a 32-byte lowercase hex pubkey (§8.11.1)",
	ReasonBaseActionInBracket:  "an action of the base protocol or of a mandatory DECK inside an open bracket (§8.11.4 rule 3)",
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
	// Position is where the identity stands, valid chain or not. For a valid
	// chain it is the C of the last recognized action (§8.9 item 5), or,
	// inside an open bracket, the bracket's base position (§8.11.4 rules 1
	// and 7). For an invalid chain it is the last valid position (§3.2,
	// §8.7.3): the position the chain gives the identity if it ended at the
	// last valid event before InvalidAt. The chain is frozen there: nothing
	// published after the invalid event can move the identity, and only a
	// respawn starts a chain that can be valid again. When the spawn itself
	// is invalid there is no valid event, and the identity stands at its
	// spawn coordinate, the coordinate of its pubkey (§3.2, §8.7.3 rule 1).
	Position *Coord
	// PositionEvent is the id of the last event the walk accepted that is
	// not a skipped action, or "" when the spawn itself is invalid.
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
	// Fork lists the ids of the chain events that name the same previous
	// event, the last event of Chain, when the chain is dead by a fork.
	Fork []string
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
	// Authentic events only (§8.7.3): every event that is not a valid NIP-01
	// event by this pubkey is discarded before resolution and treated as if
	// it never existed. Nobody can end another identity's chain with a
	// forged spawn or a forged "older" branch, and a branch through a
	// discarded event is cut off, ending the chain at the event before it.
	// Signature is validation.CheckSignature in production, which checks the
	// id hash and the sig; there is no unsigned local chain (§8.2).
	signed := events[:0:0]
	for _, e := range events {
		if e.PubKey == pubkey && e.Kind == KindMovement && (v.Signature == nil || v.Signature(e)) {
			signed = append(signed, e)
		}
	}
	res := Resolve(pubkey, signed)
	chain := res.Chain
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

	// The identity's spawn coordinate, where a dead chain leaves it.
	atSpawn := func() {
		if at, err := ParseCoord(pubkey); err == nil {
			verified := at
			vd.Position, vd.VerifiedPosition = &at, &verified
		}
	}
	// A fork kills the whole chain, whichever branch is valid or signed
	// first (arkinox, 2026-10-08). Resolution finds it before any validity
	// is checked, and the identity stands at its spawn coordinate until it
	// respawns. Only authentic events reach Resolve, so a forged event is
	// never a branch.
	if res.ForkedFrom != "" {
		atSpawn()
		// As the reference reports it: the chain runs from the spawn to the
		// event the branches name, and it is invalid from the spawn.
		vd.Reason, vd.InvalidAt, vd.InvalidIndex, vd.Fork = ReasonFork, chain[0].Event.ID, 0, res.Fork
		vd.Stopped = fmt.Sprintf("fork: %d chain events name %s as previous (%s)", len(res.Fork), res.ForkedFrom, strings.Join(res.Fork, ", "))
		return vd
	}

	spawn := chain[0]
	if reason, detail := checkSpawn(spawn, pubkey); reason != "" {
		// The newest spawn wins even when it is invalid, with no fallback
		// to an older spawn (§3.2, §8.7.3 rule 1). The identity stands at
		// its spawn coordinate, the coordinate of its pubkey, frozen until
		// it publishes another spawn. That position rests on no proof, so
		// it is also the proof-verified one.
		atSpawn()
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
		// Exactly one A tag, with a value, on every event: recognized,
		// skipped, or inside a bracket (§8.8).
		if n := countTags(cur.Event, "A", ""); n != 1 || cur.Action == "" {
			return invalid(i, ReasonATag, fmt.Sprintf("expected exactly one A tag with a value, found %d", n))
		}
		// Exactly one e genesis and one e previous on every event but the
		// spawn: recognized, skipped or virtual (arkinox, 2026-10-08).
		if reason, detail := links(cur); reason != "" {
			return invalid(i, reason, detail)
		}
		if w.bracket == nil && !recognizedActions[cur.Action] {
			// §8.9: an action this verifier does not recognize is skipped.
			// It is checked for being authentic (discarded above otherwise),
			// linked (resolution reached it) and carrying one A tag, and for
			// nothing else: its other tags, proofs and sector tags belong to
			// its DECK. It neither moves the identity (item 2) nor stands
			// before the next action for rules that look back (item 4), so
			// the walk leaves its state untouched. Its id still seeds the
			// work of the action after it, which the checker reads from that
			// action's e previous tag (item 3).
			vd.Skipped = append(vd.Skipped, cur.Event.ID)
			continue
		}
		prev := w.lookback
		if reason, detail := w.step(cur); reason != "" {
			return invalid(i, reason, detail)
		}

		// Only base and DECK-0001 actions outside a bracket carry a work
		// proof; brackets and virtual actions carry none (§8.11.2), and a
		// proof-bearing action inside a bracket was refused by step, which
		// has also checked the form of its proof tags.
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

// checkSpawn checks the first event of the active chain: exactly one A tag
// (§8.8), exactly one C, which is the pubkey (§8.3), and the sector tags
// computed from it (§8.3, §10).
func checkSpawn(spawn Move, pubkey string) (string, string) {
	if n := countTags(spawn.Event, "A", ""); n != 1 {
		return ReasonATag, fmt.Sprintf("expected exactly one A tag with a value, found %d", n)
	}
	C, err := ParseCoord(spawn.To)
	if countTags(spawn.Event, "C", "") != 1 || err != nil {
		return ReasonMalformed, "C: expected exactly one 32-byte lowercase hex coordinate"
	}
	if spawn.To != pubkey {
		return ReasonSpawnCoordinate, "the spawn's C is not its pubkey (§8.3)"
	}
	if !sectorTagsOK(spawn.Event, C) {
		return ReasonSectorTags, "the spawn's sector tags are not X, Y, Z and S once each, computed from C (§8.3, §10)"
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

// openBracket is a virtual bracket the walk is inside (§8.11). The bracket
// is opaque (§8.11.4 rule 4): the walk keeps nothing about the game, only
// the entry, whose c (which its C repeats) is the base position (rule 1).
type openBracket struct {
	entry Move
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
// the event breaks a rule, or "" when the event is valid as far as the
// verifier itself can tell (the checker is asked about proofs afterwards).
func (w *walk) step(cur Move) (string, string) {
	if w.bracket != nil {
		return w.inside(cur)
	}
	return w.outside(cur)
}

// links checks that a chain event, recognized, skipped or virtual, carries
// exactly one e genesis and one e previous tag (arkinox, 2026-10-08), each
// holding an event id. Resolution has already followed the first of each.
func links(cur Move) (string, string) {
	for _, marker := range []string{"genesis", "previous"} {
		if n := countTags(cur.Event, "e", marker); n != 1 {
			return ReasonMalformed, fmt.Sprintf("e %s: expected exactly one, found %d", marker, n)
		}
	}
	if !isHex32(cur.Genesis) || !isHex32(cur.Previous) {
		return ReasonMalformed, "e genesis and e previous: expected 32-byte lowercase hex event ids"
	}
	return "", ""
}

// coord checks that the event carries exactly one tag named name ("c" or
// "C") holding a 32-byte lowercase hex coordinate, and returns it decoded.
func coord(cur Move, name, value string) (Coord, string, string) {
	c, err := ParseCoord(value)
	if countTags(cur.Event, name, "") != 1 || err != nil {
		return Coord{}, ReasonMalformed, name + ": expected exactly one 32-byte lowercase hex coordinate"
	}
	return c, "", ""
}

// inside checks an event inside an open bracket (§8.11.4, §8.11.5 steps 2
// and 3). The bracket is opaque: a virtual action is checked only for being
// linked (resolution reached it), carrying one A tag (checked by the caller)
// and not using a reserved name (rule 3). Its c, C and sector tags are the
// game's and are neither required nor checked (rule 4).
func (w *walk) inside(cur Move) (string, string) {
	b := w.bracket
	if notInBracket[cur.Action] {
		return ReasonBaseActionInBracket, fmt.Sprintf("%s inside the bracket opened by %s (§8.11.4 rule 3)", cur.Action, b.entry.Event.ID)
	}
	if cur.Action != ActExitVirtual {
		return "", ""
	}
	// The exit-virtual (§8.11.5 step 3): its entry, its C and its sector
	// tags. Its c is optional and never read, so no c, a garbled c or two c
	// tags leave it valid (§8.11.3, rule 4).
	if n := countTags(cur.Event, "e", "entry"); n != 1 {
		return ReasonMalformed, fmt.Sprintf("e entry: expected exactly one, found %d", n)
	}
	if cur.Entry != b.entry.Event.ID {
		return ReasonExitWrongEntry, fmt.Sprintf("e entry names %s, the open bracket is %s (§8.11.4 rule 6)", cur.Entry, b.entry.Event.ID)
	}
	to, reason, detail := coord(cur, "C", cur.To)
	if reason != "" {
		return reason, detail
	}
	if cur.To != b.entry.From {
		return ReasonExitPosition, "the exit's C is not the c of its enter-virtual (§8.11.4 rule 2)"
	}
	if !sectorTagsOK(cur.Event, to) {
		return ReasonSectorTags, "the exit's sector tags are not X, Y, Z and S once each, computed from C (§8.11.3, §10)"
	}
	// The base position is restored (rule 2) and continuity resumes from
	// it; it is carried already. The look-back action is still the one
	// before the entry, which the exit stands for (rule 8).
	w.bracket = nil
	return "", ""
}

// outside checks a recognized action outside any bracket.
func (w *walk) outside(cur Move) (string, string) {
	if cur.Action == ActExitVirtual {
		return ReasonExitWithoutBracket, "no bracket is open (§8.11.4 rule 6)"
	}
	if _, reason, detail := coord(cur, "c", cur.From); reason != "" {
		return reason, detail
	}
	to, reason, detail := coord(cur, "C", cur.To)
	if reason != "" {
		return reason, detail
	}
	// Continuity (§8.9 item 2), the enter-virtual included (§8.11.5 step 1).
	if cur.From != w.carried {
		return ReasonCMismatch, "c is not the C of the nearest recognized action before it (§8.9 item 2)"
	}
	if !sectorTagsOK(cur.Event, to) {
		return ReasonSectorTags, "sector tags are not X, Y, Z and S once each, computed from C (§10)"
	}
	switch cur.Action {
	case ActEnterVirtual:
		// Entering a game does not move the identity (§8.11.1).
		if cur.To != cur.From {
			return ReasonEnterVirtualMoved, "C is not c; entering a game does not move the identity (§8.11.1)"
		}
		// The region and the game are checked for form only. Nothing has
		// to lie inside the region, the base position included: a game may
		// be declared anywhere, and proximity is the game's to enforce
		// (§8.11.1, §8.11.5).
		if _, why := parseRegion(cur.Event); why != "" {
			return ReasonRegion, why + " (§8.11.1)"
		}
		if countTags(cur.Event, "p", "game") != 1 || !isHex32(cur.Game) {
			return ReasonGameTag, "expected exactly one p tag marked game holding a 32-byte lowercase hex pubkey (§8.11.1)"
		}
		// The position is held at c (rule 1): carried and the look-back
		// action stay as they are until the exit.
		w.bracket = &openBracket{entry: cur}
		return "", ""
	case ActHop:
		if why := proofTags(cur); why != "" {
			return ReasonMalformed, why
		}
	case ActSidestep:
		if why := proofTags(cur); why != "" {
			return ReasonMalformed, why
		}
	case ActEnterHyperspace:
		if cur.To != cur.From {
			return ReasonEnterHyperspaceMoved, "C is not c; boarding does not move the identity (DECK-0001 §3.1)"
		}
		if why := proofTags(cur); why != "" {
			return ReasonMalformed, why
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
	from, okFrom := onlyDecimal(cur.Event, "from_height")
	to, okTo := onlyDecimal(cur.Event, "B")
	if !okFrom || !okTo {
		return ReasonMalformed, "from_height and B: expected exactly one each, a base-10 block height (DECK-0001 §5.2)"
	}
	// There is no zero-length ride, the first ride after boarding included,
	// and no ride is exempt from this (DECK-0001 §5.2, §5.6, §5.8). It comes
	// before the proof tags, which a zero-length ride cannot carry in a
	// verifiable form.
	if from.Cmp(to) == 0 {
		return ReasonHyperjumpZeroLength, "B equals from_height; every ride passes at least one block (DECK-0001 §5.6)"
	}
	if why := proofTags(cur); why != "" {
		return ReasonMalformed, why
	}
	if look.Action != ActEnterHyperspace && look.Action != ActHyperjump {
		return ReasonHyperjumpPredecessor, fmt.Sprintf("the action before this ride is %s (DECK-0001 §4.3)", look.Action)
	}
	if look.Action == ActEnterHyperspace {
		// The first ride after boarding declares the station set bound,
		// and the bound is at least the destination (DECK-0001 §4.2).
		// as_of is read on the first ride after boarding only. Missing, it
		// breaks DECK-0001 §4.2; present, it appears once as a height.
		if countTags(cur.Event, "as_of", "") == 0 {
			return ReasonHyperjumpAsOf, "the first ride after boarding carries no as_of (DECK-0001 §4.2)"
		}
		asOf, ok := onlyDecimal(cur.Event, "as_of")
		if !ok {
			return ReasonMalformed, "as_of: expected exactly once with a base-10 height"
		}
		if asOf.Cmp(to) < 0 {
			return ReasonHyperjumpAsOf, "as_of must be at least B (DECK-0001 §4.2, §4.3)"
		}
		return "", ""
	}
	prevB, _ := onlyDecimal(look.Event, "B") // checked when that ride was walked
	if from.Cmp(prevB) != 0 {
		return ReasonHyperjumpFromHeight, fmt.Sprintf("from_height %s but the previous ride ended at %s (DECK-0001 §4.3)", from, prevB)
	}
	return "", ""
}

// proofTags checks the form of a proof-bearing action's proof tags, which
// a chain rule reads, so each appears exactly once with a well-formed value
// (arkinox, 2026-10-08): proof (32 bytes of lowercase hex) on every one; mr
// (three colon-joined 32-byte roots), mp (a value), hx, hy and hz (base-10)
// on a sidestep (§8.5); mp on a ride (DECK-0001 §5.2). mn, on a sidestep or
// a ride, may be absent, because the exemption lists name events with none
// (§6.16, DECK-0001 §5.8), but not repeated, and it is 16 lowercase hex
// characters. Whether the values verify is the proof checker's. It returns
// why not, or "".
func proofTags(cur Move) string {
	type tagForm struct {
		name string
		form func(string) bool
	}
	nonEmpty := func(v string) bool { return v != "" }
	forms := []tagForm{{"proof", isHex32}}
	switch cur.Action {
	case ActSidestep:
		forms = append(forms, tagForm{"mr", isRoots}, tagForm{"mp", nonEmpty},
			tagForm{"hx", isDecimal}, tagForm{"hy", isDecimal}, tagForm{"hz", isDecimal})
	case ActHyperjump:
		forms = append(forms, tagForm{"mp", nonEmpty})
	}
	for _, f := range forms {
		if vs := tagValues(cur.Event, f.name); len(vs) != 1 || !f.form(vs[0]) {
			return f.name + ": expected exactly once with a well-formed value"
		}
	}
	if cur.Action == ActSidestep || cur.Action == ActHyperjump {
		if vs := tagValues(cur.Event, "mn"); len(vs) > 1 || len(vs) == 1 && !isHexLen(vs[0], 16) {
			return "mn: expected at most once, 16 lowercase hex characters"
		}
	}
	return ""
}

// isRoots reports whether s is three 32-byte lowercase hex roots joined by
// colons, the form of a sidestep's mr tag (§8.5).
func isRoots(s string) bool {
	parts := strings.Split(s, ":")
	return len(parts) == 3 && isHex32(parts[0]) && isHex32(parts[1]) && isHex32(parts[2])
}

// onlyDecimal reads the one tag named name as a base-10 height, which may
// carry leading zeros, as the reference reads it. A missing tag, a repeated
// one or a value that is not decimal gives false.
func onlyDecimal(evt nostr.Event, name string) (*big.Int, bool) {
	vs := tagValues(evt, name)
	if len(vs) != 1 || !isDecimal(vs[0]) {
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
