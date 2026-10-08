package regiongate

import (
	"fmt"
	"sort"
	"strconv"

	nostr "github.com/0ceanslim/grain/server/types"
)

// KindMovement is the Cyberspace movement event kind (§8.1).
const KindMovement = 3333

// ChainRulesRevision names the chain rules this verifier implements (§8.12).
// A verifier states the revision it runs so that two verifiers that disagree
// about a chain can see whether they are running the same rules.
const ChainRulesRevision = "2026-09-28-virtual-brackets"

// Action names (§8.8, DECK-0001, §8.11).
const (
	ActSpawn           = "spawn"
	ActHop             = "hop"
	ActSidestep        = "sidestep"
	ActEnterHyperspace = "enter-hyperspace"
	ActHyperjump       = "hyperjump"
	ActEnterVirtual    = "enter-virtual"
	ActExitVirtual     = "exit-virtual"
)

// recognizedActions are the actions this verifier recognizes (§8.9): the base
// actions (§8.8) and the actions of every mandatory DECK, which at this
// revision is DECK-0001 alone (§8.12). This relay implements no optional
// DECK, so every other action name outside a virtual bracket is skipped.
var recognizedActions = map[string]bool{
	ActSpawn: true, ActHop: true, ActSidestep: true, ActEnterVirtual: true, ActExitVirtual: true,
	ActEnterHyperspace: true, ActHyperjump: true,
}

// notInBracket are the action names that make an event inside a virtual
// bracket invalid (§8.11.4 rule 3). Rule 3 names a category, not a list:
// every action of the base protocol or of a mandatory DECK is reserved inside
// a bracket. A spawn is never inside one (it starts a new chain, §3.2) and an
// exit-virtual closes it (rule 6), so the reserved names are the recognized
// actions less those two. A new mandatory DECK added to recognizedActions is
// reserved inside brackets with no further change. Every other name inside a
// bracket is a virtual action.
var notInBracket = func() map[string]bool {
	m := map[string]bool{}
	for a := range recognizedActions {
		if a != ActSpawn && a != ActExitVirtual {
			m[a] = true
		}
	}
	return m
}()

// Move is a movement event with its chain tags pulled out. Where a tag
// appears more than once, the first one is kept, which is the one chain
// resolution follows (§8.7.3); the verifier counts the tags it reads and
// rejects a repeated one. A tag with no value still counts as that tag: a
// bare ["A"] is an A tag whose value is "".
type Move struct {
	Event nostr.Event
	// Action is the first A tag's value.
	Action string
	// IsSpawn is true when any A tag is "spawn", wherever it stands: the
	// event is then a spawn for resolution and never a link (§3.2). A spawn
	// with a second A tag is a spawn, and an invalid one (§8.8).
	IsSpawn  bool
	Genesis  string // e ... "genesis"
	Previous string // e ... "previous"
	Entry    string // e ... "entry" (exit-virtual)
	From     string // c tag
	To       string // C tag
	Game     string // p ... "game" (enter-virtual, §8.11.1)
}

// ParseMove extracts the chain tags of a kind 3333 event. ok is false for any
// other kind. An event with no A tag is still a move: it can be a link of a
// chain (§8.7.3), and the verifier reports it under a-tag when it is (§8.8).
func ParseMove(evt nostr.Event) (m Move, ok bool) {
	if evt.Kind != KindMovement {
		return Move{}, false
	}
	m.Event = evt
	seen := map[string]bool{}
	first := func(key string) bool {
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	for _, t := range evt.Tags {
		if len(t) == 0 {
			continue
		}
		v := tagValue(t)
		switch t[0] {
		case "A":
			if v == ActSpawn {
				m.IsSpawn = true
			}
			if first("A") {
				m.Action = v
			}
		case "c":
			if first("c") {
				m.From = v
			}
		case "C":
			if first("C") {
				m.To = v
			}
		case "p":
			if len(t) >= 4 && t[3] == "game" && first("p game") {
				m.Game = v
			}
		case "e":
			if len(t) < 4 || !first("e "+t[3]) {
				continue
			}
			switch t[3] {
			case "genesis":
				m.Genesis = v
			case "previous":
				m.Previous = v
			case "entry":
				m.Entry = v
			}
		}
	}
	return m, true
}

// tagValue is a tag's value, its second element, or "" when it has none.
func tagValue(t []string) string {
	if len(t) < 2 {
		return ""
	}
	return t[1]
}

// tagValues returns the value of every tag named name, "" for a tag with no
// value, which still counts as that tag.
func tagValues(evt nostr.Event, name string) []string {
	var out []string
	for _, t := range evt.Tags {
		if len(t) >= 1 && t[0] == name {
			out = append(out, tagValue(t))
		}
	}
	return out
}

// countTags counts the tags named name, a tag with no value included; with
// a marker, only those whose fourth element is that marker (["e", id,
// relay, marker], ["p", pubkey, relay, marker]).
func countTags(evt nostr.Event, name, marker string) int {
	n := 0
	for _, t := range evt.Tags {
		if len(t) >= 1 && t[0] == name && (marker == "" || len(t) >= 4 && t[3] == marker) {
			n++
		}
	}
	return n
}

// Resolution is a pubkey's events resolved by §8.7.3.
type Resolution struct {
	// Chain is the active chain from the spawn. At a fork it stops at the
	// event the branches name.
	Chain []Move
	// ForkedFrom is the id of the event on the walk that two or more chain
	// events name as previous, or "". Fork lists those events' ids, sorted.
	ForkedFrom string
	Fork       []string
}

// ActiveChain resolves a pubkey's movement events into its active chain;
// see Resolve.
func ActiveChain(pubkey string, events []nostr.Event) []Move {
	return Resolve(pubkey, events).Chain
}

// Resolve resolves a pubkey's movement events by the rule every reader must
// apply (§8.7.3):
//  1. start at the newest spawn (largest created_at; larger id on a tie),
//     whether or not it is valid; there is no fallback to an older spawn.
//     An event is a spawn when any of its A tags is "spawn";
//  2. keep only events whose genesis names that spawn: the chain events;
//  3. follow previous links forward;
//  4. a fork, two or more chain events naming the current event as previous,
//     makes the whole chain dead (arkinox, 2026-10-08), whichever branch is
//     valid or signed first; resolution stops at that event;
//  5. stop at the first event nothing names as previous.
//
// Resolution reads links, created_at and ids only, never a proof or a tag
// the chain rules check, so it comes before validity. The caller must
// already have discarded every event that is not authentic (Verifier.Verify
// does): a discarded event never existed, so it is never a branch of a fork,
// an event naming it as previous is never reached, and the chain ends at the
// event before it. Events the walk never reaches, behind a discarded event
// or naming an id nobody holds, cannot make a fork. Events by other pubkeys,
// other kinds and repeated ids are ignored. A spawn names no previous event, so it is never a link. The
// first copy of each e tag is the one followed. Chain is nil when there is
// no spawn.
func Resolve(pubkey string, events []nostr.Event) Resolution {
	var moves []Move
	seen := map[string]bool{}
	for _, evt := range events {
		if evt.PubKey != pubkey || seen[evt.ID] {
			continue
		}
		m, ok := ParseMove(evt)
		if !ok {
			continue
		}
		seen[evt.ID] = true
		moves = append(moves, m)
	}
	var spawn *Move
	for i := range moves {
		if m := &moves[i]; m.IsSpawn && (spawn == nil || newer(m.Event, spawn.Event)) {
			spawn = m
		}
	}
	if spawn == nil {
		return Resolution{}
	}
	children := map[string][]Move{}
	for _, m := range moves {
		if m.IsSpawn || m.Genesis != spawn.Event.ID || m.Previous == "" {
			continue
		}
		children[m.Previous] = append(children[m.Previous], m)
	}
	var r Resolution
	forked := func(id string) {
		r.ForkedFrom = id
		for _, m := range children[id] {
			r.Fork = append(r.Fork, m.Event.ID)
		}
		sort.Strings(r.Fork)
	}
	r.Chain = []Move{*spawn}
	for cur := spawn.Event.ID; ; {
		next := children[cur]
		if len(next) > 1 {
			forked(cur)
			return r
		}
		if len(next) == 0 || len(r.Chain) > len(moves) { // a cycle cannot happen with real ids; guard anyway
			break
		}
		r.Chain = append(r.Chain, next[0])
		cur = next[0].Event.ID
	}
	return r
}

func newer(a, b nostr.Event) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt > b.CreatedAt
	}
	return a.ID > b.ID
}

// parseRegion reads an enter-virtual's region (§8.11.1): exactly one
// ["region", coord_hex, H] tag, H a decimal in [0, 85] written with no sign
// and no leading zeros except "0", and coord_hex the cube's aligned base (the
// low H bits of each axis zero). It returns the cube, or "" and why not.
func parseRegion(evt nostr.Event) (Box, string) {
	var tag []string
	n := 0
	for _, t := range evt.Tags {
		if len(t) >= 1 && t[0] == "region" {
			tag = t
			n++
		}
	}
	if n != 1 {
		return Box{}, fmt.Sprintf("expected exactly one region tag, found %d", n)
	}
	if len(tag) < 3 {
		return Box{}, "region tag has no height"
	}
	base, err := ParseCoord(tag[1])
	if err != nil {
		return Box{}, "region base: " + err.Error()
	}
	hs := tag[2]
	if !isDecimal(hs) || (len(hs) > 1 && hs[0] == '0') {
		return Box{}, fmt.Sprintf("region height %q is not a canonical decimal", hs)
	}
	h, err := strconv.Atoi(hs)
	if err != nil || h > AxisBits {
		return Box{}, fmt.Sprintf("region height %s is above %d", hs, AxisBits)
	}
	b, err := NewBox(base, uint(h), uint(h), uint(h))
	if err != nil {
		return Box{}, "region base is not aligned to its height"
	}
	return b, ""
}

// sectorTagsOK reports whether evt carries each of the sector tags X, Y, Z
// and S exactly once, equal to the values computed from C (§10): base-10
// with no sign and no leading zeros, and S as "<sx>-<sy>-<sz>". Comparing
// with the computed strings checks the format and the values at once. A
// sector tag missing, repeated or wrong makes a base or mandatory DECK action
// invalid; virtual actions and skipped actions are not checked (§10).
func sectorTagsOK(evt nostr.Event, C Coord) bool {
	sx, sy, sz := C.Sector()
	want := map[string]string{"X": sx, "Y": sy, "Z": sz, "S": sx + "-" + sy + "-" + sz}
	for name, value := range want {
		vs := tagValues(evt, name)
		if len(vs) != 1 || vs[0] != value {
			return false
		}
	}
	return true
}

// isDecimal reports whether s is one or more ASCII digits.
func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isHex32 reports whether s is 32 bytes of lowercase hex, the form of a
// coordinate, an event id and a pubkey.
func isHex32(s string) bool { return isHexLen(s, 64) }

// isHexLen reports whether s is n lowercase hex characters.
func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
