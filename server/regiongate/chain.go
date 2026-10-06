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
// bracket invalid (§8.11.4 rule 3). Every other name inside a bracket is a
// virtual action.
var notInBracket = map[string]bool{
	ActHop: true, ActSidestep: true, ActEnterHyperspace: true, ActHyperjump: true, ActEnterVirtual: true,
}

// Move is a movement event with its chain tags pulled out. Where a tag
// appears more than once, the first one is kept, which is the one chain
// resolution follows (§8.7.3); the verifier counts the tags it reads and
// rejects a repeated one as malformed.
type Move struct {
	Event    nostr.Event
	Action   string // A tag
	Genesis  string // e ... "genesis"
	Previous string // e ... "previous"
	Entry    string // e ... "entry" (exit-virtual)
	From     string // c tag
	To       string // C tag
	Game     string // p ... "game" (enter-virtual, §8.11.1)
}

// ParseMove extracts the chain tags of a kind 3333 event. ok is false for any
// other kind. An event with no A tag is still a move: it can be a link of a
// chain (§8.7.3), and the verifier reports it as malformed when it is.
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
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "A":
			if first("A") {
				m.Action = t[1]
			}
		case "c":
			if first("c") {
				m.From = t[1]
			}
		case "C":
			if first("C") {
				m.To = t[1]
			}
		case "p":
			if len(t) >= 4 && t[3] == "game" && first("p game") {
				m.Game = t[1]
			}
		case "e":
			if len(t) < 4 || !first("e "+t[3]) {
				continue
			}
			switch t[3] {
			case "genesis":
				m.Genesis = t[1]
			case "previous":
				m.Previous = t[1]
			case "entry":
				m.Entry = t[1]
			}
		}
	}
	return m, true
}

// tagValues returns the second element of every tag named name.
func tagValues(evt nostr.Event, name string) []string {
	var out []string
	for _, t := range evt.Tags {
		if len(t) >= 2 && t[0] == name {
			out = append(out, t[1])
		}
	}
	return out
}

// countTags counts the tags named name; with a marker, only those whose
// fourth element is that marker (["e", id, relay, marker], ["p", pubkey,
// relay, marker]).
func countTags(evt nostr.Event, name, marker string) int {
	n := 0
	for _, t := range evt.Tags {
		if len(t) >= 2 && t[0] == name && (marker == "" || len(t) >= 4 && t[3] == marker) {
			n++
		}
	}
	return n
}

// ActiveChain resolves a pubkey's movement events into its active chain, from
// spawn to head, by the rule every reader must apply (§8.7.3):
//  1. start at the newest spawn (largest created_at; larger id on a tie);
//  2. keep only events whose genesis names that spawn;
//  3. follow previous links forward;
//  4. at a fork the smallest created_at continues (smaller id on a tie);
//  5. stop at the first event nothing names as previous.
//
// Events by other pubkeys are ignored. An event whose A is spawn is never a
// link: a spawn names no previous event, so it starts a chain of its own
// wherever it is published (§3.2). It returns nil when there is no spawn.
func ActiveChain(pubkey string, events []nostr.Event) []Move {
	var spawn *Move
	children := map[string][]Move{}
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
	for i := range moves {
		m := &moves[i]
		if m.Action != ActSpawn {
			continue
		}
		if spawn == nil || newer(m.Event, spawn.Event) {
			spawn = m
		}
	}
	if spawn == nil {
		return nil
	}
	for _, m := range moves {
		if m.Action == ActSpawn || m.Genesis != spawn.Event.ID || m.Previous == "" {
			continue
		}
		children[m.Previous] = append(children[m.Previous], m)
	}
	chain := []Move{*spawn}
	for cur := spawn.Event.ID; ; {
		next := children[cur]
		if len(next) == 0 {
			return chain
		}
		sort.Slice(next, func(i, j int) bool { return older(next[i].Event, next[j].Event) })
		chain = append(chain, next[0])
		cur = next[0].Event.ID
		if len(chain) > len(moves) { // a cycle cannot happen with real ids; guard anyway
			return chain
		}
	}
}

func newer(a, b nostr.Event) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt > b.CreatedAt
	}
	return a.ID > b.ID
}

func older(a, b nostr.Event) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	return a.ID < b.ID
}

// parseRegion reads an enter-virtual's region (§8.11.1): exactly one
// ["region", coord_hex, H] tag, H a decimal in [0, 85] written with no sign
// and no leading zeros except "0", and coord_hex the cube's aligned base (the
// low H bits of each axis zero). It returns the cube, or "" and why not.
func parseRegion(evt nostr.Event) (Box, string) {
	var tag []string
	n := 0
	for _, t := range evt.Tags {
		if len(t) >= 2 && t[0] == "region" {
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
func isHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
