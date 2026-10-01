package regiongate

import (
	"sort"
	"strconv"

	nostr "github.com/0ceanslim/grain/server/types"
)

// KindMovement is the Cyberspace movement event kind (§8.1).
const KindMovement = 3333

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

// baseActions may not appear inside a virtual bracket (§8.11.4 rule 3).
var baseActions = map[string]bool{
	ActHop: true, ActSidestep: true, ActEnterHyperspace: true, ActHyperjump: true, ActEnterVirtual: true,
}

// Move is a movement event with its chain tags pulled out.
type Move struct {
	Event    nostr.Event
	Action   string // A tag
	Genesis  string // e ... "genesis"
	Previous string // e ... "previous"
	Entry    string // e ... "entry" (exit-virtual)
	From     string // c tag
	To       string // C tag
	Region   []string
}

// ParseMove extracts the chain tags of a kind 3333 event. ok is false for any
// other kind or an event with no A tag.
func ParseMove(evt nostr.Event) (m Move, ok bool) {
	if evt.Kind != KindMovement {
		return Move{}, false
	}
	m.Event = evt
	for _, t := range evt.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "A":
			m.Action = t[1]
		case "c":
			m.From = t[1]
		case "C":
			m.To = t[1]
		case "region":
			m.Region = t[1:]
		case "e":
			if len(t) >= 4 {
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
	}
	return m, m.Action != ""
}

// ActiveChain resolves a pubkey's movement events into its active chain, from
// spawn to head, by the rule every reader must apply (§8.7.3):
//  1. start at the newest spawn (largest created_at; larger id on a tie);
//  2. keep only events whose genesis names that spawn;
//  3. follow previous links forward;
//  4. at a fork the smallest created_at continues (smaller id on a tie);
//  5. stop at the first event nothing names as previous.
//
// Events by other pubkeys are ignored. It returns nil when there is no spawn.
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

// parseRegion reads a bracket's ["region", coord_hex, H] tag (§8.11.1): an
// aligned cube, H canonical decimal in [0, 85].
func parseRegion(tag []string) (Box, bool) {
	if len(tag) < 2 {
		return Box{}, false
	}
	hs := tag[1]
	if hs == "" || (len(hs) > 1 && hs[0] == '0') {
		return Box{}, false
	}
	h, err := strconv.Atoi(hs)
	if err != nil || h < 0 || h > AxisBits {
		return Box{}, false
	}
	base, err := ParseCoord(tag[0])
	if err != nil {
		return Box{}, false
	}
	b, err := NewBox(base, uint(h), uint(h), uint(h))
	return b, err == nil
}
