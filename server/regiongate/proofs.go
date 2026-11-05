package regiongate

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// SpecProofs is the ProofChecker of the chain rules of ChainRulesRevision:
// every work proof checked at Level 1, as cyberspace_core.chain checks it
// (arkin0x/cyberspace-cli 5103c62).
//
//   - hop: version 2, residue openings (§5.11, §8.7.1); a version 1 hop only
//     when its id is listed (§5.13);
//   - sidestep: Level 1 with the re-roll price (§6.10, §6.11, §8.7.2); one
//     without mn only when listed (§6.16);
//   - enter-hyperspace: the entry proof (DECK-0001 §3.2);
//   - hyperjump: as_of on the line, the station, the stop of B and Level 1
//     of the ride's openings (DECK-0001 §4.2, §4.3, §5.5); one without mn
//     only when listed (DECK-0001 §5.8).
//
// Two things leave a proof unchecked rather than judged: a ride when the Line
// does not yet hold a height it needs (or there is no Line), and a hop
// taller than MaxHopHeight that passes its form and price (the reference
// raises in both cases, since no verdict can be reached without the data or
// the work).
type SpecProofs struct {
	// Line supplies the block data rides are checked against. Nil leaves
	// every ride unchecked.
	Line Line
	// MaxHopHeight is the tallest h_max verified; 0 means DefaultMaxHopHeight.
	MaxHopHeight int
	// ListedV1Hops replaces grandfathered-v1-hops.txt when non-nil, as the
	// golden vectors do with their own test list.
	ListedV1Hops map[string]bool
	// Progress, when set, keeps the residues of tall hops whose check was
	// cut short (see HopProgress).
	Progress *HopProgress
	// RideProgress, when set, keeps the finished leaves of rides whose
	// check was cut short (see RideProgress).
	RideProgress *RideProgress
}

// HopProgress keeps, by event id, the residues of hops whose check its
// deadline cut short, so the next check of the same hop computes only the
// rest: a hop costlier than one deadline is paid for once across retries.
// A residue is hop_n mod p_j, fixed by the hop's c, C and e previous, which
// the event id commits to. It is a checkpoint, never a verdict: an entry is
// dropped once its hop is judged, and the oldest go first past max.
type HopProgress struct {
	mu    sync.Mutex
	max   int
	byID  map[string]map[uint64]uint64
	order []string
}

// NewHopProgress keeps the residues of at most max hops.
func NewHopProgress(max int) *HopProgress {
	return &HopProgress{max: max, byID: map[string]map[uint64]uint64{}}
}

// hopResidues is one hop's view of a HopProgress (nil keeps nothing).
type hopResidues struct {
	p  *HopProgress
	id string
}

func (h *hopResidues) get(j uint64) (uint64, bool) {
	if h == nil {
		return 0, false
	}
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	r, ok := h.p.byID[h.id][j]
	return r, ok
}

func (h *hopResidues) put(j, r uint64) {
	if h == nil {
		return
	}
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	m := h.p.byID[h.id]
	if m == nil {
		m = map[uint64]uint64{}
		h.p.byID[h.id] = m
		h.p.order = append(h.p.order, h.id)
		if len(h.p.order) > h.p.max {
			delete(h.p.byID, h.p.order[0])
			h.p.order = h.p.order[1:]
		}
	}
	m[j] = r
	if residueKept != nil {
		residueKept()
	}
}

// done drops a judged hop's residues.
func (h *hopResidues) done() {
	if h == nil {
		return
	}
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	if _, ok := h.p.byID[h.id]; !ok {
		return
	}
	delete(h.p.byID, h.id)
	for i, id := range h.p.order {
		if id == h.id {
			h.p.order = append(h.p.order[:i], h.p.order[i+1:]...)
			break
		}
	}
}

// residueKept, when set (tests), is called after each residue is kept.
var residueKept func()

// DefaultMaxHopHeight is the tallest h_max verified unless configured: Level
// 1 of a hop costs about 2^h_max word additions per root and sample, about
// 0.7 s on one core at h24 with three tall axes. It stays at 24 until the
// incremental chain cache (speakeasy design, PR 2) means a re-sent tall hop
// is not checked again; the reference's ceiling is 32 and HOSAKA sells hops
// up to h30. The owner decides the final value.
const DefaultMaxHopHeight = 24

// MaxHopVerifyHeightLimit is the highest ceiling allowed: above h65 the
// residue count m (§5.9) no longer fits 64 bits.
const MaxHopVerifyHeightLimit = 65

// Check implements ProofChecker. Once ctx has ended the answer is always
// ProofUnchecked, whatever the check had reached: a check cut short has
// judged nothing, and a verdict must never come from one (a cache of
// verdicts builds on these answers).
func (s SpecProofs) Check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	res, why := s.check(ctx, prev, cur)
	if err := ctx.Err(); err != nil {
		return ProofUnchecked, "canceled: " + err.Error()
	}
	return res, why
}

func (s SpecProofs) check(ctx context.Context, prev, cur Move) (ProofResult, string) {
	switch cur.Action {
	case ActHop:
		return s.hop(ctx, cur)
	case ActSidestep:
		if why := verifySidestep(cur); why != "" {
			return ProofInvalid, ReasonSidestepProof + ": " + why
		}
	case ActEnterHyperspace:
		if why := verifyBoarding(cur); why != "" {
			return ProofInvalid, ReasonEnterHyperspaceProof + ": " + why
		}
	case ActHyperjump:
		// A ride the line cannot judge yet (as_of or B above its tip) is
		// left unchecked, waiting for that height, never failed (checkRide,
		// Known.LineWait); a reorganization changes LineState, which is
		// part of Gate.rules.
		if s.Line == nil {
			return ProofUnchecked, "no line: a ride needs Bitcoin's block data (DECK-0001 §5.5)"
		}
		var kept *rideKept
		if s.RideProgress != nil {
			kept = &rideKept{p: s.RideProgress, id: cur.Event.ID}
		}
		return checkRide(ctx, s.Line, prev, cur, kept)
	}
	return ProofVerified, ""
}

func (s SpecProofs) hop(ctx context.Context, cur Move) (ProofResult, string) {
	listed := ListedV1Hops
	if s.ListedV1Hops != nil {
		listed = s.ListedV1Hops
	}
	// §8.7.1 step 7, §5.13: a listed hop's proof is accepted as audited.
	// Its tags' count and form were checked by the walk (proofTags). The id
	// is the event's own NIP-01 hash: the verifier discarded every event
	// whose id is not.
	if listed[cur.Event.ID] {
		return ProofVerified, ""
	}
	mn, mp := tagValues(cur.Event, "mn"), tagValues(cur.Event, "mp")
	if len(mn) == 0 && len(mp) == 0 {
		return ProofInvalid, ReasonHopProof + ": a version 1 hop (no mn and no mp tag) not listed in grandfathered-v1-hops.txt (5.13)"
	}
	prev, _ := hex.DecodeString(cur.Previous)
	from, _ := ParseCoord(cur.From)
	to, _ := ParseCoord(cur.To)
	ceiling := s.MaxHopHeight
	if ceiling == 0 {
		ceiling = DefaultMaxHopHeight
	}
	var kept *hopResidues
	if s.Progress != nil {
		kept = &hopResidues{p: s.Progress, id: cur.Event.ID}
	}
	why, err := verifyHopLevel1Kept(ctx, prev, from, to, tagValues(cur.Event, "proof")[0], first(mn), first(mp), ceiling, kept)
	if err != nil { // too tall (ErrHopTooTall), or cut short (its residues are kept)
		return ProofUnchecked, err.Error()
	}
	kept.done()
	if why != "" {
		return ProofInvalid, ReasonHopProof + ": " + why
	}
	return ProofVerified, ""
}

func first(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// ── the exemption lists (§5.13, §6.16, DECK-0001 §5.8) ───────────────────

var (
	//go:embed rules/grandfathered-v1-hops.txt
	listV1Hops string
	//go:embed rules/grandfathered-v2-sidesteps.txt
	listV2Sidesteps string
	//go:embed rules/grandfathered-v1-hyperjumps.txt
	listV1Rides string

	// ListedV1Hops, ListedV2Sidesteps and ListedV1Rides are the exemption
	// lists, copied unchanged from arkin0x/cyberspace at 9210d6d:
	// grandfathered-v1-hops.txt (2658 ids, census 1), grandfathered-v2-sidesteps.txt
	// (36) and decks/grandfathered-v1-hyperjumps.txt (16), the same lists
	// cyberspace-cli embeds (src/cyberspace_core/grandfathered.py). A listed
	// event's proof is accepted without recomputation; everything else
	// about it is checked. The lookup is by event id, which the verifier has
	// already checked is the event's NIP-01 hash.
	ListedV1Hops      = parseList(listV1Hops)
	ListedV2Sidesteps = parseList(listV2Sidesteps)
	ListedV1Rides     = parseList(listV1Rides)
)

// parseList reads the list format of §5.13: each non-empty line that does
// not begin with # starts with a 64-character lowercase hex event id;
// anything after it is commentary.
func parseList(text string) map[string]bool {
	ids := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) >= 64 && isHex32(line[:64]) {
			ids[line[:64]] = true
		}
	}
	return ids
}

// ── the sidestep (§6, §8.5, §8.7.2) ───────────────────────────────────────

const sidestepSamples = 8

var (
	sidestepDomain       = []byte("CYBERSPACE_SIDESTEP_V2")
	sidestepGrindDomain  = []byte("CYBERSPACE_SIDESTEP_GRIND_V1")
	sidestepSampleDomain = []byte("CYBERSPACE_SIDESTEP_SAMPLE_V2")
)

// verifySidestep is Level 1 of a sidestep (§8.7.2, verify_sidestep_event):
// the geometry, the height tags, the price and the openings (or the listing
// of an event without mn, §6.16), then the proof hash of the claimed roots
// at this chain position. The walk has already checked the count and form
// of every tag read here. It returns "" or the first failure found.
func verifySidestep(cur Move) string {
	prev, _ := hex.DecodeString(cur.Previous)
	from, _ := ParseCoord(cur.From)
	to, _ := ParseCoord(cur.To)
	var roots [3][]byte
	for i, r := range strings.Split(tagValues(cur.Event, "mr")[0], ":") {
		roots[i], _ = hex.DecodeString(r)
	}
	src := [3]*big.Int{from.X, from.Y, from.Z}
	dst := [3]*big.Int{to.X, to.Y, to.Z}
	var heights [3]int
	for i, name := range []string{"x", "y", "z"} {
		heights[i] = lcaHeight(src[i], dst[i])
		if d := new(big.Int).Sub(dst[i], src[i]); d.CmpAbs(bigOne) > 0 {
			return fmt.Sprintf("geometry: axis %s moves %s gibsons; a sidestep crosses one wall by one gibson (6.3)", name, d)
		}
		if got := tagValues(cur.Event, "h"+name)[0]; got != fmt.Sprint(heights[i]) {
			return fmt.Sprintf("h%s: tag %q but the coordinates give %d", name, got, heights[i])
		}
	}
	if mn := tagValues(cur.Event, "mn"); len(mn) == 0 {
		if !ListedV2Sidesteps[cur.Event.ID] {
			if sidestepVersion1(tagValues(cur.Event, "mp")[0], heights) {
				return "mn: missing; a version 1 sidestep (one opening path per axis), invalid since 2026-09-07 (spec §6.15)"
			}
			return "mn: missing; a version 2 sidestep not listed in grandfathered-v2-sidesteps.txt (6.16)"
		}
	} else if why := sidestepOpenings(prev, src, dst, heights, roots, mn[0], tagValues(cur.Event, "mp")[0]); why != "" {
		return why
	}
	// §6.6 to §6.8: the proof hash of the claimed roots at this position.
	var m [3]*big.Int
	for i := range roots {
		m[i] = new(big.Int).SetBytes(roots[i])
	}
	region := cantorPair(new(big.Int), cantorPair(new(big.Int), m[0], m[1]), m[2])
	n := cantorPair(new(big.Int), region, temporalCantor(prev, terrainK(to)))
	if tagValues(cur.Event, "proof")[0] != doubleSHA256Hex(n) {
		return "proof: does not match the proof hash of the claimed roots (6.8)"
	}
	return ""
}

// sidestepVersion1 reports whether a sidestep's mp carries version 1
// openings (§6.15): one path of h siblings on every axis that moves, where
// versions 2 and 3 carry nine.
func sidestepVersion1(mp string, heights [3]int) bool {
	segments := strings.Split(mp, ":")
	if len(segments) != 3 {
		return false
	}
	moved := false
	for i, h := range heights {
		if h == 0 {
			continue
		}
		moved = true
		if len(segments[i]) != 64*h {
			return false
		}
	}
	return moved
}

func sidestepOpenings(prev []byte, src, dst [3]*big.Int, heights [3]int, roots [3][]byte, mn, mp string) string {
	nb, _ := hex.DecodeString(mn) // 16 lowercase hex, checked by the walk
	segments := strings.Split(mp, ":")
	if len(segments) != 3 {
		return "mp: not three colon-separated axis segments"
	}
	var openings [3][][][]byte
	for i, seg := range segments {
		o, ok := sidestepAxisOpenings(seg, heights[i])
		if !ok {
			return fmt.Sprintf("mp: axis %c segment is malformed, or a version 1 single path (8.5, 6.15)", "xyz"[i])
		}
		openings[i] = o
	}
	// §6.10: A = max(1, ceil(leaves / 8)) over the axes that move.
	leaves := new(big.Int)
	for _, h := range heights {
		if h > 0 {
			leaves.Add(leaves, new(big.Int).Lsh(bigOne, uint(h)))
		}
	}
	price := ceilDiv(leaves, big.NewInt(sidestepSamples))
	if price.Sign() == 0 {
		price.SetInt64(1)
	}
	h := sha256.New()
	h.Write(sidestepGrindDomain)
	h.Write(nb)
	h.Write(prev)
	for _, r := range roots {
		h.Write(r)
	}
	G := h.Sum(nil)
	if !meetsPrice(G, price) {
		return fmt.Sprintf("mn: nonce %s does not meet the re-roll price, A=%s (6.10)", mn, price)
	}
	for i := range heights {
		prefix := make([]byte, 0, 64)
		prefix = append(prefix, sidestepDomain...)
		prefix = append(prefix, prev...)
		prefix = append(prefix, byte(i))
		prefix = append(prefix, make([]byte, 9)...)
		if !axisOpeningsHold(prefix, byte(i), src[i], dst[i], heights[i], roots[i], openings[i], G) {
			return fmt.Sprintf("merkle_%c: openings do not prove the seeded tree", "xyz"[i])
		}
	}
	return ""
}

// sidestepAxisOpenings decodes one axis segment of a sidestep's mp (§8.5):
// empty for an axis that does not move, else the destination's path and the
// eight sampled paths, h siblings each, in lowercase hex.
func sidestepAxisOpenings(seg string, h int) ([][][]byte, bool) {
	if h == 0 {
		return nil, seg == ""
	}
	if !isLowerHex(seg, 64*h*(sidestepSamples+1)) {
		return nil, false
	}
	raw, _ := hex.DecodeString(seg)
	out := make([][][]byte, sidestepSamples+1)
	for p := range out {
		out[p] = make([][]byte, h)
		for l := 0; l < h; l++ {
			out[p][l] = raw[(p*h+l)*32 : (p*h+l+1)*32]
		}
	}
	return out, true
}

func sidestepLeaf(prefix []byte, v *big.Int) []byte {
	s := sha256.Sum256(append(append([]byte{}, prefix...), bytesMin(v)...))
	return s[:]
}

// axisOpeningsHold is Level 1 for one axis (§6.11 steps 5 and 6).
func axisOpeningsHold(prefix []byte, axis byte, v1, v2 *big.Int, h int, root []byte, openings [][][]byte, G []byte) bool {
	if h == 0 {
		return string(sidestepLeaf(prefix, v1)) == string(root)
	}
	base := aligned(v1, h)
	include := func(v *big.Int, path [][]byte) bool {
		return climbs(sidestepLeaf(prefix, v), new(big.Int).Sub(v, base), path, root)
	}
	if !include(v2, openings[0]) {
		return false
	}
	mod := new(big.Int).Lsh(bigOne, uint(h))
	for i := 0; i < sidestepSamples; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		hs := sha256.New()
		hs.Write(sidestepSampleDomain)
		hs.Write(G)
		hs.Write([]byte{axis})
		hs.Write(ib[:])
		idx := new(big.Int).SetBytes(hs.Sum(nil))
		idx.Mod(idx, mod)
		if !include(idx.Add(idx, base), openings[1+i]) {
			return false
		}
	}
	return true
}

// ── boarding (DECK-0001 §3.2) ─────────────────────────────────────────────

// verifyBoarding checks the entry proof: the double SHA-256 of
// π(0, cantor_t), the temporal tree at the terrain K of C (its plane bit
// included) seeded by the id e previous names.
func verifyBoarding(cur Move) string {
	prev, _ := hex.DecodeString(cur.Previous)
	at, _ := ParseCoord(cur.To)
	n := cantorPair(new(big.Int), new(big.Int), temporalCantor(prev, terrainK(at)))
	if tagValues(cur.Event, "proof")[0] != doubleSHA256Hex(n) {
		return "proof: does not match the entry proof at this chain position (3.2)"
	}
	return ""
}

// ── rides (DECK-0001 §4, §5) ──────────────────────────────────────────────

// Line is the Bitcoin block line rides are checked against (DECK-0001 §1,
// §4.2, §5.3): the stops by height, from 0 to the tip without a gap. How the
// stops are obtained is out of scope (DECK-0001 §2.3); AnchorLine reads them
// from this relay's kind 321 anchors.
type Line interface {
	// Tip is the highest height on the line; false when it holds none.
	Tip() (uint64, bool)
	// Stop is block height's stop coordinate, as 64 lowercase hex.
	Stop(height uint64) (string, bool)
	// BlockHash is block height's 32-byte hash in display order.
	BlockHash(height uint64) ([]byte, bool)
	// Station is the height of the stop at or below bound nearest c by
	// the distance of DECK-0001 §4.1, ties to the lowest height (§4.2).
	// bound is on the line.
	Station(c Coord, bound uint64) uint64
}

// LineState names what verdicts on rides rest on besides the blocks: the
// line's source and, for a line that can reorganize, how many times it has.
// It is part of Gate.rules, so a verdict made on another line is not used.
// The tip is deliberately not part of it: a block added at the top changes
// no verdict already reached (a ride that needed it was left unchecked, see
// LineReached), so the cache need not start over every ten minutes.
func (s SpecProofs) LineState() string {
	if s.Line == nil {
		return "none"
	}
	name := "static"
	if n, ok := s.Line.(interface{ Name() string }); ok {
		name = n.Name()
	}
	if e, ok := s.Line.(interface{ Epoch() uint64 }); ok {
		name += fmt.Sprintf("@%d", e.Epoch())
	}
	return name
}

// LineReached reports whether the line holds height h: whether a ride left
// unchecked for want of it can now be judged.
func (s SpecProofs) LineReached(h uint64) bool {
	if s.Line == nil {
		return false
	}
	tip, ok := s.Line.Tip()
	return ok && tip >= h
}

// lineComplete reports whether a line is the whole line, so that a height
// above its tip does not exist (rather than not being known yet).
func lineComplete(l Line) bool {
	c, ok := l.(interface{ Complete() bool })
	return ok && c.Complete()
}

// lineWaitPrefix starts the why of a ride left unchecked because the line
// has not reached a height it needs (as_of or B above the tip); the height
// follows. It is never a failure: Known keeps the height (LineWait), and the
// gate checks the chain again once the line holds it.
const lineWaitPrefix = "line: waiting for block "

// awaitedHeight is the height a why made by awaitLine waits for.
func awaitedHeight(why string) (uint64, bool) {
	rest, ok := strings.CutPrefix(why, lineWaitPrefix)
	if !ok {
		return 0, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	h, err := strconv.ParseUint(rest[:end], 10, 64)
	return h, err == nil
}

func awaitLine(h *big.Int, line Line) (ProofResult, string) {
	need := uint64(math.MaxUint64) // a height no line will reach
	if h.IsUint64() {
		need = h.Uint64()
	}
	tip := "the line holds no block yet"
	if t, ok := line.Tip(); ok {
		tip = fmt.Sprintf("its tip is %d", t)
	}
	return ProofUnchecked, fmt.Sprintf("%s%d; %s", lineWaitPrefix, need, tip)
}

// LineBlock is one block of a StaticLine.
type LineBlock struct {
	Height     uint64 `json:"height"`
	BlockHash  string `json:"block_hash"`
	MerkleRoot string `json:"merkle_root"`
	// Coord is the stop coordinate. For a port (the merkle root's low bit
	// is 1) it must be the merkle root; for a landfall it is the DECK-0001
	// §1.2 derivation from the block hash, which the source vouches for.
	Coord string `json:"coord"`
}

// StaticLine is a Line held in memory. Station is a linear scan, which is
// exact and fine for short lines; AnchorLine has the sorted lookup of
// DECK-0001 §4.4 a line of mainnet's length wants.
type StaticLine struct {
	stops  []Coord
	coords []string
	hashes [][]byte
}

// NewStaticLine builds a line from blocks covering heights 0 to the tip.
func NewStaticLine(blocks []LineBlock) (*StaticLine, error) {
	l := &StaticLine{stops: make([]Coord, len(blocks)), coords: make([]string, len(blocks)), hashes: make([][]byte, len(blocks))}
	seen := make([]bool, len(blocks))
	for _, b := range blocks {
		if b.Height >= uint64(len(blocks)) || seen[b.Height] {
			return nil, fmt.Errorf("line: heights must run from 0 without a gap or a repeat (height %d)", b.Height)
		}
		seen[b.Height] = true
		c, err := ParseCoord(b.Coord)
		if err != nil {
			return nil, fmt.Errorf("line: block %d: %w", b.Height, err)
		}
		if !isHex32(b.MerkleRoot) || !isHex32(b.BlockHash) {
			return nil, fmt.Errorf("line: block %d: merkle root and block hash must be 32-byte lowercase hex", b.Height)
		}
		if strings.IndexByte("13579bdf", b.MerkleRoot[63]) >= 0 {
			if b.Coord != b.MerkleRoot {
				return nil, fmt.Errorf("line: block %d is a port, so its stop is its merkle root (DECK-0001 §1.1)", b.Height)
			}
		}
		l.stops[b.Height], l.coords[b.Height] = c, b.Coord
		l.hashes[b.Height], _ = hex.DecodeString(b.BlockHash)
	}
	return l, nil
}

// Complete implements lineComplete: a StaticLine is the whole line, as the
// golden vectors' synthetic line is the whole of their world.
func (l *StaticLine) Complete() bool { return true }

func (l *StaticLine) Tip() (uint64, bool) {
	if len(l.stops) == 0 {
		return 0, false
	}
	return uint64(len(l.stops)) - 1, true
}

func (l *StaticLine) Stop(h uint64) (string, bool) {
	if h >= uint64(len(l.coords)) {
		return "", false
	}
	return l.coords[h], true
}

func (l *StaticLine) BlockHash(h uint64) ([]byte, bool) {
	if h >= uint64(len(l.hashes)) {
		return nil, false
	}
	return l.hashes[h], true
}

func (l *StaticLine) Station(c Coord, bound uint64) uint64 {
	best, bestD := uint64(0), -1
	for h := uint64(0); h <= bound && h < uint64(len(l.stops)); h++ {
		s := l.stops[h]
		d := max(lcaHeight(c.X, s.X), lcaHeight(c.Y, s.Y), lcaHeight(c.Z, s.Z))
		if bestD < 0 || d < bestD {
			best, bestD = h, d
		}
	}
	return best
}

const (
	kLine           = 6
	rideSamples     = 32
	rideGrindHeight = 16
	// tallLeafHeight: a ride leaf this tall or taller (h20 2.4 s and about
	// 100 MB at its peak, h22 14 s and 370 MB, measured) is computed one at
	// a time in the whole process, so concurrent checks cannot stack their
	// memory.
	tallLeafHeight = 20
)

// tallLeaves admits one tall ride leaf at a time.
var tallLeaves = make(chan struct{}, 1)

var (
	hyperspaceTerrainDomain = []byte("CYBERSPACE_HYPERSPACE_TERRAIN_V1")
	hyperspaceSeedDomain    = []byte("CYBERSPACE_HYPERSPACE_SEED_V1")
	hyperspaceLeafDomain    = []byte("CYBERSPACE_HYPERSPACE_LEAF_V1")
	hyperspaceGrindDomain   = []byte("CYBERSPACE_HYPERSPACE_GRIND_V1")
	hyperspaceSampleDomain  = []byte("CYBERSPACE_HYPERSPACE_SAMPLE_V2")
)

// checkRide checks the rules of a ride that need the line, in the
// reference's order: on the first ride after boarding, as_of is a height on
// the line and at least B, and from_height is the station within it
// (DECK-0001 §4.2, §4.3); then C is the stop of B (§5.5 Level 1 step 2);
// then the proof (§5.5, §5.8). The walk has already checked everything that
// reads only tags.
//
// A height the line has not reached yet (as_of or B above its tip) is not a
// failure: the ride is left unchecked, waiting for that height (awaitLine).
// The reference judges against mainnet's whole line, where such a ride is
// invalid until Bitcoin reaches the height; an AnchorLine can lag mainnet
// (the publisher waits for six confirmations, and a gap stops it), so there
// it means only that the answer is not known yet. Only a line that is the
// whole of its world (a StaticLine, such as the golden vectors' synthetic
// line, lineComplete) says that a height above its tip does not exist, and
// the ride is then invalid, as the reference has it. Every block the proof reads
// is at or below the higher of from_height and B, so once both checks pass
// it is on the line.
func checkRide(ctx context.Context, line Line, look, cur Move, kept *rideKept) (ProofResult, string) {
	from, _ := onlyDecimal(cur.Event, "from_height")
	to, _ := onlyDecimal(cur.Event, "B")
	tip, has := line.Tip()
	reached := func(h *big.Int) bool { return has && h.IsUint64() && h.Uint64() <= tip }
	complete := lineComplete(line)
	if look.Action == ActEnterHyperspace {
		asOf, _ := onlyDecimal(cur.Event, "as_of")
		if asOf.Cmp(to) < 0 || complete && !reached(asOf) {
			return ProofInvalid, ReasonHyperjumpAsOf + ": as_of must be a height on the line and at least B"
		}
		if !reached(asOf) {
			return awaitLine(asOf, line)
		}
		boarded, _ := ParseCoord(look.To)
		station := line.Station(boarded, asOf.Uint64())
		if !from.IsUint64() || from.Uint64() != station {
			return ProofInvalid, fmt.Sprintf("%s: from_height %s but the station within %s is %d", ReasonHyperjumpStation, from, asOf, station)
		}
	}
	if !reached(to) {
		if complete {
			return ProofInvalid, ReasonHyperjumpStop + ": B is not a height on the line"
		}
		return awaitLine(to, line)
	}
	if stop, ok := line.Stop(to.Uint64()); !ok || stop != cur.To {
		return ProofInvalid, fmt.Sprintf("%s: C is not the stop coordinate of block %s", ReasonHyperjumpStop, to)
	}
	if !from.IsUint64() || !reached(from) {
		// Only a ride after another can get here with from_height above the
		// tip, and that one's B was on the line when it was checked.
		return awaitLine(from, line)
	}
	why, err := verifyRideProof(ctx, line, cur, from.Uint64(), to.Uint64(), kept)
	if err != nil {
		return ProofUnchecked, err.Error()
	}
	kept.done()
	if why != "" {
		return ProofInvalid, ReasonHyperjumpProof + ": " + why
	}
	return ProofVerified, ""
}

// errRideCut is a ride's check cut short by its deadline; its leaves are
// kept (RideProgress).
var errRideCut = errors.New("canceled: the ride's check was cut short; its finished leaves are kept")

// verifyRideProof is Level 1 of a ride's openings (DECK-0001 §5.5 steps 3
// to 6, verify_ride_event). Both heights are on the line. It returns "" or
// the first failure found, or errRideCut.
//
// The answer is the reference's; how the work is done differs in three
// ways that change no answer. A block sampled more than once is computed
// once (§5.5: "implementations MAY deduplicate"), so a ride shorter than 32
// blocks costs its own length, not 32 leaves. The sampled blocks are
// computed cheapest first, so a forged root fails on the cheapest leaf the
// samples hold. And each finished leaf is kept, with a tall leaf's tree in
// progress, so a check its deadline cuts short goes on from there.
func verifyRideProof(ctx context.Context, line Line, cur Move, fromH, toH uint64, kept *rideKept) (string, error) {
	mn := tagValues(cur.Event, "mn")
	if len(mn) == 0 {
		if !ListedV1Rides[cur.Event.ID] {
			return "mn: missing; a ride without mn not listed in decks/grandfathered-v1-hyperjumps.txt (5.8)", nil
		}
		return "", nil
	}
	lo, hi := min(fromH, toH), max(fromH, toH)
	n := hi - lo
	depth := bits.Len64(n - 1)
	parts := strings.Split(tagValues(cur.Event, "mp")[0], ":")
	if len(parts) != rideSamples {
		return fmt.Sprintf("mp: not %d colon-joined paths of %d siblings each (5.5)", rideSamples, depth), nil
	}
	paths := make([][][]byte, rideSamples)
	for i, p := range parts {
		if !isLowerHex(p, 64*depth) {
			return fmt.Sprintf("mp: not %d colon-joined paths of %d siblings each (5.5)", rideSamples, depth), nil
		}
		raw, _ := hex.DecodeString(p)
		for k := 0; k < depth; k++ {
			paths[i] = append(paths[i], raw[32*k:32*(k+1)])
		}
	}
	prev, _ := hex.DecodeString(cur.Previous)
	root, _ := hex.DecodeString(tagValues(cur.Event, "proof")[0])
	nb, _ := hex.DecodeString(mn[0])
	// One attempt, a Cantor tree at height 16 (§5.5).
	G := kept.grind()
	if G == nil {
		h := sha256.New()
		h.Write(hyperspaceGrindDomain)
		h.Write(prev)
		h.Write(root)
		h.Write(nb)
		seed := h.Sum(nil)
		gBase := new(big.Int).SetBytes(seed)
		gBase.And(gBase, axisMask)
		h = sha256.New()
		h.Write(hyperspaceGrindDomain)
		h.Write(seed)
		cantorG := subtreeCantorCtx(ctx, aligned(gBase, rideGrindHeight), rideGrindHeight)
		if cantorG == nil {
			return "", errRideCut
		}
		h.Write(bytesMin(cantorG))
		G = h.Sum(nil)
		kept.putGrind(G)
	}
	price := big.NewInt(int64((n + rideSamples - 1) / rideSamples))
	if price.Sign() == 0 {
		price.SetInt64(1)
	}
	if !meetsPrice(G, price) {
		return fmt.Sprintf("mn: nonce %s does not meet the re-roll price, A=%s (5.5)", mn[0], price), nil
	}
	// The samples, by block.
	type sampled struct {
		b, idx uint64
		hash   []byte
		height int
		of     []int
	}
	byBlock := map[uint64]*sampled{}
	var blocks []*sampled
	for i := 0; i < rideSamples; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		hs := sha256.New()
		hs.Write(hyperspaceSampleDomain)
		hs.Write(G)
		hs.Write(ib[:])
		idx := new(big.Int).SetBytes(hs.Sum(nil))
		idx.Mod(idx, new(big.Int).SetUint64(n))
		b := lo + 1 + idx.Uint64()
		s := byBlock[b]
		if s == nil {
			hash, ok := line.BlockHash(b)
			if !ok {
				return fmt.Sprintf("block %d has no hash on the line", b), nil
			}
			s = &sampled{b: b, idx: idx.Uint64(), hash: hash, height: rideLeafHeight(hash)}
			byBlock[b] = s
			blocks = append(blocks, s)
		}
		s.of = append(s.of, i)
	}
	slices.SortFunc(blocks, func(x, y *sampled) int {
		if x.height != y.height {
			return x.height - y.height
		}
		return int(int64(x.b) - int64(y.b))
	})
	for _, s := range blocks {
		leaf, err := rideLeafKept(ctx, prev, s.b, s.hash, s.height, kept)
		if err != nil {
			return "", err
		}
		for _, i := range s.of {
			if !climbs(leaf, new(big.Int).SetUint64(s.idx), paths[i], root) {
				return fmt.Sprintf("mp: sample %d (block %d) does not reach the root", i, s.b), nil
			}
		}
	}
	return "", nil
}

// rideLeafHeight is h_b = K_b + 6 (DECK-0001 §5.3 steps 1 and 2).
func rideLeafHeight(blockHash []byte) int {
	d := sha256.Sum256(append(append([]byte{}, hyperspaceTerrainDomain...), blockHash...))
	return bits.OnesCount16(uint16(d[0])<<8|uint16(d[1])) + kLine
}

// rideLeaf is block b's leaf (DECK-0001 §5.3): a Cantor tree of height
// K_b + 6 seeded by the rider's previous event id and b. nil when ctx ends.
func rideLeaf(ctx context.Context, prev []byte, b uint64, blockHash []byte) []byte {
	leaf, err := rideLeafKept(ctx, prev, b, blockHash, rideLeafHeight(blockHash), nil)
	if err != nil {
		return nil
	}
	return leaf
}

func rideLeafKept(ctx context.Context, prev []byte, b uint64, blockHash []byte, height int, kept *rideKept) ([]byte, error) {
	if leaf := kept.leaf(b, blockHash); leaf != nil {
		return leaf, nil
	}
	var bb [8]byte
	binary.BigEndian.PutUint64(bb[:], b)
	tree := kept.tree(b, blockHash)
	if tree == nil {
		s := sha256.New()
		s.Write(hyperspaceSeedDomain)
		s.Write(prev)
		s.Write(bb[:])
		t := new(big.Int).SetBytes(s.Sum(nil))
		t.And(t, axisMask)
		tree = newCantorTree(aligned(t, height), height)
	}
	if height >= tallLeafHeight {
		select {
		case tallLeaves <- struct{}{}:
			defer func() { <-tallLeaves }()
		case <-ctx.Done():
			return nil, errRideCut
		}
	}
	cantor, ok := tree.run(ctx)
	if !ok {
		kept.putTree(b, blockHash, tree)
		return nil, errRideCut
	}
	leaf := sha256.New()
	leaf.Write(hyperspaceLeafDomain)
	leaf.Write(bb[:])
	leaf.Write(bytesMin(cantor))
	out := leaf.Sum(nil)
	if rideLeafHook != nil {
		rideLeafHook(b)
	}
	kept.putLeaf(b, blockHash, out)
	return out, nil
}

// RideProgress keeps, by ride event id, what checks of a ride that their
// deadline cut short had finished: its G and its leaves, each with the
// block hash it was computed from, and the tree of the one tall leaf in
// progress (rides are checked one leaf at a time). As HopProgress, it is a
// checkpoint and never a verdict: the event id commits to the previous id,
// the root and the nonce the work is seeded by, and a leaf is used again
// only for the same block hash. A ride's entry is dropped once it is
// judged, and the oldest go first past max. At most one tree in progress is
// kept in the whole process, the newest, since a tall one holds tens of MB.
type RideProgress struct {
	mu    sync.Mutex
	max   int
	byID  map[string]*rideState
	order []string
	tree  *keptTree
}

type rideState struct {
	g      []byte
	leaves map[uint64]keptLeaf
}

type keptLeaf struct {
	hash, leaf []byte
}

type keptTree struct {
	id   string
	b    uint64
	hash []byte
	t    *cantorTree
}

// maxKeptTreeBytes bounds the tree in progress that is kept: an h22 leaf's
// pending roots are under 32 MB.
const maxKeptTreeBytes = 64 << 20

// NewRideProgress keeps the progress of at most max rides.
func NewRideProgress(max int) *RideProgress {
	return &RideProgress{max: max, byID: map[string]*rideState{}}
}

// rideKept is one ride's view of a RideProgress (nil keeps nothing).
type rideKept struct {
	p  *RideProgress
	id string
}

func (k *rideKept) state(create bool) *rideState {
	st := k.p.byID[k.id]
	if st == nil && create {
		st = &rideState{leaves: map[uint64]keptLeaf{}}
		k.p.byID[k.id] = st
		k.p.order = append(k.p.order, k.id)
		if len(k.p.order) > k.p.max {
			delete(k.p.byID, k.p.order[0])
			k.p.order = k.p.order[1:]
		}
	}
	return st
}

func (k *rideKept) grind() []byte {
	if k == nil {
		return nil
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	if st := k.state(false); st != nil {
		return st.g
	}
	return nil
}

func (k *rideKept) putGrind(g []byte) {
	if k == nil {
		return
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	k.state(true).g = g
}

func (k *rideKept) leaf(b uint64, hash []byte) []byte {
	if k == nil {
		return nil
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	if st := k.state(false); st != nil {
		if l, ok := st.leaves[b]; ok && bytes.Equal(l.hash, hash) {
			return l.leaf
		}
	}
	return nil
}

func (k *rideKept) putLeaf(b uint64, hash, leaf []byte) {
	if k == nil {
		return
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	k.state(true).leaves[b] = keptLeaf{append([]byte(nil), hash...), leaf}
	if t := k.p.tree; t != nil && t.id == k.id && t.b == b {
		k.p.tree = nil
	}
}

// tree takes the kept tree in progress for block b, if it is this ride's.
func (k *rideKept) tree(b uint64, hash []byte) *cantorTree {
	if k == nil {
		return nil
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	if t := k.p.tree; t != nil && t.id == k.id && t.b == b && bytes.Equal(t.hash, hash) {
		k.p.tree = nil
		return t.t
	}
	return nil
}

func (k *rideKept) putTree(b uint64, hash []byte, t *cantorTree) {
	if k == nil || t.bytes() > maxKeptTreeBytes {
		return
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	k.p.tree = &keptTree{id: k.id, b: b, hash: append([]byte(nil), hash...), t: t}
}

// done drops a judged ride's progress.
func (k *rideKept) done() {
	if k == nil {
		return
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	if _, ok := k.p.byID[k.id]; !ok {
		return
	}
	delete(k.p.byID, k.id)
	k.p.order = slices.DeleteFunc(k.p.order, func(id string) bool { return id == k.id })
	if t := k.p.tree; t != nil && t.id == k.id {
		k.p.tree = nil
	}
}

// rideLeafHook, when set (tests), is called after each leaf is computed.
var rideLeafHook func(b uint64)
