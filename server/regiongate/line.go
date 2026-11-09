package regiongate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// AnchorLine is the Bitcoin line rides are checked against, built from the
// block anchor events (kind 321, DECK-0001 §2) one publisher signed, as this
// relay's own store holds them (owner ruling 2026-11-05: our NTH publisher,
// c6e74d44...). It holds the stops from height 0 to its tip without a gap:
// each anchor is resolved as cyberspace_core.hyperspace.resolve_stop does
// (§2.2, §2.3; a plane-0 block's landfall is always derived here from its
// hash), and each block must name the one below it as its previous (P), so
// the line is one chain of block hashes. A height the line has not reached
// is not on it: a ride that needs one is left unchecked until it is (see
// checkRide), never judged.
//
// Where two anchored chains part, the longer wins and a tie keeps the one
// already on the line, as a Bitcoin node does; a change below the tip is a
// reorganization, and Epoch counts them so that verdicts made on the old
// line are not used (Gate.rules). The publisher anchors a block only once it
// has six confirmations, so this should not happen.
//
// Once loaded, the line accepts a reorganization only if it displaces at
// most MaxReorgDepth blocks (owner ruling 2026-11-09: 6). Since anchors
// come at six confirmations, a deeper one would mean a mainnet
// reorganization more than a dozen blocks deep, which has not happened
// since 2013, so it is far more likely a leaked publisher key rewriting
// history: the line keeps its chain, reports it through Alert once per
// rival tip, drops the rival's blocks, and needs the operator.
//
// The cap protects only history below the tip. A leaked key can still
// extend the tip with fake blocks (they link to the real tip, so they are
// no reorganization), and once more than MaxReorgDepth of them are on the
// line, the cap keeps the real chain from displacing them. An update that
// appends more than MaxReorgDepth blocks at once is therefore reported
// through Alert too: the operator should check them against a Bitcoin node.
//
// A height no anchor covers, between two that do, can be filled from block
// headers fetched from a public source (Fallback): each header is fetched by
// the hash the anchor above names as previous and must hash to it, so the
// source is trusted for nothing. Off by default.
type AnchorLine struct {
	cfg AnchorLineConfig

	mu     sync.RWMutex
	hashes [][32]byte // by height
	coords [][32]byte // by height
	epoch  uint64
	index  *stationIndex // heights below index.n; the rest are scanned
	// pending holds valid blocks read but not on the line: above a gap, a
	// competing block, or a block displaced by a reorganization.
	pending map[uint64][]anchorBlock
	loaded  bool

	update sync.Mutex // one Load or Update at a time
	gapLog uint64     // the gap last logged, so each is logged once
	// refused holds the deep rivals already reported (fork height and
	// rival tip), so each is reported once, not at every poll.
	refused map[[2]uint64]bool
	// The stuck path (blocks at the tip that do not link) re-reads below
	// the tip when what sits at the tip changed (stuckSig), when the store
	// holds anchors signed after the newest one read (newest), or at least
	// every stuckEvery polls (stuckPolls): never at every poll for nothing,
	// never missing a reorganization for good. Touched under update.
	stuckSig   string
	stuckPolls int
	newest     int64
	// fillFailed holds when each block above a gap last failed to lead
	// down to the tip through the fallback, for the tip in fillTip: it is
	// asked again only after fillRetry, not at every poll (a rival's block
	// never will; a fallback that was down may next time). Like stuckSig,
	// touched only by fill, which runs under update (Load, Update): so it
	// needs no lock of mu's, though fill reads it while holding mu's read
	// lock for the line itself.
	fillFailed map[[32]byte]time.Time
	fillTip    uint64
}

// stuckEvery is the most polls the stuck path waits between re-reads when
// nothing it can see has changed: anchors below the tip signed before the
// newest one read are only found this way.
const stuckEvery = 10

// fillRetry is how long a block that failed to fill a gap waits before the
// fallback is asked about it again.
const fillRetry = 5 * time.Minute

// AnchorLineConfig configures an AnchorLine.
type AnchorLineConfig struct {
	// Publisher is the hex pubkey whose anchors make the line.
	Publisher string
	// Query reads events from the store (nostrdb's Query). MaxResults is
	// the most one call returns, or 0 when it honors any limit.
	Query      func(filters []nostr.Filter, limit int) ([]nostr.Event, error)
	MaxResults int
	// Signature checks an anchor's signature; nil trusts the store.
	Signature func(nostr.Event) bool
	// Fallback, when set, fills gaps from block headers (HeaderSource).
	Fallback HeaderSource
	// MaxFallbackGap is the longest gap filled from the fallback. Default 64.
	MaxFallbackGap int
	// Workers derive landfalls and check signatures; default half the cores.
	Workers int
	// MaxReorgDepth is the most blocks a reorganization may displace once
	// the line is loaded. Default DefaultMaxReorgDepth.
	MaxReorgDepth int
	// Log reports progress and problems; nil is silent.
	Log func(msg string, args ...any)
	// Alert reports what needs the operator (a refused deep
	// reorganization); nil uses Log.
	Alert func(msg string, args ...any)
}

// DefaultMaxReorgDepth is the deepest reorganization a loaded line accepts
// (owner ruling 2026-11-09). The publisher anchors at six confirmations, so
// displacing even one anchored block already takes a deep mainnet
// reorganization.
const DefaultMaxReorgDepth = 6

// HeaderSource returns the 80-byte header of the block with a given hash.
// Nothing it returns is trusted: the line checks that the header hashes to
// the hash it asked for.
type HeaderSource interface {
	Header(ctx context.Context, hash [32]byte) ([]byte, error)
}

// KindBlockAnchor is the kind of a block anchor event (DECK-0001 §2).
const KindBlockAnchor = 321

// anchorBlock is one block as an anchor (or a fallback header) gives it.
type anchorBlock struct {
	height            uint64
	hash, prev, coord [32]byte
	// seen is the anchor's created_at, which settles a tie between two
	// chains of one length: the one anchored first (a node's first seen).
	seen int64
}

// NewAnchorLine makes an empty line; Load fills it.
func NewAnchorLine(cfg AnchorLineConfig) *AnchorLine {
	if cfg.MaxFallbackGap <= 0 {
		cfg.MaxFallbackGap = 64
	}
	if cfg.Workers <= 0 {
		cfg.Workers = max(1, runtime.GOMAXPROCS(0)/2)
	}
	if cfg.MaxReorgDepth <= 0 {
		cfg.MaxReorgDepth = DefaultMaxReorgDepth
	}
	if cfg.Alert == nil {
		cfg.Alert = cfg.Log
	}
	return &AnchorLine{cfg: cfg, pending: map[uint64][]anchorBlock{}, refused: map[[2]uint64]bool{}}
}

func (l *AnchorLine) log(msg string, args ...any) {
	if l.cfg.Log != nil {
		l.cfg.Log(msg, args...)
	}
}

// ── Line ─────────────────────────────────────────────────────────────────

// Tip implements Line.
func (l *AnchorLine) Tip() (uint64, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.hashes) == 0 {
		return 0, false
	}
	return uint64(len(l.hashes)) - 1, true
}

// Stop implements Line.
func (l *AnchorLine) Stop(h uint64) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if h >= uint64(len(l.coords)) {
		return "", false
	}
	return hex.EncodeToString(l.coords[h][:]), true
}

// BlockHash implements Line.
func (l *AnchorLine) BlockHash(h uint64) ([]byte, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if h >= uint64(len(l.hashes)) {
		return nil, false
	}
	b := l.hashes[h]
	return b[:], true
}

// Station implements Line: the sorted lookup of DECK-0001 §4.4 over the
// indexed heights, and a scan of the few above them.
func (l *AnchorLine) Station(c Coord, bound uint64) uint64 {
	key := packCoord(c.X, c.Y, c.Z, c.Plane)
	l.mu.RLock()
	defer l.mu.RUnlock()
	return station(key, bound, l.coords, l.index)
}

// Name names the line's source for the gate's rules.
func (l *AnchorLine) Name() string {
	name := "kind321:" + l.cfg.Publisher
	if l.cfg.Fallback != nil {
		name += "+headers"
	}
	return name
}

// Epoch counts the reorganizations the line has gone through.
func (l *AnchorLine) Epoch() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.epoch
}

// ── reading anchors ──────────────────────────────────────────────────────

// errAnchor is why an anchor is not used.
var errAnchor = errors.New("anchor")

// parseAnchor resolves one anchor event, except a landfall's coordinate:
// claimed is its C, landfall says the coordinate is still to be derived
// from the hash, and hasM whether the derivation must equal claimed.
func parseAnchor(ev nostr.Event) (b anchorBlock, claimed [32]byte, landfall, hasM bool, err error) {
	bad := func(why string, a ...any) (anchorBlock, [32]byte, bool, bool, error) {
		return anchorBlock{}, [32]byte{}, false, false, fmt.Errorf("%w %s: %s", errAnchor, ev.ID, fmt.Sprintf(why, a...))
	}
	once := func(name string, required bool) (string, bool, error) {
		vs := tagValues(ev, name)
		switch {
		case len(vs) > 1:
			return "", false, fmt.Errorf("%s appears %d times", name, len(vs))
		case len(vs) == 0 && required:
			return "", false, fmt.Errorf("no %s tag", name)
		case len(vs) == 0:
			return "", false, nil
		}
		return vs[0], true, nil
	}
	hex32 := func(name string, required bool) ([32]byte, bool, error) {
		var out [32]byte
		v, ok, err := once(name, required)
		if err != nil || !ok {
			return out, ok, err
		}
		if !isHex32(v) {
			return out, false, fmt.Errorf("%s is not 32-byte lowercase hex", name)
		}
		hex.Decode(out[:], []byte(v))
		return out, true, nil
	}
	c, _, err := hex32("C", true)
	if err != nil {
		return bad("%v", err)
	}
	if b.hash, _, err = hex32("H", true); err != nil {
		return bad("%v", err)
	}
	if b.prev, _, err = hex32("P", true); err != nil {
		return bad("%v", err)
	}
	m, hasM, err := hex32("M", false)
	if err != nil {
		return bad("%v", err)
	}
	height, _, err := once("B", true)
	if err != nil {
		return bad("%v", err)
	}
	if !isCanonicalHeight(height) {
		return bad("B %q is not a base-10 height", height)
	}
	if b.height, err = strconv.ParseUint(height, 10, 64); err != nil {
		return bad("B %q is out of range", height)
	}
	// §2.2: without M, C is the merkle root. §1.1: its low bit is the
	// plane; a port's stop is its merkle root, a landfall's is derived.
	if !hasM {
		m = c
	}
	if m[31]&1 == 1 {
		if c != m {
			return bad("a port's C must be its merkle root (DECK-0001 §1.1, §2.3)")
		}
		b.coord = m
		return b, c, false, hasM, nil
	}
	return b, c, true, hasM, nil
}

// isCanonicalHeight reports a base-10 string without a sign or leading zero,
// the form of an anchor's B (a #B filter matches the string).
func isCanonicalHeight(s string) bool {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// resolveAnchors turns anchor events into blocks, on the line's workers:
// the signature, the tags, and a landfall's derivation (which must equal C
// when the anchor carries M, §2.3). Events that fail are reported and left
// out.
func (l *AnchorLine) resolveAnchors(evs []nostr.Event) []anchorBlock {
	// An anchor whose block is already on the line at its height is not
	// checked again (signature, landfall): add would drop it anyway, and a
	// re-read below the tip returns about 1,000 of them.
	onLine := l.snapshotHashes()
	out := make([]anchorBlock, len(evs))
	okAt := make([]bool, len(evs))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < l.cfg.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				ev := evs[i]
				if ev.Kind != KindBlockAnchor || ev.PubKey != l.cfg.Publisher || alreadyOnLine(ev, onLine) {
					continue
				}
				if l.cfg.Signature != nil && !l.cfg.Signature(ev) {
					l.log("line: anchor not used", "id", ev.ID, "why", "signature")
					continue
				}
				b, claimed, landfall, hasM, err := parseAnchor(ev)
				if err != nil {
					l.log("line: anchor not used", "id", ev.ID, "why", err.Error())
					continue
				}
				if landfall {
					b.coord = LandfallCoord(b.hash[:])
					if hasM && b.coord != claimed {
						l.log("line: anchor not used", "id", ev.ID, "why", "C is not the landfall its H gives (DECK-0001 §1.2, §2.3)")
						continue
					}
				}
				b.seen = ev.CreatedAt
				out[i], okAt[i] = b, true
			}
		}()
	}
	for i := range evs {
		next <- i
	}
	close(next)
	wg.Wait()
	kept := out[:0]
	for i, b := range out {
		if okAt[i] {
			kept = append(kept, b)
		}
	}
	return kept
}

// heightsPerQuery is how many heights one store question names (#B).
const heightsPerQuery = 500

// readHeights reads the publisher's anchors for heights [from, to], by
// naming the heights in a #B filter: paging that no created_at shared by
// thousands of anchors can stall. A question whose answer fills the store's
// cap is asked again in halves.
func (l *AnchorLine) readHeights(from, to uint64) ([]nostr.Event, error) {
	if from > to {
		return nil, nil
	}
	names := make([]string, 0, to-from+1)
	for h := from; h <= to; h++ {
		names = append(names, strconv.FormatUint(h, 10))
	}
	limit := l.cfg.MaxResults
	if limit <= 0 {
		limit = 4 * len(names)
	}
	evs, err := l.cfg.Query([]nostr.Filter{{Authors: []string{l.cfg.Publisher}, Kinds: []int{KindBlockAnchor}, Tags: map[string][]string{"B": names}}}, limit)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		l.newest = max(l.newest, e.CreatedAt)
	}
	if len(evs) >= limit {
		if from == to {
			return nil, fmt.Errorf("line: more than %d anchors for height %d", limit, from)
		}
		mid := from + (to-from)/2
		lo, err := l.readHeights(from, mid)
		if err != nil {
			return nil, err
		}
		hi, err := l.readHeights(mid+1, to)
		return append(lo, hi...), err
	}
	return evs, nil
}

// highestAnchored is the highest B among the publisher's newest anchors.
func (l *AnchorLine) highestAnchored() (uint64, bool, error) {
	evs, err := l.cfg.Query([]nostr.Filter{{Authors: []string{l.cfg.Publisher}, Kinds: []int{KindBlockAnchor}}}, 64)
	if err != nil {
		return 0, false, err
	}
	var top uint64
	found := false
	for _, ev := range evs {
		for _, v := range tagValues(ev, "B") {
			if h, err := strconv.ParseUint(v, 10, 64); err == nil && isCanonicalHeight(v) && (!found || h > top) {
				top, found = h, true
			}
		}
	}
	return top, found, nil
}

// Load reads the whole line from the store, a batch of heights at a time,
// until past the highest anchored height, and then fills what gaps the
// fallback can. The line answers for the heights read so far while it loads.
func (l *AnchorLine) Load(ctx context.Context) error {
	l.update.Lock()
	defer l.update.Unlock()
	start := time.Now()
	// The newest anchors give a height to read up to at least; past it,
	// reading goes on until two batches in a row hold nothing, since
	// anchors that share a created_at (a backfill signs thousands in one
	// second) make "the newest" an arbitrary few.
	top, _, err := l.highestAnchored()
	if err != nil {
		return err
	}
	empty := 0
	for from := uint64(0); from <= top || empty < 2; from += heightsPerQuery {
		if err := ctx.Err(); err != nil {
			return err
		}
		evs, err := l.readHeights(from, from+heightsPerQuery-1)
		if err != nil {
			return err
		}
		if len(evs) == 0 {
			empty++
		} else {
			empty = 0
		}
		l.add(l.resolveAnchors(evs))
	}
	l.fill(ctx)
	l.mu.Lock()
	l.loaded = true
	l.reindex(true)
	tip := len(l.hashes) - 1
	l.mu.Unlock()
	l.log("line: loaded", "tip", tip, "highest_anchored", top, "pending", l.pendingCount(), "seconds", time.Since(start).Seconds())
	return nil
}

// Update reads the anchors above the tip, and the blocks below it when one
// above does not link (a reorganization), and fills gaps.
func (l *AnchorLine) Update(ctx context.Context) error {
	l.update.Lock()
	defer l.update.Unlock()
	tip, _ := l.Tip()
	next := tip + 1
	if len(l.snapshotHashes()) == 0 {
		next = 0
	}
	evs, err := l.readHeights(next, next+heightsPerQuery-1)
	if err != nil {
		return err
	}
	l.add(l.resolveAnchors(evs))
	l.mu.RLock()
	atTip := l.pending[uint64(len(l.hashes))]
	sig := fmt.Sprint(uint64(len(l.hashes)), len(atTip))
	for _, b := range atTip {
		sig += hex.EncodeToString(b.hash[:4])
	}
	l.mu.RUnlock()
	stuck := len(atTip) > 0
	if stuck && next > 0 {
		l.stuckPolls++
		fresh, err := l.freshAnchors()
		if err != nil {
			return err
		}
		stuck = sig != l.stuckSig || fresh || l.stuckPolls >= stuckEvery
	}
	if stuck && next > 0 {
		l.stuckSig, l.stuckPolls = sig, 0
		// A block above the tip names something else as previous: read
		// the recent blocks again, competing anchors included.
		from := uint64(0)
		if next > 2*heightsPerQuery {
			from = next - 2*heightsPerQuery
		}
		evs, err := l.readHeights(from, next-1)
		if err != nil {
			return err
		}
		l.add(l.resolveAnchors(evs))
	}
	l.fill(ctx)
	l.mu.Lock()
	l.reindex(false)
	grown := uint64(len(l.hashes)) - next
	l.mu.Unlock()
	if len(l.snapshotHashes()) > 0 && next > 0 && grown > uint64(l.cfg.MaxReorgDepth) && l.cfg.Alert != nil {
		// Normal after downtime or a republished gap; also what a leaked
		// key extending the tip with fake blocks looks like.
		l.cfg.Alert("line: one update appended more blocks than the reorganization cap; check them against a Bitcoin node (the cap would keep fake ones)",
			"from_height", next, "blocks", grown, "max_depth", l.cfg.MaxReorgDepth)
	}
	return nil
}

// freshAnchors reports whether the store holds anchors by the publisher
// signed after the newest one read: one indexed question for one event.
// Called under update.
func (l *AnchorLine) freshAnchors() (bool, error) {
	since := time.Unix(l.newest+1, 0)
	evs, err := l.cfg.Query([]nostr.Filter{{Authors: []string{l.cfg.Publisher}, Kinds: []int{KindBlockAnchor}, Since: &since}}, 1)
	if err != nil {
		return false, err
	}
	return len(evs) > 0, nil
}

// Run loads the line, then updates it every interval until ctx ends.
func (l *AnchorLine) Run(ctx context.Context, interval time.Duration) {
	for {
		if err := l.Load(ctx); err == nil {
			break
		} else if ctx.Err() != nil {
			return
		} else {
			l.log("line: load failed, retrying", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.Update(ctx); err != nil {
				l.log("line: update failed", "error", err.Error())
			}
		}
	}
}

func (l *AnchorLine) snapshotHashes() [][32]byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.hashes
}

func (l *AnchorLine) pendingCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := 0
	for _, bs := range l.pending {
		n += len(bs)
	}
	return n
}

// alreadyOnLine reports whether an anchor names (by B and H) a block that
// is on the line at that height.
func alreadyOnLine(ev nostr.Event, onLine [][32]byte) bool {
	bs, hs := tagValues(ev, "B"), tagValues(ev, "H")
	if len(bs) != 1 || len(hs) != 1 {
		return false
	}
	h, err := strconv.ParseUint(bs[0], 10, 64)
	if err != nil || h >= uint64(len(onLine)) || strconv.FormatUint(h, 10) != bs[0] {
		return false
	}
	raw, err := hex.DecodeString(hs[0])
	return err == nil && len(raw) == 32 && [32]byte(raw) == onLine[h]
}

// ── linking ──────────────────────────────────────────────────────────────

// add puts blocks into pending and extends the line from them.
func (l *AnchorLine) add(blocks []anchorBlock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range blocks {
		if b.height < uint64(len(l.hashes)) && l.hashes[b.height] == b.hash {
			continue // already on the line
		}
		if !slices.ContainsFunc(l.pending[b.height], func(p anchorBlock) bool { return p.hash == b.hash }) {
			l.pending[b.height] = append(l.pending[b.height], b)
		}
	}
	l.link()
}

// link extends the line with pending blocks, and reorganizes it when a
// pending chain that parts from it below the tip is longer. Called with mu
// held.
func (l *AnchorLine) link() {
	for {
		tip := uint64(len(l.hashes))
		var prev [32]byte
		if tip > 0 {
			prev = l.hashes[tip-1]
		}
		var kids []anchorBlock
		for _, b := range l.pending[tip] {
			if b.prev == prev {
				kids = append(kids, b)
			}
		}
		if len(kids) == 1 && len(l.pending[tip+1]) <= 1 {
			l.appendBlock(kids[0]) // the usual case: one block, no rival above
			continue
		}
		if len(kids) > 0 {
			best := l.longest(kids)
			for _, b := range best {
				l.appendBlock(b)
			}
			continue
		}
		if !l.reorganize() {
			return
		}
	}
}

func (l *AnchorLine) appendBlock(b anchorBlock) {
	l.hashes = append(l.hashes, b.hash)
	l.coords = append(l.coords, b.coord)
	rest := l.pending[b.height][:0]
	for _, p := range l.pending[b.height] {
		if p.hash != b.hash {
			rest = append(rest, p)
		}
	}
	if len(rest) == 0 {
		delete(l.pending, b.height)
	} else {
		l.pending[b.height] = rest
	}
}

// longest is the longest chain of pending blocks starting with one of
// starts (all at one height); on a tie, the one whose first block was
// anchored first, then the lower hash, so the answer never depends on the
// order the store returned them in.
func (l *AnchorLine) longest(starts []anchorBlock) []anchorBlock {
	firstSeen := func(bs []anchorBlock) []anchorBlock {
		bs = slices.Clone(bs)
		slices.SortFunc(bs, func(a, b anchorBlock) int {
			if a.seen != b.seen {
				return int(a.seen - b.seen)
			}
			return bytes.Compare(a.hash[:], b.hash[:])
		})
		return bs
	}
	var best []anchorBlock
	for _, s := range firstSeen(starts) {
		chain := []anchorBlock{s}
		// The longest continuation: depth-first over the few pending
		// blocks above, which is cheap since rivals are rare.
		var walk func(b anchorBlock) []anchorBlock
		walk = func(b anchorBlock) []anchorBlock {
			var longest []anchorBlock
			for _, c := range firstSeen(l.pending[b.height+1]) {
				if c.prev == b.hash {
					if sub := append([]anchorBlock{c}, walk(c)...); len(sub) > len(longest) {
						longest = sub
					}
				}
			}
			return longest
		}
		chain = append(chain, walk(s)...)
		if len(chain) > len(best) {
			best = chain
		}
	}
	return best
}

// reorganize replaces the top of the line with a longer pending chain that
// parts from it below the tip, if there is one. The blocks it displaces go
// to pending. Once the line is loaded, a chain that would displace more
// than MaxReorgDepth blocks is refused and reported (once per rival tip): the
// line keeps its chain. During Load the cap does not apply, since the line
// is still being built in batches of heights and a rival read in one batch
// may only prove longer in the next. Called with mu held.
func (l *AnchorLine) reorganize() bool {
	tip := uint64(len(l.hashes))
	var bestFork uint64
	var best []anchorBlock
	// Map order is random; walk the fork heights in order so the result
	// and the reports never depend on it.
	heights := make([]uint64, 0, len(l.pending))
	for h := range l.pending {
		heights = append(heights, h)
	}
	slices.Sort(heights)
	for _, h := range heights {
		bs := l.pending[h]
		if h == 0 || h >= tip {
			continue
		}
		var starts []anchorBlock
		for _, b := range bs {
			if b.prev == l.hashes[h-1] && b.hash != l.hashes[h] {
				starts = append(starts, b)
			}
		}
		if len(starts) == 0 {
			continue
		}
		chain := l.longest(starts)
		if end := h + uint64(len(chain)); end > tip && l.loaded && tip-h > uint64(l.cfg.MaxReorgDepth) {
			if key := [2]uint64{h, end}; !l.refused[key] {
				l.refused[key] = true
				if l.cfg.Alert != nil {
					l.cfg.Alert("line: REFUSED a reorganization deeper than the cap; the line keeps its chain and needs the operator (a leaked publisher key?)",
						"from_height", h, "depth", tip-h, "max_depth", l.cfg.MaxReorgDepth, "tip", tip-1, "rival_tip", end-1,
						"rival_hash", hex.EncodeToString(chain[len(chain)-1].hash[:]))
				}
			}
			// Refused for good: drop its blocks, so they neither block
			// the fallback at the tip nor keep the stuck path re-reading.
			l.dropPending(chain)
			continue
		}
		if h+uint64(len(chain)) > tip && (best == nil || h+uint64(len(chain)) > bestFork+uint64(len(best))) {
			bestFork, best = h, chain
		}
	}
	if best == nil {
		return false
	}
	for h := bestFork; h < tip; h++ {
		var prev [32]byte
		if h > 0 {
			prev = l.hashes[h-1]
		}
		l.pending[h] = append(l.pending[h], anchorBlock{height: h, hash: l.hashes[h], prev: prev, coord: l.coords[h]})
	}
	// New slices, so readers of the old ones (an index build) see no change.
	l.hashes = append([][32]byte(nil), l.hashes[:bestFork]...)
	l.coords = append([][32]byte(nil), l.coords[:bestFork]...)
	for _, b := range best {
		l.appendBlock(b)
	}
	l.epoch++
	l.index = nil
	l.log("line: reorganized", "from_height", bestFork, "old_tip", tip-1, "new_tip", len(l.hashes)-1, "epoch", l.epoch)
	if depth := tip - bestFork; !l.loaded && depth > uint64(l.cfg.MaxReorgDepth) && l.cfg.Alert != nil {
		// The cap does not apply while loading, but the operator should
		// know the store holds a fork that deep.
		l.cfg.Alert("line: the load took a reorganization deeper than the cap; check the anchors (a leaked publisher key?)",
			"from_height", bestFork, "depth", depth, "max_depth", l.cfg.MaxReorgDepth, "new_tip", len(l.hashes)-1)
	}
	return true
}

// dropPending removes blocks from pending. Called with mu held.
func (l *AnchorLine) dropPending(blocks []anchorBlock) {
	for _, b := range blocks {
		rest := l.pending[b.height][:0]
		for _, p := range l.pending[b.height] {
			if p.hash != b.hash {
				rest = append(rest, p)
			}
		}
		if len(rest) == 0 {
			delete(l.pending, b.height)
		} else {
			l.pending[b.height] = rest
		}
	}
}

// ── the fallback ─────────────────────────────────────────────────────────

// fill fills the gap above the tip from the fallback, when the pending
// block just above the gap is near enough: headers fetched by hash from the
// block above down to the tip, each hashing to the hash asked for, the last
// naming the tip as its previous.
func (l *AnchorLine) fill(ctx context.Context) {
	for {
		l.mu.RLock()
		tip := uint64(len(l.hashes))
		var tipHash [32]byte
		if tip > 0 {
			tipHash = l.hashes[tip-1]
		}
		above, ok := uint64(0), false
		for h := range l.pending {
			if h > tip && (!ok || h < above) {
				above, ok = h, true
			}
		}
		// fillTip and fillFailed are fill's own, under update (see the type).
		if l.fillTip != tip || l.fillFailed == nil {
			l.fillTip, l.fillFailed = tip, map[[32]byte]time.Time{}
		}
		var tops []anchorBlock
		if ok {
			for _, b := range l.pending[above] {
				if failed, seen := l.fillFailed[b.hash]; !seen || time.Since(failed) >= fillRetry {
					tops = append(tops, b)
				}
			}
		}
		// Only a block at the tip that links to it closes the gap; a rival
		// sitting there (named another previous) must not stop the fill.
		atTip := slices.ContainsFunc(l.pending[tip], func(b anchorBlock) bool { return b.prev == tipHash })
		l.mu.RUnlock()
		if !ok || atTip || len(tops) == 0 {
			return // nothing above, the tip linked, or every candidate failed for this tip
		}
		if l.cfg.Fallback == nil || above-tip > uint64(l.cfg.MaxFallbackGap) {
			if l.gapLog != tip {
				l.gapLog = tip
				l.log("line: gap; the line stops below it", "missing_from", tip, "next_anchored", above, "fallback", l.cfg.Fallback != nil)
			}
			return
		}
		// Each block anchored just above the gap, in turn: one may be a
		// rival's, whose headers do not lead down to the tip.
		var blocks []anchorBlock
		var err error
		for _, top := range tops {
			if blocks, err = l.headersDown(ctx, top.prev, above-1, tip, tipHash); err == nil {
				break
			}
			if ctx.Err() == nil {
				l.fillFailed[top.hash] = time.Now() // not again for a while
			}
		}
		if err != nil {
			l.log("line: fallback did not fill the gap", "missing_from", tip, "next_anchored", above, "error", err.Error())
			return
		}
		l.log("line: gap filled from block headers", "from", tip, "to", above-1)
		l.add(blocks)
	}
}

// headersDown fetches the blocks from height down to low, starting from the
// hash of the block at height, checking each header hashes to the hash
// asked for and that the lowest names below as its previous.
func (l *AnchorLine) headersDown(ctx context.Context, hash [32]byte, height, low uint64, below [32]byte) ([]anchorBlock, error) {
	var out []anchorBlock
	for h := height; ; h-- {
		raw, err := l.cfg.Fallback.Header(ctx, hash)
		if err != nil {
			return nil, err
		}
		b, err := blockFromHeader(raw, hash, h)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
		hash = b.prev
		if h == low {
			if b.prev != below {
				return nil, fmt.Errorf("header of block %d does not name the line's tip as previous", h)
			}
			return out, nil
		}
	}
}

// blockFromHeader checks an 80-byte header against the hash it was asked
// for and makes its block: previous hash, merkle root and stop (§1).
func blockFromHeader(raw []byte, want [32]byte, height uint64) (anchorBlock, error) {
	if len(raw) != 80 {
		return anchorBlock{}, fmt.Errorf("header of block %d is %d bytes, not 80", height, len(raw))
	}
	first := sha256.Sum256(raw)
	got := sha256.Sum256(first[:])
	slices.Reverse(got[:]) // display order
	if got != want {
		return anchorBlock{}, fmt.Errorf("header of block %d does not hash to %x", height, want)
	}
	b := anchorBlock{height: height, hash: want}
	copy(b.prev[:], raw[4:36])
	slices.Reverse(b.prev[:])
	var merkle [32]byte
	copy(merkle[:], raw[36:68])
	slices.Reverse(merkle[:])
	if merkle[31]&1 == 1 {
		b.coord = merkle
	} else {
		b.coord = LandfallCoord(want[:])
	}
	return b, nil
}

// ── the station (DECK-0001 §4) ───────────────────────────────────────────

// reindexAfter is how many heights above the index are scanned before the
// index is rebuilt.
const reindexAfter = 4096

// reindex rebuilds the station index when it is missing or far behind the
// tip, or always when force. Called with mu held; a rebuild over a million
// stops takes about a second.
func (l *AnchorLine) reindex(force bool) {
	n := len(l.coords)
	if l.index != nil && !force && n-l.index.n < reindexAfter {
		return
	}
	l.index = newStationIndex(l.coords[:n])
}

// stationIndex orders heights by stop coordinate with the plane bit
// cleared, ties by height (DECK-0001 §4.4), with a segment tree of the least
// height over any run of that order.
type stationIndex struct {
	n     int
	order []uint32
	tree  []uint32
}

func newStationIndex(coords [][32]byte) *stationIndex {
	ix := &stationIndex{n: len(coords), order: make([]uint32, len(coords))}
	for i := range ix.order {
		ix.order[i] = uint32(i)
	}
	slices.SortFunc(ix.order, func(a, b uint32) int {
		if c := compareKeys(&coords[a], &coords[b], 255); c != 0 {
			return c
		}
		return int(int64(a) - int64(b))
	})
	ix.tree = make([]uint32, 2*ix.n)
	for i, h := range ix.order {
		ix.tree[ix.n+i] = h
	}
	for i := ix.n - 1; i > 0; i-- {
		ix.tree[i] = min(ix.tree[2*i], ix.tree[2*i+1])
	}
	return ix
}

// rangeMin is the least height among order[lo:hi], or false when empty.
func (ix *stationIndex) rangeMin(lo, hi int) (uint32, bool) {
	best, ok := uint32(0), false
	for lo, hi = lo+ix.n, hi+ix.n; lo < hi; lo, hi = lo>>1, hi>>1 {
		if lo&1 == 1 {
			if !ok || ix.tree[lo] < best {
				best, ok = ix.tree[lo], true
			}
			lo++
		}
		if hi&1 == 1 {
			hi--
			if !ok || ix.tree[hi] < best {
				best, ok = ix.tree[hi], true
			}
		}
	}
	return best, ok
}

// compareKeys compares the top bits of two coordinates, the plane bit
// (bit 0) never included: 255 is the whole interleaved coordinate.
func compareKeys(a, b *[32]byte, bits int) int {
	full := bits / 8
	if c := bytes.Compare(a[:full], b[:full]); c != 0 || full == 32 {
		return c
	}
	if rest := bits % 8; rest > 0 {
		mask := byte(0xff << (8 - rest))
		x, y := a[full]&mask, b[full]&mask
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// keyDistance is d of DECK-0001 §4.1 from packed coordinates: the axes
// interleave from the top (x84 y84 z84 x83 ...), so sharing the top L bits
// is sharing L/3 leading bits on the axis that differs first, and d is
// 85 - floor(L/3).
func keyDistance(a, b *[32]byte) int {
	L := 0
	for i := 0; i < 32; i++ {
		x := a[i] ^ b[i]
		if i == 31 {
			x &^= 1
		}
		if x == 0 {
			L += 8
			continue
		}
		for x&0x80 == 0 {
			x <<= 1
			L++
		}
		break
	}
	return AxisBits - min(L, 255)/3
}

// station is the height of the stop at or below bound nearest key, ties to
// the lowest height (§4.2): the index answers for its heights, and the
// heights above it are scanned.
func station(key [32]byte, bound uint64, coords [][32]byte, ix *stationIndex) uint64 {
	best, bestD := uint64(0), AxisBits+1
	consider := func(h uint64, d int) {
		if d < bestD || d == bestD && h < best {
			best, bestD = h, d
		}
	}
	from := uint64(0)
	if ix != nil && ix.n > 0 {
		if h, d, ok := ix.query(key, bound, coords); ok {
			consider(h, d)
		}
		from = uint64(ix.n)
	}
	for h := from; h <= bound && h < uint64(len(coords)); h++ {
		consider(h, keyDistance(&key, &coords[h]))
	}
	return best
}

// query is the station among the indexed heights: the largest q for which
// some indexed stop at or below bound shares the top 3q bits of key, the
// lowest such height, and its distance 85 - q.
func (ix *stationIndex) query(key [32]byte, bound uint64, coords [][32]byte) (uint64, int, bool) {
	within := func(q int) (uint32, bool) {
		bits := 3 * q
		lo, _ := slices.BinarySearchFunc(ix.order, 0, func(h uint32, _ int) int {
			if compareKeys(&coords[h], &key, bits) < 0 {
				return -1
			}
			return 1
		})
		hi, _ := slices.BinarySearchFunc(ix.order, 0, func(h uint32, _ int) int {
			if compareKeys(&coords[h], &key, bits) <= 0 {
				return -1
			}
			return 1
		})
		h, ok := ix.rangeMin(lo, hi)
		return h, ok && uint64(h) <= bound
	}
	if _, ok := within(0); !ok {
		return 0, 0, false
	}
	// within(q) holds for every q up to the answer and for none above.
	lo, hi := 0, AxisBits
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if _, ok := within(mid); ok {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	h, _ := within(lo)
	return uint64(h), AxisBits - lo, true
}

// HTTPHeaders is a HeaderSource over the Esplora block API that
// mempool.space and blockstream.info serve: GET <base>/block/<hash>/header
// answers the header as 160 hex characters. Each base is tried in turn.
type HTTPHeaders struct {
	Bases  []string
	Client *http.Client
}

// Header implements HeaderSource.
func (s HTTPHeaders) Header(ctx context.Context, hash [32]byte) ([]byte, error) {
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var errs []string
	for _, base := range s.Bases {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/block/"+hex.EncodeToString(hash[:])+"/header", nil)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Sprintf("%s: status %d", base, resp.StatusCode))
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(body)))
		if err != nil || len(raw) != 80 {
			errs = append(errs, base+": not an 80-byte header in hex")
			continue
		}
		return raw, nil
	}
	return nil, fmt.Errorf("no header for %x: %s", hash, strings.Join(errs, "; "))
}
