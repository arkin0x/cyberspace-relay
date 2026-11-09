package regiongate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"
)

// ── a synthetic Bitcoin chain, from real 80-byte headers ─────────────────

type testBlock struct {
	height        uint64
	header        []byte
	hash, prev    [32]byte // display order
	merkle, coord [32]byte
}

// testChain makes n blocks on top of below (zero for a chain from genesis),
// starting at height from; seed varies the merkle roots, so two chains from
// one parent differ.
func testChain(from uint64, below [32]byte, n int, seed int64) []testBlock {
	rng := rand.New(rand.NewSource(seed))
	out := make([]testBlock, n)
	prev := below
	for i := range out {
		h := make([]byte, 80)
		binary.LittleEndian.PutUint32(h[0:4], 0x20000000)
		p := prev
		slices.Reverse(p[:])
		copy(h[4:36], p[:])
		var m [32]byte
		rng.Read(m[:])
		mi := m
		slices.Reverse(mi[:])
		copy(h[36:68], mi[:])
		binary.LittleEndian.PutUint32(h[68:72], uint32(1700000000+i))
		rng.Read(h[72:80])
		first := sha256.Sum256(h)
		hash := sha256.Sum256(first[:])
		slices.Reverse(hash[:])
		b := testBlock{height: from + uint64(i), header: h, hash: hash, prev: prev, merkle: m}
		if m[31]&1 == 1 {
			b.coord = m
		} else {
			b.coord = LandfallCoord(hash[:])
		}
		out[i] = b
		prev = hash
	}
	return out
}

// anchor signs a block's anchor: legacy (no M, C the merkle root) or with M.
func (b testBlock) anchor(t *testing.T, s *signer, withM bool, at int64, extra ...[]string) nostr.Event {
	t.Helper()
	c := b.merkle
	if withM {
		c = b.coord
	}
	tags := [][]string{{"C", hex.EncodeToString(c[:])}, {"B", strconv.FormatUint(b.height, 10)},
		{"H", hex.EncodeToString(b.hash[:])}, {"P", hex.EncodeToString(b.prev[:])}}
	if withM {
		tags = append(tags, []string{"M", hex.EncodeToString(b.merkle[:])})
	}
	tags = append(tags, extra...)
	return s.sign(t, KindBlockAnchor, at, tags...)
}

// ── a store ──────────────────────────────────────────────────────────────

// memStore answers filters as nostrdb does, newest first, capped at max.
type memStore struct {
	mu      sync.Mutex
	events  []nostr.Event
	max     int
	queries int
}

func (s *memStore) add(evs ...nostr.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evs...)
}

func (s *memStore) query(filters []nostr.Filter, limit int) ([]nostr.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	if s.max > 0 && limit > s.max {
		limit = s.max
	}
	var out []nostr.Event
	for _, e := range s.events {
		for _, f := range filters {
			if f.MatchesEvent(e) {
				out = append(out, e)
				break
			}
		}
	}
	slices.SortStableFunc(out, func(a, b nostr.Event) int { return int(b.CreatedAt - a.CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func newTestLine(s *memStore, publisher string, fallback HeaderSource) (*AnchorLine, *[]string) {
	var logs []string
	var mu sync.Mutex
	l := NewAnchorLine(AnchorLineConfig{Publisher: publisher, Query: s.query, MaxResults: s.max, Fallback: fallback,
		Signature: validation.CheckSignature, Workers: 4, Log: func(msg string, args ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprint(msg, args))
			mu.Unlock()
		}})
	return l, &logs
}

func checkLine(t *testing.T, l *AnchorLine, blocks []testBlock) {
	t.Helper()
	tip, ok := l.Tip()
	if !ok || tip != blocks[len(blocks)-1].height {
		t.Fatalf("tip %d %v, want %d", tip, ok, blocks[len(blocks)-1].height)
	}
	for _, b := range blocks {
		stop, _ := l.Stop(b.height)
		hash, _ := l.BlockHash(b.height)
		if stop != hex.EncodeToString(b.coord[:]) || hex.EncodeToString(hash) != hex.EncodeToString(b.hash[:]) {
			t.Fatalf("block %d: stop %s hash %x, want %x %x", b.height, stop, hash, b.coord, b.hash)
		}
	}
}

// TestAnchorLineLoads builds a line from legacy anchors (no M: C is the
// merkle root, a landfall derived here) and anchors with M, all signed in
// the same second, from a store that answers at most 50 events at once:
// paging by height cannot stall on a created_at thousands share.
func TestAnchorLineLoads(t *testing.T) {
	pub := newSigner(t)
	blocks := testChain(0, [32]byte{}, 1200, 1)
	s := &memStore{max: 50}
	for _, b := range blocks {
		s.add(b.anchor(t, pub, b.height >= 600, 1775660875))
	}
	ports := 0
	for _, b := range blocks {
		if b.merkle[31]&1 == 1 {
			ports++
		}
	}
	if ports == 0 || ports == len(blocks) {
		t.Fatal("want both ports and landfalls")
	}
	l, _ := newTestLine(s, pub.pubkey, nil)
	if err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkLine(t, l, blocks)
	if l.Epoch() != 0 || l.pendingCount() != 0 {
		t.Fatalf("epoch %d, pending %d", l.Epoch(), l.pendingCount())
	}
}

// TestAnchorLineRefusesBadAnchors: each kind of bad anchor at a height
// leaves that height off the line, so the line stops below it, until a good
// one arrives.
func TestAnchorLineRefusesBadAnchors(t *testing.T) {
	pub, other := newSigner(t), newSigner(t)
	blocks := testChain(0, [32]byte{}, 40, 2)
	var landfall, port testBlock
	for _, b := range blocks[10:] {
		if b.merkle[31]&1 == 0 && landfall.height == 0 {
			landfall = b
		}
		if b.merkle[31]&1 == 1 && port.height == 0 {
			port = b
		}
	}
	wrongC := func(b testBlock) [32]byte { c := b.coord; c[5] ^= 1; return c }
	cases := []struct {
		name string
		make func() nostr.Event
	}{
		{"another publisher", func() nostr.Event { return landfall.anchor(t, other, true, 1) }},
		{"a bad signature", func() nostr.Event { e := landfall.anchor(t, pub, true, 1); e.Sig = strings.Repeat("0", 128); return e }},
		{"M with a landfall C that is not the derivation", func() nostr.Event {
			b := landfall
			b.coord = wrongC(b)
			return b.anchor(t, pub, true, 1)
		}},
		{"a port whose C is not its merkle root", func() nostr.Event {
			b := port
			b.coord = wrongC(b)
			return b.anchor(t, pub, true, 1)
		}},
		{"B twice", func() nostr.Event { return landfall.anchor(t, pub, true, 1, []string{"B", "7"}) }},
		{"B with a leading zero", func() nostr.Event {
			e := landfall.anchor(t, pub, true, 1)
			for i, tag := range e.Tags {
				if tag[0] == "B" {
					e.Tags[i] = []string{"B", "0" + tag[1]}
				}
			}
			return pubResign(t, pub, e)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := c.make()
			badHeight := landfall.height
			if strings.HasPrefix(c.name, "a port") {
				badHeight = port.height
			}
			s := &memStore{}
			for _, b := range blocks {
				if b.height != badHeight {
					s.add(b.anchor(t, pub, true, 1))
				}
			}
			s.add(bad)
			l, _ := newTestLine(s, pub.pubkey, nil)
			if err := l.Load(context.Background()); err != nil {
				t.Fatal(err)
			}
			if tip, _ := l.Tip(); tip != badHeight-1 {
				t.Fatalf("tip %d, want %d: the bad anchor was used", tip, badHeight-1)
			}
			// The good anchor arrives: the next update links everything.
			s.add(blocks[badHeight].anchor(t, pub, true, 2))
			if err := l.Update(context.Background()); err != nil {
				t.Fatal(err)
			}
			checkLine(t, l, blocks)
		})
	}
}

func pubResign(t *testing.T, s *signer, e nostr.Event) nostr.Event {
	return s.sign(t, e.Kind, e.CreatedAt, e.Tags...)
}

// headerServer is a HeaderSource over blocks; lie makes it answer every
// header with one bit changed.
type headerServer struct {
	byHash map[[32]byte][]byte
	lie    bool
	asked  int
}

func (h *headerServer) Header(_ context.Context, hash [32]byte) ([]byte, error) {
	h.asked++
	raw, ok := h.byHash[hash]
	if !ok {
		return nil, errors.New("no such block")
	}
	raw = append([]byte(nil), raw...)
	if h.lie {
		raw[40] ^= 1
	}
	return raw, nil
}

func headersOf(blocks []testBlock) *headerServer {
	h := &headerServer{byHash: map[[32]byte][]byte{}}
	for _, b := range blocks {
		h.byHash[b.hash] = b.header
	}
	return h
}

// TestAnchorLineGap: heights no anchor covers stop the line below them; the
// fallback fills them from headers fetched by hash and checked against it,
// and a source that lies fills nothing.
func TestAnchorLineGap(t *testing.T) {
	pub := newSigner(t)
	blocks := testChain(0, [32]byte{}, 60, 3)
	gap := map[uint64]bool{20: true, 21: true, 22: true, 40: true}
	s := &memStore{}
	for _, b := range blocks {
		if !gap[b.height] {
			s.add(b.anchor(t, pub, b.height%2 == 0, 1))
		}
	}
	t.Run("no fallback", func(t *testing.T) {
		l, logs := newTestLine(s, pub.pubkey, nil)
		l.Load(context.Background())
		if tip, _ := l.Tip(); tip != 19 {
			t.Fatalf("tip %d, want 19", tip)
		}
		if !slices.ContainsFunc(*logs, func(m string) bool { return strings.Contains(m, "gap") }) {
			t.Fatal("the gap is not reported")
		}
	})
	t.Run("a lying fallback", func(t *testing.T) {
		src := headersOf(blocks)
		src.lie = true
		l, _ := newTestLine(s, pub.pubkey, src)
		l.Load(context.Background())
		if tip, _ := l.Tip(); tip != 19 {
			t.Fatalf("tip %d, want 19: a header that does not hash to the anchored hash was used", tip)
		}
	})
	t.Run("fallback", func(t *testing.T) {
		l, _ := newTestLine(s, pub.pubkey, headersOf(blocks))
		l.Load(context.Background())
		checkLine(t, l, blocks)
		if !strings.HasSuffix(l.Name(), "+headers") {
			t.Fatalf("name %q does not say the line uses headers", l.Name())
		}
	})
	t.Run("a gap too long for the fallback", func(t *testing.T) {
		src := headersOf(blocks)
		l := NewAnchorLine(AnchorLineConfig{Publisher: pub.pubkey, Query: s.query, Fallback: src, MaxFallbackGap: 2})
		l.Load(context.Background())
		if tip, _ := l.Tip(); tip != 19 || src.asked != 0 {
			t.Fatalf("tip %d, %d headers asked; want 19 and none", tip, src.asked)
		}
	})
}

// TestAnchorLineFollowsTheLongerChain: anchors of a competing chain from
// below the tip reorganize the line only once that chain is longer, and the
// epoch counts it; a tie keeps the line.
func TestAnchorLineFollowsTheLongerChain(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 50, 4)
	s := &memStore{}
	for _, b := range main {
		s.add(b.anchor(t, pub, true, 1))
	}
	// A rival as long as the line, anchored later, read with it: the line
	// keeps the chain anchored first, however the store orders them, and
	// the next update does not move to the rival.
	rival := testChain(45, main[44].hash, 5, 5) // 45..49
	for _, b := range rival {
		s.add(b.anchor(t, pub, true, 2))
	}
	l, _ := newTestLine(s, pub.pubkey, nil)
	l.Load(context.Background())
	checkLine(t, l, main)
	l.Update(context.Background())
	checkLine(t, l, main)
	if l.Epoch() != 0 || l.pendingCount() != len(rival) {
		t.Fatalf("a tie reorganized the line (epoch %d, %d pending)", l.Epoch(), l.pendingCount())
	}
	more := testChain(50, rival[4].hash, 2, 6) // the rival grows past the tip
	for _, b := range more {
		s.add(b.anchor(t, pub, true, 3))
	}
	l.Update(context.Background())
	want := append(append(append([]testBlock(nil), main[:45]...), rival...), more...)
	checkLine(t, l, want)
	if l.Epoch() != 1 {
		t.Fatalf("epoch %d after one reorganization", l.Epoch())
	}
	if !strings.Contains((SpecProofs{Line: l}).LineState(), "@1") {
		t.Fatalf("line state %q does not carry the epoch", (SpecProofs{Line: l}).LineState())
	}
}

// asBlocks gives test blocks as the line holds them, for add.
func asBlocks(tbs ...[]testBlock) []anchorBlock {
	var out []anchorBlock
	for _, part := range tbs {
		for _, b := range part {
			out = append(out, anchorBlock{height: b.height, hash: b.hash, prev: b.prev, coord: b.coord, seen: 1})
		}
	}
	return out
}

func countLogs(logs *[]string, substr string) int {
	n := 0
	for _, m := range *logs {
		if strings.Contains(m, substr) {
			n++
		}
	}
	return n
}

// TestAnchorLineRefusesADeepReorganization: once loaded, a longer rival
// that would displace more than 6 blocks (owner ruling 2026-11-09) is
// refused: the line keeps its chain and its epoch, the refusal is reported
// once however many polls see it, and the line still grows on its own chain.
func TestAnchorLineRefusesADeepReorganization(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 60, 21)
	s := &memStore{}
	for _, b := range main[:50] {
		s.add(b.anchor(t, pub, true, 1))
	}
	l, logs := newTestLine(s, pub.pubkey, nil)
	l.Load(context.Background())
	checkLine(t, l, main[:50])
	// Parts at 43: it would displace 43..49, seven blocks, and is longer.
	rival := testChain(43, main[42].hash, 10, 22) // 43..52
	for _, b := range rival {
		s.add(b.anchor(t, pub, true, 2))
	}
	l.Update(context.Background())
	l.Update(context.Background())
	checkLine(t, l, main[:50])
	if l.Epoch() != 0 {
		t.Fatalf("epoch %d: a seven-deep reorganization was taken", l.Epoch())
	}
	if n := countLogs(logs, "REFUSED"); n != 1 {
		t.Fatalf("the refusal was reported %d times over two polls, want 1", n)
	}
	// The line goes on along its own chain past the rival's tip.
	for _, b := range main[50:] {
		s.add(b.anchor(t, pub, true, 3))
	}
	l.Update(context.Background())
	checkLine(t, l, main)
	if l.Epoch() != 0 {
		t.Fatalf("epoch %d", l.Epoch())
	}
}

// TestAnchorLineTakesASixDeepReorganization: displacing exactly 6 blocks
// is inside the cap.
func TestAnchorLineTakesASixDeepReorganization(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 50, 23)
	s := &memStore{}
	for _, b := range main {
		s.add(b.anchor(t, pub, true, 1))
	}
	l, logs := newTestLine(s, pub.pubkey, nil)
	l.Load(context.Background())
	rival := testChain(44, main[43].hash, 7, 24) // 44..50: displaces 44..49
	for _, b := range rival {
		s.add(b.anchor(t, pub, true, 2))
	}
	l.Update(context.Background())
	checkLine(t, l, append(append([]testBlock(nil), main[:44]...), rival...))
	if l.Epoch() != 1 || countLogs(logs, "REFUSED") != 0 {
		t.Fatalf("epoch %d, %d refusals", l.Epoch(), countLogs(logs, "REFUSED"))
	}
}

// TestAnchorLineCapPicksTheShallowRival: with a refused deep rival and a
// longer shallow one, the line takes the shallow one, and the deep one is
// reported once even though link looks at it again after the shallow
// reorganization.
func TestAnchorLineCapPicksTheShallowRival(t *testing.T) {
	main := testChain(0, [32]byte{}, 50, 25)
	l, logs := newTestLine(&memStore{}, "", nil)
	l.add(asBlocks(main))
	l.mu.Lock()
	l.loaded = true
	l.mu.Unlock()
	deep := testChain(40, main[39].hash, 15, 26)   // 40..54
	shallow := testChain(46, main[45].hash, 6, 27) // 46..51
	l.add(asBlocks(deep, shallow))
	checkLine(t, l, append(append([]testBlock(nil), main[:46]...), shallow...))
	if l.Epoch() != 1 || countLogs(logs, "REFUSED") != 1 {
		t.Fatalf("epoch %d, %d refusals; want 1 and 1", l.Epoch(), countLogs(logs, "REFUSED"))
	}
}

// TestAnchorLineLoadIsNotCapped: while the line is being built, a rival
// that proves longer in a later batch replaces any depth of it (the cap
// guards a running line, not the reading of the store).
func TestAnchorLineLoadIsNotCapped(t *testing.T) {
	main := testChain(0, [32]byte{}, 50, 28)
	l, logs := newTestLine(&memStore{}, "", nil)
	l.add(asBlocks(main))
	rival := testChain(20, main[19].hash, 40, 29) // 20..59
	l.add(asBlocks(rival))
	checkLine(t, l, append(append([]testBlock(nil), main[:20]...), rival...))
	if l.Epoch() != 1 || countLogs(logs, "REFUSED") != 0 {
		t.Fatalf("epoch %d, %d refusals", l.Epoch(), countLogs(logs, "REFUSED"))
	}
}

// TestAnchorLineRefusedRivalAndAGap (second review, #25 item 1): the line
// is at 49, a longer rival forked at 43 is refused, and the honest anchors
// resume at 51 with 50 missing. With the fallback configured, the line must
// fill 50 from headers and grow past 49: the refused rival may neither sit
// in pending at the tip nor be the block the fill starts from.
func TestAnchorLineRefusedRivalAndAGap(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 56, 31)
	s := &memStore{}
	for _, b := range main[:50] {
		s.add(b.anchor(t, pub, true, 1))
	}
	l, logs := newTestLine(s, pub.pubkey, headersOf(main))
	l.Load(context.Background())
	checkLine(t, l, main[:50])
	rival := testChain(43, main[42].hash, 10, 32) // 43..52
	for _, b := range rival {
		s.add(b.anchor(t, pub, true, 2))
	}
	for _, b := range main[51:] { // 50 missing
		s.add(b.anchor(t, pub, true, 3))
	}
	l.Update(context.Background())
	l.Update(context.Background())
	checkLine(t, l, main)
	if l.Epoch() != 0 || countLogs(logs, "REFUSED") != 1 {
		t.Fatalf("epoch %d, %d refusals", l.Epoch(), countLogs(logs, "REFUSED"))
	}
	// The refused rival's blocks are not kept.
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, bs := range l.pending {
		for _, b := range bs {
			if slices.ContainsFunc(rival, func(r testBlock) bool { return r.hash == b.hash }) {
				t.Fatalf("a refused rival block at %d is still pending", b.height)
			}
		}
	}
}

// TestAnchorLineStrayBlockAtTheTip: a stray block anchored at the tip's
// height that names some other previous (a stale block whose parent nobody
// anchored) must not stop the fallback from filling a gap there.
func TestAnchorLineStrayBlockAtTheTip(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 30, 33)
	stray := testChain(20, [32]byte{9}, 1, 34)[0] // at 20, parent unknown
	s := &memStore{}
	for _, b := range main {
		if b.height != 20 {
			s.add(b.anchor(t, pub, true, 1))
		}
	}
	s.add(stray.anchor(t, pub, true, 2))
	l, _ := newTestLine(s, pub.pubkey, headersOf(main))
	l.Load(context.Background())
	checkLine(t, l, main)
}

// TestAnchorLineFillTriesEveryBlockAboveTheGap: when the first block
// anchored just above a gap is a stray whose headers do not lead down to
// the tip, the fill goes on to the next one.
func TestAnchorLineFillTriesEveryBlockAboveTheGap(t *testing.T) {
	main := testChain(0, [32]byte{}, 30, 41)
	stray := testChain(21, [32]byte{5}, 1, 42) // at 21, parent unknown
	l, _ := newTestLine(&memStore{}, "", headersOf(main))
	l.add(asBlocks(main[:20]))
	l.add(asBlocks(stray)) // first above the gap at 20
	l.add(asBlocks(main[21:]))
	l.fill(context.Background())
	checkLine(t, l, main)
}

// TestAnchorLineAlertsOnABigAppend (#25 item 2): an update that appends
// more blocks than the cap is reported; a few are not.
func TestAnchorLineAlertsOnABigAppend(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 40, 35)
	s := &memStore{}
	for _, b := range main[:20] {
		s.add(b.anchor(t, pub, true, 1))
	}
	l, logs := newTestLine(s, pub.pubkey, nil)
	l.Load(context.Background())
	for _, b := range main[20:26] {
		s.add(b.anchor(t, pub, true, 2))
	}
	l.Update(context.Background())
	if n := countLogs(logs, "appended more blocks"); n != 0 {
		t.Fatalf("six appended blocks reported %d times", n)
	}
	for _, b := range main[26:] {
		s.add(b.anchor(t, pub, true, 3))
	}
	l.Update(context.Background())
	checkLine(t, l, main)
	if n := countLogs(logs, "appended more blocks"); n != 1 {
		t.Fatalf("fourteen appended blocks reported %d times, want 1", n)
	}
}

// TestAnchorLineAlertsOnADeepLoadReorganization (#25 item 3): the load is
// not capped, but a reorganization deeper than the cap during it is
// reported.
func TestAnchorLineAlertsOnADeepLoadReorganization(t *testing.T) {
	main := testChain(0, [32]byte{}, 50, 36)
	l, logs := newTestLine(&memStore{}, "", nil)
	l.add(asBlocks(main))
	l.add(asBlocks(testChain(30, main[29].hash, 30, 37))) // 20 deep
	if l.Epoch() != 1 || countLogs(logs, "the load took a reorganization deeper") != 1 {
		t.Fatalf("epoch %d, logs %v", l.Epoch(), *logs)
	}
	l2, logs2 := newTestLine(&memStore{}, "", nil)
	l2.add(asBlocks(main))
	l2.add(asBlocks(testChain(46, main[45].hash, 6, 38))) // 4 deep
	if l2.Epoch() != 1 || countLogs(logs2, "the load took") != 0 {
		t.Fatalf("a shallow load reorganization reported: %v", *logs2)
	}
}

// TestAnchorLineStuckPathIsThrottled (#25 item 4): a block at the tip that
// does not link does not make every poll read about 1,000 heights below
// again, but the re-read still comes at least every stuckEvery polls.
func TestAnchorLineStuckPathIsThrottled(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 30, 39)
	stray := testChain(30, [32]byte{7}, 1, 40)[0] // at the tip's height, parent unknown
	s := &memStore{}
	for _, b := range main {
		s.add(b.anchor(t, pub, true, 1))
	}
	s.add(stray.anchor(t, pub, true, 1))
	l, _ := newTestLine(s, pub.pubkey, nil)
	l.Load(context.Background())
	l.Update(context.Background())
	queries := func() int { s.mu.Lock(); defer s.mu.Unlock(); return s.queries }
	before := queries()
	for i := 0; i < 5; i++ {
		l.Update(context.Background())
	}
	// Each poll: the read above the tip and the one-event check for new
	// anchors. A re-read below would add one more.
	if n := queries() - before; n > 10 {
		t.Fatalf("%d queries for five polls; the stuck path re-reads every poll", n)
	}
	before = queries()
	for i := 0; i < stuckEvery; i++ {
		l.Update(context.Background())
	}
	if n := queries() - before; n <= 2*stuckEvery {
		t.Fatalf("%d queries for %d polls: no re-read below the tip at the floor", n, stuckEvery)
	}
}

// TestAnchorLineLateAnchorsBelowTheTip (second re-check, #25): a 4-block
// rival forking at 47 whose block 50 lands one poll before 47 to 49. The
// stuck path must still read them and reorganize: at once when they were
// signed after the newest anchor read, within stuckEvery polls when they
// were signed before it (as a publisher signs in height order).
func TestAnchorLineLateAnchorsBelowTheTip(t *testing.T) {
	for _, c := range []struct {
		name     string
		at50     int64
		at4749   int64
		maxPolls int
	}{
		{"signed after", 2, 3, 1},
		{"signed before", 3, 2, stuckEvery},
	} {
		t.Run(c.name, func(t *testing.T) {
			pub := newSigner(t)
			main := testChain(0, [32]byte{}, 50, 43)
			s := &memStore{}
			for _, b := range main {
				s.add(b.anchor(t, pub, true, 1))
			}
			l, _ := newTestLine(s, pub.pubkey, nil)
			l.Load(context.Background())
			rival := testChain(47, main[46].hash, 4, 44) // 47..50
			s.add(rival[3].anchor(t, pub, true, c.at50))
			l.Update(context.Background()) // 50 alone: it does not link
			checkLine(t, l, main)
			for _, b := range rival[:3] {
				s.add(b.anchor(t, pub, true, c.at4749))
			}
			polls := 0
			for l.Epoch() == 0 && polls < stuckEvery+2 {
				l.Update(context.Background())
				polls++
			}
			if l.Epoch() != 1 || polls > c.maxPolls {
				t.Fatalf("epoch %d after %d polls, want 1 within %d", l.Epoch(), polls, c.maxPolls)
			}
			checkLine(t, l, append(append([]testBlock(nil), main[:47]...), rival...))
		})
	}
}

// TestAnchorLineFillRemembersFailures (second re-check, #25 low): a
// pending block above a gap whose headers do not lead to the tip is not
// asked about again at every poll, nor logged again.
func TestAnchorLineFillRemembersFailures(t *testing.T) {
	pub := newSigner(t)
	main := testChain(0, [32]byte{}, 20, 45)
	stray := testChain(22, [32]byte{3}, 3, 46) // 22..24, its parent unknown anywhere
	s := &memStore{}
	for _, b := range main {
		s.add(b.anchor(t, pub, true, 1))
	}
	for _, b := range stray {
		s.add(b.anchor(t, pub, true, 1))
	}
	src := headersOf(main)
	l, logs := newTestLine(s, pub.pubkey, src)
	l.Load(context.Background())
	asked := src.asked
	for i := 0; i < 5; i++ {
		l.Update(context.Background())
	}
	if src.asked != asked || countLogs(logs, "fallback did not fill") != 1 {
		t.Fatalf("asked %d more times, logged %d times", src.asked-asked, countLogs(logs, "fallback did not fill"))
	}
}

// TestAnchorLineUsesOnlyItsPublisher: an anchor by anyone else is not
// used, even from a store that returned it.
func TestAnchorLineUsesOnlyItsPublisher(t *testing.T) {
	pub, other := newSigner(t), newSigner(t)
	b := testChain(0, [32]byte{}, 1, 10)[0]
	l, _ := newTestLine(&memStore{}, pub.pubkey, nil)
	if got := l.resolveAnchors([]nostr.Event{b.anchor(t, other, true, 1), b.anchor(t, pub, true, 1)}); len(got) != 1 {
		t.Fatalf("%d blocks from one anchor by the publisher and one by another key", len(got))
	}
}

// TestAnchorHeightsAreCanonical: a B with a leading zero or a sign is not
// a height an anchor may carry (a #B filter names heights canonically).
func TestAnchorHeightsAreCanonical(t *testing.T) {
	pub := newSigner(t)
	b := testChain(0, [32]byte{}, 13, 11)[12]
	for _, bad := range []string{"012", "+12", "-12", "", "1 2"} {
		e := b.anchor(t, pub, true, 1)
		for i, tag := range e.Tags {
			if tag[0] == "B" {
				e.Tags[i] = []string{"B", bad}
			}
		}
		if _, _, _, _, err := parseAnchor(pub.sign(t, e.Kind, e.CreatedAt, e.Tags...)); err == nil {
			t.Errorf("B %q accepted", bad)
		}
	}
	if _, _, _, _, err := parseAnchor(b.anchor(t, pub, true, 1)); err != nil {
		t.Fatal(err)
	}
}

// TestAnchorLineGrows: anchors published after the load are linked by the
// next update.
func TestAnchorLineGrows(t *testing.T) {
	pub := newSigner(t)
	blocks := testChain(0, [32]byte{}, 30, 7)
	s := &memStore{}
	for _, b := range blocks[:20] {
		s.add(b.anchor(t, pub, true, 1))
	}
	l, _ := newTestLine(s, pub.pubkey, nil)
	l.Load(context.Background())
	checkLine(t, l, blocks[:20])
	for _, b := range blocks[20:] {
		s.add(b.anchor(t, pub, true, 2))
	}
	l.Update(context.Background())
	checkLine(t, l, blocks)
}

// TestStationIndexAgreesWithTheScan compares the sorted lookup of
// DECK-0001 §4.4 (the index, and the scan above it) with StaticLine's
// linear scan of §4.2, over lines with clustered stops (shared prefixes,
// ties on distance) and every bound.
func TestStationIndexAgreesWithTheScan(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	for round := 0; round < 20; round++ {
		n := 50 + rng.Intn(400)
		coords := make([][32]byte, n)
		var blocks []LineBlock
		centre := make([]byte, 32)
		rng.Read(centre)
		for h := range coords {
			c := coords[h][:]
			rng.Read(c)
			// Most stops share a long prefix with the centre, so distances
			// tie often.
			if rng.Intn(4) > 0 {
				copy(c, centre[:rng.Intn(31)])
			}
			blocks = append(blocks, LineBlock{Height: uint64(h), BlockHash: strings.Repeat("00", 32), MerkleRoot: hex.EncodeToString(c), Coord: hex.EncodeToString(c)})
		}
		// A port's coordinate is its merkle root, as NewStaticLine checks.
		static, err := NewStaticLine(blocks)
		if err != nil {
			t.Fatal(err)
		}
		ix := newStationIndex(coords[:rng.Intn(n)+1]) // the rest is the scanned tail
		for q := 0; q < 200; q++ {
			key := make([]byte, 32)
			rng.Read(key)
			if rng.Intn(3) > 0 {
				copy(key, centre[:rng.Intn(32)])
			}
			if rng.Intn(5) == 0 {
				copy(key, coords[rng.Intn(n)][:])
				key[31] ^= byte(rng.Intn(2)) // the plane bit is not part of the distance
			}
			var k [32]byte
			copy(k[:], key)
			c, _ := ParseCoord(hex.EncodeToString(key))
			bound := uint64(rng.Intn(n))
			want := static.Station(c, bound)
			if got := station(k, bound, coords, ix); got != want {
				t.Fatalf("round %d: station of %x within %d: index %d, scan %d", round, key, bound, got, want)
			}
			s := static.stops[want]
			wantD := max(lcaHeight(c.X, s.X), lcaHeight(c.Y, s.Y), lcaHeight(c.Z, s.Z))
			if d := keyDistance(&k, &coords[want]); d != wantD {
				t.Fatalf("keyDistance %d, lca %d", d, wantD)
			}
		}
	}
}

// TestHTTPHeaders reads headers the way mempool.space and blockstream.info
// serve them, trying each base in turn.
func TestHTTPHeaders(t *testing.T) {
	blocks := testChain(0, [32]byte{}, 3, 9)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) }))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, b := range blocks {
			if r.URL.Path == "/api/block/"+hex.EncodeToString(b.hash[:])+"/header" {
				fmt.Fprint(w, hex.EncodeToString(b.header))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer up.Close()
	src := HTTPHeaders{Bases: []string{down.URL + "/api", up.URL + "/api/"}}
	raw, err := src.Header(context.Background(), blocks[1].hash)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := blockFromHeader(raw, blocks[1].hash, 1); err != nil || b.prev != blocks[0].hash || b.coord != blocks[1].coord {
		t.Fatalf("header: %v, prev %x", err, b.prev)
	}
	if _, err := src.Header(context.Background(), [32]byte{1}); err == nil {
		t.Fatal("an unknown block gave a header")
	}
}

// heightStore answers the line's two questions (#B heights, and the newest
// anchors) from events indexed by height, for a line of mainnet's length.
type heightStore struct {
	byB    map[string][]nostr.Event
	newest []nostr.Event
}

func (s *heightStore) query(filters []nostr.Filter, limit int) ([]nostr.Event, error) {
	var out []nostr.Event
	for _, f := range filters {
		if len(f.Tags["B"]) == 0 {
			out = append(out, s.newest...)
			continue
		}
		for _, b := range f.Tags["B"] {
			for _, e := range s.byB[b] {
				if f.MatchesEvent(e) {
					out = append(out, e)
				}
			}
		}
	}
	return out[:min(len(out), limit)], nil
}

// TestAnchorLineLoadsMainnet loads the line from real anchors
// (REGIONGATE_ANCHORS, one kind 321 event per line, as the relay holds
// them), signatures checked and landfalls derived, and logs the time, the
// memory and where it stops. With REGIONGATE_REF_LINE every stop is
// compared with the reference's; with REGIONGATE_FALLBACK=1 gaps are filled
// from mempool.space and blockstream.info (network); with REGIONGATE_RIDES=1
// the real ride vectors run on the loaded line.
func TestAnchorLineLoadsMainnet(t *testing.T) {
	path := os.Getenv("REGIONGATE_ANCHORS")
	if path == "" {
		t.Skip("REGIONGATE_ANCHORS not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &heightStore{byB: map[string][]nostr.Event{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var top nostr.Event
	for sc.Scan() {
		var e nostr.Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		for _, b := range tagValues(e, "B") {
			s.byB[b] = append(s.byB[b], e)
		}
		if e.CreatedAt >= top.CreatedAt {
			top = e
		}
	}
	f.Close()
	s.newest = []nostr.Event{top}
	var fallback HeaderSource
	if os.Getenv("REGIONGATE_FALLBACK") == "1" {
		fallback = HTTPHeaders{Bases: []string{"https://mempool.space/api", "https://blockstream.info/api"}}
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	l := NewAnchorLine(AnchorLineConfig{Publisher: DefaultLinePublisher, Query: s.query, MaxResults: 10000,
		Signature: validation.CheckSignature, Fallback: fallback, Workers: runtime.GOMAXPROCS(0) / 2,
		Log: func(msg string, args ...any) { t.Log(msg, args) }})
	start := time.Now()
	if err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	s.byB, s.newest = nil, nil
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	tip, _ := l.Tip()
	t.Logf("loaded to %d in %v on %d workers; heap in use with the line alone %d MB (with the test's store %d MB)", tip, took.Round(time.Second),
		l.cfg.Workers, after.HeapInuse>>20, before.HeapInuse>>20)
	start = time.Now()
	c, _ := ParseCoord(DefaultLinePublisher)
	for i := 0; i < 1000; i++ {
		l.Station(c, tip-uint64(i))
	}
	t.Logf("a station over the whole line: %v", (time.Since(start) / 1000).Round(time.Microsecond))
	if ref := os.Getenv("REGIONGATE_REF_LINE"); ref != "" {
		rows := readRefLine(t, ref)
		bad := 0
		for _, r := range rows {
			if r.height > tip {
				break
			}
			stop, _ := l.Stop(r.height)
			hash, _ := l.BlockHash(r.height)
			if stop != r.coord || hex.EncodeToString(hash) != r.hash {
				if bad++; bad <= 5 {
					t.Errorf("block %d: %s %x, the reference %s %s", r.height, stop, hash, r.coord, r.hash)
				}
			}
		}
		t.Logf("%d stops compared with the reference, %d differ", min(uint64(len(rows)), tip+1), bad)
	}
	// REGIONGATE_RIDES=1: the real ride vectors on the line just loaded,
	// which must reach at least the vectors' tip.
	if os.Getenv("REGIONGATE_RIDES") == "1" {
		f := loadRealRides(t)
		if tip < f.Line.Tip {
			t.Fatalf("the line ends at %d, below the vectors' tip %d", tip, f.Line.Tip)
		}
		runRealRides(t, f, l)
	}
}
