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
