package regiongate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0ceanslim/grain/client/core"
	"github.com/0ceanslim/grain/client/core/tools"
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// ── fixtures ──────────────────────────────────────────────────────────

type signer struct {
	priv   *btcec.PrivateKey
	pubkey string
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &signer{priv: priv, pubkey: hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))}
}

func (s *signer) sign(t *testing.T, kind int, at int64, tags ...[]string) nostr.Event {
	t.Helper()
	if tags == nil {
		tags = [][]string{}
	}
	evt := nostr.Event{PubKey: s.pubkey, CreatedAt: at, Kind: kind, Tags: tags, Content: ""}
	sum := sha256.Sum256([]byte(core.SerializeEvent(evt)))
	evt.ID = hex.EncodeToString(sum[:])
	sig, err := schnorr.Sign(s.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	evt.Sig = hex.EncodeToString(sig.Serialize())
	return evt
}

// chainBuilder signs a movement chain for one identity.
type chainBuilder struct {
	t     *testing.T
	s     *signer
	at    int64
	spawn nostr.Event
	last  nostr.Event
	pos   string
}

func newChain(t *testing.T, s *signer) *chainBuilder {
	b := &chainBuilder{t: t, s: s, at: 1_750_000_000}
	b.spawn = s.sign(t, KindMovement, b.at, []string{"A", ActSpawn}, []string{"C", s.pubkey})
	b.last, b.pos = b.spawn, s.pubkey
	return b
}

// move appends an action to `to` and returns its event; extra tags are added.
func (b *chainBuilder) move(action, to string, extra ...[]string) nostr.Event {
	b.at += 10
	tags := [][]string{
		{"A", action},
		{"e", b.spawn.ID, "", "genesis"},
		{"e", b.last.ID, "", "previous"},
		{"c", b.pos},
		{"C", to},
	}
	evt := b.s.sign(b.t, KindMovement, b.at, append(tags, extra...)...)
	b.last, b.pos = evt, to
	return evt
}

func mustCoord(t *testing.T, s string) Coord {
	t.Helper()
	c, err := ParseCoord(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// offset returns c moved by dx on X (same plane), as hex.
func offset(t *testing.T, c string, dx int64) string {
	t.Helper()
	p := mustCoord(t, c)
	p.X = new(big.Int).Add(p.X, big.NewInt(dx))
	return p.Hex()
}

// cubeAround is the aligned cube of height h containing c.
func cubeAround(t *testing.T, c string, h uint) Box {
	t.Helper()
	p := mustCoord(t, c)
	al := func(v *big.Int) *big.Int { return new(big.Int).Lsh(new(big.Int).Rsh(v, h), h) }
	b, err := NewBox(Coord{X: al(p.X), Y: al(p.Y), Z: al(p.Z), Plane: p.Plane}, h, h, h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func regionTag(b Box, h uint) []string {
	return []string{"region", b.Base.Hex(), big.NewInt(int64(h)).String()}
}

// gameTag is the p tag every enter-virtual carries, naming its game (§8.11.1).
func gameTag() []string { return []string{"p", strings.Repeat("ab", 32), "", "game"} }

func verifier() Verifier {
	return Verifier{Proofs: PendingSpec{}, Signature: validation.CheckSignature}
}

// ── coordinates and boxes ─────────────────────────────────────────────

func TestParseCoordMatchesPythonReference(t *testing.T) {
	data, err := os.ReadFile("testdata/coords.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Vectors []struct {
			Coord, X, Y, Z string
			Plane          uint
		}
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Vectors) < 20 {
		t.Fatal("fixtures missing")
	}
	for _, v := range fx.Vectors {
		c := mustCoord(t, v.Coord)
		if c.X.String() != v.X || c.Y.String() != v.Y || c.Z.String() != v.Z || c.Plane != v.Plane {
			t.Fatalf("%s: got (%s,%s,%s,%d) want (%s,%s,%s,%d)", v.Coord, c.X, c.Y, c.Z, c.Plane, v.X, v.Y, v.Z, v.Plane)
		}
		if c.Hex() != v.Coord {
			t.Fatalf("round trip: %s -> %s", v.Coord, c.Hex())
		}
	}
}

func TestParseCoordRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "ab", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, err := ParseCoord(s); err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

func TestBoxContainment(t *testing.T) {
	base := Coord{X: big.NewInt(1 << 20), Y: big.NewInt(3 << 20), Z: big.NewInt(0), Plane: 0}
	b, err := NewBox(base, 20, 20, 20)
	if err != nil {
		t.Fatal(err)
	}
	at := func(x, y, z int64, plane uint) Coord {
		return Coord{X: big.NewInt(x), Y: big.NewInt(y), Z: big.NewInt(z), Plane: plane}
	}
	cases := []struct {
		c    Coord
		want bool
	}{
		{at(1<<20, 3<<20, 0, 0), true},           // the base corner
		{at(2<<20-1, 4<<20-1, 1<<20-1, 0), true}, // the far corner
		{at(2<<20, 3<<20, 0, 0), false},          // one past on x
		{at(1<<20-1, 3<<20, 0, 0), false},        // one before on x
		{at(1<<20, 3<<20, 1<<20, 0), false},      // one past on z
		{at(1<<20, 3<<20, 0, 1), false},          // other plane
	}
	for i, c := range cases {
		if got := b.Contains(c.c); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
	if _, err := NewBox(at(1<<20+1, 0, 0, 0), 20, 20, 20); err == nil {
		t.Fatal("misaligned base must be refused")
	}
	if _, err := NewBox(at(0, 0, 0, 0), 86, 0, 0); err == nil {
		t.Fatal("height above 85 must be refused")
	}
}

// ── config ────────────────────────────────────────────────────────────

func TestConfigForms(t *testing.T) {
	op := newSigner(t)
	npub, err := tools.EncodePubkey(op.pubkey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig([]byte(`
enabled: true
chain_relays: [wss://a.example]
exempt_pubkeys: [` + npub + `]
regions:
  - {sector: "5-6-7", plane: 1}
  - {base: "` + strings.Repeat("0", 64) + `", height: 40}
  - {base: "` + strings.Repeat("0", 64) + `", heights: [10, 20, 85]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeStructural || len(c.boxes) != 3 || c.AlwaysAllowKinds[0] != 5 || !c.exempt[op.pubkey] {
		t.Fatalf("unexpected config: %+v", c)
	}
	s := c.boxes[0]
	if s.Base.X.Cmp(big.NewInt(5<<30)) != 0 || s.Base.Z.Cmp(big.NewInt(7<<30)) != 0 || s.Base.Plane != 1 || s.HX != 30 {
		t.Fatalf("sector box wrong: %+v", s)
	}
	for _, bad := range []string{
		"enabled: true\nchain_relays: [wss://a]\n",                                                                     // no regions
		"enabled: true\nchain_relays: [wss://a]\nregions: [{sector: \"1-2\"}]\n",                                       // bad sector
		"enabled: true\nchain_relays: [wss://a]\nregions: [{base: \"" + strings.Repeat("f", 64) + "\", height: 10}]\n", // misaligned
		"enabled: true\nchain_relays: [wss://a]\nmode: lax\nregions: [{sector: \"1-2-3\"}]\n",                          // bad mode
		"enabled: true\nuse_local_events: false\nregions: [{sector: \"1-2-3\"}]\n",                                     // no source
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Fatalf("expected error for:\n%s", bad)
		}
	}
}

// ── chain resolution (§8.7.3) ─────────────────────────────────────────

func TestActiveChainNewestSpawnAndForkRule(t *testing.T) {
	s := newSigner(t)
	old := newChain(t, s)
	oldHop := old.move(ActHop, offset(t, s.pubkey, 1))

	b := newChain(t, s)
	b.at = old.at + 100 // a respawn, newer than the old chain
	b.spawn = s.sign(t, KindMovement, b.at, []string{"A", ActSpawn}, []string{"C", s.pubkey})
	b.last, b.pos = b.spawn, s.pubkey
	h1 := b.move(ActHop, offset(t, s.pubkey, 2))
	// Fork at h1: the earlier branch continues.
	b2 := *b
	early := b.move(ActHop, offset(t, s.pubkey, 3))
	earlyNext := b.move(ActHop, offset(t, s.pubkey, 4))
	b2.at = early.CreatedAt + 5
	late := b2.move(ActHop, offset(t, s.pubkey, 9))

	other := newSigner(t)
	foreign := newChain(t, other).spawn

	chain := ActiveChain(s.pubkey, []nostr.Event{late, earlyNext, oldHop, foreign, early, old.spawn, h1, b.spawn})
	var ids []string
	for _, m := range chain {
		ids = append(ids, m.Event.ID)
	}
	want := []string{b.spawn.ID, h1.ID, early.ID, earlyNext.ID}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("active chain:\n got %v\nwant %v", ids, want)
	}
}

func TestForgedForkCannotHijackChain(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	real := b.move(ActHop, offset(t, s.pubkey, 1))
	// An "older" sibling with a broken signature, as anyone could publish.
	forged := real
	forged.CreatedAt = real.CreatedAt - 5
	forged.Tags = append([][]string{}, real.Tags...)
	forged.Tags[4] = []string{"C", offset(t, s.pubkey, 999)}
	forged.ID = strings.Repeat("0", 64)

	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, real, forged})
	if vd.PositionEvent != real.ID {
		t.Fatalf("forged event took part in fork resolution: position from %s", vd.PositionEvent)
	}
}

// ── structural verification ───────────────────────────────────────────

func TestVerifyHopsStructuralAndStrict(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	h2 := b.move(ActSidestep, offset(t, s.pubkey, 2))
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, h2})
	if !vd.HasChain || vd.Stopped != "" || vd.Length != 3 || vd.Unchecked != 2 {
		t.Fatalf("verdict: %+v", vd)
	}
	if vd.Position.Hex() != offset(t, s.pubkey, 2) || vd.PositionEvent != h2.ID {
		t.Fatal("structural position must be the head")
	}
	if vd.VerifiedPosition.Hex() != s.pubkey {
		t.Fatal("with PendingSpec the proof-verified position is the spawn point")
	}
}

func TestVerifyStopsAtInvalidEvent(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	b.pos = offset(t, s.pubkey, 50) // the next event's c will not match h1's C
	bad := b.move(ActHop, offset(t, s.pubkey, 51))
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, bad})
	if vd.Valid() || vd.Reason != ReasonCMismatch || vd.InvalidAt != bad.ID || vd.InvalidIndex != 2 || vd.PositionEvent != h1.ID {
		t.Fatalf("verdict: %+v", vd)
	}

	// A spawn whose C is not the pubkey places the identity nowhere.
	s2 := newSigner(t)
	wrong := s2.sign(t, KindMovement, 1, []string{"A", ActSpawn}, []string{"C", offset(t, s2.pubkey, 1)})
	if vd := verifier().Verify(s2.pubkey, []nostr.Event{wrong}); vd.Position != nil || !vd.HasChain || vd.Reason != ReasonSpawnCoordinate {
		t.Fatalf("bad spawn verdict: %+v", vd)
	}
	if vd := verifier().Verify(s2.pubkey, nil); vd.HasChain || vd.Reason != ReasonNoSpawn {
		t.Fatal("no events means no chain")
	}
}

func TestVerifyUnknownActionIsSkipped(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	h1 := b.move(ActHop, offset(t, s.pubkey, 1))
	carried := b.pos
	teleport := b.move("teleport", offset(t, s.pubkey, 2))

	// A chain ending on a skipped action is valid; the position is the C of
	// the last recognized action and the head is the skipped one (§8.9 step 5).
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, teleport})
	if !vd.Valid() || vd.PositionEvent != h1.ID || vd.Position.Hex() != carried || vd.Head != teleport.ID ||
		len(vd.Skipped) != 1 || vd.Skipped[0] != teleport.ID {
		t.Fatalf("verdict: %+v", vd)
	}

	// The next recognized action starts where the chain carries it, not
	// where the skipped action claimed to go (§8.9 step 2), and links
	// through the skipped action (step 1).
	from := *b
	from.pos = carried
	hop := from.move(ActHop, offset(t, s.pubkey, 3))
	vd = verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, teleport, hop})
	if !vd.Valid() || vd.PositionEvent != hop.ID || vd.Length != 4 {
		t.Fatalf("hop from the carried position: %+v", vd)
	}
	moved := b.move(ActHop, offset(t, s.pubkey, 4)) // its c is the teleport's C
	vd = verifier().Verify(s.pubkey, []nostr.Event{b.spawn, h1, teleport, moved})
	if vd.Reason != ReasonCMismatch || vd.InvalidAt != moved.ID || vd.PositionEvent != h1.ID {
		t.Fatalf("a position change across a skipped action must be invalid: %+v", vd)
	}
}

func TestVerifyHyperjumpOrdering(t *testing.T) {
	s := newSigner(t)
	b := newChain(t, s)
	heights := func(from, to string) [][]string {
		return [][]string{{"from_height", from}, {"B", to}, {"as_of", to}}
	}
	jump := b.move(ActHyperjump, offset(t, s.pubkey, 9), heights("2", "3")...)
	if vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, jump}); vd.Reason != ReasonHyperjumpPredecessor {
		t.Fatalf("hyperjump after spawn must be invalid: %+v", vd)
	}

	// enter-hyperspace, then a bracket, then a hyperjump: the bracket is
	// transparent (§8.11.4 rule 8).
	b = newChain(t, s)
	box := cubeAround(t, s.pubkey, 10)
	enterH := b.move(ActEnterHyperspace, s.pubkey)
	enterV := b.move(ActEnterVirtual, s.pubkey, regionTag(box, 10), gameTag())
	exitV := b.move(ActExitVirtual, s.pubkey, []string{"e", enterV.ID, "", "entry"})
	jump = b.move(ActHyperjump, offset(t, s.pubkey, 1<<40), heights("2", "3")...)
	vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enterH, enterV, exitV, jump})
	if !vd.Valid() || vd.PositionEvent != jump.ID {
		t.Fatalf("verdict: %+v", vd)
	}
	moved := b.move(ActEnterHyperspace, offset(t, s.pubkey, 5)) // must not move
	if vd := verifier().Verify(s.pubkey, []nostr.Event{b.spawn, enterH, enterV, exitV, jump, moved}); vd.PositionEvent != jump.ID || vd.Reason != ReasonEnterHyperspaceMoved {
		t.Fatalf("moving enter-hyperspace must be invalid: %+v", vd)
	}
}

func TestVerifyVirtualBrackets(t *testing.T) {
	s := newSigner(t)
	const h = 16
	box := cubeAround(t, s.pubkey, h)
	inside := func(dx int64) string { return offset(t, box.Base.Hex(), dx) }

	b := newChain(t, s)
	enter := b.move(ActEnterVirtual, inside(1), regionTag(box, h), gameTag())
	act := b.move("shoot", inside(2))
	open := []nostr.Event{b.spawn, enter, act}
	vd := verifier().Verify(s.pubkey, open)
	if !vd.Valid() || vd.Position.Hex() != s.pubkey || vd.OpenBracket != enter.ID || len(vd.Skipped) != 0 {
		t.Fatalf("inside an open bracket the position is the enter's c (rule 7): %+v", vd)
	}
	exit := b.move(ActExitVirtual, s.pubkey, []string{"e", enter.ID, "", "entry"})
	hop := b.move(ActHop, offset(t, s.pubkey, 1))
	vd = verifier().Verify(s.pubkey, append(open, exit, hop))
	if !vd.Valid() || vd.PositionEvent != hop.ID || vd.OpenBracket != "" {
		t.Fatalf("closed bracket: %+v", vd)
	}

	invalid := func(name string, build func(b *chainBuilder) []nostr.Event, wantReason string) {
		t.Helper()
		b := newChain(t, s)
		evs := build(b)
		vd := verifier().Verify(s.pubkey, append([]nostr.Event{b.spawn}, evs...))
		if vd.Reason != wantReason || vd.InvalidAt != evs[len(evs)-1].ID {
			t.Errorf("%s: want %s at the last event, got %q: %s", name, wantReason, vd.Reason, vd.Stopped)
		}
	}
	invalid("base action inside", func(b *chainBuilder) []nostr.Event {
		e := b.move(ActEnterVirtual, inside(1), regionTag(box, h), gameTag())
		return []nostr.Event{e, b.move(ActHop, inside(2))}
	}, ReasonBaseActionInBracket)
	invalid("virtual action outside the box", func(b *chainBuilder) []nostr.Event {
		e := b.move(ActEnterVirtual, inside(1), regionTag(box, h), gameTag())
		return []nostr.Event{e, b.move("shoot", offset(t, box.Base.Hex(), 1<<h))}
	}, ReasonOutsideRegion)
	invalid("exit naming the wrong entry", func(b *chainBuilder) []nostr.Event {
		e := b.move(ActEnterVirtual, inside(1), regionTag(box, h), gameTag())
		return []nostr.Event{e, b.move(ActExitVirtual, s.pubkey, []string{"e", strings.Repeat("a", 64), "", "entry"})}
	}, ReasonExitWrongEntry)
	invalid("exit not restoring the base position", func(b *chainBuilder) []nostr.Event {
		e := b.move(ActEnterVirtual, inside(1), regionTag(box, h), gameTag())
		return []nostr.Event{e, b.move(ActExitVirtual, inside(3), []string{"e", e.ID, "", "entry"})}
	}, ReasonExitPosition)
	invalid("exit with no bracket", func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActExitVirtual, s.pubkey, []string{"e", b.spawn.ID, "", "entry"})}
	}, ReasonExitWithoutBracket)
	invalid("misaligned region", func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActEnterVirtual, inside(1), []string{"region", inside(1), "16"}, gameTag())}
	}, ReasonRegion)
	invalid("entry naming no game", func(b *chainBuilder) []nostr.Event {
		return []nostr.Event{b.move(ActEnterVirtual, inside(1), regionTag(box, h))}
	}, ReasonGameTag)
}

// ── the gate ──────────────────────────────────────────────────────────

type fakeSource struct {
	mu     sync.Mutex
	events []nostr.Event
	calls  atomic.Int32
	fail   bool
	delay  time.Duration
}

func (f *fakeSource) Movement(ctx context.Context, pubkey string, tags map[string][]string, max int) ([]nostr.Event, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.fail {
		return nil, errors.New("relay down")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []nostr.Event
	flt := nostr.Filter{Authors: []string{pubkey}, Kinds: []int{KindMovement}, Tags: tags}
	for _, e := range f.events {
		if flt.MatchesEvent(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

func gateFor(t *testing.T, mode Mode, box Box, src Source, exempt ...string) *Gate {
	t.Helper()
	cfg := &Config{Enabled: true, Mode: mode, AlwaysAllowKinds: []int{5}, CacheTTLSeconds: 600,
		NegativeCacheTTLSeconds: 60, boxes: []Box{box}, exempt: map[string]bool{}}
	for _, e := range exempt {
		cfg.exempt[e] = true
	}
	return NewGate(cfg, verifier(), src)
}

func TestGateDecisions(t *testing.T) {
	ctx := context.Background()
	in := newSigner(t)
	box := cubeAround(t, in.pubkey, 40)

	b := newChain(t, in)
	near := b.move(ActHop, offset(t, in.pubkey, 1))
	src := &fakeSource{events: []nostr.Event{b.spawn, near}}
	g := gateFor(t, ModeStructural, box, src)

	note := in.sign(t, 1, 1, nil...)
	if ok, msg := g.Admit(ctx, note); !ok {
		t.Fatalf("identity inside the region refused: %s", msg)
	}

	// Moving out with a movement event published here is refused...
	out := b.move(ActHop, offset(t, box.Base.Hex(), 1<<41))
	if ok, msg := g.Admit(ctx, out); ok || !strings.HasPrefix(msg, "restricted:") {
		t.Fatalf("move out of the region admitted (%v, %q)", ok, msg)
	}
	// ...and deletions are always allowed.
	if ok, _ := g.Admit(ctx, in.sign(t, 5, 2, []string{"e", note.ID})); !ok {
		t.Fatal("kind 5 must always be admitted")
	}

	stranger := newSigner(t)
	if ok, msg := g.Admit(ctx, stranger.sign(t, 1, 1)); ok || !strings.Contains(msg, "no movement chain") {
		t.Fatalf("pubkey with no chain: %v %q", ok, msg)
	}
	if ok, _ := gateFor(t, ModeStructural, box, src, stranger.pubkey).Admit(ctx, stranger.sign(t, 1, 1)); !ok {
		t.Fatal("exempt pubkey refused")
	}
}

func TestGateMoveIntoRegionAndStrictMode(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	// A region that does not contain the spawn point.
	target := offset(t, s.pubkey, 1<<45)
	box := cubeAround(t, target, 20)
	if box.Contains(mustCoord(t, s.pubkey)) {
		t.Skip("spawn happens to fall in the target box")
	}
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}}
	g := gateFor(t, ModeStructural, box, src)
	if ok, _ := g.Admit(ctx, s.sign(t, 1, 1)); ok {
		t.Fatal("identity outside the region admitted")
	}
	in := b.move(ActHop, target)
	if ok, msg := g.Admit(ctx, in); !ok {
		t.Fatalf("the move into the region must be admitted with itself: %s", msg)
	}
	if ok, _ := g.Admit(ctx, s.sign(t, 1, 2)); !ok {
		t.Fatal("after moving in, the verdict is cached as admitted")
	}

	// Strict mode trusts only proof-verified positions: with PendingSpec
	// that is the spawn point, outside the box.
	src.events = append(src.events, in)
	if ok, msg := gateFor(t, ModeStrict, box, src).Admit(ctx, s.sign(t, 1, 3)); ok {
		t.Fatalf("strict mode admitted an unverified position (%q)", msg)
	}
	// But an identity whose spawn is inside is admitted in strict mode.
	if ok, _ := gateFor(t, ModeStrict, cubeAround(t, s.pubkey, 20), src).Admit(ctx, s.sign(t, 1, 4)); !ok {
		t.Fatal("strict mode refused a spawn inside the region")
	}
}

func TestGateBoundsLookupsAndCache(t *testing.T) {
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	slow := &fakeSource{delay: 200 * time.Millisecond}
	cfg := &Config{Enabled: true, Mode: ModeStructural, AlwaysAllowKinds: []int{5}, CacheTTLSeconds: 600,
		NegativeCacheTTLSeconds: 60, MaxConcurrentLookups: 1, boxes: []Box{box}, exempt: map[string]bool{}}
	g := NewGate(cfg, verifier(), slow)

	// One lookup slot: a second unknown author waiting past its deadline
	// is told to retry, and that is not cached.
	go g.Admit(context.Background(), newSigner(t).sign(t, 1, 1))
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	other := newSigner(t)
	if ok, msg := g.Admit(ctx, other.sign(t, 1, 1)); ok || msg != errBusy {
		t.Fatalf("want busy refusal, got %v %q", ok, msg)
	}
	g.mu.Lock()
	_, cachedBusy := g.cache[other.pubkey]
	g.mu.Unlock()
	if cachedBusy {
		t.Fatal("a busy refusal must not be cached")
	}

	// Expired refusals are swept once the cache is large.
	now := time.Now()
	g.now = func() time.Time { return now }
	g.mu.Lock()
	for i := 0; i < sweepAbove+10; i++ {
		g.cache[strings.Repeat("0", 60)+strconv.Itoa(1000+i)] = cached{expires: now.Add(-time.Second)}
	}
	g.mu.Unlock()
	g.remember(s.pubkey, true, "")
	g.mu.Lock()
	n := len(g.cache)
	g.mu.Unlock()
	if n > 10 {
		t.Fatalf("expired entries not swept: %d left", n)
	}
}

func TestGateIgnoresForgedNewerSpawn(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	b := newChain(t, s)
	hop := b.move(ActHop, offset(t, s.pubkey, 1))
	forged := b.spawn
	forged.CreatedAt += 1000
	forged.ID = strings.Repeat("f", 64) // unsigned "respawn"
	src := &fakeSource{events: []nostr.Event{b.spawn, hop, forged}}
	if ok, msg := gateFor(t, ModeStructural, box, src).Admit(ctx, s.sign(t, 1, 1)); !ok {
		t.Fatalf("a forged newer spawn must not hide the real chain: %s", msg)
	}
}

func TestGateCachingAndFailures(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	box := cubeAround(t, s.pubkey, 40)
	b := newChain(t, s)
	src := &fakeSource{events: []nostr.Event{b.spawn}, delay: 20 * time.Millisecond}
	g := gateFor(t, ModeStructural, box, src)

	// Concurrent events from one author share one lookup.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if ok, msg := g.Admit(ctx, s.sign(t, 1, int64(i))); !ok {
				t.Errorf("refused: %s", msg)
			}
		}(i)
	}
	wg.Wait()
	if n := src.calls.Load(); n != 2 { // spawns + chain, once
		t.Fatalf("want one lookup (2 source calls) for concurrent events, got %d calls", n)
	}

	// A refusal expires after the negative TTL.
	stranger := newSigner(t)
	now := time.Now()
	g.now = func() time.Time { return now }
	g.Admit(ctx, stranger.sign(t, 1, 1)) // no spawn: one source call
	g.Admit(ctx, stranger.sign(t, 1, 2))
	if n := src.calls.Load(); n != 3 {
		t.Fatalf("refusal not cached: %d source calls", n)
	}
	now = now.Add(61 * time.Second)
	g.Admit(ctx, stranger.sign(t, 1, 3))
	if n := src.calls.Load(); n != 4 {
		t.Fatalf("refusal not re-checked after its TTL: %d source calls", n)
	}

	// When every source fails the gate refuses, and does not cache it.
	down := &fakeSource{fail: true}
	g2 := gateFor(t, ModeStructural, box, down)
	if ok, msg := g2.Admit(ctx, s.sign(t, 1, 9)); ok || msg != errFetch {
		t.Fatalf("source failure: %v %q", ok, msg)
	}
	g2.Admit(ctx, s.sign(t, 1, 10))
	if n := down.calls.Load(); n != 2 {
		t.Fatalf("a failed lookup must not be cached: %d calls", n)
	}
}
