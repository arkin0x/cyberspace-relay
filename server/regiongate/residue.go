package regiongate

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
)

// Hop proof version 2, residue openings (CYBERSPACE_V2 §5.9 to §5.13, §8.4,
// §8.7.1), Level 1. A port of cyberspace_core/residue.py (arkin0x/cyberspace-cli
// 5103c62), itself a port of the spec's hop-residue-reference.py.
//
// A verifier never builds a root. Each of the 16 sampled residues is
// hop_n mod p for a 61-bit prime p, computed in machine words: every Cantor
// root is carried modulo p, where halving is exact on the even product
// s(s + 1), by Babbage's method of differences (§5.9 allows any equivalent
// algorithm). A root of height h costs about 2^h word additions.

const (
	hopSamples     = 16 // residues a verifier recomputes
	residueBlock   = 8  // residues per Merkle leaf
	primeBits      = 61
	widthDivisor   = 4
	hopGrindHeight = 12
)

var (
	hopPrimeDomain  = []byte("CYBERSPACE_HOP_RESIDUE_PRIME_V1")
	hopLeafDomain   = []byte("CYBERSPACE_HOP_RESIDUE_LEAF_V1")
	hopGrindDomain  = []byte("CYBERSPACE_HOP_RESIDUE_GRIND_V1")
	hopSampleDomain = []byte("CYBERSPACE_HOP_RESIDUE_SAMPLE_V1")
	// hopRerollBudget is B(h) for heights 0 to 22 (§5.10); above h22 each
	// height costs 9/4 of the one below, in exact integer arithmetic.
	hopRerollBudget = [...]int64{0, 0, 0, 0, 0, 0, 1, 2, 4, 7, 14, 30, 65, 149, 355, 782,
		1753, 4016, 8959, 20028, 44826, 99974, 223681}
	smallOddPrimes = [...]uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97}
	two256 = new(big.Int).Lsh(bigOne, 256)
)

// hopGeometry is everything a verifier derives from a hop's c, C and e
// previous, taking nothing from the prover (§5.11 step 1).
type hopGeometry struct {
	bases   [4]*big.Int // the aligned bases of x, y, z and the temporal tree
	heights [4]int      // their heights: the three LCA heights, then K
	hMax    int
	m       *big.Int // the residue count (§5.9)
	depth   int      // levels of the seal's tree above its leaves (§5.10)
	price   *big.Int // A (§5.10)
}

func newHopGeometry(prev []byte, from, to Coord) hopGeometry {
	var g hopGeometry
	for i, ax := range [3][2]*big.Int{{from.X, to.X}, {from.Y, to.Y}, {from.Z, to.Z}} {
		h := lcaHeight(ax[0], ax[1])
		g.bases[i], g.heights[i] = aligned(ax[0], h), h
	}
	k := terrainK(to)
	g.bases[3], g.heights[3] = temporalBase(prev, k), k
	for _, h := range g.heights {
		g.hMax = max(g.hMax, h)
	}
	g.m = residueCount(g.hMax)
	g.depth = merkleDepth(g.m)
	g.price = big.NewInt(0)
	for _, h := range g.heights {
		g.price.Add(g.price, rerollBudget(h))
	}
	if g.price.Sign() == 0 {
		g.price.SetInt64(1)
	}
	return g
}

// residueCount is m = max(8, 8 ceil(ceil(85 * 2^h / 244) / 8)) (§5.9).
func residueCount(hMax int) *big.Int {
	num := new(big.Int).Lsh(big.NewInt(AxisBits), uint(hMax))
	den := big.NewInt(widthDivisor * primeBits)
	m := ceilDiv(num, den)
	m = ceilDiv(m, big.NewInt(residueBlock))
	m.Mul(m, big.NewInt(residueBlock))
	if m.Cmp(big.NewInt(residueBlock)) < 0 {
		m.SetInt64(residueBlock)
	}
	return m
}

func ceilDiv(a, b *big.Int) *big.Int {
	q := new(big.Int).Add(a, new(big.Int).Sub(b, bigOne))
	return q.Quo(q, b)
}

// merkleDepth is the smallest d with 2^d >= m / 8 (§5.10).
func merkleDepth(m *big.Int) int {
	blocks := new(big.Int).Quo(m, big.NewInt(residueBlock))
	d := 0
	for new(big.Int).Lsh(bigOne, uint(d)).Cmp(blocks) < 0 {
		d++
	}
	return d
}

// rerollBudget is B(h) (§5.10).
func rerollBudget(h int) *big.Int {
	if h < len(hopRerollBudget) {
		return big.NewInt(hopRerollBudget[h])
	}
	n := uint(h - (len(hopRerollBudget) - 1))
	num := new(big.Int).Mul(big.NewInt(hopRerollBudget[len(hopRerollBudget)-1]), new(big.Int).Exp(big.NewInt(9), big.NewInt(int64(n)), nil))
	return num.Quo(num, new(big.Int).Lsh(bigOne, 2*n))
}

// mpLength is the exact width of a hop's mp tag at this depth (§8.4).
func mpLength(depth int) int { return hopSamples * (16*residueBlock + 64*depth) }

// hopPrime is p_j (§5.9): the first odd n >= 2^61 + (the top 60 bits of the
// first 8 bytes of SHA256(domain || previous_event_id || be64(j))) with no
// factor in SMALL_ODD_PRIMES that is a base-2 strong probable prime.
func hopPrime(prev []byte, j uint64) uint64 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], j)
	h := sha256.New()
	h.Write(hopPrimeDomain)
	h.Write(prev)
	h.Write(buf[:])
	x := binary.BigEndian.Uint64(h.Sum(nil)[:8]) >> 4
	n := (uint64(1)<<primeBits + x) | 1
	for !primeCandidate(n) {
		n += 2
	}
	return n
}

func primeCandidate(n uint64) bool {
	for _, q := range smallOddPrimes {
		if n%q == 0 {
			return false
		}
	}
	return isSPRP2(n)
}

// isSPRP2 is the base-2 strong probable prime test of §5.9 for odd n > 2.
func isSPRP2(n uint64) bool {
	d, r := n-1, 0
	for d&1 == 0 {
		d >>= 1
		r++
	}
	x := powMod(2, d, n)
	if x == 1 || x == n-1 {
		return true
	}
	for i := 1; i < r; i++ {
		x = mulMod(x, x, n)
		if x == n-1 {
			return true
		}
	}
	return false
}

func mulMod(a, b, p uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return bits.Rem64(hi, lo, p)
}

func powMod(b, e, p uint64) uint64 {
	r := uint64(1)
	b %= p
	for ; e > 0; e >>= 1 {
		if e&1 == 1 {
			r = mulMod(r, b, p)
		}
		b = mulMod(b, b, p)
	}
	return r
}

// pairMod is π(a, b) mod p for a, b < p (§5.9). s(s + 1) is even as an
// integer, so it is halved exactly before it is reduced.
func pairMod(a, b, p uint64) uint64 {
	s := a + b
	if s >= p {
		s -= p
	}
	hi, lo := bits.Mul64(s, s+1)
	lo = lo>>1 | hi<<63
	hi >>= 1
	r := bits.Rem64(hi, lo, p) + b
	if r >= p {
		r -= p
	}
	return r
}

// modBig is v mod p.
func modBig(v *big.Int, p uint64) uint64 {
	if v.IsUint64() {
		return v.Uint64() % p
	}
	return new(big.Int).Mod(v, new(big.Int).SetUint64(p)).Uint64()
}

// residueTree is the aligned tree of the given height whose leaves are
// b0, b0 + 1, ... (all mod p), carried modulo p pairing by pairing.
func residueTree(b0 uint64, height int, p uint64) uint64 {
	var stack [64]struct {
		v     uint64
		level int
	}
	top := 0
	leaf := b0
	for i := 0; i < 1<<height; i++ {
		cur, level := leaf, 0
		for top > 0 && stack[top-1].level == level {
			top--
			cur = pairMod(stack[top].v, cur, p)
			level++
		}
		stack[top].v, stack[top].level = cur, level
		top++
		leaf++
		if leaf == p {
			leaf = 0
		}
	}
	return stack[0].v
}

// differencesLevel is the level k whose nodes the method of differences
// steps through: each node then costs 2^k word additions and one pairing, and
// the table 4^k pairings. Any k gives the same residue.
func differencesLevel(height int) int {
	return max(0, min(7, (height-2)/2))
}

// residueRoot is compute_subtree_cantor(base, height) mod p for odd p, by
// Babbage's method of differences (§5.9): the nodes at level k of an aligned
// tree are the values of one polynomial of degree 2^k at evenly spaced
// points, so after its difference table is tabulated each further node
// costs 2^k additions modulo p. Equal to residueTree (TestResidueRootMatchesTree).
func residueRoot(base *big.Int, height int, p uint64) uint64 {
	return residueRootCtx(context.Background(), base, height, p)
}

// residueRootCtx is residueRoot that gives up, returning 0, once ctx ends.
func residueRootCtx(ctx context.Context, base *big.Int, height int, p uint64) uint64 {
	b0 := modBig(base, p)
	if height < 10 {
		return residueTree(b0, height, p)
	}
	k := differencesLevel(height)
	d, nodes := 1<<k, 1<<(height-k)
	D := make([]uint64, d+1)
	step := (uint64(1) << k) % p
	start := b0
	for j := 0; j <= d; j++ {
		D[j] = residueTree(start, k, p)
		start = (start + step) % p
	}
	for i := 1; i <= d; i++ {
		for j := d; j >= i; j-- {
			D[j] = (D[j] + p - D[j-1]) % p
		}
	}
	var stack [64]struct {
		v     uint64
		level int
	}
	top := 0
	for n := 0; n < nodes; n++ {
		if n&4095 == 4095 && ctx.Err() != nil {
			return 0
		}
		cur, level := D[0], 0
		for top > 0 && stack[top-1].level == level {
			top--
			cur = pairMod(stack[top].v, cur, p)
			level++
		}
		stack[top].v, stack[top].level = cur, level
		top++
		stepDifferences(D[:d], D[1:d+1], p)
	}
	return stack[0].v
}

// stepDifferences is one step of the method: a[i] += b[i] modulo p, where b
// is a shifted by one. Every value is below p < 2^62, so a[i] + b[i] - p
// lies in (-p, p) as a signed word and its sign bit says whether to add p
// back: no branch, whose outcome would be a coin toss on every addition.
func stepDifferences(a, b []uint64, p uint64) {
	b = b[:len(a)]
	i := 0
	for ; i+4 <= len(a); i += 4 {
		x0 := a[i] + b[i] - p
		x1 := a[i+1] + b[i+1] - p
		x2 := a[i+2] + b[i+2] - p
		x3 := a[i+3] + b[i+3] - p
		a[i] = x0 + p&uint64(int64(x0)>>63)
		a[i+1] = x1 + p&uint64(int64(x1)>>63)
		a[i+2] = x2 + p&uint64(int64(x2)>>63)
		a[i+3] = x3 + p&uint64(int64(x3)>>63)
	}
	for ; i < len(a); i++ {
		x := a[i] + b[i] - p
		a[i] = x + p&uint64(int64(x)>>63)
	}
}

// hopResidue is hop_n mod p, without hop_n (§5.9).
func (g hopGeometry) hopResidue(p uint64) uint64 {
	return g.hopResidueCtx(context.Background(), p)
}

func (g hopGeometry) hopResidueCtx(ctx context.Context, p uint64) uint64 {
	var r [4]uint64
	for i := range r {
		r[i] = residueRootCtx(ctx, g.bases[i], g.heights[i], p)
	}
	return pairMod(pairMod(pairMod(r[0], r[1], p), r[2], p), r[3], p)
}

// hopAttempt is one re-roll attempt (§5.10): G for this nonce.
func hopAttempt(prev, seal []byte, nonce uint64) []byte {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	h := sha256.New()
	h.Write(hopGrindDomain)
	h.Write(prev)
	h.Write(seal)
	h.Write(nb[:])
	seed := h.Sum(nil)
	gBase := new(big.Int).SetBytes(seed)
	gBase.And(gBase, axisMask)
	gBase = aligned(gBase, hopGrindHeight)
	rg := residueRoot(gBase, hopGrindHeight, hopPrime(prev, 0))
	var rb [8]byte
	binary.BigEndian.PutUint64(rb[:], rg)
	h = sha256.New()
	h.Write(hopGrindDomain)
	h.Write(seed)
	h.Write(rb[:])
	return h.Sum(nil)
}

// meetsPrice is G × A < 2^256, G read as a big-endian integer (§5.10,
// §6.10, DECK-0001 §5.5).
func meetsPrice(G []byte, price *big.Int) bool {
	return new(big.Int).Mul(new(big.Int).SetBytes(G), price).Cmp(two256) < 0
}

// hopLeaf is leaf_b of the seal's tree (§5.10).
func hopLeaf(prev []byte, block uint64, residues []uint64) []byte {
	buf := make([]byte, 0, len(hopLeafDomain)+32+8+8*residueBlock)
	buf = append(buf, hopLeafDomain...)
	buf = append(buf, prev...)
	buf = binary.BigEndian.AppendUint64(buf, block)
	for _, r := range residues {
		buf = binary.BigEndian.AppendUint64(buf, r)
	}
	sum := sha256.Sum256(buf)
	return sum[:]
}

// climbs reports whether leaf at position, with its siblings from the leaf
// level up, climbs to root: even positions are left children (§5.10, §6.10).
func climbs(leaf []byte, position *big.Int, siblings [][]byte, root []byte) bool {
	cur := leaf
	pos := new(big.Int).Set(position)
	buf := make([]byte, 64)
	for _, sib := range siblings {
		if pos.Bit(0) == 0 {
			copy(buf, cur)
			copy(buf[32:], sib)
		} else {
			copy(buf, sib)
			copy(buf[32:], cur)
		}
		s := sha256.Sum256(buf)
		cur = s[:]
		pos.Rsh(pos, 1)
	}
	return string(cur) == string(root)
}

// isLowerHex reports whether s is exactly n characters of 0-9 and a-f.
func isLowerHex(s string, n int) bool {
	return len(s) == n && isHexLen(s, n)
}

// ErrHopTooTall is reported when a hop that passes the form and the price
// is taller than the verifier was allowed to check: no verdict was reached.
type ErrHopTooTall struct{ HMax, Ceiling int }

func (e ErrHopTooTall) Error() string {
	return fmt.Sprintf("h_max %d exceeds the verification ceiling %d", e.HMax, e.Ceiling)
}

// verifyHopLevel1 is Level 1 of a version 2 hop (§5.11, §8.7.1 steps 7 to
// 11). It returns "" when the proof holds, or why not; err is ErrHopTooTall
// when the hop passes form and price but is taller than ceiling, which is no
// verdict. Every opening's path is checked before any residue is computed,
// since the paths are cheap; a hop is invalid when any residue or any path
// fails, so the verdict is the reference's whichever fails first. From
// h_max 20 the 16 residues are computed in parallel.
//
// ceiling is at most MaxHopVerifyHeightLimit: above it the residue count m no
// longer fits a machine word. Once ctx ends it returns early, and its answer
// means nothing.
func verifyHopLevel1(ctx context.Context, prev []byte, from, to Coord, proof, mn, mp string, ceiling int) (string, error) {
	return verifyHopLevel1Kept(ctx, prev, from, to, proof, mn, mp, ceiling, nil)
}

// verifyHopLevel1Kept is verifyHopLevel1 that keeps each residue it computes
// in kept (nil keeps none) and computes only those kept does not hold, so a
// tall hop whose check its deadline cuts short is finished by the next
// check rather than started again.
func verifyHopLevel1Kept(ctx context.Context, prev []byte, from, to Coord, proof, mn, mp string, ceiling int, kept *hopResidues) (string, error) {
	ceiling = min(ceiling, MaxHopVerifyHeightLimit)
	g := newHopGeometry(prev, from, to)
	if !isLowerHex(proof, 64) {
		return "proof: not a seal of 64 lowercase hex characters (8.4)", nil
	}
	if !isLowerHex(mn, 16) {
		return "mn: not a nonce of exactly 16 lowercase hex characters (8.4)", nil
	}
	if !isLowerHex(mp, mpLength(g.depth)) {
		return fmt.Sprintf("mp: not exactly %d lowercase hex characters, the 16 openings at depth %d (8.4)", mpLength(g.depth), g.depth), nil
	}
	seal, _ := hex.DecodeString(proof)
	nonceBytes, _ := hex.DecodeString(mn)
	G := hopAttempt(prev, seal, binary.BigEndian.Uint64(nonceBytes))
	if !meetsPrice(G, g.price) {
		return fmt.Sprintf("mn: G times A = %s is not below 2^256; the nonce misses the re-roll price (5.10)", g.price), nil
	}
	if g.hMax > ceiling {
		return "", ErrHopTooTall{g.hMax, ceiling}
	}
	raw, _ := hex.DecodeString(mp)
	width := (16*residueBlock + 64*g.depth) / 2
	idx := make([]uint64, hopSamples)
	blocks := make([][]uint64, hopSamples)
	for i := 0; i < hopSamples; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		h := sha256.New()
		h.Write(hopSampleDomain)
		h.Write(G)
		h.Write(ib[:])
		v := new(big.Int).SetBytes(h.Sum(nil))
		v.Mod(v, g.m) // m < 2^64 below the ceiling
		idx[i] = v.Uint64()
		o := raw[i*width : (i+1)*width]
		blocks[i] = make([]uint64, residueBlock)
		for r := 0; r < residueBlock; r++ {
			blocks[i][r] = binary.BigEndian.Uint64(o[8*r:])
		}
		sibs := make([][]byte, g.depth)
		for d := 0; d < g.depth; d++ {
			sibs[d] = o[8*residueBlock+32*d : 8*residueBlock+32*(d+1)]
		}
		block := idx[i] / residueBlock
		if !climbs(hopLeaf(prev, block, blocks[i]), new(big.Int).SetUint64(block), sibs, seal) {
			return fmt.Sprintf("mp: opening %d (block %d): its path does not climb to the seal (5.11)", i, block), nil
		}
	}
	want := make([]uint64, hopSamples)
	workers := 1
	if g.hMax >= 20 {
		workers = min(hopSamples, runtime.GOMAXPROCS(0))
	}
	var wg sync.WaitGroup
	next := make(chan int, hopSamples)
	for i := 0; i < hopSamples; i++ {
		next <- i
	}
	close(next)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if ctx.Err() != nil {
					continue
				}
				if r, ok := kept.get(idx[i]); ok {
					want[i] = r
					continue
				}
				r := g.hopResidueCtx(ctx, hopPrime(prev, idx[i]))
				if ctx.Err() == nil { // finished before the deadline: a true residue
					want[i] = r
					kept.put(idx[i], r)
				}
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for i := 0; i < hopSamples; i++ {
		if blocks[i][idx[i]%residueBlock] != want[i] {
			return fmt.Sprintf("mp: opening %d (index %d): residue %d of block %d is not hop_n mod p_%d (5.11)", i, idx[i], idx[i]%residueBlock, idx[i]/residueBlock, idx[i]), nil
		}
	}
	return "", nil
}
