package regiongate

import (
	"crypto/sha256"
	"math/big"
	"math/bits"
)

// The exact Cantor arithmetic the proofs of the chain rules are built on
// (§4), the terrain height K (§5.2), the temporal base (§5.3) and the packed
// form of a coordinate (§2.3). Every function here is a port of
// cyberspace_core (arkin0x/cyberspace-cli src/cyberspace_core, cantor.py,
// movement.py, terrain.py, coords.py) and is locked by the golden vectors.

// cantorPair is π(a, b) = (a + b)(a + b + 1) / 2 + b (§4.2), into z.
func cantorPair(z, a, b *big.Int) *big.Int {
	s := new(big.Int).Add(a, b)
	t := new(big.Int).Mul(s, s) // s(s + 1) = s^2 + s; math/big squares faster than it multiplies
	t.Add(t, s)
	t.Rsh(t, 1)
	return z.Add(t, b)
}

var bigOne = big.NewInt(1)

// subtreeCantor is the Cantor root of the aligned subtree of the given
// height whose leaves are base, base + 1, ..., base + 2^height - 1, built
// exactly (compute_subtree_cantor). It costs 2^height pairings of numbers that
// double in length at every level, so it is used only where the chain rules
// require the exact root: the temporal tree of a sidestep or a boarding
// (height K, at most 16) and the leaves and attempt of a ride (at most 22,
// DECK-0001 §5.3).
func subtreeCantor(base *big.Int, height int) *big.Int {
	if height == 0 {
		return new(big.Int).Set(base)
	}
	type node struct {
		v     *big.Int
		level int
	}
	stack := make([]node, 0, height+1)
	leaf := new(big.Int).Set(base)
	for i := 0; i < 1<<height; i++ {
		cur, level := new(big.Int).Set(leaf), 0
		for len(stack) > 0 && stack[len(stack)-1].level == level {
			left := stack[len(stack)-1].v
			stack = stack[:len(stack)-1]
			cur = cantorPair(left, left, cur)
			level++
		}
		stack = append(stack, node{cur, level})
		leaf.Add(leaf, bigOne)
	}
	return stack[0].v
}

// bytesMin is n as big-endian bytes with no leading zero byte, and 0 as the
// single byte 0 (int_to_bytes_be_min).
func bytesMin(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}
	return n.Bytes()
}

// doubleSHA256Hex is the lowercase hex of SHA256(SHA256(bytesMin(n))), the
// proof hash shape of §5.6, §6.8 and DECK-0001 §3.2.
func doubleSHA256Hex(n *big.Int) string {
	a := sha256.Sum256(bytesMin(n))
	b := sha256.Sum256(a[:])
	return hexOf(b[:])
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

// axisMask is 2^85 - 1.
var axisMask = new(big.Int).Sub(new(big.Int).Lsh(bigOne, AxisBits), bigOne)

// aligned is (v >> h) << h, the base of v's aligned subtree of height h.
func aligned(v *big.Int, h int) *big.Int {
	return new(big.Int).Lsh(new(big.Int).Rsh(v, uint(h)), uint(h))
}

// lcaHeight is the bit length of a XOR b, the height of the smallest aligned
// subtree holding both (§4.4).
func lcaHeight(a, b *big.Int) int {
	return new(big.Int).Xor(a, b).BitLen()
}

// packCoord interleaves x, y and z (85 bits each) and the plane bit into the
// 32 bytes of a coordinate, big-endian (§2.3, xyz_to_coord): bit 0 is the
// plane, and axis bit i sets Z at 1+3i, Y at 2+3i and X at 3+3i.
func packCoord(x, y, z *big.Int, plane uint) [32]byte {
	var w [4]uint64 // little-endian words of the 256-bit value
	w[0] = uint64(plane & 1)
	set := func(pos int) { w[pos>>6] |= 1 << uint(pos&63) }
	for _, ax := range []struct {
		v   *big.Int
		off int
	}{{z, 1}, {y, 2}, {x, 3}} {
		for i := 0; i < AxisBits; i++ {
			if ax.v.Bit(i) == 1 {
				set(ax.off + 3*i)
			}
		}
	}
	var out [32]byte
	for i := 0; i < 4; i++ {
		v := w[3-i]
		for j := 0; j < 8; j++ {
			out[8*i+j] = byte(v >> uint(56-8*j))
		}
	}
	return out
}

// terrainDomain and terrainCells are the consensus constants of §5.2.
var (
	terrainDomain = []byte("CYBERSPACE_TERRAIN_K_V2")
	terrainCells  = [4]int{3, 7, 9, 11}
)

// terrainK is the terrain height K in [0, 16] of a coordinate (§5.2), its
// plane bit included: for each cell size, the coordinate aligned to it is
// hashed, and the low nibble of each digest's first byte makes 16 bits whose
// popcount is K.
func terrainK(c Coord) int {
	word := 0
	for _, cell := range terrainCells {
		packed := packCoord(aligned(c.X, cell), aligned(c.Y, cell), aligned(c.Z, cell), c.Plane)
		h := sha256.New()
		h.Write(terrainDomain)
		h.Write([]byte{byte(cell)})
		h.Write(packed[:])
		word = word<<4 | int(h.Sum(nil)[0]&0x0f)
	}
	return bits.OnesCount(uint(word))
}

// temporalBase is the base of the temporal tree (§5.3): t = previous_event_id
// read as a big-endian integer, modulo 2^85, aligned at height K.
func temporalBase(prev []byte, k int) *big.Int {
	t := new(big.Int).SetBytes(prev)
	t.And(t, axisMask)
	return aligned(t, k)
}

// temporalCantor is the exact Cantor root of the temporal tree at height K
// (§5.3, §6.7): what a sidestep and a boarding bind their position to.
func temporalCantor(prev []byte, k int) *big.Int {
	return subtreeCantor(temporalBase(prev, k), k)
}
