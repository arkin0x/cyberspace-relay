// Package regiongate admits events only from pubkeys whose Cyberspace v2
// movement chain places them inside the relay's configured region.
//
// The gate resolves each author's active chain (CYBERSPACE_V2 §8.7.3),
// checks it structurally under the chain rules of ChainRulesRevision
// (signatures, links, coordinates, skipped actions per §8.9, virtual brackets
// per §8.11) and asks a ProofChecker about the work proofs. Until a checker
// for those proofs is built, the only ProofChecker is PendingSpec, which
// checks no proofs; see verify.go and docs/region-gate.md.
package regiongate

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// AxisBits is the width of each axis (§2.1): 85 bits per axis plus one plane
// bit make 256.
const AxisBits = 85

// Coord is a decoded 256-bit Cyberspace coordinate (§2.2): X, Y, Z are 85-bit
// unsigned integers and Plane is 0 (dataspace) or 1 (ideaspace).
type Coord struct {
	X, Y, Z *big.Int
	Plane   uint
}

// ParseCoord decodes a coordinate written as 64 lowercase hex characters.
// Bit 0 is the plane; for axis bit i, Z sits at bit 1+3i, Y at 2+3i and X at
// 3+3i (§2.3).
func ParseCoord(s string) (Coord, error) {
	if len(s) != 64 {
		return Coord{}, fmt.Errorf("coordinate must be 64 hex characters, got %d", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return Coord{}, fmt.Errorf("coordinate must be lowercase hex")
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Coord{}, err
	}
	v := new(big.Int).SetBytes(b)
	c := Coord{X: new(big.Int), Y: new(big.Int), Z: new(big.Int), Plane: v.Bit(0)}
	for i := 0; i < AxisBits; i++ {
		c.Z.SetBit(c.Z, i, v.Bit(1+3*i))
		c.Y.SetBit(c.Y, i, v.Bit(2+3*i))
		c.X.SetBit(c.X, i, v.Bit(3+3*i))
	}
	return c, nil
}

// Hex encodes the coordinate back to its 64-character form.
func (c Coord) Hex() string {
	v := new(big.Int).SetUint64(uint64(c.Plane & 1))
	for i := 0; i < AxisBits; i++ {
		v.SetBit(v, 1+3*i, c.Z.Bit(i))
		v.SetBit(v, 2+3*i, c.Y.Bit(i))
		v.SetBit(v, 3+3*i, c.X.Bit(i))
	}
	out := make([]byte, 32)
	v.FillBytes(out)
	return hex.EncodeToString(out)
}

// Sector returns the sector indexes of the coordinate as the decimal strings
// its X, Y and Z tags carry (§10): each axis shifted right by SectorBits.
func (c Coord) Sector() (sx, sy, sz string) {
	return new(big.Int).Rsh(c.X, SectorBits).String(),
		new(big.Int).Rsh(c.Y, SectorBits).String(),
		new(big.Int).Rsh(c.Z, SectorBits).String()
}

// Equal reports whether two coordinates are the same point.
func (c Coord) Equal(o Coord) bool {
	return c.Plane == o.Plane && c.X.Cmp(o.X) == 0 && c.Y.Cmp(o.Y) == 0 && c.Z.Cmp(o.Z) == 0
}

// Box is an axis-aligned region in the hint-box form (§7.7): every point
// whose axes share the base's bits above the per-axis heights, on the base's
// plane. Equal heights give the aligned cube of a virtual bracket (§8.11.1);
// heights of 30 give one sector (§10).
type Box struct {
	Base       Coord
	HX, HY, HZ uint
}

// NewBox validates heights (0..85) and alignment: the low H bits of each base
// axis must be zero, as §8.11.1 requires of a bracket's region.
func NewBox(base Coord, hx, hy, hz uint) (Box, error) {
	b := Box{Base: base, HX: hx, HY: hy, HZ: hz}
	for _, ax := range []struct {
		name string
		v    *big.Int
		h    uint
	}{{"x", base.X, hx}, {"y", base.Y, hy}, {"z", base.Z, hz}} {
		if ax.h > AxisBits {
			return Box{}, fmt.Errorf("height for %s is %d, must be 0..%d", ax.name, ax.h, AxisBits)
		}
		low := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), ax.h), big.NewInt(1))
		if new(big.Int).And(ax.v, low).Sign() != 0 {
			return Box{}, fmt.Errorf("base is not aligned: the low %d bits of %s must be zero", ax.h, ax.name)
		}
	}
	return b, nil
}

// Contains reports whether c lies inside the box: same plane, and each axis
// equal to the base's above its height (x>>H = bx>>H, §8.11.1).
func (b Box) Contains(c Coord) bool {
	if c.Plane != b.Base.Plane {
		return false
	}
	same := func(v, base *big.Int, h uint) bool {
		return new(big.Int).Rsh(v, h).Cmp(new(big.Int).Rsh(base, h)) == 0
	}
	return same(c.X, b.Base.X, b.HX) && same(c.Y, b.Base.Y, b.HY) && same(c.Z, b.Base.Z, b.HZ)
}
