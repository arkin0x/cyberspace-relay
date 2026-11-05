package regiongate

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// CoordHexLen is the length of a full coordinate in hex: 256 bits.
const CoordHexLen = 64

// PathRegion is the region a speakeasy path names: relay.onosendai.tech/<hex>
// is exactly the region of www.onosendai.tech/C/<hex> (speakeasy ruling D7,
// 2026-11-04). Both read the hex as the top 4n bits of a coordinate
// (CYBERSPACE_V2 §2.2: x84 y84 z84 x83 ... z0, then the plane bit), so the
// region is every coordinate whose 64-hex form starts with Hex.
//
// That set is an aligned box, the hint-box form of §7.7: each axis keeps its
// own number of free low bits, so the heights are equal (a cube) only when
// len(Hex) is a multiple of 3. The plane is the coordinate's lowest bit, so
// a prefix of 1 to 63 characters leaves it open and the box is the same in
// both planes; only 64 characters fix it, and name one gibson.
//
// The shared vectors are region-prefix-vectors.json at the root of
// arkin0x/cyberspace, written from ONOSENDAI's src/lib/coordRoute.ts.
type PathRegion struct {
	// Hex is the region string as read: 1 to 64 lowercase hex characters.
	Hex string
	// Base is the box's low corner. For a prefix its plane is 0, and means
	// nothing (see PlaneFixed).
	Base Coord
	// HX, HY, HZ are each axis's free low bits: the box is 2^H gibsons along
	// that axis.
	HX, HY, HZ uint
	// PlaneFixed is true only for a full coordinate, whose plane is Base.Plane.
	PlaneFixed bool
}

// ParseRegionPath reads a relay path "/<region string>" as ONOSENDAI's
// parseCoordRoute reads "/C/<region string>". Pass the path as it was sent
// (http.Request.URL.EscapedPath()), not the decoded URL.Path: the string is
// percent-decoded here exactly once, as ONOSENDAI decodes its pathname once.
//
// Reading the string, in ONOSENDAI's order: percent-decode it (on a
// malformed escape, or a result that is not UTF-8, where decodeURIComponent
// throws, keep it undecoded); trim whitespace as JavaScript's
// String.prototype.trim does; drop every trailing "/"; drop one leading "0x"
// or "0X"; lowercase. What remains must be 1 to 64 hex characters.
//
// A path whose string is not a region (a name, "/api", "/") is an error;
// the caller decides what such a path is.
func ParseRegionPath(path string) (PathRegion, error) {
	if !strings.HasPrefix(path, "/") {
		return PathRegion{}, fmt.Errorf("region path must start with /")
	}
	return parseRegionString(path[1:])
}

func parseRegionString(raw string) (PathRegion, error) {
	s, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(s) {
		s = raw
	}
	s = strings.TrimFunc(s, isJSTrimSpace)
	s = strings.TrimRight(s, "/")
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	s = strings.ToLower(s)
	if len(s) < 1 || len(s) > CoordHexLen {
		return PathRegion{}, fmt.Errorf("region must be 1 to %d hex characters, got %d", CoordHexLen, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return PathRegion{}, fmt.Errorf("region must be hex")
		}
	}
	// The low corner: the prefix with every free bit zero.
	base, err := ParseCoord(s + strings.Repeat("0", CoordHexLen-len(s)))
	if err != nil {
		return PathRegion{}, err
	}
	// The prefix fixes coordinate bits 255 down to 256 - 4n. Axis bit i of
	// z, y, x sits at coordinate bit 1+3i, 2+3i, 3+3i (§2.2), so an axis's
	// height is how many of its bits sit below the prefix.
	free := uint(4 * (CoordHexLen - len(s)))
	height := func(offset uint) uint {
		var h uint
		for i := uint(0); i < AxisBits; i++ {
			if offset+3*i < free {
				h++
			}
		}
		return h
	}
	return PathRegion{
		Hex:        s,
		Base:       base,
		HX:         height(3),
		HY:         height(2),
		HZ:         height(1),
		PlaneFixed: len(s) == CoordHexLen,
	}, nil
}

// Contains reports whether c lies in the region: each axis equal to the
// base's above its height and, for a full coordinate, the same plane. This
// is exactly strings.HasPrefix(c.Hex(), r.Hex).
func (r PathRegion) Contains(c Coord) bool {
	if r.PlaneFixed && c.Plane != r.Base.Plane {
		return false
	}
	return r.Box(c.Plane).Contains(c)
}

// Box is the region in one plane, in the form the gate's region list uses.
// For a full coordinate the plane is its own, whatever is asked.
func (r PathRegion) Box(plane uint) Box {
	base := Coord{X: r.Base.X, Y: r.Base.Y, Z: r.Base.Z, Plane: plane & 1}
	if r.PlaneFixed {
		base.Plane = r.Base.Plane
	}
	return Box{Base: base, HX: r.HX, HY: r.HY, HZ: r.HZ}
}

// isJSTrimSpace is the set String.prototype.trim removes (ECMA-262
// WhiteSpace and LineTerminator). It differs from unicode.IsSpace in two
// runes: U+FEFF is trimmed here and U+0085 is not.
func isJSTrimSpace(r rune) bool {
	switch r {
	case 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}
