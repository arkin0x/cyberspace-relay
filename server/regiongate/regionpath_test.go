package regiongate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

// regionVectorsFile holds the region strings shared with ONOSENDAI
// (speakeasy ruling D7, 2026-11-04): relay.onosendai.tech/<hex> names
// exactly the region of www.onosendai.tech/C/<hex>. It was written from
// ONOSENDAI's own route code (origin/v2 366e9df, src/lib/coordRoute.ts) by
// testdata/tools/onosendai-region-vectors.ts. The canonical copy is
// region-prefix-vectors.json at the root of arkin0x/cyberspace (added by
// arkin0x/cyberspace#88), which every implementation tests against; this
// copy is byte for byte the same (regionVectorsSHA256). To update it, regenerate it there and copy it here
// unchanged. A vector this parser disagrees with is a finding about one
// implementation or the other, never a vector to edit.
const (
	regionVectorsFile   = "testdata/region-prefix-vectors.json"
	regionVectorsSHA256 = "eaeec282fffae9bf6c96b2345d2480da417dc9de7e66ed98547a7b407ce7c9e1"
)

type regionAxis struct {
	Min, Max, Size string
	Height         uint
}

type regionPoint struct {
	Coord, X, Y, Z string
	Plane          uint
}

type regionVector struct {
	Name   string
	Input  string
	Valid  bool
	Kind   string
	Hex    string
	Region struct {
		Plane   *uint
		X, Y, Z regionAxis
	}
	Inside, Outside []regionPoint
}

func TestRegionVectorsAreTheSpecCopy(t *testing.T) {
	b, err := os.ReadFile(regionVectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != regionVectorsSHA256 {
		t.Fatalf("%s has sha256 %s, the spec root's copy %s: copy the spec's file here unchanged, never edit this one", regionVectorsFile, got, regionVectorsSHA256)
	}
}

func TestParseRegionPathVectors(t *testing.T) {
	b, err := os.ReadFile(regionVectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var vf struct{ Vectors []regionVector }
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	valid := 0
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			r, err := ParseRegionPath("/" + v.Input)
			if !v.Valid {
				if err == nil {
					t.Fatalf("%q read as region %s, the vector says invalid", v.Input, r.Hex)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: %v, the vector says %s", v.Input, err, v.Hex)
			}
			if r.Hex != v.Hex {
				t.Fatalf("%q read as %s, want %s", v.Input, r.Hex, v.Hex)
			}
			if kind := map[bool]string{true: "full", false: "prefix"}[r.PlaneFixed]; kind != v.Kind {
				t.Fatalf("kind %s, want %s", kind, v.Kind)
			}
			if v.Region.Plane == nil {
				if r.PlaneFixed {
					t.Fatalf("plane fixed at %d, the vector leaves it open", r.Base.Plane)
				}
			} else if !r.PlaneFixed || r.Base.Plane != *v.Region.Plane {
				t.Fatalf("plane fixed=%v %d, want %d", r.PlaneFixed, r.Base.Plane, *v.Region.Plane)
			}
			for _, ax := range []struct {
				name string
				want regionAxis
				base *big.Int
				h    uint
			}{{"x", v.Region.X, r.Base.X, r.HX}, {"y", v.Region.Y, r.Base.Y, r.HY}, {"z", v.Region.Z, r.Base.Z, r.HZ}} {
				size := new(big.Int).Lsh(big.NewInt(1), ax.h)
				max := new(big.Int).Add(ax.base, new(big.Int).Sub(size, big.NewInt(1)))
				if ax.base.String() != ax.want.Min || ax.h != ax.want.Height || max.String() != ax.want.Max || size.String() != ax.want.Size {
					t.Fatalf("%s: [%s, %s] height %d size %s, want [%s, %s] height %d size %s", ax.name, ax.base, max, ax.h, size, ax.want.Min, ax.want.Max, ax.want.Height, ax.want.Size)
				}
			}
			for _, side := range []struct {
				points []regionPoint
				inside bool
			}{{v.Inside, true}, {v.Outside, false}} {
				for _, p := range side.points {
					c, err := ParseCoord(p.Coord)
					if err != nil {
						t.Fatal(err)
					}
					if c.X.String() != p.X || c.Y.String() != p.Y || c.Z.String() != p.Z || c.Plane != p.Plane {
						t.Fatalf("%s decodes to (%s, %s, %s, %d), want (%s, %s, %s, %d)", p.Coord, c.X, c.Y, c.Z, c.Plane, p.X, p.Y, p.Z, p.Plane)
					}
					if got := r.Contains(c); got != side.inside {
						t.Fatalf("Contains(%s) = %v, want %v", p.Coord, got, side.inside)
					}
					if got := strings.HasPrefix(p.Coord, r.Hex); got != side.inside {
						t.Fatalf("%s starts with %s: %v, the vector says inside=%v", p.Coord, r.Hex, got, side.inside)
					}
					// The box in the point's own plane agrees, as the gate's region list will use it.
					if got := r.Box(c.Plane).Contains(c); got != side.inside {
						t.Fatalf("Box(%d).Contains(%s) = %v, want %v", c.Plane, p.Coord, got, side.inside)
					}
				}
			}
		})
		if v.Valid {
			valid++
		}
	}
	t.Logf("%d region vectors, %d valid", len(vf.Vectors), valid)
}

// A path that is not "/..." is not a region path at all.
func TestParseRegionPathNeedsSlash(t *testing.T) {
	if _, err := ParseRegionPath("abc"); err == nil {
		t.Fatal("a path without its leading slash read as a region")
	}
}
