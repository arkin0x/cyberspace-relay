// Package speakeasy runs many speakeasy relays on one grain instance: each
// registered path (relay.onosendai.tech/<region>) is its own relay, with its
// own NIP-11 document, its own NIP-42 AUTH URL and its own nostrdb database,
// open only while it is used (docs/speakeasies.md, ruling D1). The bare
// relay at / is not one of them and is unchanged by this package.
//
// This package holds the parts that need no websocket: the speakeasy config
// (speakeasies.yml), the registry of paths (registry.json in the data
// directory) and the pool of open databases. The server package routes
// requests to them (server/speakeasies.go).
package speakeasy

import "github.com/0ceanslim/grain/server/regiongate"

// PathRegion is the region a path names, in the shape of
// regiongate.PathRegion (cyberspace-relay #18): the box's low corner, each
// axis's free low bits, and whether the path fixes the plane (only a full
// 64-character coordinate does; a prefix spans both planes, as ONOSENDAI
// draws it).
type PathRegion struct {
	Base       regiongate.Coord
	HX, HY, HZ uint
	PlaneFixed bool
}

// RegionPath reads a request path "/<region string>" as a region, exactly as
// ONOSENDAI reads www.onosendai.tech/C/<region string> (ruling D7). It is
// given the path as sent (http.Request.URL.EscapedPath()): it decodes it
// once itself. It returns the region string's canonical spelling (lowercase
// hex, no 0x, no trailing slash) and the region, or ok false when the path
// is not a region (a name, "/api").
//
// The implementation is regiongate.ParseRegionPath (#18, with the vectors
// shared with ONOSENDAI): once it merges, server/speakeasies.go sets
// speakeasyRegionPath to it, copying PathRegion's fields. Until then the
// registry runs without one: a path is looked up exactly as it is spelled,
// each entry's region is the one the relay owner wrote into it, and a 64
// character id is the one whose plane is fixed. Once it is wired, a path is
// looked up by its canonical spelling, and an entry whose written region is
// not the one its path names is refused (a speakeasy at the wrong cube would
// admit the wrong people).
type RegionPath func(escapedPath string) (canonical string, region PathRegion, ok bool)

// fullCoordLen is the length of a region string that names one gibson, and
// so fixes the plane.
const fullCoordLen = 64

// sameAxes reports whether a box and a path region are the same region,
// leaving the plane aside.
func sameAxes(b regiongate.Box, r PathRegion) bool {
	return b.Base.X.Cmp(r.Base.X) == 0 && b.Base.Y.Cmp(r.Base.Y) == 0 && b.Base.Z.Cmp(r.Base.Z) == 0 &&
		b.HX == r.HX && b.HY == r.HY && b.HZ == r.HZ
}

// inPlanes is the region as the gate's set: the box in each of planes, or,
// when its plane is fixed, in its own.
func inPlanes(b regiongate.Box, fixed bool, planes []uint) *regiongate.Regions {
	if fixed {
		return regiongate.NewRegions(b)
	}
	var boxes []regiongate.Box
	for _, p := range planes {
		c := b
		c.Base = regiongate.Coord{X: b.Base.X, Y: b.Base.Y, Z: b.Base.Z, Plane: p & 1}
		boxes = append(boxes, c)
	}
	return regiongate.NewRegions(boxes...)
}

// ParseRegionPath is regiongate.ParseRegionPath as a RegionPath: the region
// string's canonical spelling and its region, for any spelling ONOSENDAI
// reads as that region (case, 0x, trailing slashes, one percent-decoding).
func ParseRegionPath(escapedPath string) (string, PathRegion, bool) {
	r, err := regiongate.ParseRegionPath(escapedPath)
	if err != nil {
		return "", PathRegion{}, false
	}
	return r.Hex, PathRegion{Base: r.Base, HX: r.HX, HY: r.HY, HZ: r.HZ, PlaneFixed: r.PlaneFixed}, true
}

// regionJSON is a path region in the registry's form.
func regionJSON(r PathRegion) RegionJSON {
	return RegionJSON{Base: r.Base.Hex(), Heights: []uint{r.HX, r.HY, r.HZ}}
}
