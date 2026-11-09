package speakeasy

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0ceanslim/grain/server/regiongate"
)

var both = []uint{0, 1}

// get is Lookup of "/"+seg, the speakeasy only.
func get(r *Registry, seg string) *Speakeasy { sp, _ := r.Lookup("/" + seg); return sp }

func writeFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func height(h uint) *uint { return &h }

// cube is an aligned cube of height h at the origin's corner shifted by n
// cubes on X: distinct n give distinct, valid regions.
func cube(t *testing.T, n int64, h uint) RegionJSON {
	t.Helper()
	c := regiongate.Coord{X: new(big.Int).Lsh(big.NewInt(n), h), Y: new(big.Int), Z: new(big.Int)}
	return RegionJSON{Base: c.Hex(), Height: height(h)}
}

func TestRegistryAddPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "speakeasies", "registry.json")
	r, bad, err := LoadRegistry(path, nil, both, writeFile)
	if err != nil || len(bad) != 0 || r.Len() != 0 {
		t.Fatalf("missing file: want an empty registry, got %d (%v, %v)", r.Len(), bad, err)
	}
	if _, err := r.Add(Entry{ID: "0fe6b3", Region: cube(t, 1, 40), Note: "paid by hand"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(Entry{ID: "0fe6b4", Region: cube(t, 2, 40)}); err != nil {
		t.Fatal(err)
	}
	r2, bad, err := LoadRegistry(path, nil, both, writeFile)
	if err != nil || len(bad) != 0 {
		t.Fatal(err, bad)
	}
	if r2.Len() != 2 || get(r2, "0fe6b3") == nil || get(r2, "0fe6b3").Note != "paid by hand" {
		t.Fatalf("reload lost entries: %+v", r2.List())
	}
	if err := r2.Remove("0fe6b3"); err != nil {
		t.Fatal(err)
	}
	if get(r2, "0fe6b3") != nil {
		t.Fatal("removed speakeasy still routed")
	}
	r3, _, _ := LoadRegistry(path, nil, both, writeFile)
	if r3.Len() != 1 || get(r3, "0fe6b4") == nil {
		t.Fatalf("remove not persisted: %+v", r3.List())
	}
	if err := r3.Remove("0fe6b3"); err != ErrNotFound {
		t.Fatalf("removing an unknown id: want ErrNotFound, got %v", err)
	}
}

func TestRegistryRefusesBadEntries(t *testing.T) {
	r, _, _ := LoadRegistry(filepath.Join(t.TempDir(), "registry.json"), nil, both, writeFile)
	unaligned := cube(t, 1, 40)
	unaligned.Height = height(41)
	for name, e := range map[string]Entry{
		"uppercase":  {ID: "0FE6", Region: cube(t, 1, 40)},
		"not hex":    {ID: "fiatjafs-speakeasy", Region: cube(t, 1, 40)},
		"traversal":  {ID: "../db", Region: cube(t, 1, 40)},
		"empty":      {ID: "", Region: cube(t, 1, 40)},
		"too long":   {ID: strings.Repeat("a", 65), Region: cube(t, 1, 40)},
		"no region":  {ID: "0fe6"},
		"unaligned":  {ID: "0fe6", Region: unaligned},
		"with names": {ID: "0fe6", Region: cube(t, 1, 40), Names: []string{"fiatjafs-speakeasy"}},
	} {
		if _, err := r.Add(e); err == nil {
			t.Errorf("%s: entry accepted", name)
		}
	}
	if _, err := r.Add(Entry{ID: "0fe6", Region: cube(t, 1, 40)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(Entry{ID: "0fe6", Region: cube(t, 2, 40)}); err == nil {
		t.Fatal("a second speakeasy at the same path was accepted")
	}
	if r.Len() != 1 {
		t.Fatalf("refused entries were kept: %d", r.Len())
	}
}

// A registry file holding a bad entry loads the others; the bad one's path
// is then not a relay.
func TestRegistryLoadLeavesOutBadEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	good := cube(t, 1, 40)
	os.WriteFile(path, []byte(`{"version":1,"speakeasies":[
		{"id":"0fe6","region":{"base":"`+good.Base+`","height":40}},
		{"id":"0FE7","region":{"base":"`+good.Base+`","height":40}},
		{"id":"0fe8","region":{"base":"zz","height":40}}]}`), 0o644)
	r, bad, err := LoadRegistry(path, nil, both, writeFile)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 || get(r, "0fe6") == nil || len(bad) != 2 {
		t.Fatalf("want 0fe6 loaded and two left out, got %d loaded, %v", r.Len(), bad)
	}
}

// The seam for regiongate.ParseRegionPath: with a parser, a path is looked
// up in its canonical spelling (and the canonical path is returned for the
// caller to redirect to), and an entry whose region is not the one its path
// names is refused (at Add and at load).
func TestRegistryUsesTheRegionPathParser(t *testing.T) {
	box, err := cube(t, 1, 40).Box()
	if err != nil {
		t.Fatal(err)
	}
	named := PathRegion{Base: box.Base, HX: box.HX, HY: box.HY, HZ: box.HZ}
	// The stub reads "/0fe6" in any case, with 0x or trailing slashes, as
	// the region named.
	parse := func(path string) (string, PathRegion, bool) {
		s := strings.ToLower(strings.TrimRight(strings.TrimPrefix(path, "/"), "/"))
		s = strings.TrimPrefix(s, "0x")
		if s != "0fe6" {
			return "", PathRegion{}, false
		}
		return "0fe6", named, true
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	r, _, _ := LoadRegistry(path, parse, both, writeFile)
	if _, err := r.Add(Entry{ID: "0fe6", Region: cube(t, 2, 40)}); err == nil {
		t.Fatal("an entry whose region is not its path's was accepted")
	}
	if _, err := r.Add(Entry{ID: "0fe7", Region: cube(t, 1, 40)}); err == nil {
		t.Fatal("an id the parser does not read as a region was accepted")
	}
	if _, err := r.Add(Entry{ID: "0fe6", Region: cube(t, 1, 40)}); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"/C/0fe6", "/0fe6", "/0FE6", "/0x0fe6", "/0fe6/", "/0fe6//", "/C/0FE6", "/c/0fe6", "/C/0x0fe6/"} {
		sp, canonical := r.Lookup(spelling)
		if sp == nil || sp.ID != "0fe6" || canonical != "/C/0fe6" {
			t.Fatalf("%s: want speakeasy 0fe6 at /C/0fe6, got %v %q", spelling, sp, canonical)
		}
	}

	// Unwired: exact spelling only.
	r2, _, _ := LoadRegistry(path, nil, both, writeFile)
	if get(r2, "0fe6") == nil || get(r2, "0FE6") != nil || get(r2, "0fe6/") != nil {
		t.Fatal("without a parser, lookups must be exact")
	}

	// At load, a parser that disagrees with a stored region leaves it out.
	other, _ := cube(t, 3, 40).Box()
	disagree := func(seg string) (string, PathRegion, bool) {
		return strings.TrimPrefix(seg, "/"), PathRegion{Base: other.Base, HX: 40, HY: 40, HZ: 40}, true
	}
	r3, bad, _ := LoadRegistry(path, disagree, both, writeFile)
	if r3.Len() != 0 || len(bad) != 1 {
		t.Fatalf("a stored region its path does not name was loaded (%d, %v)", r3.Len(), bad)
	}
}

// A region string shorter than a full coordinate never fixes the plane, so
// the speakeasy spans the configured planes (both by default); a full
// coordinate keeps its own plane whatever is configured.
func TestRegistryPlanes(t *testing.T) {
	pos := func(region RegionJSON, plane uint) regiongate.Coord {
		b, err := region.Box()
		if err != nil {
			t.Fatal(err)
		}
		return regiongate.Coord{X: b.Base.X, Y: b.Base.Y, Z: b.Base.Z, Plane: plane}
	}
	region := cube(t, 1, 40)
	for _, tc := range []struct {
		planes   []uint
		in0, in1 bool
	}{{both, true, true}, {[]uint{0}, true, false}, {[]uint{1}, false, true}} {
		r, _, _ := LoadRegistry(filepath.Join(t.TempDir(), "registry.json"), nil, tc.planes, writeFile)
		sp, err := r.Add(Entry{ID: "0fe6", Region: region})
		if err != nil {
			t.Fatal(err)
		}
		if sp.Regions.Contains(pos(region, 0)) != tc.in0 || sp.Regions.Contains(pos(region, 1)) != tc.in1 {
			t.Fatalf("planes %v: plane 0 %v, plane 1 %v", tc.planes, sp.Regions.Contains(pos(region, 0)), sp.Regions.Contains(pos(region, 1)))
		}
	}
	// A full coordinate: one gibson, on its own plane.
	c := pos(region, 1)
	full := c.Hex()
	r, _, _ := LoadRegistry(filepath.Join(t.TempDir(), "registry.json"), nil, both, writeFile)
	sp, err := r.Add(Entry{ID: full, Region: RegionJSON{Base: full, Height: height(0)}})
	if err != nil {
		t.Fatal(err)
	}
	if !sp.Regions.Contains(c) || sp.Regions.Contains(pos(region, 0)) {
		t.Fatal("a full coordinate must fix its plane")
	}
	if _, _, err := LoadRegistry(filepath.Join(t.TempDir(), "r.json"), nil, nil, writeFile); err == nil {
		t.Fatal("a registry with no plane was accepted")
	}
}

func TestConfigDefaultsAndGate(t *testing.T) {
	c, err := ParseConfig([]byte("enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxOpenDatabases != 16 || c.IdleCloseSeconds != 300 || c.MapSizeMB != 4096 || c.MaxConnectionsPerPath != 200 {
		t.Fatalf("defaults: %+v", c)
	}
	if len(c.Planes) != 2 {
		t.Fatalf("planes default: %v", c.Planes)
	}
	if c.GateConfig == nil || c.GateConfig.Mode != regiongate.ModeStrict || !*c.GateConfig.UseLocalEvents {
		t.Fatalf("gate defaults: %+v", c.GateConfig)
	}
	c, err = ParseConfig([]byte("enabled: true\npublic_url: wss://relay.example/\ngate:\n  mode: structural\n  cache_ttl_seconds: 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "wss://relay.example" || c.GateConfig.Mode != regiongate.ModeStructural || c.GateConfig.CacheTTLSeconds != 5 {
		t.Fatalf("parsed: %+v %+v", c, c.GateConfig)
	}
	for _, bad := range []string{
		"enabled: true\ngate:\n  regions: [{sector: \"1-1-1\"}]\n",
		"enabled: true\ngate:\n  gate_reads: false\n",
		"enabled: true\ngate:\n  use_local_events: false\n",
		"enabled: true\ngate:\n  mode: loose\n",
		"enabled: true\nplanes: []\n",
		"enabled: true\nplanes: [2]\n",
		"enabled: true\nplanes: [0, 0]\n",
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("accepted: %q", bad)
		}
	}
	if c, err := ParseConfig([]byte("enabled: false\ngate:\n  mode: loose\n")); err != nil || c.Enabled {
		t.Fatalf("disabled config: %v %+v", err, c)
	}
}

// Ruling D3: a name must not look like a region. "cafe" and "0xabc" fit the
// characters and both are regions, so the parser decides.
func TestCheckName(t *testing.T) {
	hexish := func(path string) (string, PathRegion, bool) {
		s := strings.TrimPrefix(strings.TrimPrefix(path, "/"), "0x")
		for _, c := range s {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return "", PathRegion{}, false
			}
		}
		return s, PathRegion{}, s != ""
	}
	for name, ok := range map[string]bool{
		"fiatjafs-speakeasy": true, "the-gibson-9": true,
		"cafe": false, "0xabc": false, "deadbeef": false,
		"ab": false, strings.Repeat("a", 41): false, "Fiatjaf": false, "fiat_jaf": false,
		"admin": false, "onosendai": false, "setup": false,
	} {
		if err := CheckName(name, hexish); (err == nil) != ok {
			t.Errorf("%q: want accepted %v, got %v", name, ok, err)
		}
	}
	if CheckName("fiatjafs-speakeasy", nil) == nil {
		t.Fatal("without the region parser no name may be accepted")
	}
}

// Through the real parser (regiongate.ParseRegionPath, #18): the owner's
// example region, owner-written with no cube (the path names it), found by
// every spelling ONOSENDAI reads as it, under one canonical path.
func TestRegistryWithParseRegionPath(t *testing.T) {
	const id = "0fe6b3deeb67e952f852e8c1df15"
	path := filepath.Join(t.TempDir(), "registry.json")
	r, _, _ := LoadRegistry(path, ParseRegionPath, both, writeFile)
	for _, bad := range []string{"0FE6B3DEEB67E952F852E8C1DF15", "0x" + id} {
		if _, err := r.Add(Entry{ID: bad}); err == nil {
			t.Fatalf("a non-canonical id %q was registered", bad)
		}
	}
	if _, err := r.Add(Entry{ID: id, Region: cube(t, 1, 40)}); err == nil {
		t.Fatal("an entry whose region is not its path's was registered")
	}
	sp, err := r.Add(Entry{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	// The region is every coordinate whose hex starts with the id, on both
	// planes (a prefix never fixes the plane).
	for _, c := range []string{id + strings.Repeat("0", 36), id + strings.Repeat("f", 36), id + strings.Repeat("0", 35) + "1"} {
		if !sp.Regions.Contains(mustCoord(t, c)) {
			t.Fatalf("%s is not inside region %s", c, id)
		}
	}
	if sp.Regions.Contains(mustCoord(t, "0fe6b3deeb67e952f852e8c1df16"+strings.Repeat("0", 36))) {
		t.Fatal("a neighbouring region is inside")
	}
	// The derived region is what the registry stores.
	r2, bad, _ := LoadRegistry(path, ParseRegionPath, both, writeFile)
	if len(bad) != 0 || r2.Get(id) == nil || r2.Get(id).Region.Base == "" {
		t.Fatalf("reload: %v %+v", bad, r2.List())
	}

	pct := func(s string, double bool) string { // percent-encode the first character
		e := fmt.Sprintf("%%%02X", s[0])
		if double {
			e = "%25" + e[1:]
		}
		return "/" + e + s[1:]
	}
	for _, spelling := range []string{
		"/" + id, "/" + strings.ToUpper(id), "/0x" + id, "/0X" + strings.ToUpper(id), "/" + id + "/", "/" + id + "///",
		"/0F" + id[2:], pct(id, false),
	} {
		for _, p := range []string{spelling, "/C" + spelling} {
			got, canonical := r2.Lookup(p)
			if got == nil || got.ID != id || canonical != "/C/"+id {
				t.Fatalf("%s: want %s at /C/%s, got %v %q", p, id, id, got, canonical)
			}
		}
	}
	// Decoded once, as ONOSENDAI decodes once: a double encoding is not the
	// region, and neither are the paths ServeMux would clean into it.
	for _, notIt := range []string{pct(id, true), "//" + id, "/x/../" + id, "/" + id + "/.", "/" + id + "0", "/C" + pct(id, true), "/C/" + id + "/.", "/C/", "/C"} {
		if got, _ := r2.Lookup(notIt); got != nil {
			t.Fatalf("%s led to the speakeasy", notIt)
		}
	}
}

// Ruling D3 through the real parser: a name must not look like a region.
func TestCheckNameWithParseRegionPath(t *testing.T) {
	for name, ok := range map[string]bool{
		"fiatjafs-speakeasy": true, "gibson-9": true, "chiba-city": true,
		"cafe": false, "0xabc": false, "deadbeef": false, "abc": false, "0x0fe6": false, "facade": false,
	} {
		if err := CheckName(name, ParseRegionPath); (err == nil) != ok {
			t.Errorf("%q: want accepted %v, got %v", name, ok, err)
		}
	}
}

func mustCoord(t *testing.T, s string) regiongate.Coord {
	t.Helper()
	c, err := regiongate.ParseCoord(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Through the real parser, a 64-character region is one gibson on its own
// plane, even with both planes configured.
func TestRegistryFullCoordinateWithParseRegionPath(t *testing.T) {
	full := "0fe6b3deeb67e952f852e8c1df15" + strings.Repeat("0", 35) + "1" // plane 1
	r, _, _ := LoadRegistry(filepath.Join(t.TempDir(), "registry.json"), ParseRegionPath, both, writeFile)
	sp, err := r.Add(Entry{ID: full})
	if err != nil {
		t.Fatal(err)
	}
	other := mustCoord(t, full[:63]+"0")
	if !sp.Regions.Contains(mustCoord(t, full)) || sp.Regions.Contains(other) {
		t.Fatal("a full coordinate must be its own gibson on its own plane")
	}
}
