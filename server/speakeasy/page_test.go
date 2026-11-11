package speakeasy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/0ceanslim/grain/server/regiongate"
)

// TestPageDescribesTheRegion: size, planes and the box's first and last
// gibson per axis, for a cube, a box, one gibson, and a one-plane relay.
func TestPageDescribesTheRegion(t *testing.T) {
	read := func(s string) regiongate.PathRegion {
		r, err := regiongate.ParseRegionPath("/" + s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	full := strings.Repeat("0", 63) + "3" // plane 1, z = 1
	for _, c := range []struct {
		region       string
		planes       []uint
		size, planeT string
		x, z         PageAxis
	}{
		{"000", []uint{0, 1}, "a cube, 2^81 gibsons a side", "both: dataspace (0) and ideaspace (1)",
			PageAxis{"x", "0", "2417851639229258349412351"}, PageAxis{"z", "0", "2417851639229258349412351"}},
		{"f", []uint{0}, "a box, 2^83 by 2^84 by 2^84 gibsons (x, y, z)", "dataspace (0) only",
			PageAxis{"x", "29014219670751100192948224", "38685626227668133590597631"}, PageAxis{"z", "19342813113834066795298816", "38685626227668133590597631"}},
		{full, []uint{0, 1}, "one gibson", "ideaspace (1)", PageAxis{"x", "0", "0"}, PageAxis{"z", "1", "1"}},
	} {
		p := NewPage(read(c.region), c.planes, nil, "")
		if p.Size != c.size || p.Planes != c.planeT || p.Axes[0] != c.x || p.Axes[2] != c.z || p.Speakeasy {
			t.Errorf("%s: %q %q %+v %+v", c.region, p.Size, p.Planes, p.Axes[0], p.Axes[2])
		}
	}
	sp := &Speakeasy{Entry: Entry{ID: "abc", CreatedAt: 1762646400, Names: []string{"cafe-du-monde"}}}
	p := NewPage(read("abc"), []uint{0, 1}, sp, "wss://relay.example/abc")
	var buf bytes.Buffer
	if err := RenderPage(&buf, p); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<title>cafe-du-monde</title>", "wss://relay.example/abc", "2025-11-09", "How to join"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("speakeasy page lacks %q", want)
		}
	}
	if !strings.Contains(buf.String(), `href="/favicon.ico"`) {
		t.Error("no relay icon: the page keeps grain's favicon")
	}
	p.Favicon = "https://relay.example/icon.png"
	buf.Reset()
	if err := RenderPage(&buf, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `<link rel="icon" href="https://relay.example/icon.png">`) || strings.Contains(buf.String(), "/favicon.ico") {
		t.Error("with a relay icon, the page's favicon is that icon")
	}
}

// TestContainingByPrefix: with the region parser, the speakeasies holding a
// coordinate are found by its hex prefixes, longest first, and agree with
// a scan of every entry, in both planes and with a one-plane setting.
func TestContainingByPrefix(t *testing.T) {
	for _, planes := range [][]uint{{0, 1}, {0}} {
		r, _, err := LoadRegistry(filepath.Join(t.TempDir(), "registry.json"), ParseRegionPath, planes, writeFile)
		if err != nil {
			t.Fatal(err)
		}
		coord := "abc0" + strings.Repeat("0", 59) + "1"
		for _, id := range []string{"a", "ab", "abc", "abd", "b", coord, coord[:63] + "0"} {
			if _, err := r.Add(Entry{ID: id, CreatedAt: 1}); err != nil {
				t.Fatal(err)
			}
		}
		for _, hex := range []string{coord, coord[:63] + "0", "b" + strings.Repeat("0", 63), strings.Repeat("f", 64)} {
			c, _ := regiongate.ParseCoord(hex)
			var got, scan []string
			for _, e := range r.Containing(c) {
				got = append(got, e.ID)
			}
			for _, s := range r.byID {
				if s.Regions.Contains(c) {
					scan = append(scan, s.ID)
				}
			}
			sort.Slice(scan, func(i, j int) bool { return len(scan[i]) > len(scan[j]) })
			if strings.Join(got, ",") != strings.Join(scan, ",") || r.ContainsAny(c) != (len(scan) > 0) {
				t.Errorf("planes %v, %s: prefixes %v, scan %v", planes, hex[:6], got, scan)
			}
		}
	}
}

// BenchmarkContaining: discovery against 100,000 registered speakeasies is
// 64 lookups, not a scan.
func BenchmarkContaining(b *testing.B) {
	r, _, err := LoadRegistry(filepath.Join(b.TempDir(), "registry.json"), ParseRegionPath, []uint{0, 1}, func(string, []byte, os.FileMode) error { return nil })
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 100_000; i++ {
		s, _ := r.check(Entry{ID: fmt.Sprintf("%06x", i)})
		r.insert(s)
	}
	c, _ := regiongate.ParseCoord("00abcd" + strings.Repeat("0", 58))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(r.Containing(c)) != 1 {
			b.Fatal("not found")
		}
	}
}

// TestPublicURLIsChecked: public_url must be a websocket URL with a host and
// no path, at config load.
func TestPublicURLIsChecked(t *testing.T) {
	for u, ok := range map[string]bool{
		"wss://relay.onosendai.tech": true, "wss://relay.onosendai.tech/": true, "ws://127.0.0.1:8080": true,
		"https://relay.onosendai.tech": false, "relay.onosendai.tech": false, "wss://": false,
		"wss://relay.onosendai.tech/x": false, "wss://relay.onosendai.tech?a=1": false, "wss://u@relay.example": false,
	} {
		_, err := ParseConfig([]byte("enabled: true\npublic_url: \"" + u + "\"\n"))
		if (err == nil) != ok {
			t.Errorf("public_url %q: %v", u, err)
		}
	}
}
