package speakeasy

import (
	"bytes"
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
}
