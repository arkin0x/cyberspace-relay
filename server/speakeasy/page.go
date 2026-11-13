package speakeasy

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"regexp"
	"time"

	"github.com/0ceanslim/grain/server/regiongate"
)

// The region dashboard (speakeasy plan step 4): a public, read-only page at
// /<region> for a browser, saying what the region is and whether it is a
// speakeasy, and how to join one. It takes grain's theme tokens and fonts.

//go:embed page.html
var pageHTML string

var pageTemplate = template.Must(template.New("region").Funcs(templateFuncs).Parse(pageHTML))

// checkoutJS is Create Speakeasy's browser side, shared by the region page
// and the landing page, so both read an order the same way.
//
//go:embed checkout.js
var checkoutJS string

// templateFuncs are the pages' helpers: checkoutJS inlines the shared
// script (the relay's own file, so it is trusted as JS).
// pow raises the power in a size ("2^45" as 2<sup>45</sup>), after
// escaping the rest.
var templateFuncs = template.FuncMap{
	"checkoutJS": func() template.JS { return template.JS(checkoutJS) },
	"pow": func(s string) template.HTML {
		return template.HTML(powRE.ReplaceAllString(template.HTMLEscapeString(s), "2<sup>$1</sup>"))
	},
}

var powRE = regexp.MustCompile(`2\^(\d+)`)

// ONOSENDAIBase is where a region is drawn: www.onosendai.tech/C/<hex> is
// the same region as relay.onosendai.tech/<hex> (ruling D7).
const ONOSENDAIBase = "https://www.onosendai.tech/C/"

// Page is what the region dashboard shows.
type Page struct {
	// Region is the region string in its canonical spelling.
	Region string
	// Size, Planes and Axes describe the box; LowCorner is its low corner
	// as a coordinate (plane bit 0 for a prefix); ONOSENDAI links the map.
	Size, Planes, LowCorner, ONOSENDAI string
	Axes                               []PageAxis
	// Speakeasy says whether the region is one; URL, its reserved Name (if
	// any) and Since describe it when it is.
	Speakeasy        bool
	URL, Name, Since string
	// NameURL is the speakeasy's address at its name, once it has one.
	NameURL string
	// Create, when set, offers Create Speakeasy (step 5): payments are on
	// and the region is not one yet, with an optional name (step 6: a name
	// comes only with creation, in the same invoice).
	Create *PageCreate
	// Favicon is the tab icon: the relay's NIP-11 icon, which the
	// speakeasy's own NIP-11 document carries too. Empty: grain's favicon.
	Favicon string
}

// PageCreate is the Create Speakeasy offer: its price, the price a name
// adds, and the endpoint the button asks for an invoice.
type PageCreate struct {
	Sats, NameSats int64
	Endpoint       string
}

// Price is the price with a thousands separator; NamedPrice the price
// with a name; NamePrice what a name adds.
func (c PageCreate) Price() string      { return groupThousands(c.Sats) }
func (c PageCreate) NamedPrice() string { return groupThousands(c.Sats + c.NameSats) }
func (c PageCreate) NamePrice() string  { return groupThousands(c.NameSats) }

func groupThousands(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// PageAxis is one axis of the box: the first and last gibson, in decimal.
type PageAxis struct {
	Name     string
	From, To string
}

// NewPage describes region r. planes are the planes a region whose path
// does not fix one spans (Config.Planes). sp is its speakeasy, or nil, and
// url that speakeasy's address.
func NewPage(r regiongate.PathRegion, planes []uint, sp *Speakeasy, url string) Page {
	p := Page{
		Region:    r.Hex,
		Size:      sizeText(r.HX, r.HY, r.HZ),
		Planes:    planesText(r, planes),
		LowCorner: r.Base.Hex(),
		ONOSENDAI: ONOSENDAIBase + r.Hex,
	}
	for _, ax := range []struct {
		name string
		v    *big.Int
		h    uint
	}{{"x", r.Base.X, r.HX}, {"y", r.Base.Y, r.HY}, {"z", r.Base.Z, r.HZ}} {
		last := new(big.Int).Lsh(big.NewInt(1), ax.h)
		last.Add(last, ax.v).Sub(last, big.NewInt(1))
		p.Axes = append(p.Axes, PageAxis{Name: ax.name, From: ax.v.String(), To: last.String()})
	}
	if sp != nil {
		p.Speakeasy, p.URL = true, url
		if len(sp.Names) > 0 { // a reserved name (step 6)
			p.Name = sp.Names[0]
		}
		p.Since = time.Unix(sp.CreatedAt, 0).UTC().Format("2006-01-02")
	}
	return p
}

// RenderPage writes the dashboard.
func RenderPage(w io.Writer, p Page) error { return pageTemplate.Execute(w, p) }

// sizeText says how big a box is, in gibsons a side.
func sizeText(hx, hy, hz uint) string {
	side := func(h uint) string {
		if h == 0 {
			return "1"
		}
		return fmt.Sprintf("2^%d", h)
	}
	switch {
	case hx == 0 && hy == 0 && hz == 0:
		return "one gibson"
	case hx == hy && hy == hz:
		return fmt.Sprintf("a cube, %s gibsons a side", side(hx))
	}
	return fmt.Sprintf("a box, %s by %s by %s gibsons (x, y, z)", side(hx), side(hy), side(hz))
}

// planesText names the planes a region spans.
func planesText(r regiongate.PathRegion, planes []uint) string {
	name := func(p uint) string {
		if p&1 == 1 {
			return "ideaspace (1)"
		}
		return "dataspace (0)"
	}
	if r.PlaneFixed {
		return name(r.Base.Plane)
	}
	if len(planes) == 1 {
		return name(planes[0]) + " only"
	}
	return "both: dataspace (0) and ideaspace (1)"
}
