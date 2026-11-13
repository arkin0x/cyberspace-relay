package speakeasy

import (
	_ "embed"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0ceanslim/grain/server/regiongate"
)

// The landing page at /speakeasy (owner, 2026-11-13): what a speakeasy is,
// what it costs, the speakeasies already open, and a tool to create one.
// It is public and read-only; the tool asks the relay about a region
// (GET /api/speakeasies/check) and buys one through the same order
// endpoints and the same browser code as the region page (checkout.js).

//go:embed landing.html
var landingHTML string

var landingTemplate = template.Must(template.New("landing").Funcs(templateFuncs).Parse(landingHTML))

// ONOSENDAIHome is where a visitor picks a region by eye (VIEW, then the
// Region button).
const ONOSENDAIHome = "https://www.onosendai.tech"

// Payment states the landing page and the check endpoint report.
const (
	PaymentsOpen   = "open"   // invoices are sold
	PaymentsPaused = "paused" // the wallet is not answering (or not checked yet)
	PaymentsOff    = "off"    // payments are not set up, or the wallet refused
)

// Landing is what the landing page shows.
type Landing struct {
	// RelayName, Favicon, Logo and LogoLight are the relay's branding (its
	// relay metadata): the wordmark leads the page.
	RelayName, Favicon, Logo, LogoLight string
	// Host is the relay's host (relay.onosendai.tech), PublicURL its
	// websocket URL; the examples and the addresses are made from them.
	Host, PublicURL string
	// Sats is a speakeasy's price, NameSats what a name adds.
	Sats, NameSats int64
	// Payments is PaymentsOpen, PaymentsPaused or PaymentsOff.
	Payments string
	// Endpoint is where invoices are asked for, CheckEndpoint where a
	// region and a name are checked.
	Endpoint, CheckEndpoint string
	// Region is the region the tool starts with (?region=), canonical, or
	// empty.
	Region string
	// BothPlanes is true when a prefix speakeasy spans both planes (the
	// planes setting).
	BothPlanes bool
	// Live is a few of the speakeasies already open; LiveMore how many
	// more there are.
	Live     []LiveSpeakeasy
	LiveMore int
}

// Price is the price with a thousands separator; NamedPrice the price with
// a name; NamePrice what a name adds.
func (l Landing) Price() string      { return groupThousands(l.Sats) }
func (l Landing) NamedPrice() string { return groupThousands(l.Sats + l.NameSats) }
func (l Landing) NamePrice() string  { return groupThousands(l.NameSats) }

// ExampleRegion is the region the price card shows an address for.
func (l Landing) ExampleRegion() string { return "56db6db6db6db6db6db6dbad" }

// RenderLanding writes the landing page.
func RenderLanding(w io.Writer, l Landing) error { return landingTemplate.Execute(w, l) }

// LiveSpeakeasy is one open speakeasy as the landing page lists it: only
// what its own NIP-11 and the discovery endpoint already say.
type LiveSpeakeasy struct {
	// Name is its reserved name, or empty; Region its region string.
	Name, Region string
	// URL is its address (at its name, when it has one), Page its page
	// on this relay.
	URL, Page string
	// Since is when it opened (YYYY-MM-DD); Size how big it is.
	Since, Size string
}

// LiveList picks the speakeasies the landing page lists, at most max: the
// named ones first, the oldest first (the first named speakeasies are the
// relay owner's), then the rest, the newest first. more is how many are
// left out. url makes a path segment's address.
func LiveList(entries []Entry, url func(seg string) string, max int) (live []LiveSpeakeasy, more int) {
	es := append([]Entry(nil), entries...)
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if (len(a.Names) > 0) != (len(b.Names) > 0) {
			return len(a.Names) > 0
		}
		if a.CreatedAt != b.CreatedAt {
			if len(a.Names) > 0 {
				return a.CreatedAt < b.CreatedAt
			}
			return a.CreatedAt > b.CreatedAt
		}
		return a.ID < b.ID
	})
	if len(es) > max {
		more, es = len(es)-max, es[:max]
	}
	for _, e := range es {
		it := LiveSpeakeasy{Region: e.ID, URL: url(e.ID), Page: PathFor(e.ID), Since: time.Unix(e.CreatedAt, 0).UTC().Format("2006-01-02")}
		if len(e.Names) > 0 {
			it.Name, it.URL, it.Page = e.Names[0], url(e.Names[0]), PathFor(e.Names[0])
		}
		if r, err := regiongate.ParseRegionPath("/" + e.ID); err == nil {
			it.Size = SizeText(r.HX, r.HY, r.HZ)
		}
		live = append(live, it)
	}
	return live, more
}

// SizeText says how big a box is, in gibsons a side (the region page's
// words).
func SizeText(hx, hy, hz uint) string { return sizeText(hx, hy, hz) }

// PlanesText names the planes a region spans (the region page's words).
func PlanesText(r regiongate.PathRegion, planes []uint) string { return planesText(r, planes) }

// maxInput bounds what InputPath reads: a URL to a full coordinate is
// well under it.
const maxInput = 512

// hostPath is a link written without its scheme: a host (with a dot),
// an optional port, then a path.
var hostPath = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?/`)

// InputPath reads what a visitor typed or pasted to name a region as a
// path as sent, in the forms the relay and ONOSENDAI write: a region
// string alone ("56db6d", "0x56db6d"), C/<hex> or /C/<hex>, or a link to
// one on any host, with or without its scheme (http, https, ws, wss):
// www.onosendai.tech/C/<hex>, relay.onosendai.tech/C/<hex>, the bare
// relay.onosendai.tech/<hex> that ONOSENDAI's REGION chip links to, or a
// speakeasy's address, which may be its name (/midwest). It returns "" for
// nothing usable. The path is left escaped: ParseRegionPath and
// Registry.Lookup decode it once themselves.
func InputPath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxInput {
		return ""
	}
	lower := strings.ToLower(s)
	scheme := false
	for _, p := range []string{"http://", "https://", "ws://", "wss://"} {
		scheme = scheme || strings.HasPrefix(lower, p)
	}
	if scheme || hostPath.MatchString(s) {
		if !scheme {
			s = "https://" + s
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return ""
		}
		p := u.EscapedPath()
		if p == "" || p == "/" {
			return ""
		}
		return p
	}
	if len(s) >= 2 && (s[0] == 'C' || s[0] == 'c') && s[1] == '/' {
		s = "/" + s
	}
	if strings.HasPrefix(s, "/") {
		return s
	}
	// A region string alone, escaped as the order endpoint escapes it.
	return "/" + url.PathEscape(s)
}

// RegionInput reads a visitor's input as a region (InputPath's forms) and
// returns its canonical region string, by the same rules (ParseRegionPath,
// the vectors shared with ONOSENDAI) the relay serves /C/<hex> with.
func RegionInput(raw string) (string, bool) {
	p := InputPath(raw)
	// The prefix with nothing after it names nothing, in either case.
	if p == "" || IsBareRegionPrefix(p) || p == "/c/" {
		return "", false
	}
	if rest, ok := cutRegionPrefix(p); ok {
		p = "/" + rest
	}
	r, err := regiongate.ParseRegionPath(p)
	if err != nil {
		return "", false
	}
	return r.Hex, true
}
