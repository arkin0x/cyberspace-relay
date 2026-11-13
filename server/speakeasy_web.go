package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0ceanslim/grain/server/regiongate"
	"github.com/0ceanslim/grain/server/speakeasy"
	"github.com/0ceanslim/grain/server/utils"
	"github.com/0ceanslim/grain/server/utils/log"
)

// The public web side of speakeasies (docs/speakeasies.md, step 4): the
// region dashboard at /<region> for a browser, and the discovery endpoint
// ONOSENDAI asks which speakeasies hold a coordinate. Both are read-only and
// served ahead of the region gate's HTTP guard: what they show (a region's
// box, a speakeasy's address) is what every speakeasy's NIP-11 already says.

// DiscoveryPath is the discovery endpoint's path.
const DiscoveryPath = "/.well-known/cyberspace-speakeasies"

// discoveryItem is one speakeasy in a discovery answer. The field names and
// types are the contract ONOSENDAI codes against.
type discoveryItem struct {
	Region    string  `json:"region"`
	Name      *string `json:"name"`
	URL       string  `json:"url"`
	CreatedAt int64   `json:"created_at"`
}

// serveDiscovery answers GET /.well-known/cyberspace-speakeasies?coord=<64
// hex>: every registered speakeasy whose region holds the coordinate, the
// longest region string (the smallest region) first. A bad coordinate is
// 400 {"error": ...}; with speakeasies off or none registered the list is
// empty. Any origin may read it (Access-Control-Allow-Origin: *): it is
// public, read-only and uses no credentials, and ONOSENDAI's preview
// deployments have origins nobody can list ahead.
func serveDiscovery(w http.ResponseWriter, r *http.Request, rt *speakeasyRuntime) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodOptions:
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		h.Set("Allow", "GET, HEAD, OPTIONS")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	raw := r.URL.Query().Get("coord")
	c, err := regiongate.ParseCoord(strings.ToLower(raw))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "coord must be a coordinate: 64 hex characters"})
		return
	}
	items := []discoveryItem{}
	if rt != nil && rt.reg != nil {
		for _, e := range rt.reg.Containing(c) {
			it := discoveryItem{Region: e.ID, URL: rt.url(e.ID), CreatedAt: e.CreatedAt}
			if len(e.Names) > 0 {
				name := e.Names[0]
				it.Name = &name
			}
			items = append(items, it)
		}
	}
	h.Set("Cache-Control", "public, max-age=30")
	writeJSON(w, http.StatusOK, map[string]any{"speakeasies": items})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// wantsPage reports whether r is a browser asking for a page: a GET or HEAD
// that accepts HTML (a websocket upgrade or NIP-11 request is routed first).
func wantsPage(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// servePage serves the region dashboard for a path that is a region string
// or a registered speakeasy path, and reports whether it did. Another
// spelling of a region is sent to its canonical one.
func (rt *speakeasyRuntime) servePage(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.EscapedPath()
	if speakeasy.IsBareRegionPrefix(path) {
		return false // /C and /C/ name nothing
	}
	sp, canonical := rt.reg.Lookup(path)
	var region regiongate.PathRegion
	switch {
	case sp != nil:
		var err error
		if region, err = regiongate.ParseRegionPath("/" + sp.ID); err != nil {
			return false
		}
	default:
		// Not registered: any region string, at /C/<string> (canonical) or
		// bare /<string> and /c/<string> (sent to /C/).
		s := path
		if rest, ok := strings.CutPrefix(path, "/C/"); ok {
			s = "/" + rest
		} else if rest, ok := strings.CutPrefix(path, "/c/"); ok {
			s = "/" + rest
		}
		parsed, err := regiongate.ParseRegionPath(s)
		if err != nil {
			return false // not a region: grain's usual handlers
		}
		region, canonical = parsed, speakeasy.RegionPrefix+parsed.Hex
	}
	// The same URL answers a websocket, NIP-11 or this page by its
	// headers: a cache must keep them apart.
	w.Header().Add("Vary", "Accept")
	if path != canonical {
		http.Redirect(w, r, canonical, http.StatusMovedPermanently)
		return true
	}
	url := ""
	if sp != nil {
		url = rt.url(sp.ID)
	}
	page := speakeasy.NewPage(region, rt.cfg.Planes, sp, url)
	page.Favicon = strings.TrimSpace(utils.GetRelayMetadataCopy().Icon)
	switch {
	case sp != nil && len(sp.Names) > 0:
		page.NameURL = rt.url(sp.Names[0])
	case sp == nil && rt.checkout != nil && rt.checkout.Selling():
		page.Create = &speakeasy.PageCreate{Sats: rt.cfg.Payments.SpeakeasySats, NameSats: rt.cfg.Payments.NameSats, Endpoint: OrdersPath}
	}
	var buf bytes.Buffer
	if err := speakeasy.RenderPage(&buf, page); err != nil {
		log.RegionGate().Error("Region page failed", "path", path, "error", err)
		http.Error(w, "could not render this page", http.StatusInternalServerError)
		return true
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(buf.Bytes())
	}
	return true
}

// ── Create Speakeasy (step 5) ────────────────────────────────────────────

// OrdersPath is where the dashboard asks for invoices:
//
//	POST OrdersPath        {"region": "<region string>"} makes (or returns
//	                       the requester's open) invoice for that region
//	GET  OrdersPath/<id>   how that order stands
const OrdersPath = "/api/speakeasies/orders"

// orderView is an order as the page sees it: never the requester.
type orderView struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Region     string `json:"region"`
	Name       string `json:"name,omitempty"`
	AmountSats int64  `json:"amount_sats"`
	// PaymentHash and ID are what a payer quotes to the relay owner.
	PaymentHash string `json:"payment_hash"`
	Invoice     string `json:"invoice"`
	QR          string `json:"qr_svg,omitempty"`
	ExpiresAt   int64  `json:"expires_at"`
	Status      string `json:"status"`
	Applied     bool   `json:"applied"`
	Outcome     string `json:"outcome,omitempty"`
	// NeedsOwner is set when the payment bought nothing (a refund owed, or
	// held): the page says so, with the order id and payment hash.
	NeedsOwner bool `json:"needs_owner,omitempty"`
	// URL is the speakeasy's address, once the paid order made it one.
	URL string `json:"url,omitempty"`
}

func (rt *speakeasyRuntime) view(o speakeasy.Order) orderView {
	v := orderView{ID: o.ID, Kind: o.Kind, Region: o.Region, Name: o.Name, AmountSats: o.AmountSats, PaymentHash: o.PaymentHash, Invoice: o.Invoice,
		ExpiresAt: o.ExpiresAt, Status: o.Status, Applied: o.Applied, Outcome: o.Outcome, NeedsOwner: speakeasy.NeedsOwner(o.Outcome)}
	if o.Status == speakeasy.StatusPending && o.ExpiresAt > time.Now().Unix() { // only an invoice that can be paid
		if qr, err := speakeasy.InvoiceQR(o.Invoice); err == nil {
			v.QR = qr
		}
	}
	// Only a payment that made the speakeasy leads to it: a refund owed
	// says so instead (the page must never show it as a success).
	if o.Applied && speakeasy.MadeSpeakeasy(o.Outcome) {
		v.URL = rt.url(o.Region)
		if o.Name != "" && o.Outcome == speakeasy.OutcomeRegistered {
			v.URL = rt.url(o.Name)
		}
	}
	return v
}

// serveOrders answers the order endpoints. They exist only while payments
// are on.
func serveOrders(w http.ResponseWriter, r *http.Request, rt *speakeasyRuntime) {
	w.Header().Set("Cache-Control", "no-store")
	if rt == nil || rt.checkout == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "creating speakeasies is not open on this relay"})
		return
	}
	path := r.URL.EscapedPath()
	switch {
	case path == OrdersPath && r.Method == http.MethodPost:
		rt.createOrder(w, r)
	case strings.HasPrefix(path, OrdersPath+"/") && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		o, ok := rt.checkout.Get(strings.TrimPrefix(path, OrdersPath+"/"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such order"})
			return
		}
		writeJSON(w, http.StatusOK, rt.view(o))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST " + OrdersPath + " or GET " + OrdersPath + "/<id>"})
	}
}

// createTimeout bounds one make_invoice round trip, queue included.
const createTimeout = 45 * time.Second

func (rt *speakeasyRuntime) createOrder(w http.ResponseWriter, r *http.Request) {
	// JSON only: a cross-site form cannot send it without a preflight,
	// which this endpoint does not grant.
	if mt, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(mt) != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "send JSON"})
		return
	}
	var body struct {
		Region string `json:"region"`
		// Name, optional, is bought with the speakeasy in one invoice.
		Name string `json:"name"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send {\"region\": \"<region>\"}"})
		return
	}
	var canonical string
	ok := false
	if speakeasyRegionPath != nil {
		canonical, _, ok = speakeasyRegionPath("/" + url.PathEscape(body.Region))
	}
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "region must be a region string: 1 to 64 hex characters"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), createTimeout)
	defer cancel()
	ip := utils.GetClientIP(r)
	o, err := rt.checkout.Create(ctx, speakeasy.OrderRequest{
		Kind: speakeasy.OrderSpeakeasy, Region: canonical, Name: body.Name, Requester: speakeasy.Requester(ip), Network: speakeasy.Network(ip),
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, rt.view(o))
	case errors.Is(err, speakeasy.ErrAlreadySpeakeasy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrBadName):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrNameTaken), errors.Is(err, speakeasy.ErrNameHeld):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrPaused), errors.Is(err, speakeasy.ErrPaymentsOff):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrTooManyInvoices), errors.Is(err, speakeasy.ErrRegionBusy), errors.Is(err, speakeasy.ErrNetworkHasOrder):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrNotRegion):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		log.RegionGate().Warn("Speakeasy invoice not made", "region", canonical, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the wallet did not make an invoice; try again"})
	}
}

// ── The landing page (/speakeasy) and its region check ───────────────────

// LandingPath is the speakeasy landing page: what a speakeasy is, and a
// tool to create one. "speakeasy" is a reserved name, so no speakeasy can
// ever be at this path.
const LandingPath = "/speakeasy"

// CheckPath answers the landing page's tool:
//
//	GET CheckPath?region=<input>&name=<name>
//
// region is anything InputPath reads (a region string, a /C/ link, a
// coordinate, a speakeasy's address); name is a name to check. Both are
// optional. The answer says what the region is (its canonical string,
// size and planes, by the relay's own rules), whether it is a speakeasy
// already, whether the name can be bought with it, and whether payments
// are open. It is read-only, shows only what discovery and NIP-11 already
// say, is never cached, and is rate-limited per address.
const CheckPath = "/api/speakeasies/check"

// checkPerMinute caps check requests per address (an IPv4 address or an
// IPv6 /64) a minute. The page asks once per pause in typing; a person
// never comes near it. Refusals are not escalated to a ban.
var checkPerMinute = 120

// liveTTL is how long the landing page's list of open speakeasies is
// reused before the registry is read again; liveMax how many it shows.
var liveTTL = 30 * time.Second

const liveMax = 12

// liveSnapshot is the landing page's list, read from the registry at.
type liveSnapshot struct {
	at    time.Time
	items []speakeasy.LiveSpeakeasy
	more  int
}

// liveList is the landing page's list of open speakeasies, from a copy at
// most liveTTL old, so a flood of page loads reads the registry at most
// once per liveTTL.
func (rt *speakeasyRuntime) liveList() ([]speakeasy.LiveSpeakeasy, int) {
	if s := rt.live.Load(); s != nil && time.Since(s.at) < liveTTL {
		return s.items, s.more
	}
	items, more := speakeasy.LiveList(rt.reg.List(), rt.url, liveMax)
	rt.live.Store(&liveSnapshot{at: time.Now(), items: items, more: more})
	return items, more
}

// paymentsState is whether Create Speakeasy is open (speakeasy.Payments*).
// Why sales are paused or off is never shown: it may name the wallet.
func (rt *speakeasyRuntime) paymentsState() string {
	switch {
	case rt.checkout == nil:
		return speakeasy.PaymentsOff
	case rt.checkout.Selling():
		return speakeasy.PaymentsOpen
	case strings.HasPrefix(rt.checkout.State(), "off:"):
		return speakeasy.PaymentsOff
	}
	return speakeasy.PaymentsPaused
}

// serveLanding serves the landing page. ?region= prefills the tool when it
// is a region (ONOSENDAI's REGION chip can link here).
func (rt *speakeasyRuntime) serveLanding(w http.ResponseWriter, r *http.Request) {
	m := utils.GetRelayMetadataCopy()
	l := speakeasy.Landing{
		RelayName: strings.TrimSpace(m.Name), Favicon: strings.TrimSpace(m.Icon),
		Logo: strings.TrimSpace(m.Logo), LogoLight: strings.TrimSpace(m.LogoLight),
		PublicURL: rt.publicURL, Host: rt.publicURL,
		Sats: rt.cfg.Payments.SpeakeasySats, NameSats: rt.cfg.Payments.NameSats,
		Payments: rt.paymentsState(), Endpoint: OrdersPath, CheckEndpoint: CheckPath,
		BothPlanes: len(rt.cfg.Planes) != 1,
	}
	if u, err := url.Parse(rt.publicURL); err == nil && u.Host != "" {
		l.Host = u.Host
	}
	if q := r.URL.Query().Get("region"); q != "" {
		if c, ok := speakeasy.RegionInput(q); ok {
			l.Region = c
		}
	}
	l.Live, l.LiveMore = rt.liveList()
	var buf bytes.Buffer
	if err := speakeasy.RenderLanding(&buf, l); err != nil {
		log.RegionGate().Error("Speakeasy landing page failed", "error", err)
		http.Error(w, "could not render this page", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Add("Vary", "Accept")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(buf.Bytes())
	}
}

// checkItem is a speakeasy in a check answer: discovery's fields, plus its
// address at its name.
type checkItem struct {
	discoveryItem
	NameURL string `json:"name_url,omitempty"`
}

// checkRegion is a region in a check answer.
type checkRegion struct {
	// Hex is the canonical region string; Coordinate is true when it is a
	// full coordinate (a place: the page offers sizes around it).
	Hex        string `json:"hex"`
	Coordinate bool   `json:"coordinate"`
	// Size and Planes are the region page's words; Heights each axis's
	// height (x, y, z), so the box is 2^h gibsons along it.
	Size    string  `json:"size"`
	Heights [3]uint `json:"heights"`
	Cube    bool    `json:"cube"`
	Planes  string  `json:"planes"`
	// URL is the address a speakeasy here has; Page its page on this
	// relay; ONOSENDAI the same region in ONOSENDAI.
	URL       string `json:"url"`
	Page      string `json:"page"`
	ONOSENDAI string `json:"onosendai"`
	// Speakeasy is the speakeasy at exactly this region, or null.
	Speakeasy *checkItem `json:"speakeasy"`
	// Inside are the speakeasies of larger regions that hold this one,
	// the smallest first.
	Inside []checkItem `json:"inside"`
}

type checkName struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type checkAnswer struct {
	Region      *checkRegion `json:"region,omitempty"`
	RegionError string       `json:"region_error,omitempty"`
	Name        *checkName   `json:"name,omitempty"`
	Payments    string       `json:"payments"`
}

func (rt *speakeasyRuntime) checkItem(sp *speakeasy.Speakeasy) *checkItem {
	it := &checkItem{discoveryItem: discoveryItem{Region: sp.ID, URL: rt.url(sp.ID), CreatedAt: sp.CreatedAt}}
	if len(sp.Names) > 0 {
		name := sp.Names[0]
		it.Name, it.NameURL = &name, rt.url(name)
	}
	return it
}

// serveCheck answers CheckPath.
func serveCheck(w http.ResponseWriter, r *http.Request, rt *speakeasyRuntime) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if rt == nil || rt.reg == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "speakeasies are not open on this relay"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	if ip := utils.GetClientIP(r); ip != "" && !takeAttempt(regiongate.AddressBucket(ip)+"\x00speakeasy-check", checkPerMinute) {
		h.Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many checks; wait a minute"})
		return
	}
	q := r.URL.Query()
	rawRegion, rawName := q.Get("region"), strings.TrimSpace(q.Get("name"))
	if len(rawRegion) > 512 || len(rawName) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too long"})
		return
	}
	out := checkAnswer{Payments: rt.paymentsState()}
	canonical := ""
	if strings.TrimSpace(rawRegion) != "" {
		c, ok := speakeasy.RegionInput(rawRegion)
		if !ok {
			// A speakeasy's address at its name leads to its region.
			if p := speakeasy.InputPath(rawRegion); p != "" {
				if sp, _ := rt.reg.Lookup(p); sp != nil {
					c, ok = sp.ID, true
				}
			}
		}
		if ok {
			canonical = c
			out.Region = rt.checkRegion(c)
		} else {
			out.RegionError = "Not a region. Paste a region hex, a /C/ link, or a full coordinate."
		}
	}
	if rawName != "" {
		n := &checkName{Name: rawName, OK: true}
		if err := rt.reg.NameFree(rawName, canonical); err != nil {
			n.OK, n.Error = false, nameProblem(rawName, err)
		}
		out.Name = n
	}
	writeJSON(w, http.StatusOK, out)
}

// checkRegion describes region c (canonical) for a check answer.
func (rt *speakeasyRuntime) checkRegion(c string) *checkRegion {
	pr, err := regiongate.ParseRegionPath("/" + c)
	if err != nil {
		return nil
	}
	out := &checkRegion{
		Hex: c, Coordinate: pr.PlaneFixed,
		Size: speakeasy.SizeText(pr.HX, pr.HY, pr.HZ), Heights: [3]uint{pr.HX, pr.HY, pr.HZ},
		Cube: pr.HX == pr.HY && pr.HY == pr.HZ, Planes: speakeasy.PlanesText(pr, rt.cfg.Planes),
		URL: rt.url(c), Page: speakeasy.RegionPrefix + c, ONOSENDAI: speakeasy.ONOSENDAIBase + c,
		Inside: []checkItem{},
	}
	if sp := rt.reg.Get(c); sp != nil {
		out.Speakeasy = rt.checkItem(sp)
	}
	// A region whose string starts with a speakeasy's lies inside it.
	for k := len(c) - 1; k >= 1; k-- {
		if sp := rt.reg.Get(c[:k]); sp != nil {
			out.Inside = append(out.Inside, *rt.checkItem(sp))
		}
	}
	return out
}

// nameProblem says, in the page's words, why name cannot be bought.
func nameProblem(name string, err error) string {
	switch {
	case errors.Is(err, speakeasy.ErrNameTaken):
		return "That name is taken."
	case !errors.Is(err, speakeasy.ErrBadName):
		return "That name can't be used."
	case len(name) < 3 || len(name) > 40:
		return "A name is 3 to 40 characters."
	case strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "":
		return "A name is lowercase letters, digits and dashes."
	case speakeasy.IsReservedName(name):
		return "That name is reserved."
	}
	return "That reads as a region hex. Add a dash, or a letter past f."
}
