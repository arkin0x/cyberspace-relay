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
	sp, canonical := rt.reg.Lookup(path)
	var region regiongate.PathRegion
	switch {
	case sp != nil:
		var err error
		if region, err = regiongate.ParseRegionPath("/" + sp.ID); err != nil {
			return false
		}
	default:
		parsed, err := regiongate.ParseRegionPath(path)
		if err != nil {
			return false // not a region: grain's usual handlers
		}
		region, canonical = parsed, "/"+parsed.Hex
	}
	if path != canonical {
		http.Redirect(w, r, canonical, http.StatusMovedPermanently)
		return true
	}
	url := ""
	if sp != nil {
		url = rt.url(sp.ID)
	}
	page := speakeasy.NewPage(region, rt.cfg.Planes, sp, url)
	if sp == nil && rt.checkout != nil {
		page.Create = &speakeasy.PageCreate{Sats: rt.cfg.Payments.SpeakeasySats, Endpoint: OrdersPath}
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
	AmountSats int64  `json:"amount_sats"`
	Invoice    string `json:"invoice"`
	QR         string `json:"qr_svg"`
	ExpiresAt  int64  `json:"expires_at"`
	Status     string `json:"status"`
	Applied    bool   `json:"applied"`
	Outcome    string `json:"outcome,omitempty"`
	// URL is the speakeasy's address, once the paid order made it one.
	URL string `json:"url,omitempty"`
}

func (rt *speakeasyRuntime) view(o speakeasy.Order) orderView {
	v := orderView{ID: o.ID, Kind: o.Kind, Region: o.Region, AmountSats: o.AmountSats, Invoice: o.Invoice,
		ExpiresAt: o.ExpiresAt, Status: o.Status, Applied: o.Applied, Outcome: o.Outcome}
	if qr, err := speakeasy.InvoiceQR(o.Invoice); err == nil {
		v.QR = qr
	}
	if o.Applied && (o.Outcome == speakeasy.OutcomeRegistered || o.Outcome == speakeasy.OutcomeAlready) {
		v.URL = rt.url(o.Region)
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
	o, err := rt.checkout.Create(ctx, speakeasy.OrderRequest{
		Kind: speakeasy.OrderSpeakeasy, Region: canonical, Requester: speakeasy.Requester(utils.GetClientIP(r)),
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, rt.view(o))
	case errors.Is(err, speakeasy.ErrAlreadySpeakeasy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrTooManyInvoices):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	case errors.Is(err, speakeasy.ErrNotRegion):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		log.RegionGate().Warn("Speakeasy invoice not made", "region", canonical, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the wallet did not make an invoice; try again"})
	}
}
