package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/0ceanslim/grain/server/regiongate"
	"github.com/0ceanslim/grain/server/speakeasy"
	"github.com/0ceanslim/grain/server/utils/log"
)

// The public web side of speakeasies (docs/speakeasies.md, step 4): the
// region dashboard at /<region> for a browser, and the discovery endpoint
// ONOSENDAI asks which speakeasies hold a coordinate. Both are read-only and
// served ahead of the region gate's HTTP guard: what they show (a region's
// box, a speakeasy's address) is what every speakeasy's NIP-11 already says.

// DiscoveryPath is the discovery endpoint's path.
const DiscoveryPath = "/.well-known/cyberspace-speakeasies"

// discoveryOrigins may read the discovery endpoint from a browser, besides
// any http or https origin on localhost.
var discoveryOrigins = map[string]bool{"https://www.onosendai.tech": true}

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
// empty.
func serveDiscovery(w http.ResponseWriter, r *http.Request, rt *speakeasyRuntime) {
	h := w.Header()
	if allowedOrigin(r.Header.Get("Origin")) {
		h.Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	}
	h.Add("Vary", "Origin")
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

// allowedOrigin reports whether a browser page at origin may read the
// discovery endpoint: www.onosendai.tech, or localhost on any port.
func allowedOrigin(origin string) bool {
	if discoveryOrigins[origin] {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" || u.User != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
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
	var buf bytes.Buffer
	if err := speakeasy.RenderPage(&buf, speakeasy.NewPage(region, rt.cfg.Planes, sp, url)); err != nil {
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
