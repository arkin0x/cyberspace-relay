package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const webYML = "enabled: true\nmax_open_databases: 1\nmap_size_mb: 32\nplanes: [0, 1]\n"

// get fetches url with the given headers, never following redirects.
func get(t *testing.T, method, url string, headers ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

const browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// TestRegionDashboard: a browser at /<region> gets the region's page, for
// any region string, registered or not; other spellings are sent to the
// canonical one; a path that is not a region, or a request that is not a
// browser's, goes on to grain's usual handlers.
func TestRegionDashboard(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	id := "0fe6b3deeb67e952f852e8c1df15"

	code, body, h := get(t, http.MethodGet, r.root+"/"+id, "Accept", browser)
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Fatalf("region page: %d %s", code, h.Get("Content-Type"))
	}
	for _, want := range []string{id, "Not a speakeasy", "a box, 2^47 by 2^48 by 2^48 gibsons (x, y, z)", "both: dataspace (0) and ideaspace (1)",
		"https://www.onosendai.tech/C/" + id, "0fe6b3deeb67e952f852e8c1df15000000000000000000000000000000000000"} {
		if !strings.Contains(body, want) {
			t.Errorf("unregistered region page lacks %q", want)
		}
	}
	if strings.Contains(body, "How to join") || strings.Contains(body, r.wsRoot+"/"+id) {
		t.Error("an unregistered region page shows a relay address")
	}

	r.register(t, id)
	_, body, _ = get(t, http.MethodGet, r.root+"/"+id, "Accept", browser)
	for _, want := range []string{"Open", r.wsRoot + "/" + id, "How to join", "AUTH, NIP-42", "A Cyberspace speakeasy"} {
		if !strings.Contains(body, want) {
			t.Errorf("speakeasy page lacks %q", want)
		}
	}

	// Another spelling of the region: a redirect to its one page.
	for _, spelling := range []string{"0X" + strings.ToUpper(id), id + "/", pct(id, false)} {
		code, _, h := get(t, http.MethodGet, r.root+"/"+spelling, "Accept", browser)
		if code != http.StatusMovedPermanently || h.Get("Location") != "/"+id {
			t.Errorf("/%s: %d to %q, want 301 to /%s", spelling, code, h.Get("Location"), id)
		}
	}
	// HEAD answers the headers only.
	if code, body, _ := get(t, http.MethodHead, r.root+"/"+id, "Accept", browser); code != 200 || body != "" {
		t.Errorf("HEAD: %d with %d bytes", code, len(body))
	}
	// Not a region, not a browser, or not a GET: not this page, but grain's
	// usual handlers (a sentinel here: the app shell needs the embedded web
	// files, which tests do not load).
	passed := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	for _, c := range []struct{ method, path, accept string }{
		{http.MethodGet, "/fiatjafs-speakeasy", browser},
		{http.MethodGet, "/" + id + "/x", browser},
		{http.MethodGet, "/", browser},
		{http.MethodGet, "/" + id, "*/*"},
		{http.MethodPost, "/" + id, browser},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("Accept", c.accept)
		speakeasyRoutes(passed).ServeHTTP(w, req)
		if w.Code != 299 {
			t.Errorf("%s %s (Accept %s): %d, want it passed on", c.method, c.path, c.accept, w.Code)
		}
	}
	// The websocket and NIP-11 at the path are still the speakeasy's.
	if code, doc, _ := nip11(t, r.root+"/"+id); code != 200 || doc["name"] != "Speakeasy "+id {
		t.Errorf("NIP-11 at a speakeasy path: %d %v", code, doc)
	}
	// Speakeasies closed (an invalid file): no page.
	rt := speakeasyState.Load()
	speakeasyState.Store(&speakeasyRuntime{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+id, nil)
	req.Header.Set("Accept", browser)
	speakeasyRoutes(passed).ServeHTTP(w, req)
	if w.Code != 299 {
		t.Errorf("closed speakeasies: %d, want the request passed on", w.Code)
	}
	speakeasyState.Store(rt)
}

type discovery struct {
	Speakeasies []struct {
		Region    string  `json:"region"`
		Name      *string `json:"name"`
		URL       string  `json:"url"`
		CreatedAt int64   `json:"created_at"`
	} `json:"speakeasies"`
	Error string `json:"error"`
}

func discover(t *testing.T, base, coord string, headers ...string) (int, discovery, http.Header, string) {
	t.Helper()
	code, body, h := get(t, http.MethodGet, base+DiscoveryPath+"?coord="+coord, headers...)
	var d discovery
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("discovery answered %d with non-JSON %q", code, body)
	}
	return code, d, h, body
}

// TestDiscoveryEndpoint locks the contract ONOSENDAI codes against:
// GET /.well-known/cyberspace-speakeasies?coord=<64 hex>.
func TestDiscoveryEndpoint(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	coord := "abc0" + strings.Repeat("0", 59) + "1" // plane 1

	// An empty registry: an empty list, never null.
	code, _, h, body := discover(t, r.root, coord)
	if code != 200 || strings.TrimSpace(body) != `{"speakeasies":[]}` {
		t.Fatalf("empty registry: %d %s", code, body)
	}
	if h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "public, max-age=30" {
		t.Errorf("headers: %q %q", h.Get("Content-Type"), h.Get("Cache-Control"))
	}

	for _, id := range []string{"a", "abc", "ab", "b", "abd"} {
		r.register(t, id)
	}
	code, d, _, _ := discover(t, r.root, coord)
	var got []string
	for _, s := range d.Speakeasies {
		got = append(got, s.Region)
		if s.Name != nil || s.URL != r.wsRoot+"/"+s.Region || s.CreatedAt == 0 {
			t.Errorf("item %+v: want name null, url %s, a created_at", s, r.wsRoot+"/"+s.Region)
		}
	}
	if code != 200 || strings.Join(got, ",") != "abc,ab,a" {
		t.Fatalf("speakeasies holding %s: %d %v, want abc,ab,a (longest first)", coord, code, got)
	}
	// The same box in plane 0, and upper case: the same answer.
	if _, d, _, _ := discover(t, r.root, strings.ToUpper(coord[:63]+"0")); len(d.Speakeasies) != 3 {
		t.Errorf("plane 0: %d speakeasies, want 3 (a prefix spans both planes)", len(d.Speakeasies))
	}
	// A 64-character speakeasy is one gibson in its own plane.
	r.register(t, coord)
	if _, d, _, _ := discover(t, r.root, coord); len(d.Speakeasies) != 4 || d.Speakeasies[0].Region != coord {
		t.Errorf("the gibson's own speakeasy should come first: %+v", d.Speakeasies)
	}
	if _, d, _, _ := discover(t, r.root, coord[:63]+"0"); len(d.Speakeasies) != 3 {
		t.Errorf("the other plane's gibson is in %d speakeasies, want 3", len(d.Speakeasies))
	}

	// Bad coordinates: 400 {"error": ...}.
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), "0x" + coord[2:], coord + "0", coord[:63] + "%20"} {
		code, d, _, _ := discover(t, r.root, bad)
		if code != 400 || d.Error == "" || d.Speakeasies != nil {
			t.Errorf("coord %q: %d %+v, want 400 with an error", bad, code, d)
		}
	}

	// CORS: www.onosendai.tech and localhost, nobody else.
	for origin, allowed := range map[string]bool{
		"https://www.onosendai.tech": true, "http://localhost:5173": true, "http://127.0.0.1:8080": true, "https://localhost": true,
		"https://onosendai.tech.evil.example": false, "http://www.onosendai.tech": false, "null": false, "https://evil.example": false,
	} {
		_, _, h, _ := discover(t, r.root, coord, "Origin", origin)
		if got := h.Get("Access-Control-Allow-Origin"); (got == origin) != allowed || (!allowed && got != "") {
			t.Errorf("Origin %s: Access-Control-Allow-Origin %q", origin, got)
		}
	}
	if code, _, h := get(t, http.MethodOptions, r.root+DiscoveryPath, "Origin", "https://www.onosendai.tech"); code != 204 || !strings.Contains(h.Get("Access-Control-Allow-Methods"), "GET") {
		t.Errorf("preflight: %d %q", code, h.Get("Access-Control-Allow-Methods"))
	}
	if code, _, _ := get(t, http.MethodPost, r.root+DiscoveryPath+"?coord="+coord); code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", code)
	}
}

// TestDiscoveryWithoutSpeakeasies: with speakeasies off (no file) the
// endpoint still answers, with an empty list.
func TestDiscoveryWithoutSpeakeasies(t *testing.T) {
	for _, rt := range []*speakeasyRuntime{nil, {}} {
		w := httptest.NewRecorder()
		serveDiscovery(w, httptest.NewRequest(http.MethodGet, DiscoveryPath+"?coord="+strings.Repeat("a", 64), nil), rt)
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"speakeasies":[]}` {
			t.Errorf("runtime %v: %d %s", rt, w.Code, w.Body.String())
		}
	}
}
