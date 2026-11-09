package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0ceanslim/grain/server/speakeasy"
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

	code, body, h := get(t, http.MethodGet, r.root+"/C/"+id, "Accept", browser)
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/html") || !strings.Contains(h.Get("Vary"), "Accept") {
		t.Fatalf("region page: %d %s, Vary %q", code, h.Get("Content-Type"), h.Get("Vary"))
	}
	for _, want := range []string{id, "Not a speakeasy", "a box, 2^47 by 2^48 by 2^48 gibsons (x, y, z)", "both: dataspace (0) and ideaspace (1)",
		"https://www.onosendai.tech/C/" + id, "0fe6b3deeb67e952f852e8c1df15000000000000000000000000000000000000"} {
		if !strings.Contains(body, want) {
			t.Errorf("unregistered region page lacks %q", want)
		}
	}
	if strings.Contains(body, "How to join") || strings.Contains(body, r.wsRoot+"/C/"+id) {
		t.Error("an unregistered region page shows a relay address")
	}

	r.register(t, id)
	_, body, _ = get(t, http.MethodGet, r.root+"/C/"+id, "Accept", browser)
	for _, want := range []string{"Open", r.wsRoot + "/C/" + id, "How to join", "AUTH, NIP-42", "A Cyberspace speakeasy"} {
		if !strings.Contains(body, want) {
			t.Errorf("speakeasy page lacks %q", want)
		}
	}

	// Another spelling of the region: a redirect to its one page.
	// The bare /<hex>, /c/, and other spellings after /C/: a redirect to
	// its one page, /C/<hex> (owner ruling 2026-11-09).
	for _, spelling := range []string{id, "c/" + id, "C/0X" + strings.ToUpper(id), "C/" + id + "/", "C/" + pct(id, false), "0X" + strings.ToUpper(id), pct(id, false)} {
		code, _, h := get(t, http.MethodGet, r.root+"/"+spelling, "Accept", browser)
		if code != http.StatusMovedPermanently || h.Get("Location") != "/C/"+id || !strings.Contains(h.Get("Vary"), "Accept") {
			t.Errorf("/%s: %d to %q, want 301 to /C/%s", spelling, code, h.Get("Location"), id)
		}
	}
	// HEAD answers the headers only.
	if code, body, _ := get(t, http.MethodHead, r.root+"/C/"+id, "Accept", browser); code != 200 || body != "" {
		t.Errorf("HEAD: %d with %d bytes", code, len(body))
	}
	// Not a region, not a browser, or not a GET: not this page, but grain's
	// usual handlers (a sentinel here: the app shell needs the embedded web
	// files, which tests do not load).
	passed := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	for _, c := range []struct{ method, path, accept string }{
		{http.MethodGet, "/fiatjafs-speakeasy", browser},
		{http.MethodGet, "/C/" + id + "/x", browser},
		{http.MethodGet, "/", browser},
		{http.MethodGet, "/C/" + id, "*/*"},
		{http.MethodPost, "/C/" + id, browser},
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
	if code, doc, _ := nip11(t, r.root+"/C/"+id); code != 200 || doc["name"] != "Speakeasy "+id {
		t.Errorf("NIP-11 at a speakeasy path: %d %v", code, doc)
	}
	// Speakeasies closed (an invalid file): no page.
	rt := speakeasyState.Load()
	speakeasyState.Store(&speakeasyRuntime{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/C/"+id, nil)
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
		if s.Name != nil || s.URL != r.wsRoot+"/C/"+s.Region || s.CreatedAt == 0 {
			t.Errorf("item %+v: want name null, url %s, a created_at", s, r.wsRoot+"/C/"+s.Region)
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

	// CORS: any origin (public, read-only, no credentials; preview
	// deployments have unlisted origins), with or without an Origin.
	for _, origin := range []string{"https://www.onosendai.tech", "http://localhost:5173", "https://onosendai-git-x.vercel.app", ""} {
		var hs []string
		if origin != "" {
			hs = []string{"Origin", origin}
		}
		_, _, h, _ := discover(t, r.root, coord, hs...)
		if got := h.Get("Access-Control-Allow-Origin"); got != "*" || h.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("Origin %q: Access-Control-Allow-Origin %q", origin, got)
		}
	}
	// Errors too, so a page can read the message.
	if _, _, h, _ := discover(t, r.root, "bad", "Origin", "https://x.example"); h.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("a 400 lacks the CORS header")
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

// TestRegionPathsAreUnderC (owner ruling 2026-11-09): a region's address is
// /C/<hex>, as www.onosendai.tech/C/<hex>. A websocket at the bare /<hex>
// or at /c/<hex> is refused, naming the /C/ address (no redirect: AUTH
// signs the exact URL); /C/<hex> itself is served; "c" can never be a name.
func TestRegionPathsAreUnderC(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	id := "abc"
	r.register(t, id)
	want := r.wsRoot + "/C/" + id
	for _, p := range []string{"/" + id, "/c/" + id, "/C/" + strings.ToUpper(id)} {
		req, _ := http.NewRequest(http.MethodGet, r.root+p, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), want) {
			t.Errorf("websocket at %s: %d %q, want 400 naming %s", p, resp.StatusCode, body, want)
		}
	}
	c := mustDial(t, want)
	if ok, msg := c.auth(newKey(t), want, c.challenge); !ok && strings.Contains(msg, "relay URL") {
		t.Fatalf("AUTH naming the /C/ address: %q", msg)
	}
	for _, name := range []string{"c", "C", "c-", "C/abc"} {
		if speakeasy.CheckName(name, speakeasyRegionPath) == nil {
			t.Errorf("%q accepted as a name", name)
		}
	}
	if speakeasyDialGuard(want) == nil || speakeasyDialGuard(r.wsRoot+"/c/"+id) == nil {
		t.Error("the built-in client may dial a /C/ address")
	}
}
