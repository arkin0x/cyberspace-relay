package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0ceanslim/grain/config"
	"github.com/0ceanslim/grain/server/speakeasy"
)

// clearCheckBuckets forgets the check endpoint's rate-limit buckets, so a
// test starts with a full allowance.
func clearCheckBuckets() {
	ipBuckets.Range(func(k, _ any) bool {
		if strings.HasSuffix(k.(string), "\x00speakeasy-check") {
			ipBuckets.Delete(k)
		}
		return true
	})
}

// TestLandingPage: a browser at /speakeasy gets the landing page while
// speakeasies are open, ahead of the name paths; /speakeasy/ is sent to
// it; ?region= prefills the tool with the canonical region only; anything
// that is not a browser's request is not the page.
func TestLandingPage(t *testing.T) {
	old := liveTTL
	liveTTL = 0
	t.Cleanup(func() { liveTTL = old })
	r := startRelay(t, speakeasyRegionPath, webYML)
	if _, msg := r.rt.Add([]any{map[string]any{"id": "56db6db6db6db6db6db6dbad", "names": []string{"midwest"}, "created_at": 1762800000}}); msg != "" {
		t.Fatal(msg)
	}
	r.register(t, "0fe6")

	code, body, h := get(t, http.MethodGet, r.root+LandingPath, "Accept", browser)
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/html") || !strings.Contains(h.Get("Vary"), "Accept") || h.Get("Cache-Control") != "no-cache" {
		t.Fatalf("landing: %d %s %q", code, h.Get("Content-Type"), h.Get("Vary"))
	}
	for _, want := range []string{"Speakeasies", "1,000", "8,000", `data-payments="off"`, `role="status"><strong>Not open yet.`, `data-check="` + CheckPath + `"`,
		"midwest", r.wsRoot + "/midwest", r.wsRoot + "/C/0fe6", `data-relay="` + r.wsRoot + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("landing lacks %q", want)
		}
	}
	if i, j := strings.Index(body, r.wsRoot+"/midwest"), strings.Index(body, r.wsRoot+"/C/0fe6"); i < 0 || j < i {
		t.Error("the named speakeasy is not listed first")
	}

	withCheckout(t, r)
	if _, body, _ := get(t, http.MethodGet, r.root+LandingPath, "Accept", browser); !strings.Contains(body, `data-payments="open"`) || !strings.Contains(body, `id="pay-note" role="status" hidden>`) {
		t.Error("payments on: the page does not say so")
	}

	// ?region= prefills, by the relay's own region rules.
	for in, want := range map[string]string{
		"0FE6B3":                              `value="0fe6b3"`,
		"https://www.onosendai.tech/C/0x0fe6": `value="0fe6"`,
		"relay.onosendai.tech/abc":            `value="abc"`,
		"<script>alert(1)</script>":           `value=""`,
		"midwest":                             `value=""`,
	} {
		_, body, _ := get(t, http.MethodGet, r.root+LandingPath+"?region="+url.QueryEscape(in), "Accept", browser)
		if !strings.Contains(body, want) || strings.Contains(body, "<script>alert") {
			t.Errorf("?region=%s: want %s", in, want)
		}
	}

	// /speakeasy/ is sent to /speakeasy, its query kept.
	if code, _, h := get(t, http.MethodGet, r.root+LandingPath+"/?region=abc", "Accept", browser); code != http.StatusMovedPermanently || h.Get("Location") != LandingPath+"?region=abc" {
		t.Errorf("/speakeasy/: %d to %q", code, h.Get("Location"))
	}
	// HEAD answers the headers only.
	if code, body, _ := get(t, http.MethodHead, r.root+LandingPath, "Accept", browser); code != 200 || body != "" {
		t.Errorf("HEAD: %d with %d bytes", code, len(body))
	}
	// NIP-11 at /speakeasy: not a relay (no speakeasy can be there).
	if code, _, _ := nip11(t, r.root+LandingPath); code != http.StatusNotFound {
		t.Errorf("NIP-11 at /speakeasy: %d", code)
	}
	// Not a browser, or not a GET: grain's usual handlers.
	passed := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	for _, c := range []struct{ method, path, accept string }{
		{http.MethodGet, LandingPath, "*/*"},
		{http.MethodPost, LandingPath, browser},
		{http.MethodGet, "/speakeasyx", browser},
		{http.MethodGet, "/speakeasy/x", browser},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("Accept", c.accept)
		speakeasyRoutes(passed).ServeHTTP(w, req)
		if w.Code != 299 {
			t.Errorf("%s %s (Accept %s): %d, want it passed on", c.method, c.path, c.accept, w.Code)
		}
	}
	// Speakeasies closed: no page, no check.
	rt := speakeasyState.Load()
	speakeasyState.Store(&speakeasyRuntime{})
	defer speakeasyState.Store(rt)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, LandingPath, nil)
	req.Header.Set("Accept", browser)
	speakeasyRoutes(passed).ServeHTTP(w, req)
	if w.Code != 299 {
		t.Errorf("closed: %d, want the request passed on", w.Code)
	}
	w = httptest.NewRecorder()
	speakeasyRoutes(passed).ServeHTTP(w, httptest.NewRequest(http.MethodGet, CheckPath+"?region=abc", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("closed check: %d", w.Code)
	}
}

// TestCheckEndpoint: the tool's question about a region and a name,
// answered by the relay's own rules and registry.
func TestCheckEndpoint(t *testing.T) {
	clearCheckBuckets()
	t.Cleanup(clearCheckBuckets)
	r := startRelay(t, speakeasyRegionPath, webYML)
	if _, msg := r.rt.Add([]any{map[string]any{"id": "56db6db6db6db6db6db6dbad", "names": []string{"midwest"}, "created_at": 1762800000}}); msg != "" {
		t.Fatal(msg)
	}
	check := func(q url.Values) (int, map[string]any) {
		t.Helper()
		return getJSON(t, r.root+CheckPath+"?"+q.Encode())
	}

	// A free region, given as an ONOSENDAI link: canonical, sized, both
	// planes, and inside midwest.
	code, out := check(url.Values{"region": {"https://www.onosendai.tech/C/56DB6DB6DB6DB6DB6DB6DBAD3c1"}})
	reg, _ := out["region"].(map[string]any)
	if code != 200 || reg == nil || reg["hex"] != "56db6db6db6db6db6db6dbad3c1" || reg["coordinate"] != false || reg["cube"] != true ||
		reg["size"] != "a cube, 2^49 gibsons a side" || reg["planes"] != "both: dataspace (0) and ideaspace (1)" ||
		reg["url"] != r.wsRoot+"/C/56db6db6db6db6db6db6dbad3c1" || reg["page"] != "/C/56db6db6db6db6db6db6dbad3c1" ||
		reg["onosendai"] != "https://www.onosendai.tech/C/56db6db6db6db6db6db6dbad3c1" || reg["speakeasy"] != nil || out["payments"] != "off" {
		t.Fatalf("free region: %d %v", code, out)
	}
	if in, _ := reg["inside"].([]any); len(in) != 1 || in[0].(map[string]any)["name"] != "midwest" || in[0].(map[string]any)["name_url"] != r.wsRoot+"/midwest" {
		t.Errorf("inside: %v", reg["inside"])
	}

	// The speakeasy itself, by its region or by its address at its name.
	for _, in := range []string{"56db6db6db6db6db6db6dbad", "wss://relay.onosendai.tech/midwest", "/midwest"} {
		_, out := check(url.Values{"region": {in}})
		reg, _ := out["region"].(map[string]any)
		sp, _ := reg["speakeasy"].(map[string]any)
		if sp == nil || sp["name"] != "midwest" || sp["url"] != r.wsRoot+"/C/56db6db6db6db6db6db6dbad" || sp["name_url"] != r.wsRoot+"/midwest" {
			t.Errorf("%s: %v", in, out)
		}
	}

	// A full coordinate is a place: the page sizes a region around it.
	full := "56db6db6db6db6db6db6dbad" + strings.Repeat("0", 39) + "1"
	if _, out := check(url.Values{"region": {full}}); out["region"].(map[string]any)["coordinate"] != true {
		t.Errorf("coordinate: %v", out)
	}

	// Not a region.
	for _, in := range []string{"midwestx", "xyz", "/C/", "<script>"} {
		if _, out := check(url.Values{"region": {in}}); out["region"] != nil || out["region_error"] == nil {
			t.Errorf("%q: %v", in, out)
		}
	}

	// Names: free, taken, reserved, bad, reads as a region; a name bound
	// to a region is free with that region only.
	for name, want := range map[string]string{
		"riverside": "", "midwest": "That name is taken.", "speakeasy": "That name is reserved.", "api": "That name is reserved.",
		"ab": "A name is 3 to 40 characters.", "Hi-There": "A name is lowercase letters, digits and dashes.",
		"cafe": "That reads as a region hex. Add a dash, or a letter past f.",
	} {
		_, out := check(url.Values{"region": {"abc"}, "name": {name}})
		n, _ := out["name"].(map[string]any)
		if n == nil || n["name"] != name || n["ok"] != (want == "") || (want != "" && n["error"] != want) {
			t.Errorf("name %q: %v", name, out)
		}
	}

	// Payments: off, open, paused (no self-check yet).
	withCheckout(t, r)
	if _, out := check(url.Values{"region": {"abc"}}); out["payments"] != "open" {
		t.Errorf("payments on: %v", out["payments"])
	}
	dir := t.TempDir()
	paused, err := speakeasy.NewCheckout(speakeasy.CheckoutConfig{
		Wallet: &memWallet{}, Registry: r.rt.reg, OrdersPath: filepath.Join(dir, "orders.json"), LedgerPath: filepath.Join(dir, "payments.jsonl"),
		Write: config.AtomicWriteFile, Host: "relay.example", SpeakeasySats: 1000, NameSats: 7000, Expiry: 10 * time.Minute, Poll: time.Hour,
		MaxPending: 8, MaxPerRequester: 3, MaxPerNetwork: 6, MaxPerRegion: 2, RequireSelfCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.rt.checkout = paused
	if _, out := check(url.Values{"region": {"abc"}}); out["payments"] != "paused" {
		t.Errorf("payments paused: %v", out["payments"])
	}
	if _, body, _ := get(t, http.MethodGet, r.root+LandingPath, "Accept", browser); !strings.Contains(body, `role="status"><strong>Payments are paused.`) {
		t.Error("the page does not say payments are paused")
	}

	// Method, size, and headers.
	if code, _ := post(t, r.root+CheckPath, "application/json", `{}`); code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", code)
	}
	if code, _ := check(url.Values{"region": {strings.Repeat("a", 600)}}); code != http.StatusBadRequest {
		t.Errorf("too long: %d", code)
	}
	_, _, h := get(t, http.MethodGet, r.root+CheckPath+"?region=abc")
	if h.Get("Cache-Control") != "no-store" || h.Get("Content-Type") != "application/json" || h.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("headers: %v", h)
	}

	// Rate-limited per address, without a ban.
	clearCheckBuckets()
	oldLimit := checkPerMinute
	checkPerMinute = 3
	t.Cleanup(func() { checkPerMinute = oldLimit })
	for i := 0; i < 3; i++ {
		if code, _ := check(url.Values{"region": {"abc"}}); code != 200 {
			t.Fatalf("check %d: %d", i, code)
		}
	}
	code, _, h = get(t, http.MethodGet, r.root+CheckPath+"?region=abc")
	if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Errorf("over the limit: %d", code)
	}
	if code, _, _ := get(t, http.MethodGet, r.root+LandingPath, "Accept", browser); code != 200 {
		t.Errorf("the page itself after the check limit: %d", code)
	}
}
