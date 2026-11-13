package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/0ceanslim/grain/client"
)

// TestStaticCardHeaders: the link-preview card is served as a PNG and cached
// for a day (its URL is versioned); the rest of /static/ stays no-cache.
func TestStaticCardHeaders(t *testing.T) {
	prev := client.GetEmbeddedWWW()
	t.Cleanup(func() { client.SetEmbeddedWWW(prev) })
	client.SetEmbeddedWWW(os.DirFS(".."))

	for _, tc := range []struct{ path, typ, cache string }{
		{"/static/og/speakeasy.png?v=1", "image/png", "public, max-age=86400"},
		{"/static/js/theme.js", "text/javascript; charset=utf-8", "no-cache"},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			initRoot(rec, httptest.NewRequest(method, tc.path, nil))
			h := rec.Result().Header
			if rec.Code != http.StatusOK || h.Get("Content-Type") != tc.typ || h.Get("Cache-Control") != tc.cache {
				t.Errorf("%s %s: HTTP %d, Content-Type %q, Cache-Control %q", method, tc.path, rec.Code, h.Get("Content-Type"), h.Get("Cache-Control"))
			}
		}
	}
}
