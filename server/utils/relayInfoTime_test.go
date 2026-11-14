package utils

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The NIP-11 response carries the relay's clock, readable from another
// origin: X-Server-Time in Unix milliseconds, and Date and X-Server-Time
// named in Access-Control-Expose-Headers (ONOSENDAI's world clock).
func TestRelayInfoExposesServerTime(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/nostr+json")
	rec := httptest.NewRecorder()
	before := time.Now().UnixMilli()
	RelayInfoHandler(rec, req)
	after := time.Now().UnixMilli()

	got := rec.Header().Get(ServerTimeHeader)
	ms, err := strconv.ParseInt(got, 10, 64)
	if err != nil {
		t.Fatalf("%s = %q, want Unix milliseconds", ServerTimeHeader, got)
	}
	if ms < before || ms > after {
		t.Errorf("%s = %d, want between %d and %d", ServerTimeHeader, ms, before, after)
	}
	exposed := rec.Header().Get("Access-Control-Expose-Headers")
	for _, h := range []string{"Date", ServerTimeHeader} {
		if !strings.Contains(exposed, h) {
			t.Errorf("Access-Control-Expose-Headers = %q, missing %s", exposed, h)
		}
	}
}
