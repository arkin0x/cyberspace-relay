package utils

import (
	"net/http/httptest"
	"testing"
)

// X-Forwarded-For is believed only from a trusted proxy (loopback or
// GRAIN_TRUSTED_PROXIES), and then only the hop that proxy wrote: the
// rightmost one that is not itself a trusted proxy. Anything to its left is
// whatever the client sent.
func TestGetClientIPTrustsOnlyTheProxy(t *testing.T) {
	defer SetTrustedProxies("")
	SetTrustedProxies("172.30.0.2, 10.9.0.0/16")
	cases := []struct {
		peer, xff, want string
	}{
		{"203.0.113.7:5000", "", "203.0.113.7"},
		{"203.0.113.7:5000", "198.51.100.1", "203.0.113.7"},           // a client cannot claim another address
		{"172.30.0.2:4000", "198.51.100.1", "198.51.100.1"},           // the proxy's hop
		{"172.30.0.2:4000", "6.6.6.6, 198.51.100.1", "198.51.100.1"},  // the client's own XFF is to the left
		{"172.30.0.2:4000", "198.51.100.1, 10.9.3.4", "198.51.100.1"}, // through two trusted proxies
		{"172.30.0.2:4000", "", "172.30.0.2"},                         // the proxy itself
		{"172.30.0.2:4000", "junk, 198.51.100.1", "198.51.100.1"},     //
		{"172.30.0.2:4000", "198.51.100.1, junk", "172.30.0.2"},       // an unreadable hop ends what is believed
		{"127.0.0.1:4000", "2001:db8::5", "2001:db8::5"},              // loopback is always trusted
		{"[2001:db8::9]:4000", "198.51.100.1", "2001:db8::9"},         // IPv6 peer, untrusted
		{"203.0.113.7", "198.51.100.1", "203.0.113.7"},                // no port
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := GetClientIP(r); got != c.want {
			t.Errorf("peer %s, X-Forwarded-For %q: got %q, want %q", c.peer, c.xff, got, c.want)
		}
	}
	// A proxy may add its own X-Forwarded-For line rather than append to
	// the client's: every line is read, in order.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.30.0.2:4000"
	r.Header.Add("X-Forwarded-For", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	if got := GetClientIP(r); got != "198.51.100.1" {
		t.Errorf("two X-Forwarded-For lines: got %q, want the proxy's hop 198.51.100.1", got)
	}
}
