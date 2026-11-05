package utils

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// trustedProxies are the peers whose X-Forwarded-For this relay believes:
// loopback, and the IPs or CIDRs in GRAIN_TRUSTED_PROXIES (comma-separated),
// such as the reverse proxy in front of the relay. A forwarded header from
// anyone else is ignored, since any client can send one.
var (
	trustedMu      sync.RWMutex
	trustedProxies = parseTrustedProxies(os.Getenv("GRAIN_TRUSTED_PROXIES"))
)

func parseTrustedProxies(s string) []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
		_, n, _ := net.ParseCIDR(cidr)
		out = append(out, n)
	}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			if ip := net.ParseIP(f); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// SetTrustedProxies replaces the trusted proxies (loopback always stays
// trusted), as GRAIN_TRUSTED_PROXIES sets them at startup.
func SetTrustedProxies(list string) {
	trustedMu.Lock()
	trustedProxies = parseTrustedProxies(list)
	trustedMu.Unlock()
}

func isTrustedProxy(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIP is the address of the client behind a request: the peer
// itself, unless the peer is a trusted proxy. Then it is the nearest hop of
// X-Forwarded-For that is not a trusted proxy, read from the right: each
// proxy appends the address it received the request from, so the rightmost
// entries are the ones trusted proxies wrote and anything to their left is
// whatever the client sent.
func GetClientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	if !isTrustedProxy(peer) {
		return peer
	}
	// Every X-Forwarded-For line, in order: a proxy may add its own line
	// rather than append to the client's.
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if xff == "" {
		return peer
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if net.ParseIP(hop) == nil {
			// No per-request debug line here: GetClientIP runs on every HTTP
			// request (RC diagnosis §C). A hop that is not an address ends
			// what can be believed.
			return peer
		}
		if !isTrustedProxy(hop) {
			return hop
		}
	}
	return strings.TrimSpace(hops[0])
}
