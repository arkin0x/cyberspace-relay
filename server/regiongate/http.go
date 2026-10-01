package regiongate

import (
	"net/http"
	"strings"
)

// SpeakeasyGuard closes every HTTP route except what a nostr client needs at
// "/": the websocket, the NIP-11 document and NIP-86 management (owner-only
// by NIP-98). grain's web client and its API read events through the
// server's own relay pool, and a browser can sign AUTH for that shared pool,
// so leaving them open would let anyone read around the read gate.
func SpeakeasyGuard(h http.Handler) http.Handler {
	return speakeasyGuard(h)
}

func speakeasyGuard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
			nip11 := strings.Contains(r.Header.Get("Accept"), "application/nostr+json")
			nip86 := r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/nostr+json+rpc")
			if upgrade || nip11 || nip86 {
				h.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
}
