package core

import (
	"errors"
	"sync/atomic"
)

// dialGuard, when set, is asked before the client opens any websocket: a
// non-nil error refuses the dial. The relay installs one so that this
// client, whose connections are shared by every visitor of the web client
// and API, never connects to one of the relay's own speakeasy paths
// (server/speakeasies.go): a speakeasy serves only authenticated members,
// and nothing read over a shared connection can be kept from anyone.
var dialGuard atomic.Pointer[func(url string) error]

// SetDialGuard installs (or, with nil, removes) the dial guard.
func SetDialGuard(f func(url string) error) {
	if f == nil {
		dialGuard.Store(nil)
		return
	}
	dialGuard.Store(&f)
}

// CheckDial reports whether the client may connect to url: the dial guard's
// answer for both the URL as given and its normalized form.
func CheckDial(url string) error {
	g := dialGuard.Load()
	if g == nil {
		return nil
	}
	if err := (*g)(url); err != nil {
		return err
	}
	if n, ok := normalizeRelayURL(url); ok && n != url {
		return (*g)(n)
	}
	return nil
}

// ErrSharedAuth is why the client never answers a NIP-42 challenge: its
// connections are shared by every visitor of the web client and API (one
// pool, AUTH state per relay URL), so a connection authenticated for one
// visitor would serve what that relay keeps for them (a speakeasy's notes,
// NIP-17 gift wraps) to everyone else.
var ErrSharedAuth = errors.New("AUTH is disabled in grain's web client: its relay connections are shared by every visitor, so an authenticated one would serve your private events to anyone; use a nostr client that connects for you alone")
