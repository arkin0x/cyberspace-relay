package handlers

import (
	"context"
	"errors"

	"github.com/0ceanslim/grain/server/db/nostrdb"
	nostr "github.com/0ceanslim/grain/server/types"
)

// Scope is the relay a connection talks to when it is not the root relay: a
// speakeasy, at its own path (server/speakeasies.go). A connection without
// one (ScopeOf nil) is the root's, and every handler then runs exactly as it
// always has, on the globals (nostrdb.GetDB, EventGate, ReadGate,
// OnEventStored, auth.relay_url).
//
// Inside a scope:
//   - every REQ, COUNT and EVENT needs NIP-42 AUTH, whatever auth.required
//     says, and AUTH must name RelayURL exactly (strict match);
//   - events go to and come from the scope's own database (Acquire), never
//     the root's;
//   - the kind and pubkey whitelists do not apply (ruling D6: any kind except
//     what the relay blocks); the blacklist does;
//   - Admit judges writes and Read judges readers;
//   - a stored event is pushed live only through Stored, to the scope's own
//     connections, and never forwarded to backup relays.
type Scope struct {
	// ID identifies the speakeasy (its region id); connections to any of its
	// paths share it. Path is the path segment, for logs.
	ID, Path string
	// RelayURL is the speakeasy's one canonical URL, the one its AUTH events
	// must name.
	RelayURL string
	// Acquire returns the scope's database for one operation and a function
	// that releases it.
	Acquire func() (*nostrdb.NDB, func(), error)
	// Admit decides whether evt, sent on a connection authenticated as
	// authed, may be stored.
	Admit func(ctx context.Context, authed string, evt nostr.Event) (bool, string)
	// Read decides whether a connection authenticated as pubkey may read.
	Read func(ctx context.Context, pubkey string) (bool, string)
	// Stored is called after an event is stored, to push it live.
	Stored func(evt nostr.Event)
}

// scoped is a client that knows its scope.
type scoped interface{ Scope() *Scope }

// ScopeOf is the client's scope, or nil for the root relay.
func ScopeOf(client nostr.ClientInterface) *Scope {
	if c, ok := client.(scoped); ok {
		return c.Scope()
	}
	return nil
}

// errNoDB is the root's "database not available".
var errNoDB = errors.New("database not available")

// acquireDB returns the database a client's requests use: the scope's, or
// the root's global one, with a release function (a no-op for the root).
func acquireDB(s *Scope) (*nostrdb.NDB, func(), error) {
	if s != nil {
		return s.Acquire()
	}
	db := nostrdb.GetDB()
	if db == nil {
		return nil, nil, errNoDB
	}
	return db, func() {}, nil
}

// scopeAuthRequired is the refusal for a request on a scope's connection that
// has not authenticated.
const scopeAuthRequired = "auth-required: this speakeasy only serves identities it can place; authenticate first"
