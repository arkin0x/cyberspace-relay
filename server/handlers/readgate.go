package handlers

import (
	"context"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils"
)

// ReadGate, when set, decides whether a connection may read: it is asked
// with the pubkey the connection authenticated as (NIP-42) and returns false
// and a NIP-01 CLOSED message to refuse. The server sets it when a gate such
// as the region gate also guards reading.
var ReadGate func(ctx context.Context, pubkey string) (bool, string)

// LiveReadGate, when set, decides without blocking whether a live event may
// be pushed to a connection authenticated as pubkey ("" = not authenticated).
var LiveReadGate func(pubkey string) bool

// readGateRefusal applies ReadGate to a connection. Reading through a gate
// always needs AUTH, whatever auth.required says, so the gate cannot be
// opened by a config slip.
func readGateRefusal(client nostr.ClientInterface, timeout time.Duration) (string, bool) {
	if ReadGate == nil {
		return "", false
	}
	pubkey := GetAuthedPubkey(client)
	if pubkey == "" {
		return "auth-required: this relay only serves readers it can place; authenticate first", true
	}
	ctx, cancel := context.WithTimeout(gateContext(context.Background(), client), timeout)
	defer cancel()
	if ok, msg := ReadGate(ctx, pubkey); !ok {
		return msg, true
	}
	return "", false
}

// ReadGateTimeout bounds one read-gate decision.
var ReadGateTimeout = 10 * time.Second

type clientIPKey struct{}

// gateContext is ctx carrying the client's address, which a gate can read
// with ClientIP to limit the work one address queues.
func gateContext(ctx context.Context, client nostr.ClientInterface) context.Context {
	ip := ""
	if ws := client.GetWS(); ws != nil && ws.Request() != nil {
		ip = utils.GetClientIP(ws.Request())
	}
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIP is the client address an EventGate or ReadGate context carries,
// or "" when it is unknown.
func ClientIP(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}
