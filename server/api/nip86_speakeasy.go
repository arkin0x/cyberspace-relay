package api

import (
	"sync"

	"github.com/0ceanslim/grain/server/utils/log"
)

// SpeakeasyAdmin is the speakeasy registry as NIP-86 sees it: the relay
// owner registers, lists and removes speakeasies, and removes events from
// one (ruling D5: only the relay owner moderates). The server installs it
// when speakeasies are on (SetSpeakeasyAdmin); while it is nil, none of
// these methods exist and supportedmethods does not list them.
//
// Each method takes the request's params and returns a result or an error
// string, as the other NIP-86 methods do.
type SpeakeasyAdmin interface {
	// List: no params. Every speakeasy, with whether its database is open.
	List(params []any) (any, string)
	// Add: [{"id": <region path>, "region": {"base": <coord>, "height": H}
	// or {"base", "heights": [hx, hy, hz]}, "name"?, "description"?,
	// "note"?}].
	Add(params []any) (any, string)
	// Remove: [<id>]. The registry entry goes; the database stays on disk.
	Remove(params []any) (any, string)
	// DeleteEvent: [<id>, <event id>]. Removes one event from that
	// speakeasy's database.
	DeleteEvent(params []any) (any, string)
	// Payments: no params. What the owner must settle by hand: ledger
	// lines whose payment bought nothing (refund owed, held) or whose
	// outcome is unknown, and open orders the wallet cannot be asked about.
	Payments(params []any) (any, string)
}

var (
	speakeasyAdminMu sync.RWMutex
	speakeasyAdmin   SpeakeasyAdmin
)

// SetSpeakeasyAdmin installs (or, with nil, removes) the speakeasy methods.
func SetSpeakeasyAdmin(a SpeakeasyAdmin) {
	speakeasyAdminMu.Lock()
	defer speakeasyAdminMu.Unlock()
	speakeasyAdmin = a
}

func currentSpeakeasyAdmin() SpeakeasyAdmin {
	speakeasyAdminMu.RLock()
	defer speakeasyAdminMu.RUnlock()
	return speakeasyAdmin
}

var speakeasyMethodNames = []string{
	"grain_speakeasy_list",
	"grain_speakeasy_add",
	"grain_speakeasy_remove",
	"grain_speakeasy_deleteevent",
	"grain_speakeasy_payments",
}

func speakeasyMethods(a SpeakeasyAdmin) map[string]func(params []any, signer string) (any, string) {
	logged := func(method string, run func([]any) (any, string)) func([]any, string) (any, string) {
		return func(params []any, signer string) (any, string) {
			result, err := run(params)
			log.RelayAPI().Info("NIP-86 speakeasy method", "method", method, "signer", signer, "error", err)
			return result, err
		}
	}
	return map[string]func([]any, string) (any, string){
		"grain_speakeasy_list":        logged("grain_speakeasy_list", a.List),
		"grain_speakeasy_add":         logged("grain_speakeasy_add", a.Add),
		"grain_speakeasy_remove":      logged("grain_speakeasy_remove", a.Remove),
		"grain_speakeasy_deleteevent": logged("grain_speakeasy_deleteevent", a.DeleteEvent),
		"grain_speakeasy_payments":    logged("grain_speakeasy_payments", a.Payments),
	}
}
