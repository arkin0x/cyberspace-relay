package server

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/0ceanslim/grain/config"
	"github.com/0ceanslim/grain/server/db/nostrdb"
	"github.com/0ceanslim/grain/server/handlers"
	"github.com/0ceanslim/grain/server/regiongate"
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils/log"
	"github.com/0ceanslim/grain/server/validation"
)

const regionConfigFile = "region.yml"

// startRegionGate installs the region gate when region.yml exists and is
// enabled. An invalid region.yml fails closed: every event is refused until
// it is fixed, because an open relay is the wrong failure for a gated one.
func startRegionGate() {
	handlers.EventGate = nil
	handlers.ReadGate = nil
	handlers.LiveReadGate = nil
	httpGuard = func(h http.Handler) http.Handler { return h }
	cfg, err := regiongate.LoadConfig(config.ConfigPath(regionConfigFile))
	if err != nil {
		log.RegionGate().Error("region.yml invalid; refusing all events until fixed", "error", err)
		failClosed()
		return
	}
	if cfg == nil || !cfg.Enabled {
		return
	}

	var sources []regiongate.Source
	if *cfg.UseLocalEvents {
		sources = append(sources, regiongate.LocalSource{Query: func(f []nostr.Filter, limit int) ([]nostr.Event, error) {
			db := nostrdb.GetDB()
			if db == nil {
				return nil, nil
			}
			return db.Query(f, limit)
		}})
	}
	if len(cfg.ChainRelays) > 0 {
		key, err := regiongate.AuthKey(os.Getenv("GRAIN_REGION_AUTH_KEY"))
		if err != nil {
			log.RegionGate().Error("GRAIN_REGION_AUTH_KEY invalid; refusing all events until fixed", "error", err)
			failClosed()
			return
		}
		sources = append(sources, regiongate.RelaySource{
			Relays:  cfg.ChainRelays,
			Timeout: time.Duration(cfg.FetchTimeoutSeconds) * time.Second,
			AuthKey: key,
		})
	}
	verifier := regiongate.Verifier{Proofs: regiongate.PendingSpec{}, Signature: validation.CheckSignature}
	gate := regiongate.NewGate(cfg, verifier, sources...)
	timeout := time.Duration(cfg.FetchTimeoutSeconds+2) * time.Second
	handlers.EventGate = func(ctx context.Context, evt nostr.Event) (bool, string) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return gate.Admit(ctx, evt)
	}
	if *cfg.GateReads {
		handlers.ReadGate = gate.AdmitPubkey
		handlers.LiveReadGate = gate.LiveAllowed
		httpGuard = speakeasyHTTP
	}
	log.RegionGate().Info("Region gate enabled",
		"chain_rules", regiongate.ChainRulesRevision, "mode", cfg.Mode, "gate_reads", *cfg.GateReads, "regions", len(cfg.Regions), "chain_relays", len(cfg.ChainRelays),
		"proof_checker", "PendingSpec (no work proofs checked until the spec is ratified)")
}

// httpGuard wraps the HTTP handler. It is the identity unless the region gate
// guards reading.
var httpGuard = func(h http.Handler) http.Handler { return h }

// speakeasyHTTP closes every HTTP route except the websocket, NIP-11 and
// NIP-86 (see regiongate.SpeakeasyGuard).
func speakeasyHTTP(h http.Handler) http.Handler { return regiongate.SpeakeasyGuard(h) }

// failClosed refuses every write and read until region.yml is fixed.
func failClosed() {
	const msg = "restricted: relay region is misconfigured"
	handlers.EventGate = func(context.Context, nostr.Event) (bool, string) { return false, msg }
	handlers.ReadGate = func(context.Context, string) (bool, string) { return false, msg }
	handlers.LiveReadGate = func(string) bool { return false }
	httpGuard = speakeasyHTTP
}
