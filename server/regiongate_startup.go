package server

import (
	"context"
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
	cfg, err := regiongate.LoadConfig(config.ConfigPath(regionConfigFile))
	if err != nil {
		log.RegionGate().Error("region.yml invalid; refusing all events until fixed", "error", err)
		handlers.EventGate = func(context.Context, nostr.Event) (bool, string) {
			return false, "restricted: relay region is misconfigured"
		}
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
			handlers.EventGate = func(context.Context, nostr.Event) (bool, string) {
				return false, "restricted: relay region is misconfigured"
			}
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
	log.RegionGate().Info("Region gate enabled",
		"mode", cfg.Mode, "regions", len(cfg.Regions), "chain_relays", len(cfg.ChainRelays),
		"proof_checker", "PendingSpec (no work proofs checked until the spec is ratified)")
}
