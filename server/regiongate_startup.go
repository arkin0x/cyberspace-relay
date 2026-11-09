package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
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

var errNoDB = errors.New("the store is not open yet")

// startRegionGate installs the region gate when region.yml exists and is
// enabled; ctx is the server instance's, which ends on a restart (the
// Bitcoin line's loader stops with it). An invalid region.yml fails closed: every event is refused until
// it is fixed, because an open relay is the wrong failure for a gated one.
func startRegionGate(ctx context.Context) {
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

	sources, err := gateSources(cfg)
	if err != nil {
		log.RegionGate().Error("GRAIN_REGION_AUTH_KEY invalid; refusing all events until fixed", "error", err)
		failClosed()
		return
	}
	gate := regiongate.NewGate(cfg, gateVerifier(ctx, cfg), sources...)
	timeout := time.Duration(cfg.FetchTimeoutSeconds+2) * time.Second
	handlers.EventGate = func(ctx context.Context, evt nostr.Event) (bool, string) {
		ctx, cancel := context.WithTimeout(regiongate.WithClientIP(ctx, handlers.ClientIP(ctx)), timeout)
		defer cancel()
		return gate.Admit(ctx, evt)
	}
	if *cfg.GateReads {
		handlers.ReadGate = func(ctx context.Context, pubkey string) (bool, string) {
			return gate.AdmitPubkey(regiongate.WithClientIP(ctx, handlers.ClientIP(ctx)), pubkey)
		}
		handlers.LiveReadGate = gate.LiveAllowed
		httpGuard = speakeasyHTTP
	}
	log.RegionGate().Info("Region gate enabled",
		"chain_rules", regiongate.ChainRulesRevision, "mode", cfg.Mode, "gate_reads", *cfg.GateReads, "regions", len(cfg.Regions), "chain_relays", len(cfg.ChainRelays),
		"proof_checker", "SpecProofs (Level 1; "+lineState(cfg)+")", "line_fallback", cfg.LineFallback, "max_hop_verify_height", cfg.MaxHopVerifyHeight,
		"max_concurrent_lookups", cfg.MaxConcurrentLookups, "max_queued_lookups", cfg.MaxQueuedLookups, "max_queued_per_ip", cfg.MaxQueuedPerIP,
		"check_timeout_seconds", cfg.CheckTimeoutSeconds, "max_cached_chains", cfg.MaxCachedChains)
}

// gateSources are where a gate reads chains: this relay's own store (the
// root database, never a speakeasy's) and the chain relays.
func gateSources(cfg *regiongate.Config) ([]regiongate.Source, error) {
	var sources []regiongate.Source
	if *cfg.UseLocalEvents {
		sources = append(sources, regiongate.LocalSource{Query: func(f []nostr.Filter, limit int) ([]nostr.Event, error) {
			db := nostrdb.GetDB()
			if db == nil {
				return nil, nil
			}
			return db.Query(f, limit)
		}, MaxResults: nostrdb.MaxQueryResults})
	}
	if len(cfg.ChainRelays) > 0 {
		key, err := regiongate.AuthKey(os.Getenv("GRAIN_REGION_AUTH_KEY"))
		if err != nil {
			return nil, err
		}
		sources = append(sources, regiongate.RelaySource{
			Relays:  cfg.ChainRelays,
			Timeout: time.Duration(cfg.FetchTimeoutSeconds) * time.Second,
			AuthKey: key,
		})
	}
	return sources, nil
}

// gateVerifier is the chain verifier a gate checks with. No Bitcoin line is
// configured yet, so rides are left unchecked: strict mode does not trust
// them, structural mode does (docs/region-gate.md).
func gateVerifier(ctx context.Context, cfg *regiongate.Config) regiongate.Verifier {
	proofs := regiongate.SpecProofs{MaxHopHeight: cfg.MaxHopVerifyHeight, Progress: regiongate.NewHopProgress(256), RideProgress: regiongate.NewRideProgress(256)}
	if *cfg.CheckRides {
		proofs.Line = rideLine(ctx, cfg)
	}
	return regiongate.Verifier{Proofs: proofs, Signature: validation.CheckSignature}
}

// rideLines holds the Bitcoin lines of this server instance, one per line
// configuration (publisher and fallback), shared by every gate that uses it:
// the root's and the speakeasies'. A restart (a new ctx) starts afresh.
var rideLines struct {
	mu    sync.Mutex
	ctx   context.Context
	byKey map[string]*regiongate.AnchorLine
}

// rideLine is the line rides are checked against under cfg, built in the
// background from this relay's own block anchors; until it holds the
// heights a ride needs, the ride waits and its chain is checked again once
// it does (docs/region-gate.md). Its loader stops with ctx.
func rideLine(ctx context.Context, cfg *regiongate.Config) *regiongate.AnchorLine {
	rideLines.mu.Lock()
	defer rideLines.mu.Unlock()
	if rideLines.ctx != ctx {
		rideLines.ctx, rideLines.byKey = ctx, map[string]*regiongate.AnchorLine{}
	}
	key := cfg.LinePublisher
	if cfg.LineFallback {
		key += " " + strings.Join(cfg.LineFallbackURLs, " ")
	}
	if l := rideLines.byKey[key]; l != nil {
		return l
	}
	lcfg := regiongate.AnchorLineConfig{
		Publisher: cfg.LinePublisher,
		Query: func(f []nostr.Filter, limit int) ([]nostr.Event, error) {
			db := nostrdb.GetDB()
			if db == nil {
				return nil, errNoDB
			}
			return db.Query(f, limit)
		},
		MaxResults: nostrdb.MaxQueryResults,
		Signature:  validation.CheckSignature,
		Log:        func(msg string, args ...any) { log.RegionGate().Info(msg, args...) },
		Alert:      func(msg string, args ...any) { log.RegionGate().Error(msg, args...) },
	}
	if cfg.LineFallback {
		lcfg.Fallback = regiongate.HTTPHeaders{Bases: cfg.LineFallbackURLs}
	}
	l := regiongate.NewAnchorLine(lcfg)
	rideLines.byKey[key] = l
	go l.Run(ctx, time.Duration(cfg.LinePollSeconds)*time.Second)
	return l
}

// lineState says, for the startup log, what rides are checked against.
func lineState(cfg *regiongate.Config) string {
	if !*cfg.CheckRides {
		return "rides unchecked: check_rides is off"
	}
	name := "kind321:" + cfg.LinePublisher
	if cfg.LineFallback {
		name += "+headers"
	}
	return "rides checked against " + name
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
