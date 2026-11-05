package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0ceanslim/grain/config"
	cfgType "github.com/0ceanslim/grain/config/types"
	relay "github.com/0ceanslim/grain/server/api"
	"github.com/0ceanslim/grain/server/db/nostrdb"
	"github.com/0ceanslim/grain/server/handlers"
	"github.com/0ceanslim/grain/server/regiongate"
	"github.com/0ceanslim/grain/server/speakeasy"
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils"
	"github.com/0ceanslim/grain/server/utils/log"
	"github.com/0ceanslim/grain/server/utils/relayurl"

	"golang.org/x/net/websocket"
)

// Speakeasies (docs/speakeasies.md, step 3): relay.onosendai.tech/<path> is
// its own relay when <path> is a registered speakeasy. The bare relay at /
// is not touched by any of this.
//
// What a path is depends on speakeasies.yml:
//
//	no file                 every path is what it always was (grain answers
//	                        a websocket or NIP-11 request on any path as the
//	                        root relay)
//	file present            only / is the root relay; a registered path is
//	                        its speakeasy; any other path answers a
//	                        websocket, NIP-11 or NIP-86 request with 404
//	file invalid, or        the same, with no path registered: every path
//	enabled: false          but / answers 404
//
// Once the file exists, an unregistered or closed path must never fall back
// to the root: a client that took /<region> for a speakeasy would post its
// private room to the public relay.

// speakeasyRegionPath reads a path segment as a region (speakeasy.RegionPath).
// It stays nil until regiongate.ParseRegionPath merges (the region string
// parser, with the vectors shared with ONOSENDAI); then it is set to it, and
// paths are looked up canonically and every entry's cube is checked against
// its path.
var speakeasyRegionPath speakeasy.RegionPath

// speakeasyRuntime is the open speakeasies of one server instance.
type speakeasyRuntime struct {
	cfg       *speakeasy.Config
	publicURL string
	reg       *speakeasy.Registry
	pool      *speakeasy.Pool
	gate      *regiongate.Gate
	timeout   time.Duration

	connMu sync.Mutex
	conns  map[string]int // open connections, by speakeasy id
}

// speakeasyState is what the router reads: nil without speakeasies.yml, a
// runtime with no registry when it is closed, a full one when open.
var speakeasyState atomic.Pointer[speakeasyRuntime]

// startSpeakeasies loads speakeasies.yml and the registry and starts the
// pool, for one server instance; stop closes every speakeasy database and
// must run before the instance is gone.
func startSpeakeasies(ctx context.Context, cfg *cfgType.ServerConfig) (stop func()) {
	speakeasyState.Store(nil)
	relay.SetSpeakeasyAdmin(nil)
	closed := func(why string, err error) func() {
		log.RegionGate().Error("Speakeasies closed: every path but / answers 404", "reason", why, "error", err)
		speakeasyState.Store(&speakeasyRuntime{})
		return func() {}
	}

	sc, err := speakeasy.LoadConfig(config.ConfigPath(speakeasy.ConfigFile))
	switch {
	case err != nil:
		return closed("speakeasies.yml invalid", err)
	case sc == nil:
		return func() {}
	case !sc.Enabled:
		log.RegionGate().Info("Speakeasies disabled: every path but / answers 404")
		speakeasyState.Store(&speakeasyRuntime{cfg: sc})
		return func() {}
	}

	// A speakeasy's AUTH must never pass at the root, so the root must
	// compare the AUTH relay tag with its path (relay_url_match: strict).
	if relayurl.ParseMode(cfg.Auth.RelayURLMatch) != relayurl.ModeStrict {
		return closed("auth.relay_url_match must be strict while speakeasies are on, or an AUTH for a speakeasy would pass at the root", nil)
	}
	public := sc.PublicURL
	if public == "" {
		public = strings.TrimRight(cfg.Auth.RelayURL, "/")
	}
	if public == "" {
		return closed("no public URL: set public_url in speakeasies.yml or auth.relay_url in config.yml", nil)
	}

	sources, err := gateSources(sc.GateConfig)
	if err != nil {
		return closed("GRAIN_REGION_AUTH_KEY invalid", err)
	}
	dir := filepath.Join(config.GetDataDir(), "speakeasies")
	reg, bad, err := speakeasy.LoadRegistry(filepath.Join(dir, "registry.json"), speakeasyRegionPath, sc.Planes, config.AtomicWriteFile)
	if err != nil {
		return closed("registry unreadable", err)
	}
	rt := &speakeasyRuntime{
		cfg: sc, publicURL: public, reg: reg,
		pool: speakeasy.NewPool(filepath.Join(dir, "db"), nostrdb.Options{
			MapSizeMB:     sc.MapSizeMB,
			FulltextKinds: cfg.Database.FulltextKinds,
		}, sc.MaxOpenDatabases, time.Duration(sc.IdleCloseSeconds)*time.Second),
		gate:    regiongate.NewSharedGate(sc.GateConfig, gateVerifier(sc.GateConfig), sources...),
		timeout: time.Duration(sc.GateConfig.FetchTimeoutSeconds+2) * time.Second,
		conns:   map[string]int{},
	}
	poolCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		rt.pool.Run(poolCtx)
		close(done)
	}()
	speakeasyState.Store(rt)
	relay.SetSpeakeasyAdmin(rt)
	log.RegionGate().Info("Speakeasies open",
		"registered", reg.Len(), "left_out", len(bad), "public_url", public,
		"region_path_parser", speakeasyRegionPath != nil, "planes", sc.Planes,
		"max_open_databases", sc.MaxOpenDatabases, "idle_close_seconds", sc.IdleCloseSeconds,
		"map_size_mb", sc.MapSizeMB, "ingest_threads", speakeasy.IngestThreads,
		"max_connections_per_path", sc.MaxConnectionsPerPath,
		"chain_rules", regiongate.ChainRulesRevision, "mode", sc.GateConfig.Mode, "chain_relays", len(sc.GateConfig.ChainRelays))
	return func() {
		relay.SetSpeakeasyAdmin(nil)
		cancel()
		<-done
	}
}

// speakeasyRoutes sends websocket, NIP-11 and NIP-86 requests for any path
// but / to the speakeasies, before the root's handler (and before the region
// gate's HTTP guard) sees them. Everything else goes on to next unchanged.
func speakeasyRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := speakeasyState.Load()
		// Matched on the path as sent, never through http.ServeMux, which
		// cleans and redirects (//abc, /x/../abc, /abc/. to /abc).
		if rt == nil || r.URL.EscapedPath() == "/" {
			next.ServeHTTP(w, r)
			return
		}
		nip86 := r.Method == http.MethodPost && r.Header.Get("Content-Type") == relay.NIP86ContentType
		ws := r.Header.Get("Upgrade") == "websocket"
		info := r.Header.Get("Accept") == "application/nostr+json"
		if !nip86 && !ws && !info {
			next.ServeHTTP(w, r)
			return
		}
		// The path as sent: the region parser decodes it once itself.
		var sp *speakeasy.Speakeasy
		canonical := ""
		if rt.reg != nil {
			sp, canonical = rt.reg.Lookup(r.URL.EscapedPath())
		}
		switch {
		case sp == nil:
			http.Error(w, "not a relay: no speakeasy at this path", http.StatusNotFound)
		case nip86:
			// The relay owner manages speakeasies through NIP-86 at /.
			http.Error(w, "manage speakeasies through NIP-86 at /", http.StatusNotFound)
		case r.URL.EscapedPath() != canonical:
			// One speakeasy, one URL: its NIP-11 and its AUTH relay tag name
			// the canonical spelling only. Other spellings of the region are
			// sent there (HTTP) or refused with the URL to use (websocket:
			// clients seldom follow redirects, and an AUTH signed for the
			// spelling used would not match).
			if ws {
				http.Error(w, "this speakeasy's address is "+rt.url(sp.ID)+"; connect there", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, canonical, http.StatusMovedPermanently)
		case ws:
			rt.serveWS(w, r, sp)
		default:
			rt.serveInfo(w, r, sp)
		}
	})
}

// url is a speakeasy's one URL: the public URL and its canonical path. Its
// NIP-11 names it, and its AUTH events must name it.
func (rt *speakeasyRuntime) url(id string) string { return rt.publicURL + "/" + id }

func (rt *speakeasyRuntime) serveWS(w http.ResponseWriter, r *http.Request, sp *speakeasy.Speakeasy) {
	if cfg := config.GetConfig(); cfg != nil {
		if !EnforceConnectionRateLimit(w, r, cfg.Server.ConnectionRateLimitPerIP) {
			return
		}
	}
	scope := rt.scope(sp)
	srv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			if !rt.takeConn(sp.ID) {
				RecordRejection("max_conn_path", utils.GetClientIP(ws.Request()))
				websocket.Message.Send(ws, `["NOTICE","error: this speakeasy is at max connections, try again later"]`)
				ws.Close()
				return
			}
			defer rt.dropConn(sp.ID)
			clientHandler(ws, scope)
		},
	}
	srv.ServeHTTP(w, r)
}

func (rt *speakeasyRuntime) takeConn(id string) bool {
	rt.connMu.Lock()
	defer rt.connMu.Unlock()
	if rt.conns[id] >= rt.cfg.MaxConnectionsPerPath {
		return false
	}
	rt.conns[id]++
	return true
}

func (rt *speakeasyRuntime) dropConn(id string) {
	rt.connMu.Lock()
	defer rt.connMu.Unlock()
	if rt.conns[id]--; rt.conns[id] <= 0 {
		delete(rt.conns, id)
	}
}

// scope is what a connection to speakeasy sp is served with.
func (rt *speakeasyRuntime) scope(sp *speakeasy.Speakeasy) *handlers.Scope {
	id, in := sp.ID, sp.Regions
	return &handlers.Scope{
		ID: id, Path: id, RelayURL: rt.url(id),
		Acquire: func() (*nostrdb.NDB, func(), error) {
			// A speakeasy taken out of the registry stops serving at once,
			// open connections included.
			if rt.reg.Get(id) == nil {
				return nil, nil, fmt.Errorf("this speakeasy is closed")
			}
			return rt.pool.Acquire(id)
		},
		Admit: func(ctx context.Context, authed string, evt nostr.Event) (bool, string) {
			return rt.admit(ctx, in, authed, evt)
		},
		Read: func(ctx context.Context, pubkey string) (bool, string) {
			return rt.gate.AdmitPubkeyIn(regiongate.WithClientIP(ctx, handlers.ClientIP(ctx)), pubkey, in)
		},
		Stored: func(evt nostr.Event) {
			broadcastScoped(id, evt, func(pubkey string) bool { return rt.gate.LiveAllowedIn(pubkey, in) })
		},
	}
}

// admit judges an event sent to a speakeasy: its author by the gate, as the
// region gate judges writers, and, when someone else sends it, the sender
// too (reads and writes both need an admitted AUTH). So kind 5 from its own
// author is admitted after they leave (always_allow_kinds), as at a gated
// root, but nobody outside can push anything in.
func (rt *speakeasyRuntime) admit(ctx context.Context, in *regiongate.Regions, authed string, evt nostr.Event) (bool, string) {
	ctx, cancel := context.WithTimeout(regiongate.WithClientIP(ctx, handlers.ClientIP(ctx)), rt.timeout)
	defer cancel()
	if authed == "" {
		return false, "auth-required: this speakeasy only serves identities it can place; authenticate first"
	}
	if authed != evt.PubKey {
		if ok, msg := rt.gate.AdmitPubkeyIn(ctx, authed, in); !ok {
			return false, msg
		}
	}
	return rt.gate.AdmitIn(ctx, evt, in)
}

// serveInfo is the speakeasy's NIP-11 document: the relay's own, renamed,
// with AUTH required and writes restricted.
func (rt *speakeasyRuntime) serveInfo(w http.ResponseWriter, r *http.Request, sp *speakeasy.Speakeasy) {
	utils.RelayInfoHandlerFor(w, r, func(md *utils.RelayMetadata) {
		md.Name = sp.Name
		if md.Name == "" {
			md.Name = "Speakeasy " + sp.ID
		}
		md.Description = sp.Description
		if md.Description == "" {
			md.Description = "A Cyberspace speakeasy: only identities whose movement chain places them inside region " +
				sp.ID + " can read or write here. Authenticate (NIP-42) to enter."
		}
		md.Limitation.AuthRequired = true
		md.Limitation.RestrictedWrites = true
		md.Limitation.PaymentRequired = false
	})
}

// ─── NIP-86 (relay owner only, ruling D5) ────────────────────────────

// speakeasyListItem is one row of grain_speakeasy_list.
type speakeasyListItem struct {
	speakeasy.Entry
	URL         string `json:"url"`
	Open        bool   `json:"database_open"`
	Connections int    `json:"connections"`
}

func (rt *speakeasyRuntime) List([]any) (any, string) {
	rt.connMu.Lock()
	conns := map[string]int{}
	for k, v := range rt.conns {
		conns[k] = v
	}
	rt.connMu.Unlock()
	items := []speakeasyListItem{}
	for _, e := range rt.reg.List() {
		items = append(items, speakeasyListItem{Entry: e, URL: rt.url(e.ID), Open: rt.pool.IsOpen(e.ID), Connections: conns[e.ID]})
	}
	return map[string]any{"speakeasies": items, "open_databases": rt.pool.Open(), "max_open_databases": rt.cfg.MaxOpenDatabases}, ""
}

func (rt *speakeasyRuntime) Add(params []any) (any, string) {
	if len(params) != 1 {
		return nil, "params: [{\"id\": <region path>, \"region\": {\"base\": <coord>, \"height\": <H>}}]"
	}
	raw, err := json.Marshal(params[0])
	if err != nil {
		return nil, "invalid params: " + err.Error()
	}
	var e speakeasy.Entry
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, "invalid speakeasy: " + err.Error()
	}
	if e.CreatedAt == 0 {
		e.CreatedAt = time.Now().Unix()
	}
	sp, err := rt.reg.Add(e)
	if err != nil {
		return nil, err.Error()
	}
	return map[string]any{"ok": true, "id": sp.ID, "url": rt.url(sp.ID)}, ""
}

func (rt *speakeasyRuntime) Remove(params []any) (any, string) {
	id, ok := stringParam(params, 0)
	if !ok || len(params) != 1 {
		return nil, "params: [<id>]"
	}
	if err := rt.reg.Remove(id); err != nil {
		return nil, err.Error()
	}
	return map[string]any{"ok": true, "id": id, "database_kept": rt.pool.Dir(id)}, ""
}

func (rt *speakeasyRuntime) DeleteEvent(params []any) (any, string) {
	id, ok1 := stringParam(params, 0)
	eventID, ok2 := stringParam(params, 1)
	if !ok1 || !ok2 || len(params) != 2 {
		return nil, "params: [<id>, <event id>]"
	}
	if rt.reg.Get(id) == nil {
		return nil, speakeasy.ErrNotFound.Error()
	}
	raw, err := hex.DecodeString(eventID)
	if err != nil || len(raw) != 32 {
		return nil, "event id must be 64 hex characters"
	}
	db, release, err := rt.pool.Acquire(id)
	if err != nil {
		return nil, err.Error()
	}
	defer release()
	var key [32]byte
	copy(key[:], raw)
	if err := db.DeleteNoteByID(key); err != nil {
		return nil, err.Error()
	}
	return map[string]any{"ok": true}, ""
}

func stringParam(params []any, i int) (string, bool) {
	if i >= len(params) {
		return "", false
	}
	s, ok := params[i].(string)
	return s, ok && s != ""
}
