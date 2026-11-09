package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0ceanslim/grain/client/core"
	"github.com/0ceanslim/grain/config"
	cfgType "github.com/0ceanslim/grain/config/types"
	relay "github.com/0ceanslim/grain/server/api"
	"github.com/0ceanslim/grain/server/db/nostrdb"
	"github.com/0ceanslim/grain/server/handlers"
	"github.com/0ceanslim/grain/server/nwc"
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

// speakeasyRegionPath reads a request path as a region:
// regiongate.ParseRegionPath, with the vectors shared with ONOSENDAI (#18).
// Every spelling ONOSENDAI reads as a region leads to its speakeasy's one
// URL, an entry's region is the one its path names, and no name can be a
// string it reads as a region (ruling D3). Tests may swap it.
var speakeasyRegionPath speakeasy.RegionPath = speakeasy.ParseRegionPath

// errSpeakeasyDial refuses the built-in client a speakeasy URL.
var errSpeakeasyDial = errors.New("grain's web client never connects to a speakeasy: its relay connections are shared by every visitor; use a nostr client to enter one")

// installSpeakeasyDialGuard makes the built-in client (client/core) refuse
// every URL whose path this relay would serve as a speakeasy, while
// speakeasies.yml exists: its pool is one set of connections for every
// visitor of the web client and API, so a speakeasy read over it would be
// read for everyone.
func installSpeakeasyDialGuard() {
	if _, err := os.Stat(config.ConfigPath(speakeasy.ConfigFile)); err != nil {
		core.SetDialGuard(nil)
		return
	}
	core.SetDialGuard(speakeasyDialGuard)
}

// speakeasyDialGuard refuses a URL on any host whose path, as sent, is a
// region string (any spelling ParseRegionPath reads, registered or not) or a
// registered speakeasy path. The host is not trusted to tell: this relay may
// be reached by many names and addresses (DNS, its IP, a proxy, localhost).
// A path the router would not serve as a speakeasy (/, //abc, /x/../abc) is
// let through, as the relay answers it itself.
func speakeasyDialGuard(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil // the client cannot dial it either
	}
	p := u.EscapedPath()
	if p == "" || p == "/" {
		return nil
	}
	if speakeasyRegionPath != nil {
		if _, _, ok := speakeasyRegionPath(p); ok {
			return errSpeakeasyDial
		}
	}
	if rt := speakeasyState.Load(); rt != nil && rt.reg != nil {
		if sp, _ := rt.reg.Lookup(p); sp != nil {
			return errSpeakeasyDial
		}
	}
	return nil
}

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

	// ownDeletions: always_allow_kinds lists 5, so an author no longer
	// inside may still delete their own events stored in a speakeasy.
	ownDeletions bool

	// checkout takes payment for new speakeasies (step 5); nil while
	// payments are off.
	checkout *speakeasy.Checkout
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
	if err := speakeasy.CheckPublicURL(public); err != nil {
		return closed("the public URL (public_url, or auth.relay_url) is not a websocket URL", err)
	}

	sources, err := gateSources(sc.GateConfig)
	if err != nil {
		return closed("GRAIN_REGION_AUTH_KEY invalid", err)
	}
	dir := filepath.Join(config.GetDataDir(), "speakeasies")
	reg, bad, err := speakeasy.LoadRegistry(filepath.Join(dir, "registry.json"), speakeasyRegionPath, sc.Planes, speakeasy.WriteDurable)
	if err != nil {
		return closed("registry unreadable", err)
	}
	rt := &speakeasyRuntime{
		cfg: sc, publicURL: public, reg: reg,
		pool: speakeasy.NewPool(filepath.Join(dir, "db"), nostrdb.Options{
			MapSizeMB:     sc.MapSizeMB,
			FulltextKinds: cfg.Database.FulltextKinds,
		}, sc.MaxOpenDatabases, time.Duration(sc.IdleCloseSeconds)*time.Second),
		gate:    regiongate.NewSharedGate(sc.GateConfig, gateVerifier(ctx, sc.GateConfig), sources...),
		timeout: time.Duration(sc.GateConfig.FetchTimeoutSeconds+2) * time.Second,
		conns:   map[string]int{},
	}
	rt.gate.SetMemberRegions(reg.ContainsAny)
	for _, k := range sc.GateConfig.AlwaysAllowKinds {
		rt.ownDeletions = rt.ownDeletions || k == 5
	}
	poolCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		rt.pool.Run(poolCtx)
		close(done)
	}()
	checkoutDone := make(chan struct{})
	if rt.checkout = startCheckout(sc, reg, dir, public); rt.checkout != nil {
		go func() {
			rt.checkout.Run(poolCtx)
			close(checkoutDone)
		}()
	} else {
		close(checkoutDone)
	}
	speakeasyState.Store(rt)
	relay.SetSpeakeasyAdmin(rt)
	log.RegionGate().Info("Speakeasies open",
		"registered", reg.Len(), "left_out", len(bad), "public_url", public,
		"region_path_parser", speakeasyRegionPath != nil, "planes", sc.Planes,
		"max_open_databases", sc.MaxOpenDatabases, "idle_close_seconds", sc.IdleCloseSeconds,
		"map_size_mb", sc.MapSizeMB, "ingest_threads", speakeasy.IngestThreads,
		"max_connections_per_path", sc.MaxConnectionsPerPath, "payments", rt.checkout != nil,
		"chain_rules", regiongate.ChainRulesRevision, "mode", sc.GateConfig.Mode, "chain_relays", len(sc.GateConfig.ChainRelays))
	return func() {
		relay.SetSpeakeasyAdmin(nil)
		cancel()
		<-done
		<-checkoutDone
	}
}

// startCheckout makes the checkout when speakeasies.yml turns payments on
// and names a valid NWC connection file, or returns nil (payments off; the
// speakeasies stay open). The connection string is never logged.
func startCheckout(sc *speakeasy.Config, reg *speakeasy.Registry, dir, public string) *speakeasy.Checkout {
	p := sc.Payments
	if !p.Enabled {
		return nil
	}
	if p.NWCFile == "" {
		log.RegionGate().Error("Speakeasy payments off: payments.nwc_file is not set")
		return nil
	}
	// Checked at open and again whenever the file changes (rotation).
	wallet, err := nwc.OpenFile(p.NWCFile, func(msg string, args ...any) { log.RegionGate().Warn(msg, args...) })
	if err != nil {
		log.RegionGate().Error("Speakeasy payments off: the NWC connection file is unusable", "error", err)
		return nil
	}
	host := public
	if u, err := url.Parse(public); err == nil && u.Host != "" {
		host = u.Host
	}
	co, err := speakeasy.NewCheckout(speakeasy.CheckoutConfig{
		Wallet: wallet, Registry: reg,
		OrdersPath: filepath.Join(dir, "orders.json"), LedgerPath: filepath.Join(dir, "payments.jsonl"),
		Write: speakeasy.WriteDurable, Host: host, SpeakeasySats: p.SpeakeasySats, NameSats: p.NameSats,
		Expiry:     time.Duration(p.InvoiceExpirySeconds) * time.Second,
		Poll:       time.Duration(p.PollSeconds) * time.Second,
		MaxPending: p.MaxPendingInvoices, MaxPerRequester: p.MaxPendingPerRequester,
		MaxPerNetwork: p.MaxPendingPerNetwork, MaxPerRegion: p.MaxPendingPerRegion,
		Log:   func(msg string, args ...any) { log.RegionGate().Info(msg, args...) },
		Alert: func(msg string, args ...any) { log.RegionGate().Error(msg, args...) },
	})
	if err != nil {
		log.RegionGate().Error("Speakeasy payments off: the orders file is unreadable", "error", err)
		return nil
	}
	log.RegionGate().Info("Speakeasy payments on", "wallet", wallet.Describe(), "speakeasy_sats", p.SpeakeasySats, "name_sats", p.NameSats,
		"invoice_expiry_seconds", p.InvoiceExpirySeconds)
	return co
}

// speakeasyRoutes sends websocket, NIP-11 and NIP-86 requests for any path
// but / to the speakeasies, before the root's handler (and before the region
// gate's HTTP guard) sees them. Everything else goes on to next unchanged.
func speakeasyRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := speakeasyState.Load()
		// The discovery endpoint answers whether or not speakeasies are on
		// (an empty list when they are not), so ONOSENDAI can always ask.
		if r.URL.EscapedPath() == DiscoveryPath {
			serveDiscovery(w, r, rt)
			return
		}
		if p := r.URL.EscapedPath(); p == OrdersPath || strings.HasPrefix(p, OrdersPath+"/") {
			serveOrders(w, r, rt)
			return
		}
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
			// A browser at /<region>: the region dashboard (step 4), while
			// speakeasies are open. Any other path goes on unchanged.
			if rt.reg != nil && wantsPage(r) && rt.servePage(w, r) {
				return
			}
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
			rt.serveWS(w, r, sp, canonical[1:])
		default:
			rt.serveInfo(w, r, sp, canonical[1:])
		}
	})
}

// url is a speakeasy's one URL: the public URL and its canonical path. Its
// NIP-11 names it, and its AUTH events must name it.
func (rt *speakeasyRuntime) url(id string) string { return rt.publicURL + "/" + id }

// serveWS serves a websocket to speakeasy sp at path (its id or its name).
func (rt *speakeasyRuntime) serveWS(w http.ResponseWriter, r *http.Request, sp *speakeasy.Speakeasy, path string) {
	// Its own per-IP budget, apart from the root's and never escalated
	// to a ban (see CheckSpeakeasyConnectionRate).
	if cfg := config.GetConfig(); cfg != nil {
		if !EnforceSpeakeasyConnectionRateLimit(w, r, sp.ID, cfg.Server.ConnectionRateLimitPerIP) {
			return
		}
		release, ok := EnforceOpenSockets(w, r, cfg)
		if !ok {
			return
		}
		defer release()
	}
	scope := rt.scope(sp, path)
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

// scope is what a connection to speakeasy sp at path (its id or its name)
// is served with. Connections to every path of one speakeasy share its id
// (its database, its live events, its connection cap); each path has its
// own URL, which that connection's AUTH must name, as a client signs AUTH
// for the URL it connected to.
func (rt *speakeasyRuntime) scope(sp *speakeasy.Speakeasy, path string) *handlers.Scope {
	id, in := sp.ID, sp.Regions
	return &handlers.Scope{
		ID: id, Path: path, RelayURL: rt.url(path),
		Acquire: func() (*nostrdb.NDB, func(), error) {
			// A speakeasy taken out of the registry stops serving at once,
			// open connections included.
			if rt.reg.Get(id) == nil {
				return nil, nil, fmt.Errorf("this speakeasy is closed")
			}
			return rt.pool.Acquire(id)
		},
		Admit: func(ctx context.Context, authed string, evt nostr.Event) (bool, string) {
			return rt.admit(ctx, id, in, authed, evt)
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
// too (reads and writes both need an admitted AUTH). always_allow_kinds does
// not open a private room to anyone: its one use here is kind 5, from an
// author no longer inside, and then only when every event it names is that
// author's own and stored in this speakeasy (ownDeletion). Anything else
// from outside is refused and stored nowhere.
func (rt *speakeasyRuntime) admit(ctx context.Context, id string, in *regiongate.Regions, authed string, evt nostr.Event) (bool, string) {
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
	ok, msg := rt.gate.AdmitAuthorIn(ctx, evt, in)
	if ok || evt.Kind != 5 || !rt.ownDeletions {
		return ok, msg
	}
	if why := rt.ownDeletion(id, evt); why != "" {
		return false, "restricted: " + why
	}
	return true, ""
}

// ownDeletion says why a kind 5 from an author outside the region may not be
// stored in speakeasy id, or "" when it may: it names at least one event, and
// every one (by e id or a address, its newest version) is the author's own,
// stored here, and no newer than the deletion. A deletion that names anything
// else would write the outsider's words into the room; so would one dated
// before its target, which NIP-09 deletes nothing with (verifyAndDeleteByID
// keeps an event newer than its deletion), so it could be sent again and
// again, each one stored.
func (rt *speakeasyRuntime) ownDeletion(id string, evt nostr.Event) string {
	const outside = "you are outside this speakeasy's region: you may only delete your own events stored here"
	db, release, err := rt.pool.Acquire(id)
	if err != nil {
		return err.Error()
	}
	defer release()
	targets := 0
	for _, tag := range evt.Tags {
		if len(tag) < 2 {
			continue
		}
		var f nostr.Filter
		switch tag[0] {
		case "e":
			if len(tag[1]) != 64 {
				return outside
			}
			f = nostr.Filter{IDs: []string{tag[1]}}
		case "a":
			parts := strings.SplitN(tag[1], ":", 3)
			kind, err := strconv.Atoi(parts[0])
			if len(parts) != 3 || err != nil || parts[1] != evt.PubKey {
				return outside
			}
			f = nostr.Filter{Kinds: []int{kind}, Authors: []string{evt.PubKey}}
			if parts[2] != "" { // a replaceable event's address has no d
				f.Tags = map[string][]string{"d": {parts[2]}}
			}
		default:
			continue
		}
		targets++
		got, err := db.Query([]nostr.Filter{f}, 1)
		if err != nil {
			return "could not check the events this deletion names, try again"
		}
		if len(got) == 0 || got[0].PubKey != evt.PubKey {
			return outside
		}
		if got[0].CreatedAt > evt.CreatedAt {
			return "you are outside this speakeasy's region: a deletion must be no older than the events it names"
		}
	}
	if targets == 0 {
		return outside
	}
	return ""
}

// serveInfo is the speakeasy's NIP-11 document at path: the relay's own,
// renamed, with AUTH required and writes restricted. At its name's path it
// is named by its name.
func (rt *speakeasyRuntime) serveInfo(w http.ResponseWriter, r *http.Request, sp *speakeasy.Speakeasy, path string) {
	utils.RelayInfoHandlerFor(w, r, func(md *utils.RelayMetadata) {
		md.Name = sp.Name
		if md.Name == "" && path != sp.ID {
			md.Name = path
		}
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
		return nil, "params: [{\"id\": <region path>}] (the region is the one the path names)"
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

// Payments lists what the relay owner must settle by hand: every ledger
// line whose payment bought nothing (refund owed, held) or whose outcome
// is unknown, and every open order the wallet cannot be asked about.
func (rt *speakeasyRuntime) Payments(params []any) (any, string) {
	if len(params) != 0 {
		return nil, "params: []"
	}
	if rt.checkout == nil {
		return map[string]any{"payments_on": false, "needs_owner": []any{}, "lookup_failing": []any{}}, ""
	}
	lines, err := rt.checkout.Ledger()
	if err != nil {
		return nil, "could not read the payments ledger: " + err.Error()
	}
	owe := []speakeasy.Order{}
	for _, o := range lines {
		if speakeasy.NeedsOwner(o.Outcome) || o.Status == speakeasy.StatusUnknown || strings.HasPrefix(o.Outcome, "unknown:") {
			owe = append(owe, o)
		}
	}
	failing := []speakeasy.Order{}
	for _, o := range rt.checkout.Orders() {
		if o.LookupFailing && o.Status == speakeasy.StatusPending {
			failing = append(failing, o)
		}
	}
	return map[string]any{"payments_on": true, "needs_owner": owe, "lookup_failing": failing}, ""
}

func stringParam(params []any, i int) (string, bool) {
	if i >= len(params) {
		return "", false
	}
	s, ok := params[i].(string)
	return s, ok && s != ""
}
