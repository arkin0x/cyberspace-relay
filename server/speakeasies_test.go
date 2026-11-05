package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0ceanslim/grain/client/core"
	"github.com/0ceanslim/grain/config"
	cfgType "github.com/0ceanslim/grain/config/types"
	"github.com/0ceanslim/grain/server/db/nostrdb"
	"github.com/0ceanslim/grain/server/handlers"
	"github.com/0ceanslim/grain/server/regiongate"
	"github.com/0ceanslim/grain/server/speakeasy"
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/utils"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/net/websocket"
)

// ── keys, chains and regions ─────────────────────────────────────────

type key struct {
	priv *btcec.PrivateKey
	pub  string
}

func newKey(t *testing.T) key {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key{priv, hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))}
}

func (k key) sign(t *testing.T, kind int, content string, tags ...[]string) nostr.Event {
	t.Helper()
	return k.signAt(t, time.Now().Unix(), kind, content, tags...)
}

// signAt is sign with created_at at.
func (k key) signAt(t *testing.T, at int64, kind int, content string, tags ...[]string) nostr.Event {
	t.Helper()
	if tags == nil {
		tags = [][]string{}
	}
	raw, _ := json.Marshal([]any{0, k.pub, at, kind, tags, content})
	h := sha256.Sum256(raw)
	sig, err := schnorr.Sign(k.priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return nostr.Event{ID: hex.EncodeToString(h[:]), PubKey: k.pub, CreatedAt: at, Kind: kind, Tags: tags, Content: content, Sig: hex.EncodeToString(sig.Serialize())}
}

// spawn is k's movement chain of one event: it stands at its pubkey's
// coordinate (§8.3), a valid chain with no proof to check.
func (k key) spawn(t *testing.T) nostr.Event {
	t.Helper()
	c, err := regiongate.ParseCoord(k.pub)
	if err != nil {
		t.Fatal(err)
	}
	sx, sy, sz := c.Sector()
	return k.sign(t, regiongate.KindMovement, "", []string{"A", "spawn"}, []string{"C", k.pub},
		[]string{"X", sx}, []string{"Y", sy}, []string{"Z", sz}, []string{"S", sx + "-" + sy + "-" + sz})
}

// ── a websocket client ───────────────────────────────────────────────

type conn struct {
	t         *testing.T
	ws        *websocket.Conn
	challenge string
	in        chan []any
	// seq makes every REQ and COUNT a new subscription: grain answers a
	// repeated REQ with the same id and filters with EOSE alone.
	seq int
}

func dial(t *testing.T, url string) (*conn, error) {
	t.Helper()
	ws, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		return nil, err
	}
	c := &conn{t: t, ws: ws, in: make(chan []any, 256)}
	go func() {
		defer close(c.in)
		for {
			var raw string
			if err := websocket.Message.Receive(ws, &raw); err != nil {
				return
			}
			var msg []any
			if json.Unmarshal([]byte(raw), &msg) == nil {
				c.in <- msg
			}
		}
	}()
	first := c.next(2 * time.Second)
	if len(first) == 2 && first[0] == "AUTH" {
		c.challenge, _ = first[1].(string)
	} else {
		return nil, fmt.Errorf("first message is not an AUTH challenge: %v", first)
	}
	t.Cleanup(func() { ws.Close() })
	return c, nil
}

func mustDial(t *testing.T, url string) *conn {
	t.Helper()
	c, err := dial(t, url)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	return c
}

func (c *conn) send(msg ...any) {
	c.t.Helper()
	raw, _ := json.Marshal(msg)
	if err := websocket.Message.Send(c.ws, string(raw)); err != nil {
		c.t.Fatal(err)
	}
}

// next is the next message, or nil after timeout.
func (c *conn) next(timeout time.Duration) []any {
	select {
	case m := <-c.in:
		return m
	case <-time.After(timeout):
		return nil
	}
}

// until reads messages until one matches, or fails.
func (c *conn) until(what string, match func([]any) bool) []any {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := c.next(time.Until(deadline)); m != nil && match(m) {
			return m
		}
	}
	c.t.Fatalf("never got %s", what)
	return nil
}

func (c *conn) ok(id string) (bool, string) {
	c.t.Helper()
	m := c.until("OK "+id, func(m []any) bool { return len(m) >= 4 && m[0] == "OK" && m[1] == id })
	ok, _ := m[2].(bool)
	msg, _ := m[3].(string)
	return ok, msg
}

func (c *conn) auth(k key, relayURL, challenge string) (bool, string) {
	c.t.Helper()
	evt := k.sign(c.t, 22242, "", []string{"relay", relayURL}, []string{"challenge", challenge})
	c.send("AUTH", evt)
	return c.ok(evt.ID)
}

func (c *conn) publish(evt nostr.Event) (bool, string) {
	c.t.Helper()
	c.send("EVENT", evt)
	return c.ok(evt.ID)
}

// req runs a REQ to EOSE and returns the ids sent, or the CLOSED reason.
func (c *conn) req(sub string, filter map[string]any) (ids []string, closed string) {
	c.t.Helper()
	c.seq++
	sub = fmt.Sprintf("%s-%d", sub, c.seq)
	c.send("REQ", sub, filter)
	for {
		m := c.until("EOSE or CLOSED for "+sub, func(m []any) bool { return len(m) >= 2 && m[1] == sub })
		switch m[0] {
		case "EVENT":
			e, _ := m[2].(map[string]any)
			id, _ := e["id"].(string)
			ids = append(ids, id)
		case "EOSE":
			return ids, ""
		case "CLOSED":
			reason, _ := m[2].(string)
			return ids, reason
		}
	}
}

func (c *conn) count(sub string, filter map[string]any) (int, string) {
	c.t.Helper()
	c.seq++
	sub = fmt.Sprintf("%s-%d", sub, c.seq)
	c.send("COUNT", sub, filter)
	m := c.until("COUNT or CLOSED for "+sub, func(m []any) bool { return len(m) >= 3 && m[1] == sub })
	if m[0] == "CLOSED" {
		reason, _ := m[2].(string)
		return -1, reason
	}
	n, _ := m[2].(map[string]any)["count"].(float64)
	return int(n), ""
}

func m1(m []any) (string, bool) {
	if len(m) < 2 {
		return "", false
	}
	s, ok := m[1].(string)
	return s, ok
}

// live reports whether an EVENT for sub arrives within wait.
func (c *conn) live(sub string, wait time.Duration) []string {
	var ids []string
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		m := c.next(time.Until(deadline))
		if id, _ := m1(m); len(m) >= 3 && m[0] == "EVENT" && strings.HasPrefix(id, sub+"-") {
			e, _ := m[2].(map[string]any)
			id, _ := e["id"].(string)
			ids = append(ids, id)
		}
	}
	return ids
}

// ── the relay under test ─────────────────────────────────────────────

type relayUnderTest struct {
	root, wsRoot string // http://host and ws://host
	rt           *speakeasyRuntime
	db           *nostrdb.NDB
	backup       *backupSink
	// restart stops the speakeasies and starts them again, as a config
	// reload restarts a server instance while websockets stay open.
	restart func()
}

// backupSink is a backup relay that records what it is sent.
type backupSink struct {
	mu  sync.Mutex
	ids map[string]bool
	srv *httptest.Server
}

func newBackupSink(t *testing.T) *backupSink {
	b := &backupSink{ids: map[string]bool{}}
	b.srv = httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		for {
			var raw string
			if websocket.Message.Receive(ws, &raw) != nil {
				return
			}
			var msg []any
			if json.Unmarshal([]byte(raw), &msg) == nil && len(msg) == 2 && msg[0] == "EVENT" {
				if e, ok := msg[1].(map[string]any); ok {
					b.mu.Lock()
					b.ids[e["id"].(string)] = true
					b.mu.Unlock()
				}
			}
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backupSink) has(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ids[id]
}

func copyProfile(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join("..", "deploy", "onosendai", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// startRelay runs the root relay (the onosendai profile) with speakeasies on,
// on a real nostrdb and real websockets, and parse as the region path parser.
func startRelay(t *testing.T, parse speakeasy.RegionPath, speakeasiesYML string) *relayUnderTest {
	t.Helper()
	dir := t.TempDir()
	oldDir := config.GetDataDir()
	config.SetDataDir(dir)
	t.Cleanup(func() { config.SetDataDir(oldDir) })
	copyProfile(t, dir, "config.yml", "whitelist.yml", "relay_metadata.json")
	os.WriteFile(filepath.Join(dir, "blacklist.yml"), []byte("enabled: true\npermanent_ban_words: [\"forbiddenword\"]\n"), 0o644)

	cfg, err := config.LoadConfig(config.ConfigPath("config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	// The blacklist config is left loaded: a banned word starts grain's own
	// background blacklist refresh, which reads it unlocked after the test.
	t.Cleanup(func() {
		config.ResetConfig()
		config.ResetWhitelistConfig()
		config.ResetSizeLimiter()
	})
	if _, err := config.LoadWhitelistConfig(config.ConfigPath("whitelist.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadBlacklistConfig(config.ConfigPath("blacklist.yml")); err != nil {
		t.Fatal(err)
	}
	config.SetRateLimit(cfg)
	config.SetSizeLimit(cfg)
	if err := utils.LoadRelayMetadata(config.ConfigPath("relay_metadata.json")); err != nil {
		t.Fatal(err)
	}
	cfg.Server.ConnectionRateLimitPerIP = 0

	os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	db, err := nostrdb.Open(filepath.Join(dir, "data"), 64, 1)
	if err != nil {
		t.Fatal(err)
	}
	nostrdb.SetGlobalDB(db)
	t.Cleanup(func() { nostrdb.SetGlobalDB(nil); db.Close() })
	handlers.OnEventStored = BroadcastEvent
	t.Cleanup(func() { handlers.OnEventStored = nil })

	mux := http.NewServeMux()
	mux.HandleFunc("/", initRoot)
	srv := httptest.NewServer(speakeasyRoutes(mux))
	t.Cleanup(srv.Close)
	wsRoot := "ws" + strings.TrimPrefix(srv.URL, "http")
	cfg.Auth.RelayURL = wsRoot

	backup := newBackupSink(t)
	cfg.BackupRelay.Enabled = true
	cfg.BackupRelay.URLs = []string{"ws" + strings.TrimPrefix(backup.srv.URL, "http")}

	os.WriteFile(filepath.Join(dir, speakeasy.ConfigFile), []byte(speakeasiesYML), 0o644)
	installSpeakeasyDialGuard()
	t.Cleanup(func() { core.SetDialGuard(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	var stop func()
	start := func() {
		oldParse := speakeasyRegionPath
		speakeasyRegionPath = parse
		stop = startSpeakeasies(ctx, cfg)
		speakeasyRegionPath = oldParse
	}
	start()
	t.Cleanup(func() { stop(); cancel(); speakeasyState.Store(nil) })
	rt := speakeasyState.Load()
	if rt == nil || rt.reg == nil {
		t.Fatal("speakeasies did not open")
	}
	r := &relayUnderTest{root: srv.URL, wsRoot: wsRoot, rt: rt, db: db, backup: backup}
	r.restart = func() {
		stop()
		start()
		r.rt = speakeasyState.Load()
	}
	return r
}

// register adds a speakeasy as the relay owner does, by its path alone: the
// path names the region.
func (r *relayUnderTest) register(t *testing.T, id string) {
	t.Helper()
	if _, msg := r.rt.Add([]any{map[string]any{"id": id}}); msg != "" {
		t.Fatalf("register %s: %s", id, msg)
	}
}

// inRegion reports whether k's spawn (its pubkey's coordinate) lies in the
// region a path's string names: its hex starts with the string, on either
// plane.
func inRegion(k key, id string) bool { return strings.HasPrefix(k.pub, id) }

// letters reports whether the first n hex characters of k's pubkey are all
// letters, so that their case can be changed.
func letters(k key, n int) bool { return strings.Trim(k.pub[:n], "abcdef") == "" }

// pct percent-encodes s's first character, once or twice.
func pct(s string, double bool) string {
	e := fmt.Sprintf("%%%02X", s[0])
	if double {
		e = "%25" + e[1:]
	}
	return e + s[1:]
}

// storeRoot puts events in the root database (where the gate reads chains)
// and waits for nostrdb to index them.
func (r *relayUnderTest) storeRoot(t *testing.T, evts ...nostr.Event) {
	t.Helper()
	for _, e := range evts {
		if err := r.db.StoreEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, e := range evts {
		for {
			got, _ := r.db.Query([]nostr.Filter{{IDs: []string{e.ID}}}, 1)
			if len(got) == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("root never indexed %s", e.ID)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func nip11(t *testing.T, url string) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/nostr+json")
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	json.Unmarshal(body, &doc)
	return resp.StatusCode, doc, resp.Header
}

// ── the test ─────────────────────────────────────────────────────────

// Two speakeasies and the root on one relay, through the real region parser
// (regiongate.ParseRegionPath): A is the region named by the first hex
// character of kAB's spawn coordinate (its pubkey), B by the first two, so B
// lies inside A. kAB stands in both, kA in A only, kOut in neither. Each step
// below fails if the behaviour it names is removed.
func TestSpeakeasiesOnOneRelay(t *testing.T) {
	var kAB, kA, kOut key
	for kAB.pub == "" || !letters(kAB, 2) {
		kAB = newKey(t)
	}
	idA, idB := kAB.pub[:1], kAB.pub[:2]
	for kA.pub == "" || !inRegion(kA, idA) || inRegion(kA, idB) {
		kA = newKey(t)
	}
	for kOut.pub == "" || inRegion(kOut, idA) {
		kOut = newKey(t)
	}
	r := startRelay(t, speakeasyRegionPath, "enabled: true\nmax_open_databases: 1\nmax_connections_per_path: 3\nmap_size_mb: 32\nplanes: [0, 1]\n")
	r.register(t, idA)
	r.register(t, idB)
	for _, bad := range []string{strings.ToUpper(kAB.pub[:3]), "0x" + kAB.pub[:3], "fiatjafs-speakeasy"} {
		if _, msg := r.rt.Add([]any{map[string]any{"id": bad}}); msg == "" {
			t.Fatalf("registered %q: only a canonical region path is an id", bad)
		}
	}
	r.storeRoot(t, kAB.spawn(t), kA.spawn(t), kOut.spawn(t))
	urlA, urlB := r.wsRoot+"/"+idA, r.wsRoot+"/"+idB

	t.Run("routing and NIP-11", func(t *testing.T) {
		code, doc, _ := nip11(t, r.root+"/"+idA)
		lim, _ := doc["limitation"].(map[string]any)
		if code != 200 || doc["name"] != "Speakeasy "+idA || lim["auth_required"] != true || lim["restricted_writes"] != true {
			t.Fatalf("speakeasy NIP-11: %d %v", code, doc)
		}
		if code, _, _ := nip11(t, r.root+"/abcdef"); code != 404 {
			t.Fatalf("unregistered path NIP-11: want 404, got %d", code)
		}
		if code, _, _ := nip11(t, r.root+"/"+idA+"/x"); code != 404 {
			t.Fatalf("a deeper path NIP-11: want 404, got %d", code)
		}
		if _, err := dial(t, r.wsRoot+"/abcdef"); err == nil {
			t.Fatal("a websocket to an unregistered path was served")
		}
		// Other spellings of a region (ParseRegionPath: case, 0x, trailing
		// slashes, one percent-decoding): NIP-11 redirects to the one URL,
		// a websocket is refused naming it (its AUTH would name the wrong URL).
		up := strings.ToUpper(idB)
		mixed := strings.ToUpper(idB[:1]) + idB[1:]
		for _, sp := range []string{up, mixed, "0x" + idB, "0X" + up, idB + "/", idB + "//", pct(idB, false), "0x" + pct(mixed, false) + "/"} {
			code, _, h := nip11(t, r.root+"/"+sp)
			if code != http.StatusMovedPermanently || h.Get("Location") != "/"+idB {
				t.Fatalf("/%s NIP-11: want 301 to /%s, got %d %q", sp, idB, code, h.Get("Location"))
			}
			resp, err := http.DefaultClient.Do(func() *http.Request {
				q, _ := http.NewRequest(http.MethodGet, r.root+"/"+sp, nil)
				q.Header.Set("Upgrade", "websocket")
				q.Header.Set("Connection", "Upgrade")
				return q
			}())
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), urlB) {
				t.Fatalf("/%s websocket: want 400 naming %s, got %d %q", sp, urlB, resp.StatusCode, body)
			}
			if _, err := dial(t, r.wsRoot+"/"+sp); err == nil {
				t.Fatalf("a websocket to /%s was served", sp)
			}
		}
		// Decoded once, as ONOSENDAI decodes once: a double encoding is not
		// the region. And matched on the path as sent: what http.ServeMux
		// would clean and redirect to /<id> is not a relay either.
		for _, p := range []string{"/" + pct(idB, true), "//" + idA, "/x/../" + idA, "/" + idA + "/."} {
			req, _ := http.NewRequest(http.MethodGet, r.root+"/", nil)
			req.URL.RawPath, req.URL.Path = p, p
			req.Header.Set("Accept", "application/nostr+json")
			cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := cl.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatalf("%s: want 404, got %d %q", p, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
		// The root's document is the root's, byte for byte as without
		// speakeasies.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "application/nostr+json")
		direct := httptest.NewRecorder()
		initRoot(direct, req)
		resp, _ := http.DefaultClient.Do(func() *http.Request {
			q, _ := http.NewRequest(http.MethodGet, r.root+"/", nil)
			q.Header.Set("Accept", "application/nostr+json")
			return q
		}())
		via, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(via) != direct.Body.String() {
			t.Fatalf("root NIP-11 changed:\n%s\nwant\n%s", via, direct.Body.String())
		}
	})

	t.Run("AUTH names the speakeasy's own URL", func(t *testing.T) {
		a := mustDial(t, urlA)
		for _, wrong := range []string{urlB, r.wsRoot, r.wsRoot + "/", urlA + "/x"} {
			if ok, msg := a.auth(kAB, wrong, a.challenge); ok || !strings.Contains(msg, "relay URL") {
				t.Fatalf("AUTH naming %s accepted on %s (%q)", wrong, urlA, msg)
			}
		}
		root := mustDial(t, r.wsRoot)
		if ok, _ := root.auth(kAB, urlA, root.challenge); ok {
			t.Fatal("an AUTH for a speakeasy was accepted at the root")
		}
		// An AUTH for A made with B's challenge is refused on B.
		b := mustDial(t, urlB)
		if ok, _ := b.auth(kAB, urlA, b.challenge); ok {
			t.Fatal("an AUTH for A was accepted on B")
		}
		if ok, msg := a.auth(kAB, urlA, a.challenge); !ok {
			t.Fatalf("AUTH naming the speakeasy refused: %s", msg)
		}
		// Replaying that accepted AUTH on another connection to A fails (its
		// challenge is spent and was never the other's).
		a2 := mustDial(t, urlA)
		evt := kAB.sign(t, 22242, "", []string{"relay", urlA}, []string{"challenge", a.challenge})
		a2.send("AUTH", evt)
		if ok, _ := a2.ok(evt.ID); ok {
			t.Fatal("an AUTH replayed on another connection was accepted")
		}
		if ok, msg := root.auth(kAB, r.wsRoot, root.challenge); !ok {
			t.Fatalf("root AUTH refused: %s", msg)
		}
	})

	t.Run("reads and writes need AUTH", func(t *testing.T) {
		a := mustDial(t, urlA)
		if _, closed := a.req("s", map[string]any{}); !strings.HasPrefix(closed, "auth-required:") {
			t.Fatalf("REQ without AUTH: %q", closed)
		}
		if _, closed := a.count("c", map[string]any{}); !strings.HasPrefix(closed, "auth-required:") {
			t.Fatalf("COUNT without AUTH: %q", closed)
		}
		if ok, msg := a.publish(kA.sign(t, 1, "hello")); ok || !strings.HasPrefix(msg, "auth-required:") {
			t.Fatalf("EVENT without AUTH: %v %q", ok, msg)
		}
	})

	t.Run("an outsider is refused", func(t *testing.T) {
		a := mustDial(t, urlA)
		if ok, msg := a.auth(kOut, urlA, a.challenge); !ok {
			t.Fatal(msg)
		}
		if _, closed := a.req("s", map[string]any{}); !strings.Contains(closed, "outside") {
			t.Fatalf("outsider REQ: %q", closed)
		}
		if ok, msg := a.publish(kOut.sign(t, 1, "let me in")); ok || !strings.Contains(msg, "outside") {
			t.Fatalf("outsider EVENT: %v %q", ok, msg)
		}
		// kA is inside A but not B.
		b := mustDial(t, urlB)
		b.auth(kA, urlB, b.challenge)
		if _, closed := b.req("s", map[string]any{}); !strings.Contains(closed, "outside") {
			t.Fatalf("kA on B: %q", closed)
		}
	})

	var nA, nB nostr.Event
	t.Run("isolation: A, B and the root never see each other's events", func(t *testing.T) {
		a := mustDial(t, urlA)
		a.auth(kA, urlA, a.challenge)
		nA = kA.sign(t, 1, "only in A") // kind 1: not on the root's whitelist (ruling D6)
		if ok, msg := a.publish(nA); !ok {
			t.Fatalf("kind 1 in a speakeasy: %s", msg)
		}
		b := mustDial(t, urlB)
		b.auth(kAB, urlB, b.challenge)
		nB = kAB.sign(t, 1, "only in B")
		if ok, msg := b.publish(nB); !ok {
			t.Fatalf("B write: %s", msg)
		}
		root := mustDial(t, r.wsRoot)
		root.auth(kAB, r.wsRoot, root.challenge)
		profile := kAB.sign(t, 0, `{"name":"only at the root"}`)
		if ok, msg := root.publish(profile); !ok {
			t.Fatalf("root write: %s", msg)
		}
		if ok, _ := root.publish(kAB.sign(t, 1, "root has a whitelist")); ok {
			t.Fatal("the root took a kind its whitelist refuses")
		}
		ids := []string{nA.ID, nB.ID, profile.ID}
		// kAB is admitted in both speakeasies, so only the store decides.
		aAB := mustDial(t, urlA)
		aAB.auth(kAB, urlA, aAB.challenge)
		for _, tc := range []struct {
			c    *conn
			name string
			want string
		}{{aAB, "A", nA.ID}, {b, "B", nB.ID}, {root, "root", profile.ID}} {
			deadline := time.Now().Add(3 * time.Second)
			var got []string
			for {
				got, _ = tc.c.req("iso", map[string]any{"ids": ids})
				if len(got) > 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("%s serves %v, want only %s", tc.name, got, tc.want)
			}
		}
		if n, _ := b.count("cnt", map[string]any{"ids": ids}); n != 1 {
			t.Fatalf("B counts %d of the three, want 1", n)
		}
		if got, _ := r.db.Query([]nostr.Filter{{IDs: []string{nA.ID, nB.ID}}}, 10); len(got) != 0 {
			t.Fatalf("speakeasy events reached the root database: %d", len(got))
		}
		time.Sleep(300 * time.Millisecond)
		if r.backup.has(nA.ID) || r.backup.has(nB.ID) {
			t.Fatal("a speakeasy event was forwarded to a backup relay")
		}
		if !r.backup.has(profile.ID) {
			t.Fatal("the root's event was not forwarded to its backup relay (the sink is not wired)")
		}
		if r.rt.pool.Open() > 1 {
			t.Fatalf("open databases %d over the cap of 1", r.rt.pool.Open())
		}
		// The gate's members are the identities inside a registered region.
		if !r.rt.gate.IsMember(kAB.pub) || !r.rt.gate.IsMember(kA.pub) {
			t.Fatal("identities inside a registered speakeasy are not the gate's members")
		}
		out := mustDial(t, urlA)
		out.auth(kOut, urlA, out.challenge)
		out.req("m", map[string]any{})
		if r.rt.gate.IsMember(kOut.pub) {
			t.Fatal("an identity outside every speakeasy is a member")
		}
	})

	t.Run("live events stay on their speakeasy", func(t *testing.T) {
		subA := mustDial(t, urlA)
		subA.auth(kAB, urlA, subA.challenge)
		subB := mustDial(t, urlB)
		subB.auth(kAB, urlB, subB.challenge)
		subRoot := mustDial(t, r.wsRoot)
		for _, c := range []*conn{subA, subB, subRoot} {
			c.req("live", map[string]any{"kinds": []int{0, 1}})
		}
		w := mustDial(t, urlA)
		w.auth(kA, urlA, w.challenge)
		n := kA.sign(t, 1, "live in A")
		if ok, msg := w.publish(n); !ok {
			t.Fatal(msg)
		}
		if got := subA.live("live", time.Second); len(got) != 1 || got[0] != n.ID {
			t.Fatalf("A's subscriber got %v, want %s", got, n.ID)
		}
		rootW := mustDial(t, r.wsRoot)
		rootW.auth(kA, r.wsRoot, rootW.challenge)
		p := kA.sign(t, 0, `{"name":"live at the root"}`)
		if ok, msg := rootW.publish(p); !ok {
			t.Fatal(msg)
		}
		if got := subRoot.live("live", time.Second); len(got) != 1 || got[0] != p.ID {
			t.Fatalf("root's subscriber got %v, want only %s", got, p.ID)
		}
		if got := subB.live("live", 300*time.Millisecond); len(got) != 0 {
			t.Fatalf("B's subscriber got %v", got)
		}
		if got := subA.live("live", 300*time.Millisecond); len(got) != 0 {
			t.Fatalf("A's subscriber got the root's event %v", got)
		}
	})

	t.Run("NIP-70 and senders on a path", func(t *testing.T) {
		a := mustDial(t, urlA)
		a.auth(kAB, urlA, a.challenge)
		if ok, msg := a.publish(kA.sign(t, 1, "protected", []string{"-"})); ok || !strings.Contains(msg, "protected") {
			t.Fatalf("another's protected event: %v %q", ok, msg)
		}
		if ok, msg := a.publish(kOut.sign(t, 1, "pushed in by a member")); ok || !strings.Contains(msg, "outside") {
			t.Fatalf("an outsider's event pushed by a member: %v %q", ok, msg)
		}
		o := mustDial(t, urlA)
		o.auth(kOut, urlA, o.challenge)
		if ok, msg := o.publish(kA.sign(t, 1, "a member's event pushed by an outsider")); ok || !strings.Contains(msg, "outside") {
			t.Fatalf("a member's event pushed by an outsider: %v %q", ok, msg)
		}
		self := mustDial(t, urlA)
		self.auth(kA, urlA, self.challenge)
		if ok, msg := self.publish(kA.sign(t, 1, "my own protected", []string{"-"})); !ok {
			t.Fatalf("own protected event: %s", msg)
		}
	})

	t.Run("grain's own client never dials a speakeasy", func(t *testing.T) {
		// Any host (the relay has many names), any spelling the router
		// reads as a region, registered or not, and the registered ones.
		up := strings.ToUpper(idB)
		for _, u := range []string{
			urlA, urlB, urlB + "/", "wss://relay.onosendai.tech/" + idA, "wss://RELAY.ONOSENDAI.TECH/" + up,
			"ws://localhost:8181/0x" + idB, "wss://203.0.113.7/" + idB + "//", "relay.onosendai.tech/" + idA,
			"https://relay.onosendai.tech/" + pct(idB, false), "wss://relay.onosendai.tech/" + idB + "?x=1",
			"wss://relay.onosendai.tech/0fe6b3deeb67e952f852e8c1df15",
		} {
			if err := core.CheckDial(u); err == nil {
				t.Fatalf("the built-in client may dial %s", u)
			}
		}
		for _, u := range []string{r.wsRoot, r.wsRoot + "/", "wss://relay.onosendai.tech", "wss://relay.damus.io", "wss://nos.lol/", "wss://relay.example/fiatjafs-speakeasy"} {
			if err := core.CheckDial(u); err != nil {
				t.Fatalf("%s refused: %v", u, err)
			}
		}
	})

	t.Run("kind 5 from outside writes nothing", func(t *testing.T) {
		out := mustDial(t, urlA)
		out.auth(kOut, urlA, out.challenge)
		for _, d := range []nostr.Event{
			kOut.sign(t, 5, "hello room, from outside"),
			kOut.sign(t, 5, "deleting a member's note", []string{"e", nA.ID}),
			kOut.sign(t, 5, "deleting nothing here", []string{"e", strings.Repeat("ab", 32)}),
			kOut.sign(t, 5, "", []string{"a", "30023:" + kAB.pub + ":x"}),
		} {
			if ok, msg := out.publish(d); ok || !strings.Contains(msg, "outside") {
				t.Fatalf("an outsider's kind 5 %q: %v %q", d.Content, ok, msg)
			}
		}
		m := mustDial(t, urlA)
		m.auth(kAB, urlA, m.challenge)
		if got, _ := m.req("k5", map[string]any{"kinds": []int{5}, "authors": []string{kOut.pub}}); len(got) != 0 {
			t.Fatalf("an outsider's kind 5 is stored in the speakeasy: %v", got)
		}
		if got, _ := m.req("still", map[string]any{"ids": []string{nA.ID}}); len(got) != 1 {
			t.Fatal("a member's note was deleted by an outsider")
		}

		// kA is outside B. An event of kA's stored in B (as when kA was
		// inside) may be deleted by kA there, and nothing else.
		db, release, err := r.rt.pool.Acquire(idB)
		if err != nil {
			t.Fatal(err)
		}
		old := kA.sign(t, 1, "kA, when inside B")
		if err := db.StoreEvent(context.Background(), old); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if got, _ := db.Query([]nostr.Filter{{IDs: []string{old.ID}}}, 1); len(got) == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("never indexed")
			}
		}
		release()
		b := mustDial(t, urlB)
		b.auth(kA, urlB, b.challenge)
		mixed := kA.sign(t, 5, "", []string{"e", old.ID}, []string{"e", nB.ID})
		if ok, msg := b.publish(mixed); ok || !strings.Contains(msg, "outside") {
			t.Fatalf("a deletion naming another's event too: %v %q", ok, msg)
		}
		bm := mustDial(t, urlB)
		bm.auth(kAB, urlB, bm.challenge)
		// Dated before its target, a deletion deletes nothing (NIP-09), so it
		// could be sent again and again: refused, and nothing stored.
		backdated := kA.signAt(t, old.CreatedAt-60, 5, "an outsider's words, backdated", []string{"e", old.ID})
		if ok, msg := b.publish(backdated); ok || !strings.Contains(msg, "no older than") {
			t.Fatalf("a backdated deletion from outside: %v %q", ok, msg)
		}
		if got, _ := bm.req("bd", map[string]any{"ids": []string{backdated.ID, old.ID}}); len(got) != 1 || got[0] != old.ID {
			t.Fatalf("after a backdated deletion B serves %v, want only the target %s", got, old.ID)
		}
		own := kA.sign(t, 5, "", []string{"e", old.ID})
		if ok, msg := b.publish(own); !ok {
			t.Fatalf("a former member deleting their own event: %s", msg)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			got, closed := bm.req("gone", map[string]any{"ids": []string{old.ID, nB.ID, mixed.ID}})
			if len(got) == 1 && got[0] == nB.ID {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after the deletions B serves %v (%q), want only %s", got, closed, nB.ID)
			}
			time.Sleep(20 * time.Millisecond)
		}
		for _, c := range []*conn{out, m, b, bm} {
			c.ws.Close()
		}
	})

	t.Run("connections per path", func(t *testing.T) {
		waitConns(t, r.rt, idB, 0)
		for i := 0; i < 3; i++ {
			mustDial(t, urlB)
		}
		ws, err := websocket.Dial(urlB, "", "http://localhost/")
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		var raw string
		ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		if websocket.Message.Receive(ws, &raw); !strings.Contains(raw, "max connections") {
			t.Fatalf("a 4th connection to B (cap 3) got %q", raw)
		}
		mustDial(t, urlA) // A is counted apart
	})

	t.Run("the blacklist applies in a speakeasy", func(t *testing.T) {
		a := mustDial(t, urlA)
		a.auth(kAB, urlA, a.challenge)
		if ok, msg := a.publish(kAB.sign(t, 1, "forbiddenword")); ok || !strings.HasPrefix(msg, "blocked:") {
			t.Fatalf("banned word in a speakeasy: %v %q", ok, msg)
		}
	})

	t.Run("a restart never reopens a database from an old connection", func(t *testing.T) {
		waitConns(t, r.rt, idB, 0)
		old := mustDial(t, urlB)
		old.auth(kAB, urlB, old.challenge)
		if _, closed := old.req("before", map[string]any{"ids": []string{nB.ID}}); closed != "" {
			t.Fatal(closed)
		}
		oldPool := r.rt.pool
		r.restart()
		if oldPool.Open() != 0 {
			t.Fatalf("the stopped instance still holds %d databases", oldPool.Open())
		}
		if _, closed := old.req("after", map[string]any{"ids": []string{nB.ID}}); !strings.Contains(closed, "restarting") {
			t.Fatalf("an old connection after a restart: %q", closed)
		}
		if oldPool.Open() != 0 || oldPool.Opened() != oldPool.Closed() {
			t.Fatalf("an old connection reopened a database in the stopped pool (open %d, opened %d, closed %d)", oldPool.Open(), oldPool.Opened(), oldPool.Closed())
		}
		fresh := mustDial(t, urlB)
		fresh.auth(kAB, urlB, fresh.challenge)
		if got, closed := fresh.req("new", map[string]any{"ids": []string{nB.ID}}); closed != "" || len(got) != 1 {
			t.Fatalf("after the restart B serves %v (%q)", got, closed)
		}
		old.ws.Close()
		fresh.ws.Close()
	})

	t.Run("a removed speakeasy stops serving", func(t *testing.T) {
		a := mustDial(t, urlA)
		a.auth(kA, urlA, a.challenge)
		if _, msg := r.rt.Remove([]any{idA}); msg != "" {
			t.Fatal(msg)
		}
		if _, closed := a.req("gone", map[string]any{}); !strings.Contains(closed, "closed") {
			t.Fatalf("REQ on a removed speakeasy's open connection: %q", closed)
		}
		if code, _, _ := nip11(t, r.root+"/"+idA); code != 404 {
			t.Fatalf("removed speakeasy NIP-11: %d", code)
		}
		if _, err := os.Stat(r.rt.pool.Dir(idA)); err != nil {
			t.Fatalf("removing a speakeasy must keep its database: %v", err)
		}
	})
}

func waitConns(t *testing.T, rt *speakeasyRuntime, id string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rt.connMu.Lock()
		got := rt.conns[id]
		rt.connMu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections to %s: %d, want %d", id, got, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Once speakeasies.yml exists, only / is the root: an invalid file closes
// every other path rather than letting it fall through to the public relay.
func TestSpeakeasiesFailClosed(t *testing.T) {
	for name, yml := range map[string]string{
		"invalid":  "enabled: true\ngate:\n  regions: []\n",
		"disabled": "enabled: false\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			oldDir := config.GetDataDir()
			config.SetDataDir(dir)
			defer config.SetDataDir(oldDir)
			os.WriteFile(filepath.Join(dir, speakeasy.ConfigFile), []byte(yml), 0o644)
			cfg := &cfgType.ServerConfig{}
			cfg.Auth.RelayURL = "ws://relay.example"
			stop := startSpeakeasies(context.Background(), cfg)
			defer func() { stop(); speakeasyState.Store(nil) }()
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
			h := speakeasyRoutes(mux)
			for path, want := range map[string]int{"/0a": 404, "/": 299} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("Accept", "application/nostr+json")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != want {
					t.Fatalf("%s: want %d, got %d", path, want, w.Code)
				}
			}
		})
	}
	// Without the file, every path is what it always was.
	speakeasyState.Store(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	req := httptest.NewRequest(http.MethodGet, "/0a", nil)
	req.Header.Set("Accept", "application/nostr+json")
	w := httptest.NewRecorder()
	speakeasyRoutes(mux).ServeHTTP(w, req)
	if w.Code != 299 {
		t.Fatalf("no speakeasies.yml: /0a must reach the root's handler, got %d", w.Code)
	}
}
