package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/net/websocket"
)

// TestSpeakeasiesE2E runs against a local grain binary, never a live relay:
//
//	SPEAKEASY_E2E_HTTP=http://127.0.0.1:<port>   the relay
//	SPEAKEASY_E2E_OWNER_SK=<hex>                  a throwaway key, its owner
//	SPEAKEASY_E2E_PID=<pid>                       for memory and threads
//	SPEAKEASY_E2E_IDLE=<seconds>                  its idle_close_seconds
//
// The relay must run the onosendai profile with speakeasies.yml enabled,
// max_open_databases 4, max_connections_per_path 3 and no chain relays.
// It is skipped without SPEAKEASY_E2E_HTTP.
func TestSpeakeasiesE2E(t *testing.T) {
	base := os.Getenv("SPEAKEASY_E2E_HTTP")
	if base == "" {
		t.Skip("SPEAKEASY_E2E_HTTP not set")
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatal("the e2e run only ever talks to a local relay")
	}
	ownerRaw, _ := hex.DecodeString(os.Getenv("SPEAKEASY_E2E_OWNER_SK"))
	ownerPriv, _ := btcec.PrivKeyFromBytes(ownerRaw)
	owner := key{ownerPriv, hex.EncodeToString(schnorr.SerializePubKey(ownerPriv.PubKey()))}
	pid := os.Getenv("SPEAKEASY_E2E_PID")
	idle := 5 * time.Second
	if v := os.Getenv("SPEAKEASY_E2E_IDLE"); v != "" {
		d, _ := time.ParseDuration(v + "s")
		idle = d
	}
	wsBase := "ws" + strings.TrimPrefix(base, "http")

	snap := func(label string) {
		t.Helper()
		status, _ := os.ReadFile("/proc/" + pid + "/status")
		fields := map[string]string{}
		for _, line := range strings.Split(string(status), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok {
				fields[k] = strings.TrimSpace(v)
			}
		}
		list, _ := nip86(t, base, owner, "grain_speakeasy_list", nil)
		m, _ := list.(map[string]any)
		t.Logf("MEASURE %-38s VmRSS %-11s VmSize %-12s Threads %-3s open_databases %v", label, fields["VmRSS"], fields["VmSize"], fields["Threads"], m["open_databases"])
	}
	snap("started")

	// Throwaway keys: kAB stands in every cube around its spawn, kA in A
	// only, kOut in none of them.
	kAB := newKey(t)
	cubes := map[string]uint{"0a": 84, "0b": 83, "0c": 82, "0d": 81, "0e": 80}
	var kA, kOut key
	for kA.pub == "" || !inside(t, kA, cubeOf(t, kAB, 84)) || inside(t, kA, cubeOf(t, kAB, 83)) {
		kA = newKey(t)
	}
	for kOut.pub == "" || inside(t, kOut, cubeOf(t, kAB, 84)) {
		kOut = newKey(t)
	}
	root := mustDial(t, wsBase)
	for _, k := range []key{kAB, kA, kOut} {
		if ok, msg := root.publish(k.spawn(t)); !ok {
			t.Fatalf("spawn to the root: %s", msg)
		}
	}

	// Registration is the relay owner's, through NIP-86.
	if _, msg := nip86(t, base, kOut, "grain_speakeasy_list", nil); !strings.Contains(msg, "403") {
		t.Fatalf("a non-owner listed speakeasies: %q", msg)
	}
	for id, h := range cubes {
		r := cubeOf(t, kAB, h)
		if _, msg := nip86(t, base, owner, "grain_speakeasy_add", map[string]any{"id": id, "region": map[string]any{"base": r.Base, "height": h}}); msg != "" {
			t.Fatalf("register %s: %s", id, msg)
		}
	}
	urlA, urlB := wsBase+"/0a", wsBase+"/0b"

	t.Run("admission", func(t *testing.T) {
		for _, tc := range []struct {
			who  key
			url  string
			want bool
		}{{kAB, urlA, true}, {kAB, urlB, true}, {kA, urlA, true}, {kA, urlB, false}, {kOut, urlA, false}, {kOut, urlB, false}} {
			c := mustDial(t, tc.url)
			if ok, msg := c.auth(tc.who, tc.url, c.challenge); !ok {
				t.Fatalf("AUTH on %s: %s", tc.url, msg)
			}
			_, closed := c.req("adm", map[string]any{"limit": 1})
			if (closed == "") != tc.want {
				t.Fatalf("%s on %s: want admitted %v, got %q", tc.who.pub[:8], tc.url, tc.want, closed)
			}
			t.Logf("ADMIT %s on /%s: admitted=%v %s", tc.who.pub[:8], tc.url[len(wsBase)+1:], closed == "", closed)
			c.ws.Close()
		}
		// max_connections_per_path is 3: let the relay count these out.
		time.Sleep(time.Second)
	})

	t.Run("isolation", func(t *testing.T) {
		a := mustDial(t, urlA)
		a.auth(kA, urlA, a.challenge)
		nA := kA.sign(t, 1, "e2e: only in A")
		if ok, msg := a.publish(nA); !ok {
			t.Fatal(msg)
		}
		b := mustDial(t, urlB)
		b.auth(kAB, urlB, b.challenge)
		nB := kAB.sign(t, 1, "e2e: only in B")
		if ok, msg := b.publish(nB); !ok {
			t.Fatal(msg)
		}
		r := mustDial(t, wsBase)
		p := kAB.sign(t, 0, `{"name":"e2e: only at the root"}`)
		if ok, msg := r.publish(p); !ok {
			t.Fatal(msg)
		}
		aAB := mustDial(t, urlA)
		aAB.auth(kAB, urlA, aAB.challenge)
		ids := []string{nA.ID, nB.ID, p.ID}
		time.Sleep(300 * time.Millisecond)
		for _, tc := range []struct {
			c          *conn
			name, want string
		}{{aAB, "A", nA.ID}, {b, "B", nB.ID}, {r, "root", p.ID}} {
			got, closed := tc.c.req("iso", map[string]any{"ids": ids})
			if closed != "" || len(got) != 1 || got[0] != tc.want {
				t.Fatalf("%s serves %v (%q), want only %s", tc.name, got, closed, tc.want)
			}
			t.Logf("ISOLATION %s asked for [A note, B note, root profile] by a reader admitted everywhere: served %d, its own", tc.name, len(got))
		}
		for _, c := range []*conn{a, b, r, aAB} {
			c.ws.Close()
		}
		time.Sleep(time.Second)
	})

	t.Run("AUTH replay", func(t *testing.T) {
		a := mustDial(t, urlA)
		b := mustDial(t, urlB)
		r := mustDial(t, wsBase)
		for _, tc := range []struct {
			name      string
			c         *conn
			relay     string
			challenge string
		}{
			{"B's URL on A", a, urlB, a.challenge},
			{"the root's URL on A", a, wsBase, a.challenge},
			{"A's URL on B, with B's challenge", b, urlA, b.challenge},
			{"A's URL on the root", r, urlA, r.challenge},
			{"A's URL and A's challenge, on B", b, urlA, a.challenge},
		} {
			ok, msg := tc.c.auth(kAB, tc.relay, tc.challenge)
			if ok {
				t.Fatalf("%s: accepted", tc.name)
			}
			t.Logf("REPLAY %s: refused %q", tc.name, msg)
		}
		if ok, msg := a.auth(kAB, urlA, a.challenge); !ok {
			t.Fatal(msg)
		}
		a2 := mustDial(t, urlA)
		evt := kAB.sign(t, 22242, "", []string{"relay", urlA}, []string{"challenge", a.challenge})
		a2.send("AUTH", evt)
		if ok, msg := a2.ok(evt.ID); ok {
			t.Fatal("a spent AUTH accepted on another connection")
		} else {
			t.Logf("REPLAY a spent AUTH for A on a second connection to A: refused %q", msg)
		}
		if code := status(t, base+"/abcdef", true); code != 404 {
			t.Fatalf("unregistered path: %d", code)
		}
		if _, err := dial(t, wsBase+"/abcdef"); err == nil {
			t.Fatal("websocket to an unregistered path served")
		}
	})

	t.Run("resource bounds: 100 registered, 5 active", func(t *testing.T) {
		for i := 0; i < 95; i++ {
			id := fmt.Sprintf("%04x", 0x1000+i)
			h := uint(60)
			c := key{pub: fmt.Sprintf("%064x", 0x1000+i)}
			r := cubeOf(t, c, h)
			if _, msg := nip86(t, base, owner, "grain_speakeasy_add", map[string]any{"id": id, "region": map[string]any{"base": r.Base, "height": h}}); msg != "" {
				t.Fatalf("register %s: %s", id, msg)
			}
		}
		list, _ := nip86(t, base, owner, "grain_speakeasy_list", nil)
		if n := len(list.(map[string]any)["speakeasies"].([]any)); n != 100 {
			t.Fatalf("registered %d", n)
		}
		time.Sleep(idle + idle/2 + 2*time.Second)
		snap("100 registered, all idle")

		var conns []*conn
		start := time.Now()
		busy := 0
		for round := 0; round < 4; round++ {
			for id := range cubes {
				url := wsBase + "/" + id
				c := mustDial(t, url)
				c.auth(kAB, url, c.challenge)
				for i := 0; i < 5; i++ {
					if ok, msg := c.publish(kAB.sign(t, 1, fmt.Sprintf("e2e %s %d %d", id, round, i))); !ok {
						if strings.Contains(msg, "busy") {
							busy++
						} else {
							t.Fatalf("%s: %s", id, msg)
						}
					}
				}
				if _, closed := c.req("live", map[string]any{"kinds": []int{1}}); strings.Contains(closed, "busy") {
					busy++
				}
				if round == 3 {
					conns = append(conns, c)
				} else {
					c.ws.Close()
				}
			}
		}
		t.Logf("MEASURE 5 speakeasies x 4 rounds x (5 writes + 1 read): %v, refused busy %d", time.Since(start).Round(time.Millisecond), busy)
		snap("5 active (cap 4), 5 connections open")
		time.Sleep(idle + idle/2 + 2*time.Second)
		snap("5 connections open, idle")

		// Cold open against warm.
		c := conns[0]
		t0 := time.Now()
		c.req("cold", map[string]any{"limit": 1})
		cold := time.Since(t0)
		t0 = time.Now()
		c.req("warm", map[string]any{"limit": 1})
		t.Logf("MEASURE REQ on a closed speakeasy (opens its database) %v; again, open %v", cold.Round(time.Microsecond), time.Since(t0).Round(time.Microsecond))

		// Connections per path: cap 3. Close the ones above first and give
		// the relay a moment to count them out.
		for _, c := range conns {
			c.ws.Close()
		}
		time.Sleep(time.Second)
		var held []*conn
		for len(held) < 3 {
			held = append(held, mustDial(t, urlB))
		}
		ws, err := dialRaw(urlB)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ws, "max connections") {
			t.Fatalf("4th connection to B: %q", ws)
		}
		t.Logf("BOUND 4th connection to /0b (max_connections_per_path 3): %s", ws)
	})
}

// nip86 calls a NIP-86 method at the root, signed (NIP-98) by k; the error
// string is the envelope's, or the HTTP status when it is not 200.
func nip86(t *testing.T, base string, k key, method string, param any) (any, string) {
	t.Helper()
	params := []any{}
	if param != nil {
		params = append(params, param)
	}
	body, _ := json.Marshal(map[string]any{"method": method, "params": params})
	sum := sha256.Sum256(body)
	auth := k.sign(t, 27235, "", []string{"u", base + "/"}, []string{"method", "POST"}, []string{"payload", hex.EncodeToString(sum[:])})
	raw, _ := json.Marshal(auth)
	req, _ := http.NewRequest(http.MethodPost, base+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/nostr+json+rpc")
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString(raw))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Sprintf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	var env struct {
		Result any    `json:"result"`
		Error  string `json:"error"`
	}
	json.Unmarshal(out, &env)
	return env.Result, env.Error
}

func status(t *testing.T, url string, info bool) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if info {
		req.Header.Set("Accept", "application/nostr+json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// dialRaw opens a websocket and returns its first message.
func dialRaw(url string) (string, error) {
	ws, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		return "", err
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	var raw string
	err = websocket.Message.Receive(ws, &raw)
	return raw, err
}
