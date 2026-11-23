package server

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0ceanslim/grain/config"
	cfgType "github.com/0ceanslim/grain/config/types"
	nostr "github.com/0ceanslim/grain/server/types"
	"golang.org/x/net/websocket"
)

// A remote signer (NIP-46) holds one subscription, {"kinds":[24133],"#p":[its
// key]}, and may send nothing for minutes. Until 2026-11-23 the relay closed
// any connection that sent nothing for server.read_timeout (60 s on
// ONOSENDAI): 98% of Amber's connections ended that way, a minute after they
// opened, and every request sent while it reconnected was lost (24133 is
// ephemeral and never stored). These tests pin the rules: a connection that
// holds a subscription is waiting for events and stays open; one that holds
// none is still closed by the read deadline and the idle timeout; the relay
// pings every connection, and a ping is not activity.

// quietServer serves clientHandler with the given timeouts and hands each
// new connection's *Client to the test.
func quietServer(t *testing.T, readSec, idleSec int) (string, chan *Client) {
	t.Helper()
	prev := config.GetConfig()
	cfg := &cfgType.ServerConfig{}
	cfg.Server.ReadTimeout = readSec
	cfg.Server.WriteTimeout = 5
	cfg.Server.IdleTimeout = idleSec
	config.SetConfigForTesting(cfg)
	t.Cleanup(func() { config.SetConfigForTesting(prev) })

	got := make(chan *Client, 4)
	srv := httptest.NewServer(websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			go func() {
				for i := 0; i < 200; i++ {
					clientsMu.Lock()
					c := clients[ws]
					clientsMu.Unlock()
					if c != nil {
						got <- c
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
			clientHandler(ws, nil)
		},
	})
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), got
}

func dialQuiet(t *testing.T, url string, got chan *Client) (*websocket.Conn, *Client) {
	t.Helper()
	ws, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	var first string
	if err := websocket.Message.Receive(ws, &first); err != nil || !strings.HasPrefix(first, `["AUTH"`) {
		t.Fatalf("want the AUTH challenge first, got %q, %v", first, err)
	}
	select {
	case c := <-got:
		return ws, c
	case <-time.After(2 * time.Second):
		t.Fatal("the relay did not register the connection")
	}
	return nil, nil
}

// alive sends the app-level PING after the quiet spell and wants PONG back.
func alive(ws *websocket.Conn) bool {
	if err := websocket.Message.Send(ws, `["PING"]`); err != nil {
		return false
	}
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var reply string
	err := websocket.Message.Receive(ws, &reply)
	return err == nil && reply == `["PONG"]`
}

var signerFilter = []nostr.Filter{{Kinds: []int{24133}, Tags: map[string][]string{"p": {strings.Repeat("a", 64)}}}}

func TestQuietSubscriberOutlivesReadTimeout(t *testing.T) {
	url, got := quietServer(t, 1, 0)

	signer, c := dialQuiet(t, url, got)
	// The subscription is set out of band, so one message re-arms the
	// reader as the REQ that opens it would.
	c.SetSubscription("nip46", signerFilter)
	if !alive(signer) {
		t.Fatal("no PONG")
	}
	idle, _ := dialQuiet(t, url, got) // holds nothing

	time.Sleep(2500 * time.Millisecond) // past read_timeout (1 s), twice
	if !alive(signer) {
		t.Fatal("a connection holding a subscription was closed for being quiet past read_timeout")
	}
	if alive(idle) {
		t.Fatal("a connection holding nothing outlived read_timeout; the deadline must still apply to it")
	}
}

func TestIdleMonitorSparesSubscriber(t *testing.T) {
	oldCheck, oldPing := minIdleCheckInterval, pingInterval
	minIdleCheckInterval, pingInterval = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { minIdleCheckInterval, pingInterval = oldCheck, oldPing })
	url, got := quietServer(t, 0, 1)

	signer, c := dialQuiet(t, url, got)
	c.SetSubscription("nip46", signerFilter)
	idle, _ := dialQuiet(t, url, got)

	// Pings go out every 100 ms all the while: they must not count as
	// activity, or the idle connection would never be closed.
	time.Sleep(2500 * time.Millisecond)
	if !alive(signer) {
		t.Fatal("the idle monitor closed a connection holding a subscription")
	}
	if alive(idle) {
		t.Fatal("the idle monitor spared a connection holding nothing (were pings counted as activity?)")
	}
}

// TestRelayPingsQuietConnection reads the raw frames: x/net/websocket's own
// client answers pings out of sight, so the handshake is done by hand.
func TestRelayPingsQuietConnection(t *testing.T) {
	old := pingInterval
	pingInterval = 150 * time.Millisecond
	t.Cleanup(func() { pingInterval = old })
	url, _ := quietServer(t, 0, 0)

	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "ws://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nOrigin: http://localhost/\r\n\r\n", key)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var h [2]byte
		if _, err := br.Read(h[:1]); err != nil {
			t.Fatalf("no ping within 3 s: %v", err)
		}
		if _, err := br.Read(h[1:]); err != nil {
			t.Fatal(err)
		}
		opcode, n := h[0]&0x0f, int(h[1]&0x7f)
		switch n {
		case 126:
			var ext [2]byte
			br.Read(ext[:])
			n = int(ext[0])<<8 | int(ext[1])
		case 127:
			t.Fatal("unexpected 64-bit frame length")
		}
		if _, err := br.Discard(n); err != nil {
			t.Fatal(err)
		}
		if opcode == 0x9 {
			return // a ping
		}
	}
}
