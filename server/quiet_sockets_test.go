package server

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
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
// pings every connection, a ping is not activity, and a peer that answers no
// ping is closed.

// quietServer serves clientHandler with the given timeouts, on a
// liveListener as in production, and hands each new connection's *Client to
// the test.
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
	srv := httptest.NewUnstartedServer(websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			go func() {
				for i := 0; i < 400; i++ {
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
	srv.Listener = liveListener{srv.Listener}
	srv.Config.ConnContext = withLiveConn
	srv.Start()
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

// alive sends the app-level PING and wants PONG back.
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
	url, got := quietServer(t, 2, 0)

	signer, c := dialQuiet(t, url, got)
	// The subscription is set out of band, so one message re-arms the
	// reader as the REQ that opens it would.
	c.SetSubscription("nip46", signerFilter)
	if !alive(signer) {
		t.Fatal("no PONG")
	}
	idle, _ := dialQuiet(t, url, got) // holds nothing

	time.Sleep(5 * time.Second) // past read_timeout (2 s), twice
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
	// activity, or the idle connection would never be closed. (Neither
	// client reads, so neither answers them: pongGrace keeps both from
	// being called dead here.)
	time.Sleep(2500 * time.Millisecond)
	if !alive(signer) {
		t.Fatal("the idle monitor closed a connection holding a subscription")
	}
	if alive(idle) {
		t.Fatal("the idle monitor spared a connection holding nothing (were pings counted as activity?)")
	}
}

// rawConn is a websocket client written by hand, so a test sees every frame
// (x/net/websocket's client answers pings out of sight) and decides whether
// to answer pings.
type rawConn struct {
	net.Conn
	br *bufio.Reader
}

func rawDial(t *testing.T, url string) *rawConn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "ws://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nOrigin: http://localhost/\r\n\r\n", key)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	return &rawConn{conn, br}
}

// frame reads one frame: its first byte (FIN and opcode) and its payload.
func (c *rawConn) frame() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		return 0, nil, fmt.Errorf("unexpected 64-bit frame length")
	}
	payload := make([]byte, n)
	_, err := io.ReadFull(c.br, payload)
	return h[0], payload, err
}

// pong answers a ping (a client's frames are masked; the payload is empty).
func (c *rawConn) pong() error {
	_, err := c.Write([]byte{0x8a, 0x80, 1, 2, 3, 4})
	return err
}

func TestRelayPingsQuietConnection(t *testing.T) {
	old := pingInterval
	pingInterval = 150 * time.Millisecond
	t.Cleanup(func() { pingInterval = old })
	url, _ := quietServer(t, 0, 0)

	c := rawDial(t, url)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		head, payload, err := c.frame()
		if err != nil {
			t.Fatalf("no ping within 3 s: %v", err)
		}
		if head&0x0f == 0x9 {
			if head != 0x89 || len(payload) != 0 {
				t.Fatalf("the ping is not one empty final frame: first byte %#x, %d bytes", head, len(payload))
			}
			return
		}
	}
}

// TestPeerThatNeverPongsIsClosed: a peer that answers the relay's pings stays
// open with nothing else to say; one that answers none is gone and is
// closed, subscription or not (behind a proxy no write to it fails).
func TestPeerThatNeverPongsIsClosed(t *testing.T) {
	oldPing, oldGrace := pingInterval, pongGrace
	pingInterval, pongGrace = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { pingInterval, pongGrace = oldPing, oldGrace })
	url, got := quietServer(t, 0, 0)

	answers := rawDial(t, url)
	(<-got).SetSubscription("nip46", signerFilter)
	ghost := rawDial(t, url)
	(<-got).SetSubscription("nip46", signerFilter)

	ghostClosed := make(chan error, 1)
	go func() {
		ghost.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			head, _, err := ghost.frame() // reads, never answers
			if err != nil {
				ghostClosed <- err
				return
			}
			if head&0x0f == 0x8 {
				ghostClosed <- nil // the relay's close frame
				return
			}
		}
	}()

	answers.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	pings := 0
	for {
		head, _, err := answers.frame()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			break // 1.5 s of pings, answered
		}
		if err != nil {
			t.Fatalf("a peer that answers every ping was closed after %d pings: %v", pings, err)
		}
		switch head & 0x0f {
		case 0x9:
			pings++
			if err := answers.pong(); err != nil {
				t.Fatal(err)
			}
		case 0x8:
			t.Fatalf("a peer that answers every ping got a close frame after %d pings", pings)
		}
	}
	if pings < 5 {
		t.Fatalf("only %d pings in 1.5 s at 100 ms", pings)
	}
	select {
	case err := <-ghostClosed:
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("a peer that answers no ping was still open after 3 s")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a peer that answers no ping was still open after 3 s")
	}
}
