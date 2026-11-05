package handlers

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/websocket"
)

// wsClient is a noopClient on a real websocket.
type wsClient struct {
	noopClient
	ws *websocket.Conn
}

func (c wsClient) GetWS() *websocket.Conn { return c.ws }

// A gate's context carries the address of the client the request came from
// (the region gate's work queue limits work per address), and "" when the
// client has no websocket.
func TestGateContextCarriesTheClientAddress(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		got <- ClientIP(gateContext(context.Background(), wsClient{ws: ws}))
	}))
	defer srv.Close()
	ws, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if ip := <-got; ip != "127.0.0.1" {
		t.Fatalf("want the client's address 127.0.0.1, got %q", ip)
	}
	if ip := ClientIP(gateContext(context.Background(), noopClient{})); ip != "" {
		t.Fatalf("no websocket: want \"\", got %q", ip)
	}
	if ip := ClientIP(context.Background()); ip != "" {
		t.Fatalf("a context without one: want \"\", got %q", ip)
	}
}
