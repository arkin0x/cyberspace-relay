package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// liveConn is an accepted connection that records when bytes last arrived
// from the peer. x/net/websocket answers pings and swallows pongs out of
// sight, so the bytes are the only way to see a pong: a client that answers
// the relay's pings (writeLoop) is heard from at least every pingInterval,
// even when it sends no message. Behind a proxy (Caddy) the TCP peer is the
// proxy, whose writes never fail, so this is also the only way to find a
// client that went away without closing (a phone asleep or off the network).
type liveConn struct {
	net.Conn
	lastRead atomic.Int64 // UnixNano
}

func (c *liveConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.lastRead.Store(time.Now().UnixNano())
	}
	return n, err
}

// touch counts now as heard from the peer.
func (c *liveConn) touch() { c.lastRead.Store(time.Now().UnixNano()) }

// heardWithin reports whether any byte arrived from the peer within d.
func (c *liveConn) heardWithin(d time.Duration) bool {
	return time.Since(time.Unix(0, c.lastRead.Load())) <= d
}

// CloseWrite and ReadFrom pass through, so net/http keeps its TCP half-close
// and sendfile paths on a wrapped connection.
func (c *liveConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *liveConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.Conn}, r)
}

// liveListener wraps each accepted connection in a liveConn.
type liveListener struct{ net.Listener }

func (l liveListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	lc := &liveConn{Conn: c}
	lc.lastRead.Store(time.Now().UnixNano())
	return lc, nil
}

type liveConnKey struct{}

// withLiveConn is the http.Server's ConnContext: it puts the liveConn in
// every request's context, where clientHandler finds it.
func withLiveConn(ctx context.Context, c net.Conn) context.Context {
	if lc, ok := c.(*liveConn); ok {
		return context.WithValue(ctx, liveConnKey{}, lc)
	}
	return ctx
}

// liveConnOf is the request's liveConn, or nil when the server was not
// started on a liveListener (tests that serve clientHandler directly).
func liveConnOf(r *http.Request) *liveConn {
	if r == nil {
		return nil
	}
	lc, _ := r.Context().Value(liveConnKey{}).(*liveConn)
	return lc
}

// pongGrace is how long past two ping intervals the relay waits to hear
// from a peer before it calls the connection dead (a variable for tests).
var pongGrace = 15 * time.Second

// silentTooLong reports whether the peer has sent nothing, not even a pong,
// for two ping intervals and the grace while the reader was waiting for it:
// a peer that is gone.
func (c *Client) silentTooLong() bool {
	return c.live != nil && !c.handling.Load() && !c.live.heardWithin(c.silentAfter)
}

// markReading is called by the reader before it waits for the next message.
func (c *Client) markReading() {
	c.handling.Store(false)
	if c.live != nil {
		c.live.touch()
	}
}
