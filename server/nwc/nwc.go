// Package nwc is a Nostr Wallet Connect client (NIP-47) with two methods
// only: make_invoice and lookup_invoice. The relay uses it to take payment
// for speakeasies (docs/speakeasies.md, ruling D2): it makes each invoice
// itself on the HOSAKA wallet, so it knows the payment hash to look up, and
// it can never spend, since this client has no method that pays and the
// connection the owner makes in his wallet should grant only those two.
//
// The connection string holds a secret. Nothing in this package logs it or
// puts it in an error: errors name the wallet by a short prefix of its
// pubkey and the relay by its URL.
package nwc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0ceanslim/grain/client/core"
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/net/websocket"
)

// NIP-47 event kinds.
const (
	KindInfo     = 13194
	KindRequest  = 23194
	KindResponse = 23195
)

// Invoice is an invoice as the wallet describes it (NIP-47 make_invoice and
// lookup_invoice results).
type Invoice struct {
	Type            string `json:"type"`
	State           string `json:"state"`
	Invoice         string `json:"invoice"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash"`
	Preimage        string `json:"preimage"`
	PaymentHash     string `json:"payment_hash"`
	Amount          int64  `json:"amount"` // millisatoshis
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
	SettledAt       int64  `json:"settled_at"`
}

// Settled reports whether the wallet says the invoice is paid.
func (i Invoice) Settled() bool { return i.SettledAt > 0 || i.State == "settled" }

// Error is an error the wallet answered with (NIP-47 error codes:
// RATE_LIMITED, NOT_IMPLEMENTED, INSUFFICIENT_BALANCE, QUOTA_EXCEEDED,
// RESTRICTED, UNAUTHORIZED, INTERNAL, NOT_FOUND, OTHER).
type Error struct {
	Code, Message string
}

func (e *Error) Error() string { return "wallet: " + e.Code + ": " + e.Message }

// IsNotFound reports whether err is the wallet saying it has no such
// invoice.
func IsNotFound(err error) bool {
	var we *Error
	return errors.As(err, &we) && we.Code == "NOT_FOUND"
}

// URI is a parsed connection string:
// nostr+walletconnect://<wallet pubkey>?relay=<url>&secret=<hex>.
type URI struct {
	WalletPubkey string
	Relays       []string
	secret       string
}

// ParseURI parses a connection string. Errors never quote it.
func ParseURI(s string) (URI, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil {
		return URI{}, errors.New("nwc: the connection string is not a URI")
	}
	if u.Scheme != "nostr+walletconnect" && u.Scheme != "nostrwalletconnect" {
		return URI{}, errors.New("nwc: the connection string must start with nostr+walletconnect://")
	}
	pub := u.Host
	if pub == "" {
		pub = strings.TrimPrefix(u.Opaque, "//")
	}
	pub = strings.ToLower(pub)
	if !isHex(pub, 64) {
		return URI{}, errors.New("nwc: the wallet pubkey must be 64 hex characters")
	}
	q := u.Query()
	out := URI{WalletPubkey: pub, secret: strings.ToLower(q.Get("secret"))}
	if !isHex(out.secret, 64) {
		return URI{}, errors.New("nwc: the secret must be 64 hex characters")
	}
	for _, r := range q["relay"] {
		ru, err := url.Parse(r)
		if err != nil || (ru.Scheme != "wss" && ru.Scheme != "ws") || ru.Host == "" {
			return URI{}, errors.New("nwc: a relay in the connection string is not a ws:// or wss:// URL")
		}
		out.Relays = append(out.Relays, r)
	}
	if len(out.Relays) == 0 {
		return URI{}, errors.New("nwc: the connection string names no relay")
	}
	return out, nil
}

// String names the connection without its secret, for logs.
func (u URI) String() string {
	return fmt.Sprintf("wallet %s… via %s", u.WalletPubkey[:8], strings.Join(u.Relays, ", "))
}

// Client talks to one wallet over its relays.
type Client struct {
	uri     URI
	signer  *core.EventSigner
	priv    *btcec.PrivateKey
	walletK *btcec.PublicKey
	// Timeout bounds one request: dial, send, and the wallet's answer.
	Timeout time.Duration
	// Origin is the HTTP origin sent with the websocket handshake.
	Origin string

	mu  sync.Mutex
	enc string // "nip44_v2" or "nip04", once the info event is read
}

// New makes a client for uri.
func New(uri URI) (*Client, error) {
	signer, err := core.NewEventSigner(uri.secret)
	if err != nil {
		return nil, errors.New("nwc: the secret is not a valid key")
	}
	raw, _ := hex.DecodeString(uri.secret)
	priv, _ := btcec.PrivKeyFromBytes(raw)
	wb, _ := hex.DecodeString(uri.WalletPubkey)
	wk, err := schnorr.ParsePubKey(wb)
	if err != nil {
		return nil, errors.New("nwc: the wallet pubkey is not a valid key")
	}
	return &Client{uri: uri, signer: signer, priv: priv, walletK: wk, Timeout: 20 * time.Second, Origin: "http://localhost/"}, nil
}

// URI is the connection the client uses.
func (c *Client) URI() URI { return c.uri }

// MakeInvoice asks the wallet for an invoice of amountMsat millisatoshis.
func (c *Client) MakeInvoice(ctx context.Context, amountMsat int64, description string, expiry time.Duration) (Invoice, error) {
	params := map[string]any{"amount": amountMsat, "description": description}
	if expiry > 0 {
		params["expiry"] = int64(expiry / time.Second)
	}
	var inv Invoice
	err := c.call(ctx, "make_invoice", params, &inv)
	return inv, err
}

// LookupInvoice asks the wallet about the invoice with this payment hash.
func (c *Client) LookupInvoice(ctx context.Context, paymentHash string) (Invoice, error) {
	var inv Invoice
	err := c.call(ctx, "lookup_invoice", map[string]any{"payment_hash": paymentHash}, &inv)
	return inv, err
}

// call sends one request and waits for its answer, on each relay in turn
// until one answers. A wallet error is final; a relay that fails is not.
func (c *Client) call(ctx context.Context, method string, params map[string]any, result any) error {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var last error
	for _, relay := range c.uri.Relays {
		s, err := c.sessionOn(ctx, relay)
		if err == nil {
			err = s.call(ctx, method, params, result)
			s.Close()
		}
		var we *Error
		if err == nil || errors.As(err, &we) || ctx.Err() != nil {
			return err
		}
		last = err
	}
	return last
}

// Session is one connection to the wallet's relay, reused for several
// requests one after another (a poll pass looks up every open invoice on
// one connection). It is not safe for concurrent use.
type Session struct {
	c     *Client
	relay string
	conn  *wsConn
	enc   string
}

// Lookuper looks up invoices on one connection until closed.
type Lookuper interface {
	LookupInvoice(ctx context.Context, paymentHash string) (Invoice, error)
	Close()
}

// LookupSession opens a Session on the first relay that answers.
func (c *Client) LookupSession(ctx context.Context) (Lookuper, error) {
	dctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var last error
	for _, relay := range c.uri.Relays {
		s, err := c.sessionOn(dctx, relay)
		if err == nil {
			return s, nil
		}
		last = err
	}
	return nil, last
}

func (c *Client) sessionOn(ctx context.Context, relay string) (*Session, error) {
	conn, err := dial(ctx, relay, c.Origin)
	if err != nil {
		return nil, fmt.Errorf("nwc: %s: %w", relay, err)
	}
	enc, err := c.encryption(ctx, conn)
	if err != nil {
		conn.close()
		return nil, fmt.Errorf("nwc: %s: %w", relay, err)
	}
	return &Session{c: c, relay: relay, conn: conn, enc: enc}, nil
}

// Close closes the connection.
func (s *Session) Close() { s.conn.close() }

// LookupInvoice is Client.LookupInvoice on this connection.
func (s *Session) LookupInvoice(ctx context.Context, paymentHash string) (Invoice, error) {
	ctx, cancel := context.WithTimeout(ctx, s.c.Timeout)
	defer cancel()
	var inv Invoice
	err := s.call(ctx, "lookup_invoice", map[string]any{"payment_hash": paymentHash}, &inv)
	return inv, err
}

func (s *Session) call(ctx context.Context, method string, params map[string]any, result any) error {
	c, conn, relay, enc := s.c, s.conn, s.relay, s.enc
	body, _ := json.Marshal(map[string]any{"method": method, "params": params})
	content, err := c.encrypt(enc, string(body))
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	req := nostr.Event{
		CreatedAt: now,
		Kind:      KindRequest,
		Tags:      [][]string{{"p", c.uri.WalletPubkey}, {"expiration", fmt.Sprint(now + int64(c.Timeout/time.Second) + 30)}},
		Content:   content,
	}
	if enc == "nip44_v2" {
		req.Tags = append(req.Tags, []string{"encryption", "nip44_v2"})
	}
	if err := c.signer.SignEvent(&req); err != nil {
		return fmt.Errorf("nwc: sign: %w", err)
	}
	// Subscribe to the answer before sending, so it cannot be missed.
	sub := "nwc-" + req.ID[:16]
	if err := conn.send("REQ", sub, map[string]any{"kinds": []int{KindResponse}, "authors": []string{c.uri.WalletPubkey}, "#e": []string{req.ID}}); err != nil {
		return fmt.Errorf("nwc: %s: %w", relay, err)
	}
	if err := conn.send("EVENT", req); err != nil {
		return fmt.Errorf("nwc: %s: %w", relay, err)
	}
	defer conn.send("CLOSE", sub)
	for {
		label, msg, err := conn.next(ctx)
		if err != nil {
			return fmt.Errorf("nwc: %s: no answer from the wallet: %w", relay, err)
		}
		switch {
		case len(msg) >= 4 && label == "OK":
			var id string
			var ok bool
			json.Unmarshal(msg[1], &id)
			json.Unmarshal(msg[2], &ok)
			if id == req.ID && !ok {
				var why string
				json.Unmarshal(msg[3], &why)
				return fmt.Errorf("nwc: %s refused the request: %s", relay, why)
			}
		case len(msg) >= 3 && label == "EVENT":
			var ev nostr.Event
			if json.Unmarshal(msg[2], &ev) != nil || !c.isAnswer(ev, req.ID) {
				continue
			}
			return c.decodeAnswer(enc, ev, method, result)
		case len(msg) >= 3 && label == "CLOSED":
			var id, why string
			json.Unmarshal(msg[1], &id)
			if id != sub {
				continue // another subscription's (an earlier request on this connection)
			}
			json.Unmarshal(msg[2], &why)
			return fmt.Errorf("nwc: %s closed the subscription: %s", relay, why)
		}
	}
}

// isAnswer reports whether ev is the wallet's signed answer to request id.
func (c *Client) isAnswer(ev nostr.Event, id string) bool {
	if ev.Kind != KindResponse || ev.PubKey != c.uri.WalletPubkey || !validation.CheckSignature(ev) {
		return false
	}
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "e" && t[1] == id {
			return true
		}
	}
	return false
}

func (c *Client) decodeAnswer(enc string, ev nostr.Event, method string, result any) error {
	plain, err := c.decrypt(ev.Content)
	if err != nil {
		return fmt.Errorf("nwc: could not decrypt the wallet's answer: %w", err)
	}
	var resp struct {
		ResultType string          `json:"result_type"`
		Error      *Error          `json:"error"`
		Result     json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(plain), &resp); err != nil {
		return fmt.Errorf("nwc: the wallet's answer is not JSON")
	}
	if resp.Error != nil && (resp.Error.Code != "" || resp.Error.Message != "") {
		return resp.Error
	}
	if resp.ResultType != method {
		return fmt.Errorf("nwc: the wallet answered %q to %q", resp.ResultType, method)
	}
	if err := json.Unmarshal(resp.Result, result); err != nil {
		return fmt.Errorf("nwc: the wallet's %s result is malformed", method)
	}
	return nil
}

// UnmarshalJSON reads a NIP-47 error object.
func (e *Error) UnmarshalJSON(b []byte) error {
	var v struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	e.Code, e.Message = v.Code, v.Message
	return nil
}

// encryption is the scheme the wallet asks for: nip44_v2 when its info
// event (kind 13194) lists it, otherwise nip04, as NIP-47 says for a wallet
// that names none. It is read once per client, or each time while no
// relay has returned the info event.
func (c *Client) encryption(ctx context.Context, conn *wsConn) (string, error) {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc != "" {
		return enc, nil
	}
	if err := conn.send("REQ", "nwc-info", map[string]any{"kinds": []int{KindInfo}, "authors": []string{c.uri.WalletPubkey}, "limit": 1}); err != nil {
		return "", err
	}
	enc = "nip04"
	seen := false
	for {
		label, msg, err := conn.next(ctx)
		if err != nil {
			return "", fmt.Errorf("reading the wallet's info event: %w", err)
		}
		if label == "EOSE" || label == "CLOSED" {
			if len(msg) < 2 {
				continue
			}
			var id string
			json.Unmarshal(msg[1], &id)
			if id != "nwc-info" {
				continue
			}
			break
		}
		if len(msg) < 3 || label != "EVENT" {
			continue
		}
		var ev nostr.Event
		if json.Unmarshal(msg[2], &ev) != nil || ev.Kind != KindInfo || ev.PubKey != c.uri.WalletPubkey || !validation.CheckSignature(ev) {
			continue
		}
		seen = true
		for _, t := range ev.Tags {
			if len(t) >= 2 && t[0] == "encryption" && slicesContains(strings.Fields(t[1]), "nip44_v2") {
				enc = "nip44_v2"
			}
		}
	}
	conn.send("CLOSE", "nwc-info")
	// Kept only from a real info event: a relay that answered without one
	// (it may not hold it) is asked again next time.
	if seen {
		c.mu.Lock()
		c.enc = enc
		c.mu.Unlock()
	}
	return enc, nil
}

func (c *Client) encrypt(enc, plain string) (string, error) {
	if enc == "nip44_v2" {
		return c.signer.NIP44Encrypt(c.uri.WalletPubkey, plain)
	}
	return nip04Encrypt(c.priv, c.walletK, plain)
}

// decrypt reads either scheme: a NIP-04 payload carries "?iv=".
func (c *Client) decrypt(payload string) (string, error) {
	if strings.Contains(payload, "?iv=") {
		return nip04Decrypt(c.priv, c.walletK, payload)
	}
	return c.signer.NIP44Decrypt(c.uri.WalletPubkey, payload)
}

// ── NIP-04 ───────────────────────────────────────────────────────────────

// nip04Key is the shared x coordinate, unhashed, as NIP-04 uses it.
func nip04Key(priv *btcec.PrivateKey, pub *btcec.PublicKey) []byte {
	return btcec.GenerateSharedSecret(priv, pub)
}

func nip04Encrypt(priv *btcec.PrivateKey, pub *btcec.PublicKey, plain string) (string, error) {
	block, err := aes.NewCipher(nip04Key(priv, pub))
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	buf := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	return base64.StdEncoding.EncodeToString(buf) + "?iv=" + base64.StdEncoding.EncodeToString(iv), nil
}

func nip04Decrypt(priv *btcec.PrivateKey, pub *btcec.PublicKey, payload string) (string, error) {
	ct64, iv64, ok := strings.Cut(payload, "?iv=")
	if !ok {
		return "", errors.New("nip04: no iv")
	}
	ct, err1 := base64.StdEncoding.DecodeString(ct64)
	iv, err2 := base64.StdEncoding.DecodeString(iv64)
	if err1 != nil || err2 != nil || len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", errors.New("nip04: malformed payload")
	}
	block, err := aes.NewCipher(nip04Key(priv, pub))
	if err != nil {
		return "", err
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ct, ct)
	pad := int(ct[len(ct)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(ct) {
		return "", errors.New("nip04: bad padding")
	}
	for _, b := range ct[len(ct)-pad:] {
		if int(b) != pad {
			return "", errors.New("nip04: bad padding")
		}
	}
	return string(ct[:len(ct)-pad]), nil
}

// ── a websocket ──────────────────────────────────────────────────────────

type wsConn struct {
	ws        *websocket.Conn
	msgs      chan []json.RawMessage
	err       error // why the reader stopped; set before msgs is closed
	closeOnce sync.Once
}

func dial(ctx context.Context, relay, origin string) (*wsConn, error) {
	cfg, err := websocket.NewConfig(relay, origin)
	if err != nil {
		return nil, err
	}
	type res struct {
		ws  *websocket.Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		ws, err := cfg.DialContext(ctx)
		done <- res{ws, err}
	}()
	var r res
	select {
	case r = <-done:
	case <-ctx.Done():
		go func() {
			if r := <-done; r.ws != nil {
				r.ws.Close()
			}
		}()
		return nil, ctx.Err()
	}
	if r.err != nil {
		return nil, r.err
	}
	c := &wsConn{ws: r.ws, msgs: make(chan []json.RawMessage, 16)}
	go c.read()
	return c, nil
}

// maxMessageBytes bounds one relay message. A wallet's answer to
// make_invoice or lookup_invoice is a few KB.
const maxMessageBytes = 1 << 20

// read passes each relay message to next. A relay may split one message
// across several websocket frames: relay.getalby.com sends any message over
// 1 KiB as a 1024-byte frame and its continuation, and a wallet's answer to
// make_invoice is larger than that. websocket.Message.Receive returns one
// frame at a time, so a split message never parsed as JSON and the wallet's
// answer was dropped, leaving the request to time out. Conn.Read streams
// the frames' payloads in order, so a JSON decoder over it reads whole
// messages however the relay frames them. A message that is valid JSON but
// not a non-empty array is skipped. A stream that is plainly not JSON ends
// the connection and the call moves on to the next relay; a truncated
// message cannot be told from one still arriving, so it holds the reader
// until the connection closes or the call times out (a JSON relay never
// sends one; the old per-frame reader dropped it instead).
func (c *wsConn) read() {
	lim := &messageLimit{r: c.ws, max: maxMessageBytes}
	dec := json.NewDecoder(lim)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			c.err = err
			close(c.msgs)
			return
		}
		lim.n = 0
		var msg []json.RawMessage
		if json.Unmarshal(raw, &msg) != nil || len(msg) == 0 {
			continue
		}
		c.msgs <- msg
	}
}

// messageLimit fails a read once max bytes have come in since the last whole
// message (read resets n), so a relay cannot make the decoder buffer an
// endless message.
type messageLimit struct {
	r      io.Reader
	n, max int
}

func (l *messageLimit) Read(p []byte) (int, error) {
	if l.n >= l.max {
		return 0, fmt.Errorf("a relay message is over %d bytes", l.max)
	}
	if len(p) > l.max-l.n {
		p = p[:l.max-l.n]
	}
	k, err := l.r.Read(p)
	l.n += k
	return k, err
}

// next is the next message: its label ("EVENT", "OK", ...) and the whole
// message.
func (c *wsConn) next(ctx context.Context) (string, []json.RawMessage, error) {
	select {
	case msg, ok := <-c.msgs:
		if !ok {
			return "", nil, c.err // the close happens after err is set
		}
		var label string
		json.Unmarshal(msg[0], &label)
		return label, msg, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func (c *wsConn) send(v ...any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return websocket.Message.Send(c.ws, string(b))
}

func (c *wsConn) close() {
	c.closeOnce.Do(func() {
		c.ws.Close()
		for range c.msgs { // let the reader finish
		}
	})
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func slicesContains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
