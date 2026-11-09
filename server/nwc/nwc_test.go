package nwc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0ceanslim/grain/client/core"
	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/0ceanslim/grain/server/validation"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/net/websocket"
)

// ── a fake wallet behind a fake relay ────────────────────────────────────

type fakeWallet struct {
	t       *testing.T
	signer  *core.EventSigner
	priv    *btcec.PrivateKey
	pub     string
	nip44   bool // the info event lists nip44_v2
	noInfo  bool // no info event at all
	refuse  bool // the relay answers OK false
	forge   bool // answer with another key's signature
	wrongE  bool // answer naming another request
	errCode string

	mu       sync.Mutex
	invoices map[string]*Invoice
	methods  []string
	encs     []string // the scheme each request used
	senders  []string // the pubkey each request came from
}

func newFakeWallet(t *testing.T) *fakeWallet {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := core.NewEventSigner(hex.EncodeToString(priv.Serialize()))
	return &fakeWallet{t: t, signer: signer, priv: priv, pub: signer.PublicKey(), invoices: map[string]*Invoice{}}
}

func (w *fakeWallet) pay(hash string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.invoices[hash].SettledAt = time.Now().Unix()
	w.invoices[hash].State = "settled"
}

func (w *fakeWallet) serve() *httptest.Server {
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		subs := map[string]string{} // request id -> subscription
		send := func(v ...any) {
			b, _ := json.Marshal(v)
			websocket.Message.Send(ws, string(b))
		}
		for {
			var raw string
			if websocket.Message.Receive(ws, &raw) != nil {
				return
			}
			var msg []json.RawMessage
			json.Unmarshal([]byte(raw), &msg)
			var label, sub string
			json.Unmarshal(msg[0], &label)
			switch label {
			case "REQ":
				json.Unmarshal(msg[1], &sub)
				var f struct {
					Kinds []int    `json:"kinds"`
					E     []string `json:"#e"`
				}
				json.Unmarshal(msg[2], &f)
				if len(f.Kinds) == 1 && f.Kinds[0] == KindInfo {
					if !w.noInfo {
						enc := "nip04"
						if w.nip44 {
							enc = "nip44_v2 nip04"
						}
						info := nostr.Event{CreatedAt: time.Now().Unix(), Kind: KindInfo, Content: "make_invoice lookup_invoice", Tags: [][]string{{"encryption", enc}}}
						w.signer.SignEvent(&info)
						send("EVENT", sub, info)
					}
					send("EOSE", sub)
					continue
				}
				for _, id := range f.E {
					subs[id] = sub
				}
			case "EVENT":
				var ev nostr.Event
				json.Unmarshal(msg[1], &ev)
				if w.refuse {
					send("OK", ev.ID, false, "blocked: no")
					continue
				}
				send("OK", ev.ID, true, "")
				if resp, ok := w.answer(ev); ok {
					send("EVENT", subs[ev.ID], resp)
				}
			}
		}
	}))
	w.t.Cleanup(srv.Close)
	return srv
}

// answer is the wallet's response to a request event, as NIP-47 has it.
func (w *fakeWallet) answer(req nostr.Event) (nostr.Event, bool) {
	t := w.t
	if req.Kind != KindRequest || !validation.CheckSignature(req) {
		t.Errorf("the wallet got a bad request: kind %d", req.Kind)
		return nostr.Event{}, false
	}
	clientPub, _ := schnorr.ParsePubKey(mustHex(req.PubKey))
	enc := "nip04"
	for _, tag := range req.Tags {
		if len(tag) >= 2 && tag[0] == "encryption" {
			enc = tag[1]
		}
	}
	var plain string
	var err error
	if enc == "nip44_v2" {
		plain, err = w.signer.NIP44Decrypt(req.PubKey, req.Content)
	} else {
		plain, err = nip04Decrypt(w.priv, clientPub, req.Content)
	}
	if err != nil {
		t.Errorf("the wallet could not decrypt (%s): %v", enc, err)
		return nostr.Event{}, false
	}
	var body struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	json.Unmarshal([]byte(plain), &body)
	w.mu.Lock()
	w.methods = append(w.methods, body.Method)
	w.encs = append(w.encs, enc)
	w.senders = append(w.senders, req.PubKey)
	resp := map[string]any{"result_type": body.Method}
	switch {
	case w.errCode != "":
		resp["error"] = map[string]string{"code": w.errCode, "message": "no"}
	case body.Method == "make_invoice":
		sum := sha256.Sum256([]byte(fmt.Sprint(body.Params["description"], len(w.invoices))))
		hash := hex.EncodeToString(sum[:])
		inv := &Invoice{Type: "incoming", State: "pending", Invoice: "lnbc10u1fake" + hash[:20], Description: fmt.Sprint(body.Params["description"]),
			PaymentHash: hash, Amount: int64(body.Params["amount"].(float64)), CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + int64(body.Params["expiry"].(float64))}
		w.invoices[hash] = inv
		resp["result"] = inv
	case body.Method == "lookup_invoice":
		inv, ok := w.invoices[fmt.Sprint(body.Params["payment_hash"])]
		if !ok {
			resp["error"] = map[string]string{"code": "NOT_FOUND", "message": "no such invoice"}
		} else {
			resp["result"] = inv
		}
	}
	w.mu.Unlock()
	b, _ := json.Marshal(resp)
	var content string
	if enc == "nip44_v2" {
		content, _ = w.signer.NIP44Encrypt(req.PubKey, string(b))
	} else {
		content, _ = nip04Encrypt(w.priv, clientPub, string(b))
	}
	e := req.ID
	if w.wrongE {
		e = strings.Repeat("0", 64)
	}
	out := nostr.Event{CreatedAt: time.Now().Unix(), Kind: KindResponse, Content: content, Tags: [][]string{{"p", req.PubKey}, {"e", e}}}
	signer := w.signer
	if w.forge {
		signer, _ = core.NewEventSignerFromRandom()
	}
	signer.SignEvent(&out)
	if w.forge {
		out.PubKey = w.pub // claims to be the wallet; the signature is not its
	}
	return out, true
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func wsURL(srv *httptest.Server) string { return "ws" + strings.TrimPrefix(srv.URL, "http") }

const testSecret = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"

func connString(walletPub string, secret string, relays ...string) string {
	s := "nostr+walletconnect://" + walletPub + "?secret=" + secret
	for _, r := range relays {
		s += "&relay=" + r
	}
	return s
}

func newClient(t *testing.T, w *fakeWallet, relays ...string) *Client {
	t.Helper()
	uri, err := ParseURI(connString(w.pub, testSecret, relays...))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(uri)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 5 * time.Second
	return c
}

// ── tests ────────────────────────────────────────────────────────────────

// TestParseURI: the connection string's parts, and no error or log form
// ever carries the secret.
func TestParseURI(t *testing.T) {
	pub := strings.Repeat("b", 64)
	u, err := ParseURI("  " + connString(pub, testSecret, "wss://relay.getalby.com/v1", "wss://two.example") + "&lud16=hosaka%40getalby.com\n")
	if err != nil || u.WalletPubkey != pub || len(u.Relays) != 2 || u.secret != testSecret {
		t.Fatalf("%+v %v", u, err)
	}
	if strings.Contains(u.String(), testSecret) || strings.Contains(fmt.Sprintf("%v %+v", u, u), testSecret) {
		t.Fatal("the secret shows in the URI's printed form")
	}
	for _, bad := range []string{
		"https://" + pub + "?secret=" + testSecret + "&relay=wss://r.example",
		connString("abc", testSecret, "wss://r.example"),
		connString(pub, "", "wss://r.example"),
		connString(pub, testSecret[:63], "wss://r.example"),
		connString(pub, testSecret),
		connString(pub, testSecret, "https://r.example"),
	} {
		_, err := ParseURI(bad)
		if err == nil {
			t.Errorf("accepted %q", bad)
		} else if strings.Contains(err.Error(), testSecret[:16]) {
			t.Errorf("an error quotes the secret: %v", err)
		}
	}
}

// TestNIP04RoundTrip: what one side encrypts the other decrypts; a wrong
// key or a tampered payload does not decrypt to the message.
func TestNIP04RoundTrip(t *testing.T) {
	a, _ := btcec.NewPrivateKey()
	b, _ := btcec.NewPrivateKey()
	c, _ := btcec.NewPrivateKey()
	for _, msg := range []string{"", "x", "exactly sixteen!", strings.Repeat("long ", 100)} {
		ct, err := nip04Encrypt(a, b.PubKey(), msg)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := nip04Decrypt(b, a.PubKey(), ct); err != nil || got != msg {
			t.Fatalf("round trip %q: %q %v", msg, got, err)
		}
		if got, err := nip04Decrypt(c, a.PubKey(), ct); err == nil && got == msg {
			t.Fatal("a third key decrypted it")
		}
	}
	for _, bad := range []string{"", "abc", "abc?iv=", "AAAA?iv=AAAA"} {
		if _, err := nip04Decrypt(b, a.PubKey(), bad); err == nil {
			t.Errorf("decrypted %q", bad)
		}
	}
}

// TestClientMakesAndLooksUpInvoices: make_invoice then lookup_invoice
// against a wallet that offers nip44_v2 (used) and one that names no
// scheme (nip04, as NIP-47 says).
func TestClientMakesAndLooksUpInvoices(t *testing.T) {
	for _, c := range []struct {
		name          string
		nip44, noInfo bool
		want          string
	}{{"nip44", true, false, "nip44_v2"}, {"nip04 by info", false, false, "nip04"}, {"no info event", false, true, "nip04"}} {
		t.Run(c.name, func(t *testing.T) {
			w := newFakeWallet(t)
			w.nip44, w.noInfo = c.nip44, c.noInfo
			cl := newClient(t, w, wsURL(w.serve()))
			ctx := context.Background()
			inv, err := cl.MakeInvoice(ctx, 1_000_000, "relay.onosendai.tech speakeasy abc", 10*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if inv.Amount != 1_000_000 || inv.Description != "relay.onosendai.tech speakeasy abc" || len(inv.PaymentHash) != 64 || inv.Settled() {
				t.Fatalf("made %+v", inv)
			}
			got, err := cl.LookupInvoice(ctx, inv.PaymentHash)
			if err != nil || got.Settled() {
				t.Fatalf("before paying: %+v %v", got, err)
			}
			w.pay(inv.PaymentHash)
			if got, err = cl.LookupInvoice(ctx, inv.PaymentHash); err != nil || !got.Settled() {
				t.Fatalf("after paying: %+v %v", got, err)
			}
			_, err = cl.LookupInvoice(ctx, strings.Repeat("e", 64))
			if !IsNotFound(err) {
				t.Fatalf("an unknown hash: %v", err)
			}
			w.mu.Lock()
			defer w.mu.Unlock()
			if strings.Join(w.methods, ",") != "make_invoice,lookup_invoice,lookup_invoice,lookup_invoice" {
				t.Fatalf("methods sent: %v", w.methods)
			}
			for _, e := range w.encs {
				if e != c.want {
					t.Fatalf("encryption %v, want %s", w.encs, c.want)
				}
			}
		})
	}
}

// TestClientRefusesWhatIsNotTheWallets: an answer signed by another key, or
// naming another request, is never taken; a wallet error and a relay's
// refusal come back as errors.
func TestClientRefusesWhatIsNotTheWallets(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		set  func(*fakeWallet)
		want string
	}{
		{"forged signature", func(w *fakeWallet) { w.forge = true }, "no answer"},
		{"another request's answer", func(w *fakeWallet) { w.wrongE = true }, "no answer"},
		{"relay refuses", func(w *fakeWallet) { w.refuse = true }, "refused the request"},
		{"wallet error", func(w *fakeWallet) { w.errCode = "RESTRICTED" }, "RESTRICTED"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newFakeWallet(t)
			c.set(w)
			cl := newClient(t, w, wsURL(w.serve()))
			cl.Timeout = 700 * time.Millisecond
			_, err := cl.MakeInvoice(ctx, 1000, "x", time.Minute)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
			var we *Error
			if (c.want == "RESTRICTED") != errors.As(err, &we) {
				t.Fatalf("wallet error type: %T", err)
			}
		})
	}
}

// TestEncryptionIsKeptOnlyFromAnInfoEvent: a relay that answers without
// the wallet's info event leaves the choice open (nip04 for now), so once
// the event is there, nip44_v2 is used.
func TestEncryptionIsKeptOnlyFromAnInfoEvent(t *testing.T) {
	w := newFakeWallet(t)
	w.noInfo = true
	cl := newClient(t, w, wsURL(w.serve()))
	ctx := context.Background()
	if _, err := cl.MakeInvoice(ctx, 1000, "one", time.Minute); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.noInfo, w.nip44 = false, true
	w.mu.Unlock()
	if _, err := cl.MakeInvoice(ctx, 1000, "two", time.Minute); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if strings.Join(w.encs, ",") != "nip04,nip44_v2" {
		t.Fatalf("encryption %v, want nip04 then nip44_v2", w.encs)
	}
}

// TestClientTriesTheNextRelay: a relay that cannot be reached is skipped.
func TestClientTriesTheNextRelay(t *testing.T) {
	w := newFakeWallet(t)
	dead := httptest.NewServer(nil)
	deadURL := wsURL(dead)
	dead.Close()
	cl := newClient(t, w, deadURL, wsURL(w.serve()))
	if _, err := cl.MakeInvoice(context.Background(), 1000, "x", time.Minute); err != nil {
		t.Fatal(err)
	}
}

// TestFileWalletRotates: replacing the connection file changes the key the
// next request is signed with, with no restart; a broken file is an error
// that does not quote it.
func TestFileWalletRotates(t *testing.T) {
	w := newFakeWallet(t)
	relay := wsURL(w.serve())
	path := filepath.Join(t.TempDir(), "nwc")
	os.WriteFile(path, []byte(connString(w.pub, testSecret, relay)+"\n"), 0o600)
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Insecure() || strings.Contains(f.Describe(), testSecret) {
		t.Fatalf("insecure %v, describe %q", f.Insecure(), f.Describe())
	}
	ctx := context.Background()
	if _, err := f.MakeInvoice(ctx, 1000, "one", time.Minute); err != nil {
		t.Fatal(err)
	}
	second := strings.Repeat("1", 64)
	os.WriteFile(path, []byte(connString(w.pub, second, relay, relay)), 0o600)
	if _, err := f.MakeInvoice(ctx, 1000, "two", time.Minute); err != nil {
		t.Fatal(err)
	}
	s1, _ := core.NewEventSigner(testSecret)
	s2, _ := core.NewEventSigner(second)
	w.mu.Lock()
	senders := append([]string(nil), w.senders...)
	w.mu.Unlock()
	if len(senders) != 2 || senders[0] != s1.PublicKey() || senders[1] != s2.PublicKey() {
		t.Fatalf("senders %v, want the first key then the rotated one", senders)
	}
	os.WriteFile(path, []byte("nostr+walletconnect://broken?secret="+second), 0o600)
	os.Chmod(path, 0o644)
	if !f.Insecure() {
		t.Error("a world-readable file is not reported")
	}
	_, err = f.MakeInvoice(ctx, 1000, "three", time.Minute)
	if err == nil || strings.Contains(err.Error(), second[:16]) {
		t.Fatalf("broken file: %v", err)
	}
	if _, err := OpenFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing file opened")
	}
}
