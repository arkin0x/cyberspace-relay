package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0ceanslim/grain/client/core"
	"github.com/0ceanslim/grain/config"
	"github.com/0ceanslim/grain/server/nwc"
	"github.com/0ceanslim/grain/server/speakeasy"
)

// memWallet stands in for the HOSAKA wallet: no network, invoices in memory.
type memWallet struct {
	mu          sync.Mutex
	invoices    map[string]*nwc.Invoice
	failLookups bool
}

func (w *memWallet) MakeInvoice(_ context.Context, msat int64, desc string, expiry time.Duration) (nwc.Invoice, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	sum := sha256.Sum256([]byte(fmt.Sprint(desc, len(w.invoices))))
	h := hex.EncodeToString(sum[:])
	// BOLT 11's data characters (bech32) have no "1".
	data := strings.Map(func(r rune) rune {
		return rune("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[strings.IndexRune("0123456789abcdef", r)])
	}, h[:50])
	inv := &nwc.Invoice{Invoice: fmt.Sprintf("lnbc%du1p", msat/100_000) + data, Description: desc, PaymentHash: h, Amount: msat,
		ExpiresAt: time.Now().Add(expiry).Unix()}
	w.invoices[h] = inv
	return *inv, nil
}

func (w *memWallet) LookupInvoice(_ context.Context, h string) (nwc.Invoice, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failLookups {
		return nwc.Invoice{}, errors.New("wallet relay down")
	}
	if inv, ok := w.invoices[h]; ok {
		return *inv, nil
	}
	return nwc.Invoice{}, &nwc.Error{Code: "NOT_FOUND"}
}

func (w *memWallet) pay(h string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.invoices[h].SettledAt = time.Now().Unix()
}

// withCheckout turns payments on for a relay under test, with a memWallet.
func withCheckout(t *testing.T, r *relayUnderTest) (*memWallet, *speakeasy.Checkout) {
	t.Helper()
	w := &memWallet{invoices: map[string]*nwc.Invoice{}}
	dir := t.TempDir()
	co, err := speakeasy.NewCheckout(speakeasy.CheckoutConfig{
		Wallet: w, Registry: r.rt.reg, OrdersPath: filepath.Join(dir, "orders.json"), LedgerPath: filepath.Join(dir, "payments.jsonl"),
		Write: config.AtomicWriteFile, Host: "relay.example", SpeakeasySats: 1000, Expiry: 10 * time.Minute, Poll: time.Hour,
		MaxPending: 8, MaxPerRequester: 3, MaxPerNetwork: 6, MaxPerRegion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.rt.checkout = co
	r.rt.cfg.Payments.SpeakeasySats = 1000
	t.Cleanup(func() { r.rt.checkout = nil })
	return w, co
}

func post(t *testing.T, url, contentType, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	code, body, _ := get(t, http.MethodGet, url)
	var out map[string]any
	json.Unmarshal([]byte(body), &out)
	return code, out
}

// TestCreateSpeakeasy: the page offers Create while payments are on; the
// button's endpoint makes one invoice per region and requester; once the
// wallet says it is paid, the path is a live speakeasy.
func TestCreateSpeakeasy(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	orders := r.root + OrdersPath

	// Payments off: no offer, no endpoint.
	if _, body, _ := get(t, http.MethodGet, r.root+"/abc", "Accept", browser); strings.Contains(body, "Create speakeasy") {
		t.Fatal("Create offered while payments are off")
	}
	if code, out := post(t, orders, "application/json", `{"region":"abc"}`); code != 404 || out["error"] == nil {
		t.Fatalf("payments off: %d %v", code, out)
	}

	w, co := withCheckout(t, r)
	_, body, _ := get(t, http.MethodGet, r.root+"/abc", "Accept", browser)
	if !strings.Contains(body, "Create speakeasy for 1,000 sats") || !strings.Contains(body, `data-endpoint="`+OrdersPath+`"`) || !strings.Contains(body, `data-region="abc"`) {
		t.Fatal("the page does not offer Create Speakeasy for 1,000 sats")
	}

	for _, c := range []struct {
		ct, body string
		code     int
	}{
		{"", `{"region":"abc"}`, 415},
		{"text/plain", `{"region":"abc"}`, 415},
		{"application/json", `{"region":"xyz"}`, 400},
		{"application/json", `{"region":"abc","sats":1}`, 400},
		{"application/json", `not json`, 400},
	} {
		if code, out := post(t, orders, c.ct, c.body); code != c.code || out["error"] == nil {
			t.Errorf("POST %q %s: %d %v, want %d", c.ct, c.body, code, out, c.code)
		}
	}

	code, o := post(t, orders, "application/json; charset=utf-8", `{"region":"0xABC"}`)
	if code != 200 || o["region"] != "abc" || o["amount_sats"] != float64(1000) || o["status"] != "pending" || len(fmt.Sprint(o["payment_hash"])) != 64 ||
		!strings.HasPrefix(fmt.Sprint(o["qr_svg"]), "<svg") || !strings.HasPrefix(fmt.Sprint(o["invoice"]), "lnbc") || o["url"] != nil || o["requester"] != nil {
		t.Fatalf("create: %d %v", code, o)
	}
	id := o["id"].(string)
	if _, again := post(t, orders, "application/json", `{"region":"abc"}`); again["id"] != id {
		t.Fatal("asking again made another invoice")
	}
	if code, st := getJSON(t, orders+"/"+id); code != 200 || st["status"] != "pending" || st["applied"] != false {
		t.Fatalf("status: %d %v", code, st)
	}
	if code, _ := getJSON(t, orders+"/"+strings.Repeat("0", 32)); code != 404 {
		t.Fatalf("an unknown order: %d", code)
	}

	// Paid: the relay registers it, and the path is a speakeasy.
	got, _ := co.Get(id)
	w.pay(got.PaymentHash)
	co.Poll(context.Background())
	if code, st := getJSON(t, orders+"/"+id); code != 200 || st["applied"] != true || st["url"] != r.wsRoot+"/abc" || st["outcome"] != speakeasy.OutcomeRegistered || st["qr_svg"] != nil {
		t.Fatalf("after paying: %d %v", code, st)
	}
	if code, doc, _ := nip11(t, r.root+"/abc"); code != 200 || doc["name"] != "Speakeasy abc" {
		t.Fatalf("the paid speakeasy's NIP-11: %d %v", code, doc)
	}
	if _, body, _ := get(t, http.MethodGet, r.root+"/abc", "Accept", browser); strings.Contains(body, "Create speakeasy") || !strings.Contains(body, r.wsRoot+"/abc") {
		t.Fatal("the page still offers Create, or lacks the address")
	}
	if code, out := post(t, orders, "application/json", `{"region":"abc"}`); code != 409 {
		t.Fatalf("a speakeasy offered again: %d %v", code, out)
	}
}

// TestStartCheckout: payments are on only when enabled with a usable NWC
// connection file; any problem leaves them off and speakeasies open.
func TestStartCheckout(t *testing.T) {
	dir := t.TempDir()
	reg, _, err := speakeasy.LoadRegistry(filepath.Join(dir, "registry.json"), speakeasy.ParseRegionPath, []uint{0, 1}, os.WriteFile)
	if err != nil {
		t.Fatal(err)
	}
	walletKey, _ := core.NewEventSignerFromRandom()
	good := filepath.Join(dir, "nwc")
	os.WriteFile(good, []byte("nostr+walletconnect://"+walletKey.PublicKey()+"?relay=wss://wallet.invalid&secret="+strings.Repeat("1", 64)), 0o600)
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("not a connection string"), 0o600)
	for _, c := range []struct {
		yml string
		on  bool
	}{
		{"enabled: true\n", false},
		{"enabled: true\npayments: {enabled: false, nwc_file: " + good + "}\n", false},
		{"enabled: true\npayments: {enabled: true}\n", false},
		{"enabled: true\npayments: {enabled: true, nwc_file: " + bad + "}\n", false},
		{"enabled: true\npayments: {enabled: true, nwc_file: " + filepath.Join(dir, "missing") + "}\n", false},
		{"enabled: true\npayments: {enabled: true, nwc_file: " + good + "}\n", true},
	} {
		sc, err := speakeasy.ParseConfig([]byte(c.yml))
		if err != nil {
			t.Fatal(err)
		}
		if co := startCheckout(sc, reg, dir, "wss://relay.example"); (co != nil) != c.on {
			t.Errorf("%q: payments on %v, want %v", c.yml, co != nil, c.on)
		}
	}
	sc, _ := speakeasy.ParseConfig([]byte("enabled: true\n"))
	if p := sc.Payments; p.SpeakeasySats != 1000 || p.InvoiceExpirySeconds != 600 || p.Enabled {
		t.Errorf("defaults: %+v", p)
	}
	if _, err := speakeasy.ParseConfig([]byte("enabled: true\npayments: {speakeasy_sats: -1}\n")); err == nil {
		t.Error("a negative price accepted")
	}
}

// TestRefundOwedIsVisible: a second payment for a region is shown as a
// refund owed (never as a success: no url), with its order id and payment
// hash, and NIP-86 grain_speakeasy_payments lists it for the owner.
func TestRefundOwedIsVisible(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	orders := r.root + OrdersPath
	if res, msg := r.rt.Payments(nil); msg != "" || res.(map[string]any)["payments_on"] != false {
		t.Fatalf("payments off: %v %q", res, msg)
	}
	w, co := withCheckout(t, r)
	_, a := post(t, orders, "application/json", `{"region":"abc"}`)
	// A second requester, as the HTTP layer would key one.
	b, err := co.Create(context.Background(), speakeasy.OrderRequest{Kind: speakeasy.OrderSpeakeasy, Region: "abc", Requester: "other", Network: "other"})
	if err != nil {
		t.Fatal(err)
	}
	ga, _ := co.Get(a["id"].(string))
	w.pay(ga.PaymentHash)
	w.pay(b.PaymentHash)
	co.Poll(context.Background())
	// Both settled in one pass: whichever was applied first made the
	// speakeasy; the other is owed back.
	won, lost := ga, b
	if gb, _ := co.Get(b.ID); gb.Outcome == speakeasy.OutcomeRegistered {
		won, lost = gb, ga
	}
	_, st := getJSON(t, orders+"/"+lost.ID)
	if st["applied"] != true || st["needs_owner"] != true || st["url"] != nil || st["payment_hash"] != lost.PaymentHash || st["id"] != lost.ID ||
		!strings.HasPrefix(fmt.Sprint(st["outcome"]), "refund owed") {
		t.Fatalf("the refund as the page sees it: %v", st)
	}
	if _, st := getJSON(t, orders+"/"+won.ID); st["url"] != r.wsRoot+"/abc" || st["needs_owner"] != nil {
		t.Fatalf("the payment that made it: %v", st)
	}
	res, msg := r.rt.Payments(nil)
	m, _ := res.(map[string]any)
	owe, _ := m["needs_owner"].([]speakeasy.Order)
	if msg != "" || len(owe) != 1 || owe[0].PaymentHash != lost.PaymentHash {
		t.Fatalf("grain_speakeasy_payments: %v %q", res, msg)
	}
	// The page script shows the order and hash, and never calls a refund a
	// success.
	_, body, _ := get(t, http.MethodGet, r.root+"/abd", "Accept", browser)
	for _, want := range []string{`id="order-id"`, `id="payment-hash"`, "bought nothing", "localStorage"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
}

// TestPausedSalesAndResolve: while sales are paused the page offers no
// Create and the endpoint answers 503; an expired invoice's QR is not
// shown; NIP-86 grain_speakeasy_payment_resolve takes a refund off the
// owner's list.
func TestPausedSalesAndResolve(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	orders := r.root + OrdersPath
	w, co := withCheckout(t, r)
	_, a := post(t, orders, "application/json", `{"region":"abc"}`)
	b, err := co.Create(context.Background(), speakeasy.OrderRequest{Kind: speakeasy.OrderSpeakeasy, Region: "abc", Requester: "other", Network: "other"})
	if err != nil {
		t.Fatal(err)
	}
	ga, _ := co.Get(a["id"].(string))
	w.pay(ga.PaymentHash)
	w.pay(b.PaymentHash)
	co.Poll(context.Background())
	res, _ := r.rt.Payments(nil)
	owe := res.(map[string]any)["needs_owner"].([]speakeasy.Order)
	if len(owe) != 1 || res.(map[string]any)["sales"] != "" {
		t.Fatalf("payments: %v", res)
	}
	if _, msg := r.rt.PaymentResolve([]any{owe[0].PaymentHash, "refunded by hand"}); msg != "" {
		t.Fatal(msg)
	}
	if res, _ := r.rt.Payments(nil); len(res.(map[string]any)["needs_owner"].([]speakeasy.Order)) != 0 {
		t.Fatalf("still listed after resolve: %v", res)
	}
	if _, msg := r.rt.PaymentResolve([]any{owe[0].PaymentHash, "again"}); msg == "" {
		t.Fatal("resolved twice")
	}

	// An open invoice past its expiry: no QR.
	_, c := post(t, orders, "application/json", `{"region":"abd"}`)
	co.Orders() // the order exists
	got, _ := co.Get(c["id"].(string))
	if _, st := getJSON(t, orders+"/"+got.ID); st["qr_svg"] == nil {
		t.Fatal("no QR while payable")
	}

	// Paused: no offer, 503.
	w.mu.Lock()
	w.failLookups = true
	w.mu.Unlock()
	co.Poll(context.Background())
	if _, body, _ := get(t, http.MethodGet, r.root+"/abe", "Accept", browser); strings.Contains(body, "Create speakeasy for") {
		t.Fatal("Create offered while paused")
	}
	if code, out := post(t, orders, "application/json", `{"region":"abe"}`); code != 503 {
		t.Fatalf("paused: %d %v", code, out)
	}
}

// TestQROnlyWhilePayable: an order still open past its expiry (its answer
// awaited) shows no QR; one that can be paid does.
func TestQROnlyWhilePayable(t *testing.T) {
	rt := &speakeasyRuntime{publicURL: "wss://relay.example"}
	inv := "lnbc10u1p" + strings.Repeat("q", 50)
	if v := rt.view(speakeasy.Order{Status: speakeasy.StatusPending, Invoice: inv, ExpiresAt: time.Now().Add(time.Minute).Unix()}); v.QR == "" {
		t.Fatal("no QR while payable")
	}
	if v := rt.view(speakeasy.Order{Status: speakeasy.StatusPending, Invoice: inv, ExpiresAt: time.Now().Add(-time.Second).Unix()}); v.QR != "" {
		t.Fatal("a QR for an invoice that can no longer be paid")
	}
}
