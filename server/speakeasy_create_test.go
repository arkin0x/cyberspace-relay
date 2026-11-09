package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	mu       sync.Mutex
	invoices map[string]*nwc.Invoice
}

func (w *memWallet) MakeInvoice(_ context.Context, msat int64, desc string, _ time.Duration) (nwc.Invoice, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	sum := sha256.Sum256([]byte(fmt.Sprint(desc, len(w.invoices))))
	h := hex.EncodeToString(sum[:])
	inv := &nwc.Invoice{Invoice: "lnbc10u1p" + h[:50], Description: desc, PaymentHash: h, Amount: msat}
	w.invoices[h] = inv
	return *inv, nil
}

func (w *memWallet) LookupInvoice(_ context.Context, h string) (nwc.Invoice, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
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
		MaxPending: 8, MaxPerRequester: 3,
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
	if code != 200 || o["region"] != "abc" || o["amount_sats"] != float64(1000) || o["status"] != "pending" ||
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
