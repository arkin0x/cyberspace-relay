package speakeasy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0ceanslim/grain/server/nwc"
)

// fakeWallet is a wallet in memory: invoices by payment hash.
type fakeWallet struct {
	mu       sync.Mutex
	invoices map[string]*nwc.Invoice
	makes    int
	makeErr  error
	bolt11   string // when set, what make_invoice answers as the invoice
	answer   func(nwc.Invoice) nwc.Invoice
	delay    time.Duration
}

func newFakeWallet() *fakeWallet { return &fakeWallet{invoices: map[string]*nwc.Invoice{}} }

func (w *fakeWallet) MakeInvoice(ctx context.Context, msat int64, desc string, expiry time.Duration) (nwc.Invoice, error) {
	time.Sleep(w.delay)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.makeErr != nil {
		return nwc.Invoice{}, w.makeErr
	}
	w.makes++
	sum := sha256.Sum256([]byte(fmt.Sprint(desc, w.makes)))
	hash := hex.EncodeToString(sum[:])
	inv := &nwc.Invoice{Invoice: "lnbc10u1p" + hash[:40], Description: desc, PaymentHash: hash, Amount: msat, State: "pending"}
	if w.bolt11 != "" {
		inv.Invoice = w.bolt11
	}
	w.invoices[hash] = inv
	return *inv, nil
}

func (w *fakeWallet) LookupInvoice(ctx context.Context, hash string) (nwc.Invoice, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	inv, ok := w.invoices[hash]
	if !ok {
		return nwc.Invoice{}, &nwc.Error{Code: "NOT_FOUND", Message: "no"}
	}
	out := *inv
	if w.answer != nil {
		out = w.answer(out)
	}
	return out, nil
}

func (w *fakeWallet) pay(hash string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.invoices[hash].State = "settled"
	w.invoices[hash].SettledAt = 1762700000
}

type checkoutRig struct {
	t        *testing.T
	dir      string
	wallet   *fakeWallet
	reg      *Registry
	co       *Checkout
	now      time.Time
	failSave bool
	alerts   []string
}

func newCheckoutRig(t *testing.T) *checkoutRig {
	r := &checkoutRig{t: t, dir: t.TempDir(), wallet: newFakeWallet(), now: time.Unix(1762700000, 0)}
	reg, _, err := LoadRegistry(filepath.Join(r.dir, "registry.json"), ParseRegionPath, []uint{0, 1}, func(p string, d []byte, m os.FileMode) error {
		if r.failSave {
			return errors.New("disk full")
		}
		return os.WriteFile(p, d, m)
	})
	if err != nil {
		t.Fatal(err)
	}
	r.reg = reg
	r.open()
	return r
}

// open makes the checkout (again, as a restart would).
func (r *checkoutRig) open() {
	co, err := NewCheckout(CheckoutConfig{
		Wallet: r.wallet, Registry: r.reg,
		OrdersPath: filepath.Join(r.dir, "orders.json"), LedgerPath: filepath.Join(r.dir, "payments.jsonl"),
		Write: os.WriteFile, Host: "relay.example", SpeakeasySats: DefaultSpeakeasySats,
		Expiry: 10 * time.Minute, Poll: time.Hour, MaxPending: 5, MaxPerRequester: 3,
		Now:   func() time.Time { return r.now },
		Alert: func(msg string, args ...any) { r.alerts = append(r.alerts, msg) },
	})
	if err != nil {
		r.t.Fatal(err)
	}
	r.co = co
}

func (r *checkoutRig) create(region, who string) (Order, error) {
	return r.co.Create(context.Background(), OrderRequest{Kind: OrderSpeakeasy, Region: region, Requester: Requester(who)})
}

func (r *checkoutRig) mustCreate(region, who string) Order {
	r.t.Helper()
	o, err := r.create(region, who)
	if err != nil {
		r.t.Fatal(err)
	}
	return o
}

func (r *checkoutRig) ledger() []Order {
	f, err := os.Open(filepath.Join(r.dir, "payments.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Order
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var o Order
		json.Unmarshal(sc.Bytes(), &o)
		out = append(out, o)
	}
	return out
}

// TestCheckoutCreatesAndApplies: an invoice for 1,000 sats marked with the
// region; nothing happens until it is paid; once paid, the region is a
// speakeasy, the ledger has one line, and later polls change nothing.
func TestCheckoutCreatesAndApplies(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.2.3.4")
	if o.AmountSats != 1000 || o.Status != StatusPending || o.Description != "relay.example speakeasy abc" || o.ExpiresAt != r.now.Unix()+600 {
		t.Fatalf("order %+v", o)
	}
	if inv := r.wallet.invoices[o.PaymentHash]; inv.Amount != 1_000_000 || !strings.Contains(inv.Description, "abc") {
		t.Fatalf("invoice %+v: want 1,000,000 msat marked with the region", inv)
	}
	if strings.Contains(o.Requester, "1.2.3.4") {
		t.Fatal("the order keeps the address itself")
	}
	r.co.Poll(context.Background())
	if got, _ := r.co.Get(o.ID); got.Status != StatusPending || r.reg.Get("abc") != nil {
		t.Fatalf("unpaid: %+v", got)
	}
	r.wallet.pay(o.PaymentHash)
	r.co.Poll(context.Background())
	got, _ := r.co.Get(o.ID)
	sp := r.reg.Get("abc")
	if got.Status != StatusPaid || !got.Applied || got.Outcome != OutcomeRegistered || sp == nil || sp.CreatedAt != 1762700000 || !strings.Contains(sp.Note, o.PaymentHash) {
		t.Fatalf("paid: %+v, speakeasy %+v", got, sp)
	}
	r.co.Poll(context.Background())
	r.co.Poll(context.Background())
	if l := r.ledger(); len(l) != 1 || l[0].PaymentHash != o.PaymentHash || l[0].Outcome != OutcomeRegistered {
		t.Fatalf("ledger %+v, want one line", l)
	}
	if _, err := r.create("abc", "5.6.7.8"); !errors.Is(err, ErrAlreadySpeakeasy) {
		t.Fatalf("a speakeasy offered again: %v", err)
	}
}

// TestCheckoutOneOpenInvoicePerRegionAndRequester: asking again returns
// the same invoice, also many times at once; another requester gets their
// own; caps per requester and in all; a region in another spelling, or not
// a region, is refused before the wallet is asked.
func TestCheckoutOneOpenInvoicePerRegionAndRequester(t *testing.T) {
	r := newCheckoutRig(t)
	r.wallet.delay = 20 * time.Millisecond
	var wg sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o, err := r.create("abc", "1.2.3.4")
			if err != nil {
				t.Error(err)
			}
			ids[i] = o.ID
		}(i)
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("one requester got several orders: %v", ids)
		}
	}
	if r.wallet.makes != 1 {
		t.Fatalf("%d invoices made, want 1", r.wallet.makes)
	}
	if o := r.mustCreate("abc", "5.6.7.8"); o.ID == ids[0] {
		t.Fatal("another requester got the first one's invoice")
	}
	r.mustCreate("abd", "1.2.3.4")
	r.mustCreate("abe", "1.2.3.4")
	if _, err := r.create("abf", "1.2.3.4"); !errors.Is(err, ErrTooManyInvoices) {
		t.Fatalf("a fourth region for one requester: %v", err)
	}
	r.mustCreate("abf", "9.9.9.9") // 5 open in all
	if _, err := r.create("ac0", "8.8.8.8"); !errors.Is(err, ErrTooManyInvoices) {
		t.Fatalf("a sixth open invoice: %v", err)
	}
	makes := r.wallet.makes
	for _, bad := range []string{"ABC", "0xabc", "abc/", "fiatjafs-speakeasy", ""} {
		if _, err := r.create(bad, "7.7.7.7"); !errors.Is(err, ErrNotRegion) {
			t.Errorf("region %q: %v", bad, err)
		}
	}
	if r.wallet.makes != makes {
		t.Fatal("the wallet was asked for a refused region")
	}
	// An open invoice with under a minute left is not handed out again.
	r = newCheckoutRig(t)
	first := r.mustCreate("abc", "1.2.3.4")
	r.now = r.now.Add(8*time.Minute + 30*time.Second)
	if o := r.mustCreate("abc", "1.2.3.4"); o.ID != first.ID {
		t.Fatal("an invoice with time left was not handed out again")
	}
	r.now = r.now.Add(time.Minute)
	if o := r.mustCreate("abc", "1.2.3.4"); o.ID == first.ID {
		t.Fatal("an invoice about to expire was handed out again")
	}
}

// TestCheckoutBindsThePaymentToItsRegion: a paid invoice that the wallet
// describes differently (another region's description, a lower amount,
// another hash) is never applied; it is held for the relay owner.
func TestCheckoutBindsThePaymentToItsRegion(t *testing.T) {
	for name, answer := range map[string]func(nwc.Invoice) nwc.Invoice{
		"description": func(i nwc.Invoice) nwc.Invoice { i.Description = "relay.example speakeasy fff"; return i },
		"amount":      func(i nwc.Invoice) nwc.Invoice { i.Amount = 1000; return i },
		"hash":        func(i nwc.Invoice) nwc.Invoice { i.PaymentHash = strings.Repeat("0", 64); return i },
		"invoice":     func(i nwc.Invoice) nwc.Invoice { i.Invoice = "lnbc1other"; return i },
	} {
		t.Run(name, func(t *testing.T) {
			r := newCheckoutRig(t)
			o := r.mustCreate("abc", "1.2.3.4")
			r.wallet.pay(o.PaymentHash)
			r.wallet.answer = answer
			r.co.Poll(context.Background())
			got, _ := r.co.Get(o.ID)
			if r.reg.Get("abc") != nil || !got.Applied || !strings.HasPrefix(got.Outcome, "held for the relay owner") || len(r.alerts) != 1 {
				t.Fatalf("%+v, alerts %v", got, r.alerts)
			}
			r.co.Poll(context.Background())
			if len(r.alerts) != 1 || len(r.ledger()) != 0 {
				t.Fatal("a held order was looked at again")
			}
		})
	}
}

// TestCheckoutSecondPaymentForARegion: two requesters pay for one region;
// the first makes it a speakeasy, the second has what it paid for.
func TestCheckoutSecondPaymentForARegion(t *testing.T) {
	r := newCheckoutRig(t)
	a := r.mustCreate("abc", "1.1.1.1")
	r.now = r.now.Add(time.Second)
	b := r.mustCreate("abc", "2.2.2.2")
	r.wallet.pay(a.PaymentHash)
	r.wallet.pay(b.PaymentHash)
	r.co.Poll(context.Background())
	ga, _ := r.co.Get(a.ID)
	gb, _ := r.co.Get(b.ID)
	if ga.Outcome != OutcomeRegistered || gb.Outcome != OutcomeAlready || len(r.ledger()) != 2 {
		t.Fatalf("%q %q, %d ledger lines", ga.Outcome, gb.Outcome, len(r.ledger()))
	}
}

// TestCheckoutSurvivesARestart: an order made before a restart and paid
// while the relay was down is applied after it; an unpaid one expires
// after its grace.
func TestCheckoutSurvivesARestart(t *testing.T) {
	r := newCheckoutRig(t)
	paid := r.mustCreate("abc", "1.1.1.1")
	unpaid := r.mustCreate("abd", "1.1.1.1")
	r.wallet.pay(paid.PaymentHash)
	r.open()
	r.co.Poll(context.Background())
	if got, _ := r.co.Get(paid.ID); !got.Applied || r.reg.Get("abc") == nil {
		t.Fatalf("after a restart: %+v", got)
	}
	r.now = r.now.Add(10*time.Minute + lookupGrace - time.Second)
	r.co.Poll(context.Background())
	if got, _ := r.co.Get(unpaid.ID); got.Status != StatusPending {
		t.Fatalf("expired inside its grace: %+v", got)
	}
	r.now = r.now.Add(2 * time.Second)
	r.co.Poll(context.Background())
	if got, _ := r.co.Get(unpaid.ID); got.Status != StatusExpired {
		t.Fatalf("not expired after its grace: %+v", got)
	}
	// A day later closed orders are dropped from the orders file; the
	// ledger keeps the paid one.
	r.now = r.now.Add(25 * time.Hour)
	r.co.Poll(context.Background())
	if _, ok := r.co.Get(paid.ID); ok {
		t.Fatal("a closed order kept past a day")
	}
	if len(r.ledger()) != 1 {
		t.Fatal("the ledger lost a payment")
	}
}

// TestCheckoutRetriesARegistryWrite: paid, but the registry cannot be
// written: the order stays paid and unapplied, and the next poll applies it.
func TestCheckoutRetriesARegistryWrite(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.wallet.pay(o.PaymentHash)
	r.failSave = true
	r.co.Poll(context.Background())
	if got, _ := r.co.Get(o.ID); got.Status != StatusPaid || got.Applied || len(r.alerts) == 0 {
		t.Fatalf("%+v %v", got, r.alerts)
	}
	r.failSave = false
	r.co.Poll(context.Background())
	if got, _ := r.co.Get(o.ID); !got.Applied || r.reg.Get("abc") == nil {
		t.Fatalf("not applied on the retry: %+v", got)
	}
}

// TestCheckoutRefusesABadInvoice: a wallet error, or an invoice that is not
// a BOLT 11 string (it goes into a lightning: link), makes no order.
func TestCheckoutRefusesABadInvoice(t *testing.T) {
	r := newCheckoutRig(t)
	r.wallet.makeErr = &nwc.Error{Code: "RESTRICTED", Message: "no"}
	if _, err := r.create("abc", "1.1.1.1"); err == nil {
		t.Fatal("an order without an invoice")
	}
	r.wallet.makeErr = nil
	r.wallet.bolt11 = "javascript:alert(1)//lnbc"
	if _, err := r.create("abc", "1.1.1.1"); err == nil {
		t.Fatal("an order with a bad invoice")
	}
	if len(r.co.orders) != 0 {
		t.Fatal("a failed order was kept")
	}
}

// TestInvoiceQR draws a scannable-size SVG.
func TestInvoiceQR(t *testing.T) {
	svg, err := InvoiceQR("lnbc10u1p" + strings.Repeat("q", 300))
	if err != nil || !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "M4 4h1v1h-1z") {
		t.Fatalf("%v %.80s", err, svg)
	}
}

// TestExampleConfigParses: the documented example parses, with payments off
// and the ruled price.
func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "speakeasies.example.yml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Payments.Enabled || c.Payments.SpeakeasySats != 1000 || c.Payments.NWCFile != "" {
		t.Fatalf("payments %+v", c.Payments)
	}
}
