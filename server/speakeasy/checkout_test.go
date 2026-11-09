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

// ── a fake wallet ────────────────────────────────────────────────────────

// fakeWallet is a wallet in memory that behaves as an NWC wallet does: it
// makes invoices that expire, says NOT_FOUND for invoices it does not hold
// (as a rotated connection does for another connection's), settles them
// when told, and can be made to answer with fields missing or wrong.
type fakeWallet struct {
	mu       sync.Mutex
	now      func() time.Time
	invoices map[string]*nwc.Invoice
	makes    int
	lookups  int
	sessions int
	delay    time.Duration
	makeErr  error
	// lookupErr fails every lookup; rotated makes every lookup NOT_FOUND
	// (a new connection that cannot see the old one's invoices).
	lookupErr error
	rotated   bool
	// failHashes fails the lookups of these invoices only.
	failHashes map[string]bool
	// shape changes what make_invoice answers; answer what lookup does.
	shape  func(*nwc.Invoice)
	answer func(nwc.Invoice) nwc.Invoice
}

func newFakeWallet(now func() time.Time) *fakeWallet {
	return &fakeWallet{now: now, invoices: map[string]*nwc.Invoice{}}
}

// hrp encodes msat as BOLT 11 writes an amount.
func hrp(msat int64) string {
	switch {
	case msat%100_000 == 0:
		return fmt.Sprintf("%du", msat/100_000)
	case msat%100 == 0:
		return fmt.Sprintf("%dn", msat/100)
	}
	return fmt.Sprintf("%dp", msat*10)
}

// bech32ish spells hex in BOLT 11's data characters (bech32 has no "1").
func bech32ish(h string) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	out := make([]byte, len(h))
	for i := range h {
		v := strings.IndexByte("0123456789abcdef", h[i])
		out[i] = charset[v]
	}
	return string(out)
}

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
	now := w.now()
	inv := &nwc.Invoice{Invoice: "lnbc" + hrp(msat) + "1p" + bech32ish(hash[:40]), Description: desc, PaymentHash: hash, Amount: msat,
		State: "pending", CreatedAt: now.Unix(), ExpiresAt: now.Add(expiry).Unix()}
	if w.shape != nil {
		w.shape(inv)
	}
	w.invoices[hash] = inv
	return *inv, nil
}

func (w *fakeWallet) LookupInvoice(ctx context.Context, hash string) (nwc.Invoice, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lookups++
	if w.lookupErr != nil {
		return nwc.Invoice{}, w.lookupErr
	}
	if w.failHashes[hash] {
		return nwc.Invoice{}, errors.New("timeout")
	}
	inv, ok := w.invoices[hash]
	if !ok || w.rotated {
		return nwc.Invoice{}, &nwc.Error{Code: "NOT_FOUND", Message: "no such invoice"}
	}
	out := *inv
	if out.SettledAt == 0 && w.now().Unix() > out.ExpiresAt {
		out.State = "expired"
	}
	if w.answer != nil {
		out = w.answer(out)
	}
	return out, nil
}

// pay settles an invoice now, as a payer's wallet would.
func (w *fakeWallet) pay(hash string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.invoices[hash].State = "settled"
	w.invoices[hash].SettledAt = w.now().Unix()
}

// sessionFake adds one-connection lookups, counting connections.
type sessionFake struct{ *fakeWallet }

type fakeSession struct{ w *fakeWallet }

func (s fakeSession) LookupInvoice(ctx context.Context, h string) (nwc.Invoice, error) {
	return s.w.LookupInvoice(ctx, h)
}
func (s fakeSession) Close() {}

func (f sessionFake) LookupSession(ctx context.Context) (nwc.Lookuper, error) {
	f.mu.Lock()
	f.sessions++
	f.mu.Unlock()
	return fakeSession{f.fakeWallet}, nil
}

// ── a rig ────────────────────────────────────────────────────────────────

type checkoutRig struct {
	t        *testing.T
	dir      string
	wallet   *fakeWallet
	reg      *Registry
	co       *Checkout
	now      time.Time
	failSave bool
	alerts   []string
	cfg      func(*CheckoutConfig)
	mu       sync.Mutex
}

func newCheckoutRig(t *testing.T) *checkoutRig {
	r := &checkoutRig{t: t, dir: t.TempDir(), now: time.Unix(1762700000, 0)}
	r.wallet = newFakeWallet(r.clock)
	reg, _, err := LoadRegistry(filepath.Join(r.dir, "registry.json"), ParseRegionPath, []uint{0, 1}, func(p string, d []byte, m os.FileMode) error {
		if r.failSave {
			return errors.New("disk full")
		}
		return WriteDurable(p, d, m)
	})
	if err != nil {
		t.Fatal(err)
	}
	r.reg = reg
	r.open()
	return r
}

func (r *checkoutRig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *checkoutRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

// open makes the checkout (again, as a restart would).
func (r *checkoutRig) open() {
	cfg := CheckoutConfig{
		Wallet: r.wallet, Registry: r.reg,
		OrdersPath: filepath.Join(r.dir, "orders.json"), LedgerPath: filepath.Join(r.dir, "payments.jsonl"),
		Write: WriteDurable, Host: "relay.example", SpeakeasySats: DefaultSpeakeasySats,
		Expiry: 10 * time.Minute, Poll: time.Hour,
		MaxPending: 256, MaxPerRequester: 3, MaxPerNetwork: 6, MaxPerRegion: 2,
		Now:   r.clock,
		Alert: func(msg string, args ...any) { r.alerts = append(r.alerts, msg) },
	}
	if r.cfg != nil {
		r.cfg(&cfg)
	}
	co, err := NewCheckout(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.co = co
}

func (r *checkoutRig) create(region, who string) (Order, error) {
	return r.co.Create(context.Background(), OrderRequest{Kind: OrderSpeakeasy, Region: region, Requester: Requester(who), Network: Network(who)})
}

func (r *checkoutRig) mustCreate(region, who string) Order {
	r.t.Helper()
	o, err := r.create(region, who)
	if err != nil {
		r.t.Fatal(err)
	}
	return o
}

func (r *checkoutRig) poll() { r.co.Poll(context.Background()) }

func (r *checkoutRig) get(id string) Order {
	o, _ := r.co.Get(id)
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

// ── creating ─────────────────────────────────────────────────────────────

// TestCheckoutCreatesAndApplies: an invoice for 1,000 sats marked with the
// region; nothing happens until it is paid; once paid, the region is a
// speakeasy carrying the payment hash, the ledger has one line, and later
// polls change nothing.
func TestCheckoutCreatesAndApplies(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.2.3.4")
	if o.AmountSats != 1000 || o.Status != StatusPending || o.Description != "relay.example speakeasy abc" ||
		o.ExpiresAt != r.now.Unix()+600 || o.WatchUntil != r.now.Unix()+600+120 {
		t.Fatalf("order %+v", o)
	}
	if strings.Contains(o.Requester, "1.2.3.4") || strings.Contains(o.Network, "1.2.3") {
		t.Fatal("the order keeps the address itself")
	}
	r.poll()
	if got := r.get(o.ID); got.Status != StatusPending || r.reg.Get("abc") != nil {
		t.Fatalf("unpaid: %+v", got)
	}
	r.wallet.pay(o.PaymentHash)
	r.poll()
	got := r.get(o.ID)
	sp := r.reg.Get("abc")
	if got.Status != StatusPaid || !got.Applied || got.Outcome != OutcomeRegistered || sp == nil || sp.PaymentHash != o.PaymentHash {
		t.Fatalf("paid: %+v, speakeasy %+v", got, sp)
	}
	r.poll()
	r.poll()
	if l := r.ledger(); len(l) != 1 || l[0].PaymentHash != o.PaymentHash || l[0].Outcome != OutcomeRegistered {
		t.Fatalf("ledger %+v, want one line", l)
	}
	if _, err := r.create("abc", "5.6.7.8"); !errors.Is(err, ErrAlreadySpeakeasy) {
		t.Fatalf("a speakeasy offered again: %v", err)
	}
}

// TestCheckoutRefusesUnusableInvoices: what make_invoice answers must be a
// BOLT 11 invoice encoding exactly the price, the wallet must state that
// amount and a payment hash, and the invoice must expire, no later than
// asked and not within a minute. Each refusal makes no order.
func TestCheckoutRefusesUnusableInvoices(t *testing.T) {
	for name, shape := range map[string]func(*nwc.Invoice){
		"not bolt11":         func(i *nwc.Invoice) { i.Invoice = "javascript:alert(1)//lnbc" },
		"encodes 1 sat":      func(i *nwc.Invoice) { i.Invoice = "lnbc10n1p" + strings.Repeat("q", 40) },
		"encodes no amount":  func(i *nwc.Invoice) { i.Invoice = "lnbc1p" + strings.Repeat("q", 40) },
		"amount missing":     func(i *nwc.Invoice) { i.Amount = 0 },
		"amount wrong":       func(i *nwc.Invoice) { i.Amount = 999_000 },
		"hash missing":       func(i *nwc.Invoice) { i.PaymentHash = "" },
		"description":        func(i *nwc.Invoice) { i.Description = "relay.example speakeasy fff" },
		"expiry missing":     func(i *nwc.Invoice) { i.ExpiresAt = 0 },
		"expires later":      func(i *nwc.Invoice) { i.ExpiresAt += 3600 },
		"expires in seconds": func(i *nwc.Invoice) { i.ExpiresAt = i.CreatedAt + 30 },
	} {
		t.Run(name, func(t *testing.T) {
			r := newCheckoutRig(t)
			r.wallet.shape = shape
			if _, err := r.create("abc", "1.1.1.1"); err == nil {
				t.Fatal("an order with an unusable invoice")
			}
			if len(r.co.Orders()) != 0 || len(r.alerts) != 1 {
				t.Fatalf("%d orders, alerts %v", len(r.co.Orders()), r.alerts)
			}
		})
	}
	// A shorter expiry than asked is fine: it is the one shown and watched.
	r := newCheckoutRig(t)
	r.wallet.shape = func(i *nwc.Invoice) { i.ExpiresAt = i.CreatedAt + 300 }
	o := r.mustCreate("abc", "1.1.1.1")
	if o.ExpiresAt != r.now.Unix()+300 || o.WatchUntil != r.now.Unix()+600+120 {
		t.Fatalf("expiry %d watch %d", o.ExpiresAt-r.now.Unix(), o.WatchUntil-r.now.Unix())
	}
	r = newCheckoutRig(t)
	r.wallet.makeErr = &nwc.Error{Code: "RESTRICTED", Message: "no"}
	if _, err := r.create("abc", "1.1.1.1"); err == nil {
		t.Fatal("an order without an invoice")
	}
}

// TestBolt11Amounts reads the amount from the human-readable part.
func TestBolt11Amounts(t *testing.T) {
	for inv, want := range map[string]int64{
		"lnbc10u1pabc":   1_000_000,
		"lnbc80u1pabc":   8_000_000,
		"lnbc2500u1pxyz": 250_000_000,
		"lnbc1m1pxyz":    100_000_000,
		"lnbc20n1pxyz":   2_000,
		"lnbc10p1pxyz":   1,
		"lnbc1p1pxyz":    0, // a pico amount that is not whole msat
		"lntb10u1pxyz":   1_000_000,
		"lnbcrt10u1pxy":  1_000_000,
		"lnbc1pxyz":      0, // no amount
		"lnbc01u1pxyz":   0, // a leading zero
		"lnbc10x1pxyz":   0,
		"LNBC10U1PABC":   1_000_000,
		"lnbc2pxyz":      0,
	} {
		if got := bolt11Msat(inv); got != want {
			t.Errorf("%s: %d, want %d", inv, got, want)
		}
	}
}

// TestCheckoutOneOpenInvoicePerRegionAndRequester: asking again returns the
// same invoice, also many times at once; caps per requester (/64), per
// network (/48 or /24), per region and in all; a region in another
// spelling, or not a region, is refused before the wallet is asked.
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
	r.wallet.delay = 0
	// Per region: 2 across requesters.
	r.mustCreate("abc", "5.6.7.8")
	if _, err := r.create("abc", "9.9.9.9"); !errors.Is(err, ErrRegionBusy) {
		t.Fatalf("a third open invoice for one region: %v", err)
	}
	// Per requester (an IPv6 /64): 3.
	for _, region := range []string{"ab1", "ab2", "ab3"} {
		r.mustCreate(region, "2001:db8:1:1::"+region[2:])
	}
	if _, err := r.create("ab4", "2001:db8:1:1::ffff"); !errors.Is(err, ErrTooManyInvoices) {
		t.Fatalf("a fourth for one /64: %v", err)
	}
	// Per network (a /48): 6.
	for i, region := range []string{"ac1", "ac2", "ac3"} {
		r.mustCreate(region, fmt.Sprintf("2001:db8:1:%x::1", 2+i))
	}
	if _, err := r.create("ac4", "2001:db8:1:9::1"); !errors.Is(err, ErrTooManyInvoices) {
		t.Fatalf("a seventh for one /48: %v", err)
	}
	if _, err := r.create("ac4", "2001:db8:2::1"); err != nil {
		t.Fatalf("another /48: %v", err)
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
	// In all.
	r2 := newCheckoutRig(t)
	r2.cfg = func(c *CheckoutConfig) { c.MaxPending = 2 }
	r2.open()
	r2.mustCreate("abc", "1.1.1.1")
	r2.mustCreate("abd", "2.2.2.2")
	if _, err := r2.create("abe", "3.3.3.3"); !errors.Is(err, ErrTooManyInvoices) {
		t.Fatalf("past the total: %v", err)
	}
	// An invoice that can no longer be paid holds no slot.
	r2.advance(11 * time.Minute)
	if _, err := r2.create("abe", "3.3.3.3"); err != nil {
		t.Fatalf("after the open ones stopped being payable: %v", err)
	}
	// An open invoice with under a minute left is not handed out again.
	r3 := newCheckoutRig(t)
	first := r3.mustCreate("abc", "1.2.3.4")
	r3.advance(8*time.Minute + 30*time.Second)
	if o := r3.mustCreate("abc", "1.2.3.4"); o.ID != first.ID {
		t.Fatal("an invoice with time left was not handed out again")
	}
	r3.advance(time.Minute)
	if o := r3.mustCreate("abc", "1.2.3.4"); o.ID == first.ID {
		t.Fatal("an invoice about to expire was handed out again")
	}
}

// TestCheckoutCreateRespectsTheContext: a request waiting for another's
// make_invoice gives up when its context ends.
func TestCheckoutCreateRespectsTheContext(t *testing.T) {
	r := newCheckoutRig(t)
	r.wallet.delay = 300 * time.Millisecond
	go r.create("abc", "1.1.1.1")
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := r.co.Create(ctx, OrderRequest{Kind: OrderSpeakeasy, Region: "abd", Requester: "x", Network: "y"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the deadline", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("the waiting request outlived its context")
	}
}

// TestRequesterAndNetworkKeys: IPv6 by /64 (requester) and /48 (network),
// IPv4 by address and /24.
func TestRequesterAndNetworkKeys(t *testing.T) {
	if Requester("2001:db8:1:2::1") != Requester("2001:db8:1:2:ffff::9") {
		t.Error("two addresses in one /64 are different requesters")
	}
	if Requester("2001:db8:1:2::1") == Requester("2001:db8:1:3::1") || Requester("1.2.3.4") == Requester("1.2.3.5") {
		t.Error("different requesters are one")
	}
	if Network("2001:db8:1:2::1") != Network("2001:db8:1:ff::1") || Network("1.2.3.4") != Network("1.2.3.200") {
		t.Error("one network counted as two")
	}
	if Network("2001:db8:1::1") == Network("2001:db8:2::1") || Network("1.2.3.4") == Network("1.2.4.4") {
		t.Error("two networks counted as one")
	}
}

// ── paying ───────────────────────────────────────────────────────────────

// TestCheckoutBindsThePaymentToItsRegion: a paid invoice the wallet
// describes differently, or without its payment hash or amount, is never
// applied: it is held for the relay owner, alerted and ledgered.
func TestCheckoutBindsThePaymentToItsRegion(t *testing.T) {
	for name, answer := range map[string]func(nwc.Invoice) nwc.Invoice{
		"description":  func(i nwc.Invoice) nwc.Invoice { i.Description = "relay.example speakeasy fff"; return i },
		"amount lower": func(i nwc.Invoice) nwc.Invoice { i.Amount = 1000; return i },
		"no amount":    func(i nwc.Invoice) nwc.Invoice { i.Amount = 0; return i },
		"hash":         func(i nwc.Invoice) nwc.Invoice { i.PaymentHash = strings.Repeat("0", 64); return i },
		"no hash":      func(i nwc.Invoice) nwc.Invoice { i.PaymentHash = ""; return i },
		"invoice":      func(i nwc.Invoice) nwc.Invoice { i.Invoice = "lnbc1other"; return i },
	} {
		t.Run(name, func(t *testing.T) {
			r := newCheckoutRig(t)
			o := r.mustCreate("abc", "1.2.3.4")
			r.wallet.pay(o.PaymentHash)
			r.wallet.answer = answer
			r.poll()
			got := r.get(o.ID)
			if r.reg.Get("abc") != nil || !got.Applied || !strings.HasPrefix(got.Outcome, OutcomeHeld) || !NeedsOwner(got.Outcome) || len(r.alerts) != 1 {
				t.Fatalf("%+v, alerts %v", got, r.alerts)
			}
			r.poll()
			if len(r.alerts) != 1 {
				t.Fatal("a held order was looked at again")
			}
			if l := r.ledger(); len(l) != 1 || !strings.HasPrefix(l[0].Outcome, OutcomeHeld) {
				t.Fatalf("a held payment is not in the ledger: %+v", l)
			}
		})
	}
}

// TestCheckoutSecondPaymentForARegion: two payers for one region; the first
// makes it a speakeasy; the second bought nothing: a refund is owed.
func TestCheckoutSecondPaymentForARegion(t *testing.T) {
	r := newCheckoutRig(t)
	a := r.mustCreate("abc", "1.1.1.1")
	r.advance(time.Second)
	b := r.mustCreate("abc", "2.2.2.2")
	r.wallet.pay(a.PaymentHash)
	r.wallet.pay(b.PaymentHash)
	r.poll()
	ga, gb := r.get(a.ID), r.get(b.ID)
	if ga.Outcome != OutcomeRegistered || gb.Outcome != OutcomeAlready || !NeedsOwner(gb.Outcome) || len(r.ledger()) != 2 || len(r.alerts) != 1 {
		t.Fatalf("%q %q, %d ledger lines, alerts %v", ga.Outcome, gb.Outcome, len(r.ledger()), r.alerts)
	}
}

// TestCheckoutCrashWindow: the registry entry was written but a crash kept
// the order from being marked applied. After the restart the entry carries
// this order's payment hash, so the outcome is "registered", not a refund.
func TestCheckoutCrashWindow(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.wallet.pay(o.PaymentHash)
	// The state after the crash: the order marked paid, the entry written,
	// nothing after.
	r.co.update(o.ID, func(x *Order) { x.Status, x.SettledAt = StatusPaid, r.now.Unix() })
	if _, err := r.reg.Add(Entry{ID: "abc", CreatedAt: r.now.Unix(), PaymentHash: o.PaymentHash}); err != nil {
		t.Fatal(err)
	}
	r.open()
	r.poll()
	if got := r.get(o.ID); got.Outcome != OutcomeRegistered || len(r.alerts) != 0 {
		t.Fatalf("after the crash: %+v, alerts %v", got, r.alerts)
	}
}

// TestCheckoutSurvivesARestart: an order made before a restart and paid
// while the relay was down is applied after it.
func TestCheckoutSurvivesARestart(t *testing.T) {
	r := newCheckoutRig(t)
	paid := r.mustCreate("abc", "1.1.1.1")
	r.wallet.pay(paid.PaymentHash)
	r.open()
	r.poll()
	if got := r.get(paid.ID); !got.Applied || r.reg.Get("abc") == nil {
		t.Fatalf("after a restart: %+v", got)
	}
}

// ── expiry, late settles, failed lookups ─────────────────────────────────

// TestCheckoutWatchesUntilTheLaterExpiry: an invoice is watched at every
// poll until the later of the wallet's expiry and the relay's, plus the
// grace; a payment that settles inside that window is applied; after it,
// an unpaid answer closes the order.
func TestCheckoutWatchesUntilTheLaterExpiry(t *testing.T) {
	r := newCheckoutRig(t)
	r.wallet.shape = func(i *nwc.Invoice) { i.ExpiresAt = i.CreatedAt + 300 } // the wallet's is sooner
	late := r.mustCreate("abc", "1.1.1.1")
	idle := r.mustCreate("abd", "1.1.1.1")
	r.advance(10*time.Minute + 2*time.Minute - time.Second) // inside the watch
	r.wallet.pay(late.PaymentHash)                          // a last-moment settle
	r.poll()
	if got := r.get(late.ID); !got.Applied {
		t.Fatalf("a payment inside the watch was not applied: %+v", got)
	}
	if got := r.get(idle.ID); got.Status != StatusPending {
		t.Fatalf("closed inside its watch: %+v", got)
	}
	r.advance(2 * time.Second)
	r.poll()
	if got := r.get(idle.ID); got.Status != StatusExpired {
		t.Fatalf("not closed after its watch: %+v", got)
	}
}

// TestCheckoutLateSettleAfterExpiry: a payment that settles after the order
// was closed is found by the last lookup before the order is dropped, and
// applied, with an alert; an unpaid one is dropped then.
func TestCheckoutLateSettleAfterExpiry(t *testing.T) {
	r := newCheckoutRig(t)
	paid := r.mustCreate("abc", "1.1.1.1")
	unpaid := r.mustCreate("abd", "1.1.1.1")
	r.advance(13 * time.Minute)
	r.poll()
	if r.get(paid.ID).Status != StatusExpired || r.get(unpaid.ID).Status != StatusExpired {
		t.Fatal("not expired")
	}
	r.wallet.pay(paid.PaymentHash) // the wallet settles it after all
	r.advance(23 * time.Hour)
	r.poll()
	if r.get(paid.ID).Status != StatusExpired || len(r.alerts) != 0 {
		t.Fatal("looked at before the last lookup was due")
	}
	r.advance(2 * time.Hour)
	r.poll()
	got := r.get(paid.ID)
	if got.Status != StatusPaid || !got.Applied || got.Outcome != OutcomeRegistered || r.reg.Get("abc") == nil || len(r.alerts) != 1 {
		t.Fatalf("the late payment: %+v, alerts %v", got, r.alerts)
	}
	if _, ok := r.co.Get(unpaid.ID); ok {
		t.Fatal("an unpaid expired order was kept after its last lookup")
	}
}

// TestCheckoutNotFoundAfterRotation: after the connection is rotated, the
// wallet says NOT_FOUND for the old invoices. That is not "unpaid": the
// order stays open, one alert says so, it holds no slot, and sales go on
// (the wallet answers, so lookups work). A wallet that cannot be reached
// is different: sales pause, with one alert for the outage. Either way,
// when the wallet answers again, the payment is applied.
func TestCheckoutNotFoundAfterRotation(t *testing.T) {
	for name, c := range map[string]struct {
		fail   func(*fakeWallet)
		paused bool
	}{
		"NOT_FOUND":   {func(w *fakeWallet) { w.rotated = true }, false},
		"unreachable": {func(w *fakeWallet) { w.lookupErr = errors.New("relay down") }, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newCheckoutRig(t)
			o := r.mustCreate("abc", "1.1.1.1")
			r.wallet.pay(o.PaymentHash)
			c.fail(r.wallet)
			r.advance(time.Hour)
			r.poll()
			r.advance(10 * time.Minute)
			r.poll()
			if got := r.get(o.ID); got.Status != StatusPending || !got.LookupFailing || len(r.alerts) != 1 {
				t.Fatalf("after failed lookups: %+v, alerts %v", got, r.alerts)
			}
			before := len(r.alerts)
			r.open() // across a restart too (a new process may alert once more,
			r.poll() // after its own two bad passes)
			r.poll()
			if got := r.get(o.ID); got.Status != StatusPending || len(r.alerts) > before+1 {
				t.Fatalf("after a restart: %+v, alerts %v", got, r.alerts)
			}
			_, err := r.create("abd", "1.1.1.1")
			if c.paused != errors.Is(err, ErrPaused) || !c.paused && err != nil {
				t.Fatalf("selling while %s: %v", name, err)
			}
			r.wallet.rotated, r.wallet.lookupErr = false, nil
			r.advance(10 * time.Minute)
			r.poll()
			if got := r.get(o.ID); !got.Applied || r.reg.Get("abc") == nil {
				t.Fatalf("the late answer was not applied: %+v", got)
			}
			if _, err := r.create("abe", "1.1.1.1"); err != nil {
				t.Fatalf("sales did not resume: %v", err)
			}
		})
	}
}

// TestCheckoutGivesUpOnlyAfterAWeek: an order the wallet never answers
// about is ledgered as unknown, with an alert, only GiveUp after its watch.
func TestCheckoutGivesUpOnlyAfterAWeek(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.wallet.rotated = true
	r.advance(6 * 24 * time.Hour)
	r.poll()
	if got := r.get(o.ID); got.Status != StatusPending {
		t.Fatalf("gave up early: %+v", got)
	}
	r.advance(25 * time.Hour)
	r.poll()
	got := r.get(o.ID)
	if got.Status != StatusUnknown || len(r.ledger()) != 1 || len(r.alerts) != 2 {
		t.Fatalf("after a week: %+v, %d ledger lines, alerts %v", got, len(r.ledger()), r.alerts)
	}
}

// TestCheckoutShutdownIsNotAFailure: a lookup cut short by shutdown counts
// nothing and alerts nothing.
func TestCheckoutShutdownIsNotAFailure(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.advance(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	r.wallet.lookupErr = context.Canceled
	cancel()
	r.co.Poll(ctx)
	r.co.lookup(ctx, &lookups{c: r.co}, o)
	if got := r.get(o.ID); got.LookupFailing || len(r.alerts) != 0 {
		t.Fatalf("shutdown counted as a failure: %+v %v", got, r.alerts)
	}
}

// TestCheckoutUsesOneConnectionPerPoll: a wallet that offers sessions is
// asked about every open invoice on one connection per poll.
func TestCheckoutUsesOneConnectionPerPoll(t *testing.T) {
	r := newCheckoutRig(t)
	sw := sessionFake{r.wallet}
	r.cfg = func(c *CheckoutConfig) { c.Wallet = sw }
	r.open()
	for _, region := range []string{"abc", "abd", "abe"} {
		r.mustCreate(region, region)
	}
	r.poll()
	r.poll()
	if r.wallet.sessions != 2 || r.wallet.lookups != 6 {
		t.Fatalf("%d connections for %d lookups, want 2 for 6", r.wallet.sessions, r.wallet.lookups)
	}
}

// TestCheckoutRetriesARegistryWrite: paid, but the registry cannot be
// written: the order stays paid and unapplied, the region is not sold
// again, and the next poll applies it.
func TestCheckoutRetriesARegistryWrite(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.wallet.pay(o.PaymentHash)
	r.failSave = true
	r.poll()
	if got := r.get(o.ID); got.Status != StatusPaid || got.Applied || len(r.alerts) == 0 {
		t.Fatalf("%+v %v", got, r.alerts)
	}
	if _, err := r.create("abc", "9.9.9.9"); !errors.Is(err, ErrAlreadySpeakeasy) {
		t.Fatalf("a region being applied was offered again: %v", err)
	}
	r.failSave = false
	r.poll()
	if got := r.get(o.ID); !got.Applied || r.reg.Get("abc") == nil {
		t.Fatalf("not applied on the retry: %+v", got)
	}
}

// TestLedgerListsWhatTheOwnerOwes: Ledger reads back every line.
func TestLedgerListsWhatTheOwnerOwes(t *testing.T) {
	r := newCheckoutRig(t)
	a := r.mustCreate("abc", "1.1.1.1")
	b := r.mustCreate("abc", "2.2.2.2")
	r.wallet.pay(a.PaymentHash)
	r.wallet.pay(b.PaymentHash)
	r.poll()
	l, err := r.co.Ledger()
	if err != nil || len(l) != 2 {
		t.Fatalf("%v %v", l, err)
	}
	owed := 0
	for _, o := range l {
		if NeedsOwner(o.Outcome) {
			owed++
		}
	}
	if owed != 1 {
		t.Fatalf("%d owed, want 1", owed)
	}
}

// TestWriteDurable replaces a file whole and leaves no temp file.
func TestWriteDurable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	for _, data := range []string{"one", "two, longer"} {
		if err := WriteDurable(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(p); string(got) != data {
			t.Fatalf("%q", got)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("%d files left", len(ents))
	}
	if err := WriteDurable(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Fatal("wrote into a missing directory")
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
// and the ruled price and caps.
func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "speakeasies.example.yml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Payments
	if p.Enabled || p.SpeakeasySats != 1000 || p.NWCFile != "" || p.MaxPendingInvoices != 256 || p.MaxPendingPerRequester != 3 ||
		p.MaxPendingPerNetwork != 6 || p.MaxPendingPerRegion != 2 {
		t.Fatalf("payments %+v", p)
	}
}

// TestCheckoutFinalLookupMustBeAnswered: an expired order whose last lookup
// fails is kept (and asked again), and dropped only GiveUp after its watch,
// ledgered as unknown with an alert.
func TestCheckoutFinalLookupMustBeAnswered(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.advance(13 * time.Minute)
	r.poll()
	if r.get(o.ID).Status != StatusExpired {
		t.Fatal("not expired")
	}
	r.wallet.rotated = true
	r.advance(25 * time.Hour)
	r.poll()
	if _, ok := r.co.Get(o.ID); !ok {
		t.Fatal("an expired order was dropped without a last answer")
	}
	r.advance(6 * 24 * time.Hour)
	r.poll()
	if _, ok := r.co.Get(o.ID); ok || len(r.alerts) != 1 {
		t.Fatalf("kept past GiveUp, alerts %v", r.alerts)
	}
	if l := r.ledger(); len(l) != 1 || !strings.HasPrefix(l[0].Outcome, "unknown:") {
		t.Fatalf("ledger %+v", l)
	}
}

// ── B3: sales pause while lookups fail ───────────────────────────────────

// TestSalesPauseWhileLookupsAreRefused models the likely misconfiguration,
// a connection made without lookup_invoice (RESTRICTED), for a day of
// 5-minute polls: sales pause at the first refused lookup, one alert names
// the configuration error, no further invoice is sold, and the orders file
// is written at most once per pass. Fixed, sales resume.
func TestSalesPauseWhileLookupsAreRefused(t *testing.T) {
	r := newCheckoutRig(t)
	writes := 0
	r.cfg = func(c *CheckoutConfig) {
		c.Write = func(p string, d []byte, m os.FileMode) error { writes++; return WriteDurable(p, d, m) }
	}
	r.open()
	r.mustCreate("abc", "1.1.1.1")
	r.wallet.lookupErr = &nwc.Error{Code: "RESTRICTED", Message: "not allowed"}
	writes = 0
	makes := r.wallet.makes
	for i := 0; i < 288; i++ {
		r.poll()
		if _, err := r.create(fmt.Sprintf("a%02x", i%250), fmt.Sprintf("10.0.%d.1", i%250)); !errors.Is(err, ErrPaused) {
			t.Fatalf("poll %d: sold while lookups are refused: %v", i, err)
		}
		r.advance(5 * time.Minute)
	}
	if r.wallet.makes != makes {
		t.Fatalf("%d invoices sold while paused", r.wallet.makes-makes)
	}
	if len(r.alerts) != 1 || !strings.Contains(r.alerts[0], "configuration error") {
		t.Fatalf("alerts over a day: %v", r.alerts)
	}
	if writes > 288 {
		t.Fatalf("%d writes of the orders file for 288 passes", writes)
	}
	if !strings.HasPrefix(r.co.State(), "paused: RESTRICTED") {
		t.Fatalf("state %q", r.co.State())
	}
	r.wallet.lookupErr = nil
	r.poll()
	if _, err := r.create("fff", "9.9.9.9"); err != nil || r.co.State() != "" {
		t.Fatalf("sales did not resume: %v %q", err, r.co.State())
	}
}

// TestPauseEndsOnAProbe: paused with no open order to look up, a pass asks
// about an invoice nobody made; NOT_FOUND shows lookups work, so sales
// resume. A probe that fails keeps them paused.
func TestPauseEndsOnAProbe(t *testing.T) {
	r := newCheckoutRig(t)
	r.co.mu.Lock()
	r.co.paused = "relay down"
	r.co.mu.Unlock()
	r.wallet.lookupErr = errors.New("still down")
	r.poll()
	if r.co.Selling() {
		t.Fatal("resumed on a failed probe")
	}
	r.wallet.lookupErr = nil
	lookups := r.wallet.lookups
	r.poll()
	if !r.co.Selling() || r.wallet.lookups != lookups+1 {
		t.Fatalf("selling %v after %d lookups", r.co.Selling(), r.wallet.lookups-lookups)
	}
	r.poll()
	if r.wallet.lookups != lookups+1 {
		t.Fatal("probed while healthy with nothing to look up")
	}
}

// TestLingeringOrdersCapPausesSales: at MaxLingering orders that can no
// longer be paid but wait for an answer, sales pause, though the wallet
// answers; and the pass's newly unverifiable orders make one alert.
func TestLingeringOrdersCapPausesSales(t *testing.T) {
	r := newCheckoutRig(t)
	r.cfg = func(c *CheckoutConfig) { c.MaxLingering = 3 }
	r.open()
	for i, region := range []string{"abc", "abd", "abe"} {
		r.mustCreate(region, fmt.Sprintf("10.%d.0.1", i))
	}
	r.wallet.rotated = true
	r.advance(15 * time.Minute)
	r.poll()
	if len(r.alerts) != 1 {
		t.Fatalf("alerts for three unverifiable orders: %v", r.alerts)
	}
	if _, err := r.create("fff", "9.9.9.9"); !errors.Is(err, ErrPaused) || !strings.Contains(r.co.State(), "too many old invoices") {
		t.Fatalf("at the lingering cap: %v %q", err, r.co.State())
	}
}

// TestSelfCheck: with RequireSelfCheck, nothing is sold until a 1-sat
// invoice could be made and looked up; a refused lookup keeps payments off
// with a clear reason.
func TestSelfCheck(t *testing.T) {
	r := newCheckoutRig(t)
	r.cfg = func(c *CheckoutConfig) { c.RequireSelfCheck = true }
	r.open()
	if _, err := r.create("abc", "1.1.1.1"); !errors.Is(err, ErrPaused) {
		t.Fatalf("sold before the self-check: %v", err)
	}
	if err := r.co.SelfCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inv := r.wallet.invoices; len(inv) != 1 {
		t.Fatalf("%d invoices made by the self-check", len(inv))
	}
	r.mustCreate("abc", "1.1.1.1")

	for code, want := range map[string]string{"RESTRICTED": "refuses lookup_invoice (RESTRICTED)", "NOT_IMPLEMENTED": "refuses lookup_invoice (NOT_IMPLEMENTED)"} {
		r2 := newCheckoutRig(t)
		r2.cfg = func(c *CheckoutConfig) { c.RequireSelfCheck = true }
		r2.open()
		r2.wallet.lookupErr = &nwc.Error{Code: code}
		err := r2.co.SelfCheck(context.Background())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", code, err)
		}
		if _, err := r2.create("abc", "1.1.1.1"); !errors.Is(err, ErrPaymentsOff) {
			t.Fatalf("%s: sold after a failed self-check: %v", code, err)
		}
	}
	r3 := newCheckoutRig(t)
	r3.cfg = func(c *CheckoutConfig) { c.RequireSelfCheck = true }
	r3.open()
	r3.wallet.makeErr = &nwc.Error{Code: "RESTRICTED"}
	if err := r3.co.SelfCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "refuses make_invoice") {
		t.Fatalf("make refused: %v", err)
	}
}

// TestOneOpenInvoicePerNetworkPerRegion (ruling): per region, at most one
// open invoice per network, and the cap of 2 counts distinct networks, so
// one address cannot block a region for free.
func TestOneOpenInvoicePerNetworkPerRegion(t *testing.T) {
	r := newCheckoutRig(t)
	r.mustCreate("abc", "10.1.1.1")
	if _, err := r.create("abc", "10.1.1.2"); !errors.Is(err, ErrNetworkHasOrder) {
		t.Fatalf("a second requester in the same /24: %v", err)
	}
	if _, err := r.create("abc", "2001:db8:1:1::1"); err != nil {
		t.Fatalf("another network: %v", err)
	}
	if _, err := r.create("abc", "2001:db8:1:2::1"); !errors.Is(err, ErrNetworkHasOrder) {
		t.Fatalf("a second /64 in the same /48: %v", err)
	}
	if _, err := r.create("abc", "10.9.9.9"); !errors.Is(err, ErrRegionBusy) {
		t.Fatalf("a third network: %v", err)
	}
	if _, err := r.create("abd", "10.1.1.2"); err != nil {
		t.Fatalf("another region from the first network: %v", err)
	}
}

// TestOverpaymentIsAccepted: BOLT 11 lets a payer pay more; the lookup
// accepts at least the price (creation still requires the exact amount).
func TestOverpaymentIsAccepted(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	r.wallet.pay(o.PaymentHash)
	r.wallet.answer = func(i nwc.Invoice) nwc.Invoice { i.Amount = 1_500_000; return i }
	r.poll()
	if got := r.get(o.ID); got.Outcome != OutcomeRegistered {
		t.Fatalf("an overpayment: %+v", got)
	}
}

// TestResolveAPayment: the owner marks a refund paid; the owner's list no
// longer shows it, the ledger keeps it, and it cannot be resolved twice.
func TestResolveAPayment(t *testing.T) {
	r := newCheckoutRig(t)
	r.cfg = func(c *CheckoutConfig) { c.ResolvedPath = filepath.Join(r.dir, "resolved.jsonl") }
	r.open()
	a := r.mustCreate("abc", "1.1.1.1")
	r.advance(time.Second)
	b := r.mustCreate("abc", "2.2.2.2")
	r.wallet.pay(a.PaymentHash)
	r.wallet.pay(b.PaymentHash)
	r.poll()
	open, _ := r.co.NeedsOwnerOpen()
	if len(open) != 1 || open[0].PaymentHash != b.PaymentHash {
		t.Fatalf("open %+v", open)
	}
	if _, err := r.co.Resolve(open[0].LineID, "refunded by hand"); err != nil {
		t.Fatal(err)
	}
	if open, _ := r.co.NeedsOwnerOpen(); len(open) != 0 {
		t.Fatalf("still listed: %+v", open)
	}
	if len(r.ledger()) != 2 {
		t.Fatal("the ledger lost history")
	}
	for _, id := range []string{open[0].LineID, b.PaymentHash, strings.Repeat("0", 32)} {
		if _, err := r.co.Resolve(id, "again"); !errors.Is(err, ErrNothingToResolve) {
			t.Errorf("resolve %s: %v", id[:8], err)
		}
	}
}

// TestOnePassWritesTheOrdersOnce: however many orders change in one poll
// pass (here 40 expire), the orders file is written once for it.
func TestOnePassWritesTheOrdersOnce(t *testing.T) {
	r := newCheckoutRig(t)
	writes := 0
	r.cfg = func(c *CheckoutConfig) {
		c.Write = func(p string, d []byte, m os.FileMode) error { writes++; return WriteDurable(p, d, m) }
	}
	r.open()
	for i := 0; i < 40; i++ {
		r.mustCreate(fmt.Sprintf("a%02x", i), fmt.Sprintf("10.%d.0.1", i))
	}
	r.advance(13 * time.Minute)
	writes = 0
	r.poll()
	if n := len(r.co.Orders()); writes != 1 || n != 40 || r.get(r.co.Orders()[0].ID).Status != StatusExpired {
		t.Fatalf("%d writes for a pass that closed %d orders", writes, n)
	}
}

// ── the third payments review ────────────────────────────────────────────

// TestSelfCheckRetries (the reviewer's probe): a self-check that times out
// at boot leaves payments waiting, not off; it is retried with backoff and
// sales start once the wallet answers. The waiting state is logged once.
func TestSelfCheckRetries(t *testing.T) {
	r := newCheckoutRig(t)
	r.cfg = func(c *CheckoutConfig) {
		c.RequireSelfCheck, c.SelfCheckRetry, c.SelfCheckRetryCap = true, 5*time.Millisecond, 20*time.Millisecond
	}
	r.open()
	r.wallet.mu.Lock()
	r.wallet.makeErr = errors.New("timeout")
	r.wallet.mu.Unlock()
	var mu sync.Mutex
	var infos, alerts []string
	done := make(chan struct{})
	go func() {
		r.co.RunSelfCheck(context.Background(),
			func(m string, _ ...any) { mu.Lock(); infos = append(infos, m); mu.Unlock() },
			func(m string, _ ...any) { mu.Lock(); alerts = append(alerts, m); mu.Unlock() })
		close(done)
	}()
	time.Sleep(60 * time.Millisecond)
	if _, err := r.create("abc", "1.1.1.1"); !errors.Is(err, ErrPaused) || !strings.HasPrefix(r.co.State(), "waiting: the wallet self-check failed") {
		t.Fatalf("while the self-check fails: %v %q", err, r.co.State())
	}
	r.wallet.mu.Lock()
	r.wallet.makeErr = nil
	r.wallet.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the self-check was not retried")
	}
	if !r.co.Selling() {
		t.Fatalf("not selling after a passed retry: %q", r.co.State())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 1 || len(infos) != 1 || !strings.Contains(infos[0], "payments on") {
		t.Fatalf("alerts %v, infos %v", alerts, infos)
	}
}

// TestSelfCheckPermanentFailures: a refused method, or lookup not finding
// the invoice make just made, turns payments off at once, with no retry.
func TestSelfCheckPermanentFailures(t *testing.T) {
	for name, set := range map[string]func(*fakeWallet){
		"lookup refused": func(w *fakeWallet) { w.lookupErr = &nwc.Error{Code: "RESTRICTED"} },
		"make refused":   func(w *fakeWallet) { w.makeErr = &nwc.Error{Code: "UNAUTHORIZED"} },
		"own invoice":    func(w *fakeWallet) { w.rotated = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := newCheckoutRig(t)
			r.cfg = func(c *CheckoutConfig) { c.RequireSelfCheck, c.SelfCheckRetry = true, time.Millisecond }
			r.open()
			set(r.wallet)
			var alerts []string
			r.co.RunSelfCheck(context.Background(), func(string, ...any) {}, func(m string, _ ...any) { alerts = append(alerts, m) })
			if _, err := r.create("abc", "1.1.1.1"); !errors.Is(err, ErrPaymentsOff) || len(alerts) != 1 || !strings.Contains(alerts[0], "payments off") {
				t.Fatalf("%v, alerts %v", err, alerts)
			}
			if r.wallet.makes > 1 {
				t.Fatalf("retried a permanent failure: %d makes", r.wallet.makes)
			}
		})
	}
}

// TestAbandonedCheckoutsDoNotLinger (the reviewer's probe): 66 unpaid
// invoices from 11 networks, past their expiry but in their 2-minute
// grace, are ordinary abandoned checkouts, not lingering orders: sales go
// on. Orders past their watch with no answer do count.
func TestAbandonedCheckoutsDoNotLinger(t *testing.T) {
	r := newCheckoutRig(t)
	n := 0
	for net := 0; net < 11; net++ {
		for i := 0; i < 6; i++ {
			r.mustCreate(fmt.Sprintf("%03x", 0x100+n), fmt.Sprintf("10.%d.0.%d", net, 1+i/3))
			n++
		}
	}
	r.advance(10*time.Minute + time.Minute) // expired, in the grace
	r.poll()
	if _, err := r.create("fff", "192.0.2.1"); err != nil {
		t.Fatalf("66 abandoned checkouts in their grace paused sales: %v (%q)", err, r.co.State())
	}
	// Past the watch with no answer: those linger.
	r2 := newCheckoutRig(t)
	r2.cfg = func(c *CheckoutConfig) { c.MaxLingering = 2 }
	r2.open()
	r2.mustCreate("abc", "10.0.0.1")
	r2.mustCreate("abd", "10.1.0.1")
	r2.wallet.rotated = true
	r2.advance(13 * time.Minute)
	r2.poll()
	if _, err := r2.create("abe", "10.2.0.1"); !errors.Is(err, ErrPaused) {
		t.Fatalf("two orders past their watch with no answer, cap 2: %v", err)
	}
}

// TestPauseNeedsTwoBadPasses: a one-off timeout pauses nothing; a pass with
// a minority of failures is not bad; two bad passes in a row pause; a
// configuration error pauses at once.
func TestPauseNeedsTwoBadPasses(t *testing.T) {
	r := newCheckoutRig(t)
	var hashes []string
	for i, region := range []string{"abc", "abd", "abe"} {
		hashes = append(hashes, r.mustCreate(region, fmt.Sprintf("10.%d.0.1", i)).PaymentHash)
	}
	r.wallet.failHashes = map[string]bool{hashes[0]: true} // one of three, every pass
	for i := 0; i < 5; i++ {
		r.poll()
	}
	if !r.co.Selling() || len(r.alerts) != 0 {
		t.Fatalf("a minority of failures paused sales: %q %v", r.co.State(), r.alerts)
	}
	r.wallet.failHashes = nil
	r.wallet.lookupErr = errors.New("timeout") // one bad pass
	r.poll()
	if !r.co.Selling() {
		t.Fatal("one bad pass paused sales")
	}
	r.wallet.lookupErr = nil
	r.poll()
	r.wallet.lookupErr = errors.New("timeout") // bad, good, bad: no pause
	r.poll()
	if !r.co.Selling() {
		t.Fatal("two bad passes that were not in a row paused sales")
	}
	r.poll() // the second in a row
	if r.co.Selling() || len(r.alerts) != 1 {
		t.Fatalf("two bad passes in a row: selling %v, alerts %v", r.co.Selling(), r.alerts)
	}
	r2 := newCheckoutRig(t)
	r2.mustCreate("abc", "10.0.0.1")
	r2.wallet.lookupErr = &nwc.Error{Code: "NOT_IMPLEMENTED"}
	r2.poll()
	if r2.co.Selling() {
		t.Fatal("a configuration error did not pause at once")
	}
}

// TestResolveOneLedgerLine: resolving a line leaves a later line for the
// same payment hash with another outcome listed; a line written twice is
// one item, resolved together.
func TestResolveOneLedgerLine(t *testing.T) {
	r := newCheckoutRig(t)
	o := r.mustCreate("abc", "1.1.1.1")
	unknown, refund := o, o
	unknown.Outcome = "unknown: the wallet never answered; check the wallet for payment hash " + o.PaymentHash
	refund.Outcome = OutcomeAlready
	r.co.ledger(unknown)
	r.co.ledger(unknown) // written twice (a crash)
	r.co.ledger(refund)  // later: it was paid after all, and owed back
	open, _ := r.co.NeedsOwnerOpen()
	if len(open) != 2 {
		t.Fatalf("%d open items, want 2 (the repeated line is one)", len(open))
	}
	if _, err := r.co.Resolve(o.PaymentHash, "by hash"); !errors.Is(err, ErrNothingToResolve) {
		t.Fatalf("resolved by payment hash, not a line id: %v", err)
	}
	if _, err := r.co.Resolve(open[0].LineID, "checked the wallet"); err != nil {
		t.Fatal(err)
	}
	open, _ = r.co.NeedsOwnerOpen()
	if len(open) != 1 || open[0].Outcome != OutcomeAlready {
		t.Fatalf("after resolving the unknown line: %+v", open)
	}
}

// TestSelfCheckBackoff: 30 s, 1 min, 2 min, ... capped at 10 min.
func TestSelfCheckBackoff(t *testing.T) {
	w, limit := 30*time.Second, 10*time.Minute
	var got []time.Duration
	for i := 0; i < 7; i++ {
		got = append(got, w)
		w = nextWait(w, limit)
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%v, want %v", got, want)
	}
}
