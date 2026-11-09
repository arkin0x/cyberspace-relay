package speakeasy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0ceanslim/grain/server/nwc"
)

// Paid creation (docs/speakeasies.md, step 5, ruling D2). A visitor asks for
// a speakeasy at a region; the relay makes an invoice on the HOSAKA wallet
// through NWC, marked with the region, and watches it with lookup_invoice.
// Once paid, the registry gets the entry and the path is a speakeasy.
//
// What binds a payment to a region is the order, kept here by the relay: the
// visitor never names a region when a payment settles, so a paid invoice
// cannot be claimed for another one. The invoice's description names the
// region too, and must come back unchanged from the wallet.

// Wallet is what the checkout needs from a wallet: NWC's make_invoice and
// lookup_invoice (nwc.Client, nwc.FileWallet), or a fake in tests.
type Wallet interface {
	MakeInvoice(ctx context.Context, amountMsat int64, description string, expiry time.Duration) (nwc.Invoice, error)
	LookupInvoice(ctx context.Context, paymentHash string) (nwc.Invoice, error)
}

// Order kinds.
const (
	OrderSpeakeasy = "speakeasy"
)

// Order statuses.
const (
	StatusPending = "pending" // the invoice can be paid
	StatusPaid    = "paid"    // the wallet says it is paid
	StatusExpired = "expired" // never paid, and past its expiry
)

// Order is one invoice for one region, as the relay keeps it.
type Order struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Region string `json:"region"`
	// Requester is a hash of the client's address: one pending order per
	// region and requester.
	Requester   string `json:"requester"`
	AmountSats  int64  `json:"amount_sats"`
	Invoice     string `json:"invoice"`
	PaymentHash string `json:"payment_hash"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at"`
	Status      string `json:"status"`
	SettledAt   int64  `json:"settled_at,omitempty"`
	// Applied is set once the paid order has done what it was for (or
	// could not, and says why in Outcome); until then each poll retries.
	Applied bool   `json:"applied,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

// Outcomes of a paid order.
const (
	OutcomeRegistered = "registered"
	// OutcomeAlready: someone else's payment made the region a speakeasy
	// first. The payer has what they paid for.
	OutcomeAlready = "already a speakeasy"
)

// CheckoutConfig configures a Checkout.
type CheckoutConfig struct {
	Wallet   Wallet
	Registry *Registry
	// OrdersPath keeps the open orders (so a restart does not lose a
	// payment); LedgerPath gets one JSON line per paid order, forever.
	OrdersPath, LedgerPath string
	// Write replaces OrdersPath atomically (config.AtomicWriteFile).
	Write func(string, []byte, os.FileMode) error
	// Host names the relay in invoice descriptions (relay.onosendai.tech).
	Host          string
	SpeakeasySats int64
	Expiry        time.Duration // an invoice's life
	Poll          time.Duration // how often pending invoices are looked up
	// MaxPending caps open invoices in all; MaxPerRequester caps one
	// requester's (each for another region).
	MaxPending, MaxPerRequester int
	Now                         func() time.Time
	Log                         func(msg string, args ...any)
	Alert                       func(msg string, args ...any)
}

// Checkout makes and watches invoices.
type Checkout struct {
	cfg CheckoutConfig

	create sync.Mutex // one make_invoice at a time
	mu     sync.Mutex
	orders map[string]*Order
}

// Checkout errors a caller shows to the visitor.
var (
	ErrAlreadySpeakeasy = errors.New("this region is already a speakeasy")
	ErrTooManyInvoices  = errors.New("too many open invoices; try again in a few minutes")
	ErrNotRegion        = errors.New("not a region string")
)

// lookupGrace is how long after its expiry an unpaid invoice is still
// looked up, for a payment that settled at the last moment.
const lookupGrace = 2 * time.Minute

// keepClosed is how long a closed order stays in OrdersPath, so a page
// polling it still sees how it ended.
const keepClosed = 24 * time.Hour

// NewCheckout loads the open orders and makes a checkout.
func NewCheckout(cfg CheckoutConfig) (*Checkout, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	if cfg.Alert == nil {
		cfg.Alert = cfg.Log
	}
	c := &Checkout{cfg: cfg, orders: map[string]*Order{}}
	data, err := os.ReadFile(cfg.OrdersPath)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", cfg.OrdersPath, err)
	default:
		var f struct {
			Orders []*Order `json:"orders"`
		}
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", cfg.OrdersPath, err)
		}
		for _, o := range f.Orders {
			c.orders[o.ID] = o
		}
	}
	return c, nil
}

// Requester turns a client address into the key orders are kept by, so the
// orders file holds no addresses.
func Requester(addr string) string {
	sum := sha256.Sum256([]byte("speakeasy-requester:" + addr))
	return hex.EncodeToString(sum[:12])
}

// OrderRequest is what a visitor asks for.
type OrderRequest struct {
	Kind, Region, Requester string
}

// Create returns the requester's open order for this region, or makes one
// with a new invoice. region must be a region string in its canonical
// spelling.
func (c *Checkout) Create(ctx context.Context, req OrderRequest) (Order, error) {
	if req.Kind != OrderSpeakeasy {
		return Order{}, fmt.Errorf("unknown order kind %q", req.Kind)
	}
	if !c.canonicalRegion(req.Region) {
		return Order{}, ErrNotRegion
	}
	if c.cfg.Registry.Get(req.Region) != nil {
		return Order{}, ErrAlreadySpeakeasy
	}
	if o, ok := c.open(req); ok {
		return o, nil
	}
	// One make_invoice at a time: the check above is repeated inside, so
	// two requests at once get one invoice.
	c.create.Lock()
	defer c.create.Unlock()
	if o, ok := c.open(req); ok {
		return o, nil
	}
	if err := c.room(req.Requester); err != nil {
		return Order{}, err
	}
	sats := c.cfg.SpeakeasySats
	desc := fmt.Sprintf("%s speakeasy %s", c.cfg.Host, req.Region)
	inv, err := c.cfg.Wallet.MakeInvoice(ctx, sats*1000, desc, c.cfg.Expiry)
	if err != nil {
		return Order{}, fmt.Errorf("the wallet made no invoice: %w", err)
	}
	if !validBolt11(inv.Invoice) || !isLowerHex(strings.ToLower(inv.PaymentHash), 64) || (inv.Amount != 0 && inv.Amount != sats*1000) {
		return Order{}, errors.New("the wallet's invoice is malformed")
	}
	now := c.cfg.Now()
	o := &Order{
		ID: newID(), Kind: req.Kind, Region: req.Region, Requester: req.Requester,
		AmountSats: sats, Invoice: strings.ToLower(inv.Invoice), PaymentHash: strings.ToLower(inv.PaymentHash),
		Description: desc, CreatedAt: now.Unix(), ExpiresAt: now.Add(c.cfg.Expiry).Unix(), Status: StatusPending,
	}
	if inv.ExpiresAt > 0 && inv.ExpiresAt < o.ExpiresAt {
		o.ExpiresAt = inv.ExpiresAt
	}
	c.mu.Lock()
	c.orders[o.ID] = o
	err = c.saveLocked()
	if err != nil {
		delete(c.orders, o.ID)
	}
	out := *o
	c.mu.Unlock()
	if err != nil {
		return Order{}, fmt.Errorf("could not keep the order: %w", err)
	}
	c.cfg.Log("speakeasy: invoice made", "order", o.ID, "kind", o.Kind, "region", o.Region, "sats", sats, "payment_hash", o.PaymentHash)
	return out, nil
}

// open is the requester's pending order for this region, if it still has a
// minute left to be paid.
func (c *Checkout) open(req OrderRequest) (Order, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	soon := c.cfg.Now().Add(time.Minute).Unix()
	for _, o := range c.orders {
		if o.Status == StatusPending && o.Kind == req.Kind && o.Region == req.Region && o.Requester == req.Requester && o.ExpiresAt > soon {
			return *o, true
		}
	}
	return Order{}, false
}

// room says whether one more pending order fits.
func (c *Checkout) room(requester string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	all, mine := 0, 0
	for _, o := range c.orders {
		if o.Status == StatusPending {
			all++
			if o.Requester == requester {
				mine++
			}
		}
	}
	if all >= c.cfg.MaxPending || mine >= c.cfg.MaxPerRequester {
		return ErrTooManyInvoices
	}
	return nil
}

func (c *Checkout) canonicalRegion(region string) bool {
	p := c.cfg.Registry.parse
	if p == nil {
		return false
	}
	canonical, _, ok := p("/" + region)
	return ok && canonical == region
}

// Get returns an order by id.
func (c *Checkout) Get(id string) (Order, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.orders[id]
	if !ok {
		return Order{}, false
	}
	return *o, true
}

// Run looks up the open invoices every Poll until ctx ends, starting at
// once, so orders left open by a restart are picked up.
func (c *Checkout) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.Poll)
	defer t.Stop()
	for {
		c.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll looks up every open invoice once, applies the paid ones and closes
// the expired ones.
func (c *Checkout) Poll(ctx context.Context) {
	c.mu.Lock()
	var todo []Order
	for _, o := range c.orders {
		if o.Status == StatusPending || o.Status == StatusPaid && !o.Applied {
			todo = append(todo, *o)
		}
	}
	c.mu.Unlock()
	sort.Slice(todo, func(i, j int) bool { return todo[i].CreatedAt < todo[j].CreatedAt })
	for _, o := range todo {
		if ctx.Err() != nil {
			return
		}
		if o.Status == StatusPending {
			c.lookup(ctx, o)
		} else {
			c.apply(o.ID)
		}
	}
	c.prune()
}

func (c *Checkout) lookup(ctx context.Context, o Order) {
	inv, err := c.cfg.Wallet.LookupInvoice(ctx, o.PaymentHash)
	now := c.cfg.Now()
	if err == nil && inv.Settled() {
		if why := mismatch(o, inv); why != "" {
			// Never apply a payment the wallet describes differently: it
			// is not the invoice this order made.
			c.cfg.Alert("speakeasy: the wallet's paid invoice does not match the order; not applied", "order", o.ID, "payment_hash", o.PaymentHash, "why", why)
			c.update(o.ID, func(x *Order) { x.Status, x.Applied, x.Outcome = StatusPaid, true, "held for the relay owner: "+why })
			return
		}
		settled := inv.SettledAt
		if settled == 0 {
			settled = now.Unix()
		}
		c.update(o.ID, func(x *Order) { x.Status, x.SettledAt = StatusPaid, settled })
		c.cfg.Log("speakeasy: invoice paid", "order", o.ID, "region", o.Region, "sats", o.AmountSats, "payment_hash", o.PaymentHash)
		c.apply(o.ID)
		return
	}
	if err != nil && !nwc.IsNotFound(err) {
		c.cfg.Log("speakeasy: invoice lookup failed", "order", o.ID, "error", err.Error())
	}
	if now.Unix() > o.ExpiresAt+int64(lookupGrace/time.Second) {
		c.update(o.ID, func(x *Order) { x.Status = StatusExpired })
	}
}

// mismatch says how a paid invoice differs from the order, or "".
func mismatch(o Order, inv nwc.Invoice) string {
	switch {
	case inv.PaymentHash != "" && !strings.EqualFold(inv.PaymentHash, o.PaymentHash):
		return "payment hash"
	case inv.Amount != 0 && inv.Amount < o.AmountSats*1000:
		return "amount"
	case inv.Description != "" && inv.Description != o.Description:
		return "description"
	case inv.Invoice != "" && !strings.EqualFold(inv.Invoice, o.Invoice):
		return "invoice"
	}
	return ""
}

// apply does what a paid order is for, once. A failure to write the
// registry leaves it to the next poll.
func (c *Checkout) apply(id string) {
	o, ok := c.Get(id)
	if !ok || o.Status != StatusPaid || o.Applied {
		return
	}
	outcome := OutcomeRegistered
	_, err := c.cfg.Registry.Add(Entry{
		ID: o.Region, CreatedAt: o.SettledAt,
		Note: fmt.Sprintf("paid %d sats, payment hash %s", o.AmountSats, o.PaymentHash),
	})
	switch {
	case err == nil:
	case c.cfg.Registry.Get(o.Region) != nil:
		outcome = OutcomeAlready
	default:
		c.cfg.Alert("speakeasy: paid but the registry write failed; retrying", "order", o.ID, "region", o.Region, "error", err.Error())
		return
	}
	c.update(id, func(x *Order) { x.Applied, x.Outcome = true, outcome })
	o.Applied, o.Outcome = true, outcome
	c.ledger(o)
	c.cfg.Log("speakeasy: order applied", "order", o.ID, "region", o.Region, "outcome", outcome)
}

// ledger appends a paid order to the ledger, the record that outlives the
// orders file.
func (c *Checkout) ledger(o Order) {
	if c.cfg.LedgerPath == "" {
		return
	}
	line, _ := json.Marshal(o)
	f, err := os.OpenFile(c.cfg.LedgerPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.Write(append(line, '\n'))
		if err == nil {
			err = f.Sync()
		}
		f.Close()
	}
	if err != nil {
		c.cfg.Alert("speakeasy: could not write the payments ledger", "order", o.ID, "error", err.Error())
	}
}

func (c *Checkout) update(id string, f func(*Order)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if o := c.orders[id]; o != nil {
		f(o)
		if err := c.saveLocked(); err != nil {
			c.cfg.Alert("speakeasy: could not save the orders", "error", err.Error())
		}
	}
}

// prune drops closed orders older than keepClosed.
func (c *Checkout) prune() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cut := c.cfg.Now().Add(-keepClosed).Unix()
	n := len(c.orders)
	for id, o := range c.orders {
		closed := o.Status == StatusExpired || o.Status == StatusPaid && o.Applied
		if closed && o.ExpiresAt < cut {
			delete(c.orders, id)
		}
	}
	if len(c.orders) != n {
		c.saveLocked()
	}
}

func (c *Checkout) saveLocked() error {
	list := make([]*Order, 0, len(c.orders))
	for _, o := range c.orders {
		list = append(list, o)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt < list[j].CreatedAt || list[i].CreatedAt == list[j].CreatedAt && list[i].ID < list[j].ID
	})
	data, err := json.MarshalIndent(map[string]any{"orders": list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.cfg.OrdersPath), 0o755); err != nil {
		return err
	}
	return c.cfg.Write(c.cfg.OrdersPath, append(data, '\n'), 0o600)
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// validBolt11 accepts a BOLT 11 invoice's shape: "ln", then bech32
// characters only, so it is safe in a lightning: link.
func validBolt11(s string) bool {
	s = strings.ToLower(s)
	if len(s) < 20 || len(s) > 2048 || !strings.HasPrefix(s, "ln") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
