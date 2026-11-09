package speakeasy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

// sessionWallet is a Wallet that can look up many invoices on one
// connection: a poll pass uses one when it can.
type sessionWallet interface {
	LookupSession(ctx context.Context) (nwc.Lookuper, error)
}

// Order kinds.
const (
	OrderSpeakeasy = "speakeasy"
)

// Order statuses.
const (
	StatusPending = "pending" // the invoice can be paid, or its answer is awaited
	StatusPaid    = "paid"    // the wallet says it is paid
	StatusExpired = "expired" // the wallet said unpaid after the watch ended
	// StatusUnknown: the wallet never answered about it for GiveUp after
	// its watch ended. Ledgered and alerted; the owner settles it by hand.
	StatusUnknown = "unknown"
)

// Order is one invoice for one region, as the relay keeps it.
type Order struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Region string `json:"region"`
	// Requester is a hash of the client's address (an IPv6 address by its
	// /64), Network a hash of its network (/48, or /24 for IPv4): the caps
	// on open invoices count by them.
	Requester   string `json:"requester"`
	Network     string `json:"network,omitempty"`
	AmountSats  int64  `json:"amount_sats"`
	Invoice     string `json:"invoice"`
	PaymentHash string `json:"payment_hash"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
	// ExpiresAt is when the invoice stops being payable, as the wallet
	// says. WatchUntil is when the relay stops asking about it at every
	// poll: the later of that and the relay's own expiry, plus a grace.
	ExpiresAt  int64  `json:"expires_at"`
	WatchUntil int64  `json:"watch_until"`
	Status     string `json:"status"`
	SettledAt  int64  `json:"settled_at,omitempty"`
	// Applied is set once the paid order has done what it was for (or
	// could not, and says why in Outcome); until then each poll retries.
	Applied bool   `json:"applied,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	// LookupFailing is set once the owner was told the wallet cannot be
	// asked about this order after it stopped being payable.
	LookupFailing bool `json:"lookup_failing,omitempty"`
	// LineID names one ledger line (set when it is written), so the owner
	// resolves that line, not every line with its payment hash.
	LineID string `json:"line_id,omitempty"`
	// ClosedAt is when the relay saw it paid, or gave up on it
	// (StatusUnknown): what keepClosed counts from.
	ClosedAt int64 `json:"closed_at,omitempty"`
}

// Outcomes of a paid order. Every outcome that bought nothing starts with
// OutcomeRefund or OutcomeHeld; the owner settles those by hand (NIP-86
// grain_speakeasy_payments lists them).
const (
	OutcomeRegistered = "registered"
	OutcomeRefund     = "refund owed: "
	OutcomeHeld       = "held for the relay owner: "
	// OutcomeAlready: another payment made the region a speakeasy first
	// (two payers, or one who paid two invoices).
	OutcomeAlready = OutcomeRefund + "already a speakeasy"
)

// NeedsOwner reports whether an outcome is one the relay owner must settle
// by hand (a refund owed, or a payment held).
func NeedsOwner(outcome string) bool {
	return strings.HasPrefix(outcome, OutcomeRefund) || strings.HasPrefix(outcome, OutcomeHeld)
}

// CheckoutConfig configures a Checkout.
type CheckoutConfig struct {
	Wallet   Wallet
	Registry *Registry
	// OrdersPath keeps the open orders (so a restart does not lose a
	// payment); LedgerPath gets one JSON line per paid order, forever.
	OrdersPath, LedgerPath string
	// Write replaces OrdersPath atomically and durably (WriteDurable).
	Write func(string, []byte, os.FileMode) error
	// Host names the relay in invoice descriptions (relay.onosendai.tech).
	Host          string
	SpeakeasySats int64
	Expiry        time.Duration // an invoice's life, as asked of the wallet
	Poll          time.Duration // how often open invoices are looked up
	// Caps on payable open invoices: in all, per requester (/64), per
	// network (/48 or /24), per region (distinct networks; and at most one
	// per network per region).
	MaxPending, MaxPerRequester, MaxPerNetwork, MaxPerRegion int
	// MaxLingering caps orders past their watch window with no answer yet,
	// or marked LookupFailing: at the cap, sales pause. Default 64.
	MaxLingering int
	// ResolvedPath records the payments the owner marked resolved
	// (Resolve), so the owner's list shows only open items.
	ResolvedPath string
	// RequireSelfCheck keeps sales off until SelfCheck has passed.
	RequireSelfCheck bool
	// SelfCheckRetry is RunSelfCheck's first wait after a failure that
	// may pass later (default 30 s); it doubles up to SelfCheckRetryCap
	// (default 10 min).
	SelfCheckRetry, SelfCheckRetryCap time.Duration
	Now                               func() time.Time
	Log                               func(msg string, args ...any)
	Alert                             func(msg string, args ...any)
}

// Checkout makes and watches invoices.
type Checkout struct {
	cfg CheckoutConfig

	create chan struct{} // one make_invoice at a time (a one-slot lock)
	mu     sync.Mutex
	orders map[string]*Order
	// lastLookup paces lookups of orders whose watch has ended.
	lastLookup map[string]time.Time
	// paused says why sales are paused (lookups failed in the last poll
	// pass), or "". off says why they never start (the self-check
	// failed); ready is false until a required self-check passed.
	paused, off string
	ready       bool
	// checkErr is the last self-check failure that may pass on a retry.
	checkErr string
	// badPasses counts poll passes in a row whose lookups mostly failed:
	// sales pause at two (at once for a configuration error).
	badPasses int
	// While a poll pass runs, changes mark the orders dirty and the pass
	// saves them once at its end (batching), not once per change.
	batching, dirty bool
}

// Checkout errors a caller shows to the visitor.
var (
	ErrAlreadySpeakeasy = errors.New("this region is already a speakeasy")
	ErrTooManyInvoices  = errors.New("too many open invoices; try again in a few minutes")
	ErrRegionBusy       = errors.New("this region has open invoices from others; try again in a few minutes")
	ErrNotRegion        = errors.New("not a region string")
	// ErrNetworkHasOrder: per region, at most one open invoice per
	// network (/48 or /24).
	ErrNetworkHasOrder = errors.New("an invoice for this region from your network is already open; pay it or wait for it to expire")
	// ErrPaused: sales are paused while the wallet cannot be asked about
	// invoices (or too many old ones still wait for an answer).
	ErrPaused = errors.New("payments are paused; try again later")
	// ErrPaymentsOff: the startup self-check failed; see the relay's log.
	ErrPaymentsOff = errors.New("payments are off on this relay")
)

// DefaultMaxLingering is MaxLingering when unset.
const DefaultMaxLingering = 64

const (
	// lookupGrace is how long past the watch's start an unpaid invoice is
	// still looked up at every poll, for a payment that settled at the
	// last moment.
	lookupGrace = 2 * time.Minute
	// lateEvery paces lookups of an order whose watch has ended but whose
	// answer is not known (the wallet failed or said NOT_FOUND).
	lateEvery = 5 * time.Minute
	// keepClosed is how long a closed order stays in OrdersPath, so a page
	// polling it still sees how it ended. An expired order is looked up
	// one last time before it is dropped.
	keepClosed = 24 * time.Hour
	// GiveUp is how long after its watch ended an order the wallet never
	// answered about is kept open before it is ledgered as unknown.
	GiveUp = 7 * 24 * time.Hour
	// expirySlack is how much later than asked the wallet's expires_at may
	// be (clock skew); later than that, the invoice is refused.
	expirySlack = time.Minute
)

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
	if cfg.MaxLingering <= 0 {
		cfg.MaxLingering = DefaultMaxLingering
	}
	if cfg.SelfCheckRetry <= 0 {
		cfg.SelfCheckRetry = 30 * time.Second
	}
	if cfg.SelfCheckRetryCap <= 0 {
		cfg.SelfCheckRetryCap = 10 * time.Minute
	}
	if cfg.ResolvedPath == "" && cfg.LedgerPath != "" {
		cfg.ResolvedPath = cfg.LedgerPath + ".resolved"
	}
	c := &Checkout{cfg: cfg, create: make(chan struct{}, 1), orders: map[string]*Order{}, lastLookup: map[string]time.Time{}, ready: !cfg.RequireSelfCheck}
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
			if o.WatchUntil == 0 { // written before watch_until existed
				o.WatchUntil = o.ExpiresAt + int64(lookupGrace/time.Second)
			}
			c.orders[o.ID] = o
		}
	}
	return c, nil
}

// Requester turns a client address into the key orders are kept by, so the
// orders file holds no addresses. An IPv6 address counts by its /64, which
// one host usually holds whole, so rotating addresses inside it does not
// dodge the caps.
func Requester(addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		addr = ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return hashKey("speakeasy-requester:" + addr)
}

// Network is the hashed network of a client address: its /48 for IPv6,
// its /24 for IPv4 (as the gate's work queue counts networks).
func Network(addr string) string {
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return hashKey("speakeasy-network:" + addr)
	case ip.To4() != nil:
		return hashKey("speakeasy-network:" + ip.Mask(net.CIDRMask(24, 32)).String() + "/24")
	}
	return hashKey("speakeasy-network:" + ip.Mask(net.CIDRMask(48, 128)).String() + "/48")
}

func hashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:12])
}

// OrderRequest is what a visitor asks for. Requester and Network come from
// the client address (Requester, Network).
type OrderRequest struct {
	Kind, Region, Requester, Network string
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
	if err := c.selling(); err != nil {
		return Order{}, err
	}
	if c.cfg.Registry.Get(req.Region) != nil || c.paidFor(req.Region) {
		return Order{}, ErrAlreadySpeakeasy
	}
	if o, ok := c.open(req); ok {
		return o, nil
	}
	// One make_invoice at a time, but never longer than the caller waits.
	select {
	case c.create <- struct{}{}:
	case <-ctx.Done():
		return Order{}, ctx.Err()
	}
	defer func() { <-c.create }()
	if o, ok := c.open(req); ok { // made while this one waited
		return o, nil
	}
	if err := c.room(req); err != nil {
		return Order{}, err
	}
	sats := c.cfg.SpeakeasySats
	desc := fmt.Sprintf("%s speakeasy %s", c.cfg.Host, req.Region)
	now := c.cfg.Now()
	inv, err := c.cfg.Wallet.MakeInvoice(ctx, sats*1000, desc, c.cfg.Expiry)
	if err != nil {
		return Order{}, fmt.Errorf("the wallet made no invoice: %w", err)
	}
	if why := badInvoice(inv, sats*1000, desc, now, c.cfg.Expiry); why != "" {
		c.cfg.Alert("speakeasy: the wallet's new invoice was refused", "why", why, "payment_hash", inv.PaymentHash)
		return Order{}, fmt.Errorf("the wallet's invoice is unusable: %s", why)
	}
	relayExpiry := now.Add(c.cfg.Expiry).Unix()
	o := &Order{
		ID: newID(), Kind: req.Kind, Region: req.Region, Requester: req.Requester, Network: req.Network,
		AmountSats: sats, Invoice: strings.ToLower(inv.Invoice), PaymentHash: strings.ToLower(inv.PaymentHash),
		Description: desc, CreatedAt: now.Unix(), ExpiresAt: inv.ExpiresAt,
		WatchUntil: max(relayExpiry, inv.ExpiresAt) + int64(lookupGrace/time.Second), Status: StatusPending,
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

// badInvoice says why a new invoice from make_invoice cannot be sold, or
// "": it must be a BOLT 11 string encoding exactly wantMsat, the wallet
// must say the same amount and a payment hash, the description (when
// given) must be ours, and it must expire, no later than asked and not
// within a minute.
func badInvoice(inv nwc.Invoice, wantMsat int64, desc string, now time.Time, expiry time.Duration) string {
	switch {
	case !validBolt11(inv.Invoice):
		return "not a BOLT 11 invoice"
	case bolt11Msat(inv.Invoice) != wantMsat:
		return "the invoice encodes another amount"
	case inv.Amount != wantMsat:
		return "the wallet states another amount, or none"
	case !isLowerHex(strings.ToLower(inv.PaymentHash), 64):
		return "no payment hash"
	case inv.Description != "" && inv.Description != desc:
		return "another description"
	case inv.ExpiresAt == 0:
		return "no expiry"
	case inv.ExpiresAt > now.Add(expiry+expirySlack).Unix():
		return "expires later than asked"
	case inv.ExpiresAt < now.Add(time.Minute).Unix():
		return "expires within a minute"
	}
	return ""
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

// paidFor reports whether a paid order for region is still being applied
// (its registry write is being retried): the region is sold.
func (c *Checkout) paidFor(region string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, o := range c.orders {
		if o.Status == StatusPaid && !o.Applied && o.Kind == OrderSpeakeasy && o.Region == region {
			return true
		}
	}
	return false
}

// room says whether one more payable invoice fits the caps. Only invoices
// that can still be paid count: one whose answer is awaited after it
// expired holds no slot.
func (c *Checkout) room(req OrderRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now().Unix()
	all, mine, network := 0, 0, 0
	regionNets := map[string]bool{} // the networks with an open invoice for this region
	for _, o := range c.orders {
		if o.Status != StatusPending || o.ExpiresAt <= now {
			continue
		}
		all++
		if o.Requester == req.Requester {
			mine++
		}
		if req.Network != "" && o.Network == req.Network {
			network++
		}
		// The requester's own invoice with under a minute left is not
		// handed out again (open), so it does not hold the region for them.
		ownExpiring := o.Requester == req.Requester && o.ExpiresAt <= now+60
		if o.Region == req.Region && !ownExpiring {
			if o.Network == req.Network {
				// One open invoice per network per region, so one address
				// cannot take a region's whole cap.
				return ErrNetworkHasOrder
			}
			regionNets[o.Network] = true
		}
	}
	switch {
	case len(regionNets) >= c.cfg.MaxPerRegion:
		return ErrRegionBusy
	case all >= c.cfg.MaxPending || mine >= c.cfg.MaxPerRequester || network >= c.cfg.MaxPerNetwork:
		return ErrTooManyInvoices
	}
	return nil
}

// selling says why no invoice can be sold now, or nil.
func (c *Checkout) selling() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.off != "":
		return ErrPaymentsOff
	case !c.ready:
		return fmt.Errorf("%w (checking the wallet)", ErrPaused)
	case c.paused != "":
		return ErrPaused
	case c.lingeringLocked() >= c.cfg.MaxLingering:
		return fmt.Errorf("%w (too many old invoices still wait for an answer)", ErrPaused)
	}
	return nil
}

// Selling reports whether invoices can be sold now (the page offers
// Create only then).
func (c *Checkout) Selling() bool { return c.selling() == nil }

// State says whether sales are paused or off, and why ("" when selling).
func (c *Checkout) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.off != "":
		return "off: " + c.off
	case !c.ready && c.checkErr != "":
		return "waiting: the wallet self-check failed (" + c.checkErr + "); retrying"
	case !c.ready:
		return "waiting for the self-check"
	case c.paused != "":
		return "paused: " + c.paused
	case c.lingeringLocked() >= c.cfg.MaxLingering:
		return "paused: too many old invoices still wait for an answer"
	}
	return ""
}

// lingeringLocked counts orders that linger: past their watch (expiry
// plus grace) with no answer yet, or marked LookupFailing. An ordinary
// abandoned checkout in its grace does not count. Called with mu held.
func (c *Checkout) lingeringLocked() int {
	now, n := c.cfg.Now().Unix(), 0
	for _, o := range c.orders {
		if o.Status == StatusPending && (now > o.WatchUntil || o.LookupFailing) {
			n++
		}
	}
	return n
}

// selfCheckMsat is the amount of the self-check's invoice: 1 sat.
const selfCheckMsat = 1000

// SelfCheck makes a 1-sat invoice and looks it up, once, as payments
// will. On success sales may start. A permanent failure (the wallet
// refuses a method: a connection made without it; or lookup cannot find
// the invoice make just made) turns payments off; any other failure (a
// timeout, a relay down) leaves them waiting, for RunSelfCheck to retry.
func (c *Checkout) SelfCheck(ctx context.Context) error {
	err := c.selfCheck(ctx)
	permanent := errors.Is(err, ErrSelfCheckPermanent)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		c.ready, c.off, c.checkErr = true, "", ""
	case permanent:
		c.off = err.Error()
	default:
		c.checkErr = err.Error()
	}
	return err
}

// ErrSelfCheckPermanent marks a self-check failure no retry can fix.
var ErrSelfCheckPermanent = errors.New("permanent")

// RunSelfCheck runs SelfCheck until it passes or fails permanently,
// retrying other failures with backoff (SelfCheckRetry, doubling, capped
// at SelfCheckRetryCap), and logs each change of state: on, waiting, off.
func (c *Checkout) RunSelfCheck(ctx context.Context, info, alert func(msg string, args ...any)) {
	wait := c.cfg.SelfCheckRetry
	failing := ""
	for {
		err := c.SelfCheck(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil:
			info("speakeasy payments on: the wallet self-check passed")
			return
		case errors.Is(err, ErrSelfCheckPermanent):
			alert("speakeasy payments off: the wallet self-check failed; fix the NWC connection and restart", "error", err.Error())
			return
		case failing != err.Error():
			failing = err.Error()
			alert("speakeasy payments waiting: the wallet self-check failed; retrying", "error", failing, "retry_in", wait.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = nextWait(wait, c.cfg.SelfCheckRetryCap)
	}
}

// nextWait is the self-check's next wait: double, capped.
func nextWait(wait, limit time.Duration) time.Duration { return min(2*wait, limit) }

func (c *Checkout) selfCheck(ctx context.Context) error {
	inv, err := c.cfg.Wallet.MakeInvoice(ctx, selfCheckMsat, c.cfg.Host+" payments self-check", time.Minute)
	if err != nil {
		if code, cfgErr := walletTrouble(err); cfgErr {
			return fmt.Errorf("%w: the wallet refuses make_invoice (%s): make the NWC connection with make_invoice and lookup_invoice", ErrSelfCheckPermanent, code)
		}
		return fmt.Errorf("make_invoice failed: %w", err)
	}
	if !isLowerHex(strings.ToLower(inv.PaymentHash), 64) {
		return errors.New("make_invoice gave no payment hash")
	}
	if _, err := c.cfg.Wallet.LookupInvoice(ctx, strings.ToLower(inv.PaymentHash)); err != nil {
		if nwc.IsNotFound(err) {
			return fmt.Errorf("%w: lookup_invoice cannot find the invoice make_invoice just made", ErrSelfCheckPermanent)
		}
		if code, cfgErr := walletTrouble(err); cfgErr {
			return fmt.Errorf("%w: the wallet refuses lookup_invoice (%s): make the NWC connection with make_invoice and lookup_invoice", ErrSelfCheckPermanent, code)
		}
		return fmt.Errorf("lookup_invoice failed: %w", err)
	}
	return nil
}

// walletTrouble names what a failed lookup says about the wallet: "" when
// the wallet answered (no error, or NOT_FOUND: the connection works), the
// error code and true for a connection made without the method
// (RESTRICTED, UNAUTHORIZED, NOT_IMPLEMENTED), or another reason.
func walletTrouble(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	var we *nwc.Error
	if errors.As(err, &we) {
		switch we.Code {
		case "NOT_FOUND":
			return "", false
		case "RESTRICTED", "UNAUTHORIZED", "NOT_IMPLEMENTED":
			return we.Code, true
		}
		return "wallet error " + we.Code, false
	}
	return err.Error(), false
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

// Orders returns every order the checkout holds, oldest first.
func (c *Checkout) Orders() []Order {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Order, 0, len(c.orders))
	for _, o := range c.orders {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt < out[j].CreatedAt || out[i].CreatedAt == out[j].CreatedAt && out[i].ID < out[j].ID
	})
	return out
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

// lookups is one poll pass's way to the wallet: one connection for the
// whole pass when the wallet offers it, reopened once after a broken one.
type lookups struct {
	c    *Checkout
	sess nwc.Lookuper
	lost bool // a session broke; plain calls from now on
	// What the pass learned about the wallet: answers (NOT_FOUND
	// included: the connection works), the first trouble, whether it was
	// a configuration error; orders newly unverifiable, and given up.
	answers, failures int
	trouble           string
	config            bool
	newlyFailing      int
	gaveUp, dropped   int
}

// lookup asks about one invoice and records what the answer says about the
// wallet.
func (l *lookups) lookup(ctx context.Context, hash string) (nwc.Invoice, error) {
	inv, err := l.ask(ctx, hash)
	if ctx.Err() != nil {
		return inv, err
	}
	if trouble, cfg := walletTrouble(err); trouble == "" {
		l.answers++
	} else {
		l.failures++
		if l.trouble == "" || cfg {
			l.trouble, l.config = trouble, cfg
		}
	}
	return inv, err
}

func (l *lookups) ask(ctx context.Context, hash string) (nwc.Invoice, error) {
	sw, ok := l.c.cfg.Wallet.(sessionWallet)
	if !ok || l.lost {
		return l.c.cfg.Wallet.LookupInvoice(ctx, hash)
	}
	if l.sess == nil {
		s, err := sw.LookupSession(ctx)
		if err != nil {
			l.lost = true
			return l.c.cfg.Wallet.LookupInvoice(ctx, hash)
		}
		l.sess = s
	}
	inv, err := l.sess.LookupInvoice(ctx, hash)
	var we *nwc.Error
	if err != nil && !errors.As(err, &we) && ctx.Err() == nil {
		// The connection broke: drop it, and try this one plainly.
		l.sess.Close()
		l.sess, l.lost = nil, true
		return l.c.cfg.Wallet.LookupInvoice(ctx, hash)
	}
	return inv, err
}

func (l *lookups) close() {
	if l.sess != nil {
		l.sess.Close()
	}
}

// Poll looks up every open invoice once (an order whose watch has ended at
// most every lateEvery), applies the paid ones, closes the expired ones,
// and gives expired orders due to be dropped one last lookup.
func (c *Checkout) Poll(ctx context.Context) {
	now := c.cfg.Now()
	c.mu.Lock()
	c.batching = true
	failing := false
	var todo []Order
	for _, o := range c.orders {
		failing = failing || o.Status == StatusPending && o.LookupFailing
		switch {
		case o.Status == StatusPaid && !o.Applied:
			todo = append(todo, *o)
		case o.Status == StatusPending:
			// Unanswered after its watch: ask every lateEvery, not every poll.
			if now.Unix() > o.WatchUntil && o.LookupFailing && now.Sub(c.lastLookup[o.ID]) < lateEvery {
				continue
			}
			todo = append(todo, *o)
		case o.Status == StatusExpired && now.Unix() > o.WatchUntil+int64(keepClosed/time.Second):
			if now.Sub(c.lastLookup[o.ID]) >= lateEvery {
				todo = append(todo, *o)
			}
		}
	}
	c.mu.Unlock()
	sort.Slice(todo, func(i, j int) bool {
		return todo[i].CreatedAt < todo[j].CreatedAt || todo[i].CreatedAt == todo[j].CreatedAt && todo[i].ID < todo[j].ID
	})
	l := &lookups{c: c}
	defer func() {
		l.close()
		c.mu.Lock()
		c.batching = false
		if c.dirty {
			c.dirty = false
			if err := c.saveLocked(); err != nil {
				c.cfg.Alert("speakeasy: could not save the orders", "error", err.Error())
			}
		}
		c.mu.Unlock()
	}()
	for _, o := range todo {
		if ctx.Err() != nil {
			return
		}
		switch o.Status {
		case StatusPaid:
			c.apply(o.ID)
		case StatusPending:
			c.lookup(ctx, l, o)
		case StatusExpired:
			c.finalLookup(ctx, l, o)
		}
	}
	c.mu.Lock()
	paused := c.paused != ""
	c.mu.Unlock()
	c.mu.Lock()
	unsure := c.badPasses > 0
	c.mu.Unlock()
	if (paused || failing || unsure) && l.answers == 0 && l.trouble == "" && ctx.Err() == nil {
		// Nothing this pass showed whether lookups work: ask about an
		// invoice nobody made. NOT_FOUND means the connection answers.
		l.lookup(ctx, newID()+newID())
	}
	if ctx.Err() == nil {
		c.health(l)
	}
	c.prune()
}

// health pauses sales while lookups fail and resumes them once the wallet
// answers, with one alert per outage (not one per order), and merges the
// pass's per-order news into one alert each.
func (c *Checkout) health(l *lookups) {
	c.mu.Lock()
	was := c.paused
	open := 0
	for _, o := range c.orders {
		if o.Status == StatusPending {
			open++
		}
	}
	// A pass is bad when its lookups got no answer at all, or failed more
	// often than not. Sales pause at once on a configuration error, and on
	// other trouble after two bad passes in a row, so a one-off timeout
	// pauses nothing. A pass that got answers and was not bad resumes them.
	bad := l.failures > 0 && (l.answers == 0 || l.failures > l.answers)
	switch {
	case l.config:
		c.badPasses++
		c.paused = l.trouble
	case bad:
		c.badPasses++
		if c.badPasses >= 2 {
			c.paused = l.trouble
		}
	case l.answers > 0:
		c.badPasses = 0
		c.paused = ""
	}
	now := c.paused
	c.mu.Unlock()
	switch {
	case now != "" && was == "" && l.config:
		c.cfg.Alert("speakeasy: payments paused: the wallet refuses lookup_invoice, a configuration error; make the NWC connection with make_invoice and lookup_invoice",
			"code", l.trouble, "open_orders", open)
	case now != "" && was == "":
		c.cfg.Alert("speakeasy: payments paused: the wallet cannot be asked about invoices; open orders stay open until it answers",
			"reason", l.trouble, "open_orders", open)
	case now == "" && was != "":
		c.cfg.Log("speakeasy: the wallet answers again; payments resume", "was", was)
	}
	// During an outage (or a bad pass that may start one) its one alert
	// covers them; this is for orders the wallet answers about (NOT_FOUND).
	if l.newlyFailing > 0 && now == "" && !bad && !l.config {
		c.cfg.Alert("speakeasy: invoices that can no longer be paid cannot be checked (the wallet does not know them, or did not answer); they stay open until it answers",
			"orders", l.newlyFailing)
	}
	if l.gaveUp+l.dropped > 0 {
		c.cfg.Alert("speakeasy: gave up on orders the wallet never answered about; check the wallet by hand (grain_speakeasy_payments lists them)",
			"orders", l.gaveUp+l.dropped)
	}
}

func (c *Checkout) markLooked(id string) {
	c.mu.Lock()
	c.lastLookup[id] = c.cfg.Now()
	c.mu.Unlock()
}

// lookup asks the wallet about one pending order.
func (c *Checkout) lookup(ctx context.Context, l *lookups, o Order) {
	inv, err := l.lookup(ctx, o.PaymentHash)
	if ctx.Err() != nil {
		return // shutting down: nothing learned, nothing counted
	}
	c.markLooked(o.ID)
	now := c.cfg.Now()
	if err == nil && inv.Settled() {
		c.settle(o, inv, false)
		return
	}
	if err != nil {
		// No answer, or NOT_FOUND (a rotated connection may not see
		// invoices another one made): never close an order on that, since
		// it may have been paid. Once it can no longer be paid, tell the
		// owner once and keep asking; give up only after GiveUp.
		c.cfg.Log("speakeasy: invoice lookup failed", "order", o.ID, "error", err.Error())
		if now.Unix() > o.ExpiresAt && !o.LookupFailing {
			l.newlyFailing++ // one alert for the pass (health)
			c.update(o.ID, func(x *Order) { x.LookupFailing = true })
		}
		if now.Unix() > o.WatchUntil+int64(GiveUp/time.Second) {
			o.Status, o.Outcome = StatusUnknown, "unknown: the wallet never answered; check the wallet for payment hash "+o.PaymentHash
			c.ledger(o)
			l.gaveUp++
			c.update(o.ID, func(x *Order) { x.Status, x.Outcome, x.ClosedAt = o.Status, o.Outcome, now.Unix() })
		}
		return
	}
	// The wallet answered: not paid. Close it once the watch has ended.
	if now.Unix() > o.WatchUntil {
		c.update(o.ID, func(x *Order) { x.Status = StatusExpired })
	}
}

// finalLookup asks once more about an expired order before it is dropped:
// a payment that settled after all is applied (or owed back), never lost.
func (c *Checkout) finalLookup(ctx context.Context, l *lookups, o Order) {
	inv, err := l.lookup(ctx, o.PaymentHash)
	if ctx.Err() != nil {
		return
	}
	c.markLooked(o.ID)
	switch {
	case err == nil && inv.Settled():
		c.cfg.Alert("speakeasy: an expired order was paid after all; applying it", "order", o.ID, "region", o.Region, "payment_hash", o.PaymentHash)
		c.settle(o, inv, true)
	case err == nil:
		c.drop(o.ID) // answered: never paid
	case c.cfg.Now().Unix() > o.WatchUntil+int64(GiveUp/time.Second):
		o.Outcome = "unknown: no last answer from the wallet; check the wallet for payment hash " + o.PaymentHash
		c.ledger(o)
		l.dropped++
		c.drop(o.ID)
	}
}

// settle records a paid invoice and applies it, or holds it when the wallet
// describes it differently from the order.
func (c *Checkout) settle(o Order, inv nwc.Invoice, late bool) {
	if why := mismatch(o, inv); why != "" {
		// Never apply a payment the wallet describes differently: it is not
		// (provably) the invoice this order made.
		c.cfg.Alert("speakeasy: the wallet's paid invoice does not match the order; not applied", "order", o.ID, "payment_hash", o.PaymentHash, "why", why)
		held := OutcomeHeld + why
		o.Status, o.Applied, o.Outcome = StatusPaid, true, held
		c.ledger(o)
		seen := c.cfg.Now().Unix()
		c.update(o.ID, func(x *Order) { x.Status, x.Applied, x.Outcome, x.ClosedAt = StatusPaid, true, held, seen })
		return
	}
	settled := inv.SettledAt
	if settled == 0 {
		settled = c.cfg.Now().Unix()
	}
	seen := c.cfg.Now().Unix()
	c.update(o.ID, func(x *Order) { x.Status, x.SettledAt, x.ClosedAt = StatusPaid, settled, seen })
	c.cfg.Log("speakeasy: invoice paid", "order", o.ID, "region", o.Region, "sats", o.AmountSats, "payment_hash", o.PaymentHash, "late", late)
	c.apply(o.ID)
}

// mismatch says how a paid invoice differs from the order, or "". The
// payment hash must be there and equal, and the amount there and at least
// the price (an overpayment is allowed, BOLT 11; creation requires the
// exact amount); the
// description and invoice, when the wallet gives them, must be ours.
func mismatch(o Order, inv nwc.Invoice) string {
	switch {
	case inv.PaymentHash == "":
		return "the wallet's answer has no payment hash"
	case !strings.EqualFold(inv.PaymentHash, o.PaymentHash):
		return "payment hash"
	case inv.Amount == 0:
		return "the wallet's answer has no amount"
	case inv.Amount < o.AmountSats*1000:
		// BOLT 11 lets a payer pay more than asked; less is never enough.
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
	outcome, retry := c.applyTo(o)
	if retry != nil {
		c.cfg.Alert("speakeasy: paid but the registry write failed; retrying", "order", o.ID, "region", o.Region, "error", retry.Error())
		return
	}
	if NeedsOwner(outcome) {
		c.cfg.Alert("speakeasy: paid but bought nothing; a refund is owed", "order", o.ID, "region", o.Region,
			"sats", o.AmountSats, "payment_hash", o.PaymentHash, "outcome", outcome)
	}
	// The ledger first: after a crash in between, a line twice is better
	// than none.
	o.Applied, o.Outcome = true, outcome
	c.ledger(o)
	c.update(id, func(x *Order) { x.Applied, x.Outcome = true, outcome })
	c.cfg.Log("speakeasy: order applied", "order", o.ID, "region", o.Region, "outcome", outcome)
}

// applyTo writes a paid order into the registry and says how it ended, or
// returns an error worth retrying (the registry could not be written). An
// entry that already carries this order's payment hash is this order's
// own write, made before a crash kept the order from being marked applied.
func (c *Checkout) applyTo(o Order) (string, error) {
	reg := c.cfg.Registry
	if sp := reg.Get(o.Region); sp != nil {
		if sp.PaymentHash == o.PaymentHash {
			return OutcomeRegistered, nil
		}
		return OutcomeAlready, nil
	}
	_, err := reg.Add(Entry{
		ID: o.Region, CreatedAt: o.SettledAt, PaymentHash: o.PaymentHash,
		Note: fmt.Sprintf("paid %d sats, payment hash %s", o.AmountSats, o.PaymentHash),
	})
	switch {
	case err == nil:
		return OutcomeRegistered, nil
	case reg.Get(o.Region) != nil: // added in between
		return c.applyTo(o)
	}
	return "", err
}

// ledger appends an order to the ledger, the record that outlives the
// orders file.
func (c *Checkout) ledger(o Order) {
	if c.cfg.LedgerPath == "" {
		return
	}
	o.LineID = newID()
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

// Ledger reads the ledger: every paid, held, refund-owed and unknown order
// ever recorded, oldest first (a line written twice after a crash appears
// twice).
func (c *Checkout) Ledger() ([]Order, error) {
	data, err := os.ReadFile(c.cfg.LedgerPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Order
	for _, line := range strings.Split(string(data), "\n") {
		var o Order
		if strings.TrimSpace(line) != "" && json.Unmarshal([]byte(line), &o) == nil {
			out = append(out, o)
		}
	}
	return out, nil
}

// Resolution is the owner's mark that one ledger line needing them (a
// refund owed, held, unknown) is settled.
type Resolution struct {
	LineID      string `json:"line_id"`
	PaymentHash string `json:"payment_hash"`
	Outcome     string `json:"outcome"`
	Note        string `json:"note"`
	ResolvedAt  int64  `json:"resolved_at"`
}

// ErrNothingToResolve: no open line needing the owner has that id.
var ErrNothingToResolve = errors.New("no open payment line needing the owner has that line id")

// Resolve marks one ledger line the owner settled by hand (a refund paid,
// a held payment checked), by its line id, appending to ResolvedPath; the
// ledger is not changed. A later line for the same payment hash with
// another outcome stays listed.
func (c *Checkout) Resolve(lineID, note string) (Resolution, error) {
	open, err := c.NeedsOwnerOpen()
	if err != nil {
		return Resolution{}, err
	}
	var line *Order
	for i := range open {
		if open[i].LineID == lineID {
			line = &open[i]
		}
	}
	if line == nil {
		return Resolution{}, ErrNothingToResolve
	}
	r := Resolution{LineID: lineID, PaymentHash: line.PaymentHash, Outcome: line.Outcome, Note: note, ResolvedAt: c.cfg.Now().Unix()}
	data, _ := json.Marshal(r)
	f, err := os.OpenFile(c.cfg.ResolvedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Resolution{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return Resolution{}, err
	}
	return r, f.Sync()
}

// NeedsOwnerOpen is every ledger line the owner must settle by hand (a
// refund owed, held, or unknown) and has not resolved, oldest first. A
// line written twice (a crash between the ledger and the orders file) is
// one item: same payment hash and outcome; resolving either resolves both.
func (c *Checkout) NeedsOwnerOpen() ([]Order, error) {
	lines, err := c.Ledger()
	if err != nil {
		return nil, err
	}
	type key struct{ hash, outcome string }
	resolved := map[key]bool{}
	if c.cfg.ResolvedPath != "" {
		data, err := os.ReadFile(c.cfg.ResolvedPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			var r Resolution
			if json.Unmarshal([]byte(line), &r) == nil && r.LineID != "" {
				resolved[key{r.PaymentHash, r.Outcome}] = true
			}
		}
	}
	out := []Order{}
	seen := map[key]bool{}
	for _, o := range lines {
		k := key{o.PaymentHash, o.Outcome}
		if !(NeedsOwner(o.Outcome) || strings.HasPrefix(o.Outcome, "unknown:")) || resolved[k] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, o)
	}
	return out, nil
}

func (c *Checkout) update(id string, f func(*Order)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if o := c.orders[id]; o != nil {
		f(o)
		c.changedLocked()
	}
}

func (c *Checkout) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.orders, id)
	delete(c.lastLookup, id)
	c.changedLocked()
}

// changedLocked saves the orders, or, during a poll pass, marks them for
// the pass's one save at its end: the file is written at most once per
// pass, whatever the number of orders. Called with mu held.
func (c *Checkout) changedLocked() {
	if c.batching {
		c.dirty = true
		return
	}
	if err := c.saveLocked(); err != nil {
		c.cfg.Alert("speakeasy: could not save the orders", "error", err.Error())
	}
}

// prune drops applied and unknown orders kept past keepClosed since they
// closed (their watch ended, they settled, or they were given up on).
// Expired ones are dropped only by their last lookup (finalLookup).
func (c *Checkout) prune() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cut := c.cfg.Now().Add(-keepClosed).Unix()
	n := len(c.orders)
	for id, o := range c.orders {
		done := o.Status == StatusPaid && o.Applied || o.Status == StatusUnknown
		if done && max(o.WatchUntil, o.SettledAt, o.ClosedAt) < cut {
			delete(c.orders, id)
			delete(c.lastLookup, id)
		}
	}
	if len(c.orders) != n {
		c.changedLocked()
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

// validBolt11 accepts a BOLT 11 invoice's shape: "ln", a human-readable
// part of letters and digits, the separator "1", and data in bech32's
// characters only (which has no "1", so the last "1" is the separator).
// It is then safe in a lightning: link.
func validBolt11(s string) bool {
	s = strings.ToLower(s)
	if len(s) < 20 || len(s) > 2048 || !strings.HasPrefix(s, "ln") {
		return false
	}
	sep := strings.LastIndexByte(s, '1')
	if sep < 3 || len(s)-sep < 8 {
		return false
	}
	for i := 0; i < sep; i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	for i := sep + 1; i < len(s); i++ {
		if !strings.ContainsRune(bech32Chars, rune(s[i])) {
			return false
		}
	}
	return true
}

const bech32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

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

// bolt11Msat is the amount a BOLT 11 invoice's human-readable part
// encodes, in millisatoshis, or 0 when it has none or cannot be read:
// "ln" + currency letters + amount digits + an optional multiplier (m, u,
// n, p), up to the last "1".
func bolt11Msat(inv string) int64 {
	inv = strings.ToLower(inv)
	sep := strings.LastIndexByte(inv, '1')
	if !strings.HasPrefix(inv, "ln") || sep < 3 {
		return 0
	}
	hrp := inv[2:sep]
	i := 0
	for i < len(hrp) && hrp[i] >= 'a' && hrp[i] <= 'z' {
		i++
	}
	num := hrp[i:]
	if num == "" {
		return 0
	}
	mult := byte(0)
	if last := num[len(num)-1]; last < '0' || last > '9' {
		mult, num = last, num[:len(num)-1]
	}
	if num == "" || len(num) > 15 || num[0] == '0' {
		return 0
	}
	var n int64
	for j := 0; j < len(num); j++ {
		if num[j] < '0' || num[j] > '9' {
			return 0
		}
		n = n*10 + int64(num[j]-'0')
	}
	// 1 BTC = 100,000,000,000 msat.
	var factor int64
	switch mult {
	case 0:
		factor = 100_000_000_000
	case 'm':
		factor = 100_000_000
	case 'u':
		factor = 100_000
	case 'n':
		factor = 100
	case 'p':
		if n%10 != 0 {
			return 0 // BOLT 11: a pico amount must be whole millisatoshis
		}
		return n / 10
	default:
		return 0
	}
	if n > (1<<62)/factor {
		return 0
	}
	return n * factor
}
