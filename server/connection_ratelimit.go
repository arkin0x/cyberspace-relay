package server

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/0ceanslim/grain/config"
	cfgType "github.com/0ceanslim/grain/config/types"
	"github.com/0ceanslim/grain/server/regiongate"
	"github.com/0ceanslim/grain/server/utils"
	"github.com/0ceanslim/grain/server/utils/log"
)

// Per-IP connection-attempt rate limiting and aggregated rejection logging.
//
// The relay used to log one WARN per rejected connection. v0.5.0 production
// logs hit 169,272 max-conn WARNs over four hours (peak 720/min). The
// relay correctly bounced them, but every other useful signal drowned in
// the spam. This file replaces that with two coupled mechanisms:
//
//  1. A pre-upgrade per-IP attempt limiter that runs in the HTTP handler
//     before websocket.Server.ServeHTTP, so a connection storm pays only
//     the cost of a TCP accept + 429, not a full WS upgrade.
//  2. An aggregator that batches rejection counts (max-conn, per-IP rate
//     limit, blocked-IP) and emits one WARN per minute with the top
//     offending IPs, instead of one per rejection.
//
// See issue #61 for the production data and #62 for the IP-blocklist
// follow-on that consumes RecordIPViolation.

// ipBucket tracks a single IP's connection attempts inside the current
// 60-second window. lastSeen lets the cleanup goroutine evict idle
// buckets so memory under sustained scanning is bounded.
type ipBucket struct {
	mu          sync.Mutex
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

var (
	ipBuckets sync.Map // map[string]*ipBucket
)

// CheckIPConnectionRate consumes one attempt from the given IP's bucket.
// Returns false if the attempt would put the IP over limitPerMinute and
// must be rejected. limitPerMinute=0 disables the check.
//
// Each rejection here is also reported to RecordIPViolation so #62's
// auto-escalation has a feed to consume.
func CheckIPConnectionRate(ip string, limitPerMinute int) bool {
	if limitPerMinute <= 0 {
		return true
	}
	if ip == "" {
		// Unknown IP — don't bucket against the empty string, just allow.
		// The max-conn cap and per-client rate limiter still apply.
		return true
	}
	if takeAttempt(ip, limitPerMinute) {
		return true
	}
	RecordIPViolation(ip)
	return false
}

// takeAttempt consumes one attempt from the bucket named key and reports
// whether it was within limitPerMinute.
func takeAttempt(key string, limitPerMinute int) bool {
	now := time.Now()
	v, _ := ipBuckets.LoadOrStore(key, &ipBucket{windowStart: now})
	b := v.(*ipBucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	if now.Sub(b.windowStart) >= time.Minute {
		b.windowStart = now
		b.count = 0
	}
	b.lastSeen = now
	b.count++
	return b.count <= limitPerMinute
}

// CheckSpeakeasyConnectionRate is CheckIPConnectionRate for a websocket to
// one speakeasy (server/speakeasies.go). Its buckets are apart from the
// root's and keyed by the host's address (an IPv4 address or an IPv6 /64):
//
//   - every attempt, passed or refused, is charged to one bucket per
//     address for all speakeasies at speakeasyBudgetFactor times the limit,
//     and going over it is a rate violation (RecordIPViolation), which
//     escalates to a ban as at the root: a flood is stopped;
//   - each (address, speakeasy) pair also has its own bucket at the limit,
//     whose refusals are counted but never escalated, so a player inside
//     several nested speakeasies who redials them all on a resume, and
//     retries a few, is refused at worst, never banned.
//
// The root's bucket and its escalation are unchanged; a blocked IP is
// still refused at a speakeasy (403).
func CheckSpeakeasyConnectionRate(ip, speakeasyID string, limitPerMinute int) bool {
	if limitPerMinute <= 0 || ip == "" {
		return true
	}
	key := regiongate.AddressBucket(ip)
	if !takeAttempt(key+"\x00speakeasies", speakeasyBudgetFactor*limitPerMinute) {
		// Charged to the address's key (an IPv6 /64), so a host rotating
		// addresses inside its /64 escalates as one, and is banned as one.
		RecordIPViolation(key)
		return false
	}
	if !takeAttempt(key+"\x00speakeasy:"+speakeasyID, limitPerMinute) {
		RecordRejection("rate_limit", ip)
		return false
	}
	return true
}

// speakeasyBudgetFactor sizes the per-address bucket all speakeasies
// share, as a multiple of connection_rate_limit_per_ip.
const speakeasyBudgetFactor = 4

// ── open sockets per address ─────────────────────────────────────────────

// DefaultMaxOpenSocketsPerIP is max_open_sockets_per_ip when unset:
// generous, since a carrier NAT puts many players behind one address.
const DefaultMaxOpenSocketsPerIP = 32

var openSockets = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

// openSocketLimit is the configured cap on open websockets per address.
// 0 (unset) is the default; negative turns it off.
func openSocketLimit(cfg *cfgType.ServerConfig) int {
	if cfg == nil {
		return 0
	}
	switch v := cfg.Server.MaxOpenSocketsPerIP; {
	case v == 0:
		return DefaultMaxOpenSocketsPerIP
	case v < 0:
		return 0
	default:
		return v
	}
}

// takeSocket reserves one open websocket for ip's address (an IPv4 address
// or an IPv6 /64), across the root and every speakeasy, so one host cannot
// fill server.max_connections. It returns the release, or false when the
// address already holds limit sockets. limit 0 is off.
func takeSocket(ip string, limit int) (release func(), ok bool) {
	if limit <= 0 || ip == "" {
		return func() {}, true
	}
	key := regiongate.AddressBucket(ip)
	openSockets.Lock()
	defer openSockets.Unlock()
	if openSockets.n[key] >= limit {
		return nil, false
	}
	openSockets.n[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			openSockets.Lock()
			defer openSockets.Unlock()
			if openSockets.n[key]--; openSockets.n[key] <= 0 {
				delete(openSockets.n, key)
			}
		})
	}, true
}

// EnforceOpenSockets reserves an open websocket for the request's address
// before the upgrade, or answers 429 and returns false. The caller runs
// release when the socket closes (websocket.Server.ServeHTTP returns then).
func EnforceOpenSockets(w http.ResponseWriter, r *http.Request, cfg *cfgType.ServerConfig) (release func(), ok bool) {
	ip := utils.GetClientIP(r)
	release, ok = takeSocket(ip, openSocketLimit(cfg))
	if !ok {
		RecordRejection("max_conn_ip", ip)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many open connections from your address", http.StatusTooManyRequests)
	}
	return release, ok
}

// EnforceSpeakeasyConnectionRateLimit is EnforceConnectionRateLimit for a
// websocket to speakeasy speakeasyID: the IP block list (403), then the
// speakeasy's own per-IP bucket (429), with no escalation.
func EnforceSpeakeasyConnectionRateLimit(w http.ResponseWriter, r *http.Request, speakeasyID string, limitPerMinute int) bool {
	ip := utils.GetClientIP(r)
	if blocked, _ := config.IsIPBlocked(ip); blocked {
		RecordRejection("blocked", ip)
		w.WriteHeader(http.StatusForbidden)
		return false
	}
	if CheckSpeakeasyConnectionRate(ip, speakeasyID, limitPerMinute) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	return false
}

// startBucketCleanup runs in the background, evicting per-IP buckets idle
// for more than 5 minutes. Bounds memory under address-space scanning.
func startBucketCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-5 * time.Minute)
				ipBuckets.Range(func(k, v interface{}) bool {
					b := v.(*ipBucket)
					b.mu.Lock()
					idle := b.lastSeen.Before(cutoff)
					b.mu.Unlock()
					if idle {
						ipBuckets.Delete(k)
					}
					return true
				})
			}
		}
	}()
}

// Rejection aggregator.
//
// Three reject categories are tracked: max-conn (post-upgrade gate),
// rate-limit (pre-upgrade per-IP), and blocklist (pre-upgrade IP block,
// once #62 lands). Each tracked rejection bumps its counter and the
// per-IP top-offender map. Once per minute the aggregator emits one
// WARN summarizing all three counts and the top 5 offending IPs,
// then resets.

type rejectionStats struct {
	mu          sync.Mutex
	maxConn     int
	maxConnPath int // a speakeasy at max_connections_per_path
	maxConnIP   int // an address at max_open_sockets_per_ip
	rateLimit   int
	blocked     int
	topIPs      map[string]int
}

var rejAgg = &rejectionStats{topIPs: make(map[string]int)}

// RecordRejection bumps the appropriate counter for a rejected connection
// attempt. category is one of: "max_conn", "max_conn_path",
// "max_conn_ip", "rate_limit", "blocked". ip is
// the offending IP (may be empty if unknown — in that case the counter
// still advances but no IP is attributed).
func RecordRejection(category, ip string) {
	rejAgg.mu.Lock()
	defer rejAgg.mu.Unlock()
	switch category {
	case "max_conn":
		rejAgg.maxConn++
	case "max_conn_path":
		rejAgg.maxConnPath++
	case "max_conn_ip":
		rejAgg.maxConnIP++
	case "rate_limit":
		rejAgg.rateLimit++
	case "blocked":
		rejAgg.blocked++
	}
	if ip != "" {
		rejAgg.topIPs[ip]++
	}
}

// RecordIPViolation is the per-IP rate-limit hook. It feeds the
// rejection aggregator and drives #62's auto-escalation state machine
// (config.RecordIPRateViolation), so a rate-limit hit can graduate to a
// temp ban and eventually a permanent block. The escalation no-ops if
// the relevant thresholds in BlacklistConfig are unset.
func RecordIPViolation(ip string) {
	RecordRejection("rate_limit", ip)
	if cfg := config.GetConfig(); cfg != nil {
		config.RecordIPRateViolation(ip, cfg.Blacklist)
	}
}

// startRejectionAggregator emits one summary WARN per minute. If no
// rejections happened in the window, nothing is logged.
func startRejectionAggregator(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				emitAndReset()
			}
		}
	}()
}

// emitAndReset snapshots the aggregator under lock, resets it, and
// (outside the lock) emits the summary WARN if anything happened.
func emitAndReset() {
	rejAgg.mu.Lock()
	if rejAgg.maxConn == 0 && rejAgg.maxConnPath == 0 && rejAgg.maxConnIP == 0 && rejAgg.rateLimit == 0 && rejAgg.blocked == 0 {
		rejAgg.mu.Unlock()
		return
	}
	maxConn, rateLimit, blocked := rejAgg.maxConn, rejAgg.rateLimit, rejAgg.blocked
	maxConnPath, maxConnIP := rejAgg.maxConnPath, rejAgg.maxConnIP
	ips := make([]string, 0, len(rejAgg.topIPs))
	for ip := range rejAgg.topIPs {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return rejAgg.topIPs[ips[i]] > rejAgg.topIPs[ips[j]] })
	top := make([]string, 0, 5)
	for i := 0; i < len(ips) && i < 5; i++ {
		top = append(top, ips[i]+":"+itoa(rejAgg.topIPs[ips[i]]))
	}
	rejAgg.maxConn = 0
	rejAgg.maxConnPath = 0
	rejAgg.maxConnIP = 0
	rejAgg.rateLimit = 0
	rejAgg.blocked = 0
	rejAgg.topIPs = make(map[string]int)
	rejAgg.mu.Unlock()

	log.RelayClient().Warn("Connection rejections (last minute)",
		"max_conn", maxConn,
		"max_conn_path", maxConnPath,
		"max_conn_ip", maxConnIP,
		"rate_limit", rateLimit,
		"blocked", blocked,
		"top_offending_ips", top)
}

// itoa avoids a strconv import for this single call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// startConnectionRejectionInfrastructure starts the cleanup and
// aggregator goroutines. Idempotent only insofar as InitStatsMonitoring
// itself is called once at startup; do not call this directly.
func startConnectionRejectionInfrastructure(ctx context.Context) {
	startBucketCleanup(ctx)
	startRejectionAggregator(ctx)
}

// EnforceConnectionRateLimit is the HTTP middleware-style guard that runs
// before the WebSocket upgrade. It enforces, in order:
//
//  1. IP block list (#62) — both admin-curated and auto-escalated. 403.
//  2. Per-IP attempt rate limit (#61). 429 + Retry-After.
//
// Returns true if the request should be allowed to proceed to the WS
// upgrade. limitPerMinute=0 disables the rate-limit stage; the block
// check still runs because there's no equivalent kill switch — admins
// who want it off should empty their lists.
func EnforceConnectionRateLimit(w http.ResponseWriter, r *http.Request, limitPerMinute int) bool {
	ip := utils.GetClientIP(r)

	// IP block list short-circuits before rate counting so a banned IP
	// doesn't get to consume tokens and pollute the top-offenders map
	// with rate_limit events instead of blocked events.
	if blocked, _ := config.IsIPBlocked(ip); blocked {
		RecordRejection("blocked", ip)
		w.WriteHeader(http.StatusForbidden)
		return false
	}

	if limitPerMinute <= 0 {
		return true
	}
	if CheckIPConnectionRate(ip, limitPerMinute) {
		return true
	}
	// CheckIPConnectionRate already routed through RecordIPViolation,
	// which credits the rate_limit counter, the top-IP map, and the
	// auto-escalation state machine.
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	return false
}
