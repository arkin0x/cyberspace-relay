package server

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0ceanslim/grain/config"
	cfgType "github.com/0ceanslim/grain/config/types"
)

// withEscalation turns on the IP ban escalation (a ban after 2 rate
// violations), as an operator's blacklist settings would.
func withEscalation(t *testing.T) {
	t.Helper()
	old := config.GetConfig()
	config.SetConfigForTesting(&cfgType.ServerConfig{Blacklist: cfgType.BlacklistConfig{
		IPRateViolationThreshold: 1, IPMaxTempBans: 3, IPTempBanDuration: 600,
	}})
	config.ResetIPBlocklistForTest()
	resetRateLimitState()
	t.Cleanup(func() {
		config.SetConfigForTesting(old)
		config.ResetIPBlocklistForTest()
		resetRateLimitState()
	})
}

// TestNestedSpeakeasiesDoNotBanAPlayer: a player inside three nested
// speakeasies redials them and the root on every resume. Each speakeasy
// has its own budget, so the resumes that fit the root's budget fit every
// speakeasy's too, and nothing escalates.
func TestNestedSpeakeasiesDoNotBanAPlayer(t *testing.T) {
	withEscalation(t)
	const ip, limit = "21.21.21.21", 3
	for resume := 0; resume < limit; resume++ {
		if !CheckIPConnectionRate(ip, limit) {
			t.Fatalf("resume %d: root refused", resume)
		}
		for _, id := range []string{"a", "ab", "abc"} {
			if !CheckSpeakeasyConnectionRate(ip, id, limit) {
				t.Fatalf("resume %d: speakeasy %s refused", resume, id)
			}
		}
	}
	if blocked, _ := config.IsIPBlocked(ip); blocked {
		t.Fatal("a player with nested speakeasies was banned")
	}
}

// TestSpeakeasyBudgetLimits, at the real limit (30 a minute): a normal
// client, one resume plus three retries across five nested speakeasies, is
// never refused or banned; a flood against one speakeasy is refused past
// its own budget, and once it has spent the shared budget (every attempt
// counts, passed or refused), escalated to a ban.
func TestSpeakeasyBudgetLimits(t *testing.T) {
	withEscalation(t)
	const limit = 30
	normal, flood := "25.25.25.25", "26.26.26.26"
	for try := 0; try < 4; try++ {
		for _, id := range []string{"a", "ab", "abc", "abcd", "abcde"} {
			if !CheckSpeakeasyConnectionRate(normal, id, limit) {
				t.Fatalf("a normal client was refused at %s, try %d", id, try)
			}
		}
	}
	if blocked, _ := config.IsIPBlocked(normal); blocked {
		t.Fatal("a normal client was banned")
	}
	refused := 0
	for i := 0; i < speakeasyBudgetFactor*limit; i++ {
		if !CheckSpeakeasyConnectionRate(flood, "a", limit) {
			refused++
		}
	}
	if refused != speakeasyBudgetFactor*limit-limit {
		t.Fatalf("%d refused within the shared budget, want %d (past its own)", refused, speakeasyBudgetFactor*limit-limit)
	}
	if blocked, _ := config.IsIPBlocked(flood); blocked {
		t.Fatal("banned while still inside the shared budget")
	}
	for i := 0; i < 3; i++ {
		CheckSpeakeasyConnectionRate(flood, "a", limit)
	}
	if blocked, _ := config.IsIPBlocked(flood); !blocked {
		t.Fatal("a flood past the shared budget was never banned")
	}
}

// TestSpeakeasyBucketsCountBySlash64: two IPv6 addresses in one /64 share
// the speakeasy buckets; another /64 does not.
func TestSpeakeasyBucketsCountBySlash64(t *testing.T) {
	withEscalation(t)
	const limit = 2
	if !CheckSpeakeasyConnectionRate("2001:db8:1:1::1", "a", limit) || !CheckSpeakeasyConnectionRate("2001:db8:1:1::2", "a", limit) {
		t.Fatal("refused inside the budget")
	}
	if CheckSpeakeasyConnectionRate("2001:db8:1:1:ffff::3", "a", limit) {
		t.Fatal("a third address in the same /64 got its own budget")
	}
	if !CheckSpeakeasyConnectionRate("2001:db8:1:2::1", "a", limit) {
		t.Fatal("another /64 was refused")
	}
}

// TestOpenSocketsPerAddress: at most the cap of open sockets per IPv4
// address or IPv6 /64; a release frees one; release is safe to call twice;
// a negative setting is off and unset is the default.
func TestOpenSocketsPerAddress(t *testing.T) {
	var rel []func()
	for i := 0; i < 2; i++ {
		r, ok := takeSocket(fmt.Sprintf("2001:db8:9:9::%d", i), 2)
		if !ok {
			t.Fatalf("socket %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := takeSocket("2001:db8:9:9::7", 2); ok {
		t.Fatal("a third socket for one /64")
	}
	if r, ok := takeSocket("2001:db8:9:a::7", 2); !ok {
		t.Fatal("another /64 refused")
	} else {
		r()
	}
	rel[0]()
	rel[0]()
	if r, ok := takeSocket("2001:db8:9:9::7", 2); !ok {
		t.Fatal("not freed by a release")
	} else {
		r()
	}
	rel[1]()
	for v, want := range map[int]int{0: DefaultMaxOpenSocketsPerIP, -1: 0, 5: 5} {
		cfg := &cfgType.ServerConfig{}
		cfg.Server.MaxOpenSocketsPerIP = v
		if got := openSocketLimit(cfg); got != want {
			t.Errorf("setting %d: limit %d, want %d", v, got, want)
		}
	}
	openSockets.Lock()
	defer openSockets.Unlock()
	if len(openSockets.n) != 0 {
		t.Fatalf("counts left: %v", openSockets.n)
	}
}

// TestRejectionCategories: the speakeasy and per-address caps are counted
// in the summary.
func TestRejectionCategories(t *testing.T) {
	resetRateLimitState()
	RecordRejection("max_conn_path", "1.1.1.1")
	RecordRejection("max_conn_ip", "1.1.1.1")
	rejAgg.mu.Lock()
	defer rejAgg.mu.Unlock()
	if rejAgg.maxConnPath != 1 || rejAgg.maxConnIP != 1 || rejAgg.topIPs["1.1.1.1"] != 2 {
		t.Fatalf("%+v", rejAgg)
	}
}

// TestManySpeakeasiesFromOneIPStillEscalate: one IP opening sockets to many
// speakeasies passes each one's own bucket, but the bucket they share (4
// times the limit) refuses it past that and escalates to a ban.
func TestManySpeakeasiesFromOneIPStillEscalate(t *testing.T) {
	withEscalation(t)
	const ip, limit = "24.24.24.24", 3
	passed := 0
	for i := 0; i < 10; i++ {
		for j := 0; j < limit; j++ {
			if CheckSpeakeasyConnectionRate(ip, fmt.Sprintf("a%d", i), limit) {
				passed++
			}
		}
	}
	if passed != speakeasyBudgetFactor*limit {
		t.Fatalf("%d sockets passed across 10 speakeasies, want %d", passed, speakeasyBudgetFactor*limit)
	}
	if blocked, _ := config.IsIPBlocked(ip); !blocked {
		t.Fatal("an IP spreading sockets over many speakeasies was never banned")
	}
}

// TestRootEscalationIsKept: the root's budget and its escalation are as
// before, and a banned IP is refused at a speakeasy too.
func TestRootEscalationIsKept(t *testing.T) {
	withEscalation(t)
	const ip, limit = "23.23.23.23", 2
	for i := 0; i < limit+2; i++ {
		CheckIPConnectionRate(ip, limit)
	}
	if blocked, _ := config.IsIPBlocked(ip); !blocked {
		t.Fatal("the root's rate violations no longer ban")
	}
	r := httptest.NewRequest("GET", "/a", nil)
	r.RemoteAddr = ip + ":1"
	w := httptest.NewRecorder()
	if EnforceSpeakeasyConnectionRateLimit(w, r, "a", limit) || w.Code != 403 {
		t.Fatalf("a banned IP at a speakeasy: %d", w.Code)
	}
}

// TestSpeakeasySocketsHaveTheirOwnBudget, over real websockets: with the
// root's budget spent, a speakeasy still accepts its own; past its own, it
// answers 429; the root stays refused.
func TestSpeakeasySocketsHaveTheirOwnBudget(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	r.register(t, "ab")
	cfg := config.GetConfig()
	old := cfg.Server.ConnectionRateLimitPerIP
	cfg.Server.ConnectionRateLimitPerIP = 2
	resetRateLimitState()
	t.Cleanup(func() { cfg.Server.ConnectionRateLimitPerIP = old; resetRateLimitState() })

	// The root's websocket rate limit runs in initRoot; the test harness
	// mounts initRoot, so the root path is limited as in production.
	for i := 0; i < 2; i++ {
		mustDial(t, r.wsRoot)
	}
	if _, err := dial(t, r.wsRoot); err == nil {
		t.Fatal("the root's third socket in a minute was accepted")
	}
	for i := 0; i < 2; i++ {
		if _, err := dial(t, r.wsRoot+"/C/ab"); err != nil {
			t.Fatalf("speakeasy socket %d after the root's budget was spent: %v", i, err)
		}
	}
	if _, err := dial(t, r.wsRoot+"/C/ab"); err == nil {
		t.Fatal("the speakeasy's third socket in a minute was accepted")
	}
}

// TestOpenSocketCapOverWebsockets: with max_open_sockets_per_ip 2, one root
// socket and one speakeasy socket from an address fill it; a third, at
// either, is refused (429); closing one frees a place.
func TestOpenSocketCapOverWebsockets(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	r.register(t, "ab")
	cfg := config.GetConfig()
	old := cfg.Server.MaxOpenSocketsPerIP
	cfg.Server.MaxOpenSocketsPerIP = 2
	t.Cleanup(func() { cfg.Server.MaxOpenSocketsPerIP = old })
	root := mustDial(t, r.wsRoot)
	mustDial(t, r.wsRoot+"/C/ab")
	if _, err := dial(t, r.wsRoot); err == nil {
		t.Fatal("a third socket at the root was accepted")
	}
	if _, err := dial(t, r.wsRoot+"/C/ab"); err == nil {
		t.Fatal("a third socket at the speakeasy was accepted")
	}
	root.ws.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := dial(t, r.wsRoot+"/C/ab"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing a socket freed no place")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestOpenSocketCapComesFirst (second re-check, #29): refusals by the
// open-socket cap spend no rate tokens and are no rate violations, at the
// root and at a speakeasy: past the cap, retries are refused 429 by the
// cap alone, and once a socket closes the next connection is accepted.
func TestOpenSocketCapComesFirst(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	r.register(t, "ab")
	cfg := config.GetConfig()
	oldCap, oldRate := cfg.Server.MaxOpenSocketsPerIP, cfg.Server.ConnectionRateLimitPerIP
	cfg.Server.MaxOpenSocketsPerIP, cfg.Server.ConnectionRateLimitPerIP = 1, 3
	t.Cleanup(func() {
		cfg.Server.MaxOpenSocketsPerIP, cfg.Server.ConnectionRateLimitPerIP = oldCap, oldRate
		resetRateLimitState()
	})
	for _, path := range []string{"", "/C/ab"} {
		resetRateLimitState()
		held := mustDial(t, r.wsRoot+path) // one rate token
		for i := 0; i < 6; i++ {
			if _, err := dial(t, r.wsRoot+path); err == nil {
				t.Fatalf("%q: a socket past the cap was accepted", path)
			}
		}
		rejAgg.mu.Lock()
		rate, capped := rejAgg.rateLimit, rejAgg.maxConnIP
		rejAgg.mu.Unlock()
		if rate != 0 || capped != 6 {
			t.Fatalf("%q: %d rate refusals, %d cap refusals; want 0 and 6", path, rate, capped)
		}
		held.ws.Close()
		deadline := time.Now().Add(3 * time.Second)
		for {
			c, err := dial(t, r.wsRoot+path) // the second rate token, of 3
			if err == nil {
				c.ws.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%q: no connection after the socket closed: %v", path, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // let the last socket's release run
	}
}

// TestSlash64EscalatesAsOne (second re-check, #29): a flood rotating
// addresses inside one /64 is charged to that /64 and banned as one: every
// address in it is refused, another /64 is not.
func TestSlash64EscalatesAsOne(t *testing.T) {
	withEscalation(t)
	const limit = 2
	for i := 0; i < speakeasyBudgetFactor*limit+3; i++ {
		CheckSpeakeasyConnectionRate(fmt.Sprintf("2001:db8:5:5::%x", i+1), fmt.Sprintf("a%d", i), limit)
	}
	for _, ip := range []string{"2001:db8:5:5::1", "2001:db8:5:5:ffff::99"} {
		if blocked, _ := config.IsIPBlocked(ip); !blocked {
			t.Errorf("%s is not banned with its /64", ip)
		}
	}
	if blocked, _ := config.IsIPBlocked("2001:db8:5:6::1"); blocked {
		t.Error("another /64 was banned")
	}
}
