package server

import (
	"fmt"
	"net/http/httptest"
	"testing"

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

// TestSpeakeasyRetriesNeverBan: a client hammering one speakeasy is refused
// past its budget (429), counted, but never banned, and its other paths
// and the root keep their own budgets.
func TestSpeakeasyRetriesNeverBan(t *testing.T) {
	withEscalation(t)
	const ip, limit = "22.22.22.22", 3
	refused := 0
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/a", nil)
		r.RemoteAddr = ip + ":1"
		w := httptest.NewRecorder()
		if !EnforceSpeakeasyConnectionRateLimit(w, r, "a", limit) {
			refused++
			if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
				t.Fatalf("refusal %d: %d %q", refused, w.Code, w.Header().Get("Retry-After"))
			}
		}
	}
	if refused != 20-limit {
		t.Fatalf("%d refused, want %d", refused, 20-limit)
	}
	if blocked, _ := config.IsIPBlocked(ip); blocked {
		t.Fatal("speakeasy retries escalated to an IP ban")
	}
	rejAgg.mu.Lock()
	counted := rejAgg.rateLimit
	rejAgg.mu.Unlock()
	if counted != 20-limit {
		t.Fatalf("%d rate-limit rejections counted, want %d", counted, 20-limit)
	}
	if !CheckSpeakeasyConnectionRate(ip, "ab", limit) || !CheckIPConnectionRate(ip, limit) {
		t.Fatal("one speakeasy's budget spent another's or the root's")
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
		if _, err := dial(t, r.wsRoot+"/ab"); err != nil {
			t.Fatalf("speakeasy socket %d after the root's budget was spent: %v", i, err)
		}
	}
	if _, err := dial(t, r.wsRoot+"/ab"); err == nil {
		t.Fatal("the speakeasy's third socket in a minute was accepted")
	}
}
