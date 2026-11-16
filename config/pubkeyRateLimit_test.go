package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cfgType "github.com/0ceanslim/grain/config/types"
	"gopkg.in/yaml.v3"
)

// fakeClock is a clock the tests move by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func testLimiter(max int, limits ...cfgType.PubkeyKindLimitConfig) (*pubkeyKindLimiter, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	l := newPubkeyKindLimiter(max, clk.now)
	l.configure(limits)
	return l, clk
}

var avatarLimit = cfgType.PubkeyKindLimitConfig{Kind: 11333, PerHour: 12, Burst: 6, Label: "avatars"}

// take calls allow n times and counts the events it let through.
func take(l *pubkeyKindLimiter, pubkey string, kind, n int) int {
	got := 0
	for i := 0; i < n; i++ {
		if ok, _, _ := l.allow(pubkey, kind); ok {
			got++
		}
	}
	return got
}

func TestPubkeyLimiterBurstThenRefuses(t *testing.T) {
	l, _ := testLimiter(100, avatarLimit)
	if got := take(l, "alice", 11333, 6); got != 6 {
		t.Fatalf("the burst: %d of 6 allowed", got)
	}
	ok, msg, refund := l.allow("alice", 11333)
	if ok || refund != nil {
		t.Fatal("the 7th avatar in a burst of 6 was allowed")
	}
	want := "rate-limited: at most 12 avatars an hour per key; try again in 5 minutes"
	if msg != want {
		t.Fatalf("refusal: got %q, want %q", msg, want)
	}
}

func TestPubkeyLimiterRefillsAtPerHour(t *testing.T) {
	l, clk := testLimiter(100, avatarLimit)
	take(l, "alice", 11333, 6)
	// 12 an hour is one every 5 minutes.
	clk.advance(4*time.Minute + 59*time.Second)
	if ok, msg, _ := l.allow("alice", 11333); ok {
		t.Fatal("allowed before 5 minutes had passed")
	} else if !strings.HasSuffix(msg, "try again in 1 second") {
		t.Fatalf("refusal at 4m59s: %q", msg)
	}
	// A millisecond past the 5 minutes, so the test does not hang on how
	// 300 x 12/3600 rounds.
	clk.advance(time.Second + time.Millisecond)
	if ok, _, _ := l.allow("alice", 11333); !ok {
		t.Fatal("refused after 5 minutes")
	}
	if ok, _, _ := l.allow("alice", 11333); ok {
		t.Fatal("5 minutes earned two avatars")
	}
	// A long rest refills to the burst and no further.
	clk.advance(24 * time.Hour)
	if got := take(l, "alice", 11333, 10); got != 6 {
		t.Fatalf("after a day: %d allowed, want the burst of 6", got)
	}
}

func TestPubkeyLimiterKeysAndKindsAreSeparate(t *testing.T) {
	other := cfgType.PubkeyKindLimitConfig{Kind: 3367, PerHour: 1, Burst: 1}
	l, _ := testLimiter(100, avatarLimit, other)
	take(l, "alice", 11333, 6)
	if ok, _, _ := l.allow("alice", 11333); ok {
		t.Fatal("alice's 7th avatar was allowed")
	}
	if got := take(l, "bob", 11333, 6); got != 6 {
		t.Fatalf("bob's avatars after alice ran out: %d of 6", got)
	}
	if ok, _, _ := l.allow("alice", 3367); !ok {
		t.Fatal("alice's avatar budget spent her kind 3367 budget")
	}
	if ok, msg, _ := l.allow("alice", 3367); ok || !strings.Contains(msg, "at most 1 kind 3367 events an hour") {
		t.Fatalf("kind 3367 has a burst of 1: got %v %q", ok, msg)
	}
	// A kind with no rule is never limited.
	if got := take(l, "alice", 1, 1000); got != 1000 {
		t.Fatalf("an unlimited kind: %d of 1000 allowed", got)
	}
	if n := l.lru.Len(); n != 3 {
		t.Fatalf("buckets: %d, want 3 (an unlimited kind keeps none)", n)
	}
}

func TestPubkeyLimiterRefundGivesTheEventBack(t *testing.T) {
	l, _ := testLimiter(100, avatarLimit)
	for i := 0; i < 20; i++ {
		ok, _, refund := l.allow("alice", 11333)
		if !ok {
			t.Fatalf("refused on try %d though every try was refunded", i+1)
		}
		refund()
	}
	// Refunds never raise a bucket past its burst.
	_, _, refund := l.allow("alice", 11333)
	refund()
	refund()
	if got := take(l, "alice", 11333, 10); got != 6 {
		t.Fatalf("after extra refunds: %d allowed, want 6", got)
	}
}

func TestPubkeyLimiterIdleBucketsAreDropped(t *testing.T) {
	l, clk := testLimiter(100, avatarLimit)
	for i := 0; i < 5; i++ {
		take(l, fmt.Sprintf("key%d", i), 11333, 1)
	}
	if n := l.lru.Len(); n != 5 {
		t.Fatalf("buckets: %d, want 5", n)
	}
	// One avatar refills in 5 minutes: after that the five buckets are
	// full again, so a new key's call drops them (losslessly).
	clk.advance(5 * time.Minute)
	take(l, "fresh", 11333, 1)
	if n := l.lru.Len(); n != 1 {
		t.Fatalf("buckets after the idle ones refilled: %d, want 1", n)
	}
	if len(l.buckets) != l.lru.Len() {
		t.Fatalf("map %d and list %d disagree", len(l.buckets), l.lru.Len())
	}
}

func TestPubkeyLimiterIsBounded(t *testing.T) {
	l, _ := testLimiter(4, avatarLimit)
	// Spend all six of alice's avatars, then five more keys arrive while
	// no bucket is idle.
	take(l, "alice", 11333, 6)
	for i := 0; i < 5; i++ {
		take(l, fmt.Sprintf("key%d", i), 11333, 1)
		if n := l.lru.Len(); n > 4 {
			t.Fatalf("buckets: %d, over the cap of 4", n)
		}
	}
	if len(l.buckets) != 4 || l.lru.Len() != 4 {
		t.Fatalf("map %d, list %d: want 4 and 4", len(l.buckets), l.lru.Len())
	}
	// The least recently used bucket (alice's) went first: she starts over.
	if _, found := l.buckets[pubkeyKindKey{"alice", 11333}]; found {
		t.Fatal("alice's bucket, the least recently used, was kept at the cap")
	}
	// A key in use is moved to the front and kept.
	take(l, "key1", 11333, 1)
	take(l, "key9", 11333, 1)
	if _, found := l.buckets[pubkeyKindKey{"key1", 11333}]; !found {
		t.Fatal("a just-used bucket was evicted")
	}
	// A refund on an evicted bucket touches nothing.
	l2, _ := testLimiter(1, avatarLimit)
	_, _, refund := l2.allow("alice", 11333)
	take(l2, "bob", 11333, 1)
	refund()
	if _, found := l2.buckets[pubkeyKindKey{"alice", 11333}]; found || l2.lru.Len() != 1 {
		t.Fatal("a refund brought an evicted bucket back")
	}
}

func TestPubkeyLimiterReconfigure(t *testing.T) {
	other := cfgType.PubkeyKindLimitConfig{Kind: 3367, PerHour: 1, Burst: 1}
	l, _ := testLimiter(100, avatarLimit, other)
	take(l, "alice", 11333, 6)
	take(l, "alice", 3367, 1)

	// Same numbers for 11333 (a new label is not a new limit): the spent
	// bucket is kept, so a reload does not hand out fresh bursts. 3367's
	// numbers changed: its bucket starts over.
	relabeled := avatarLimit
	relabeled.Label = "shapes"
	l.configure([]cfgType.PubkeyKindLimitConfig{relabeled, {Kind: 3367, PerHour: 2, Burst: 3}})
	if ok, msg, _ := l.allow("alice", 11333); ok || !strings.Contains(msg, "12 shapes") {
		t.Fatalf("an unchanged limit lost its bucket on reload: %v %q", ok, msg)
	}
	if got := take(l, "alice", 3367, 5); got != 3 {
		t.Fatalf("a changed limit: %d allowed, want the new burst of 3", got)
	}

	// Removing a kind removes its limit and its buckets.
	l.configure(nil)
	if got := take(l, "alice", 11333, 50); got != 50 {
		t.Fatalf("no rules: %d of 50 allowed", got)
	}
	if l.lru.Len() != 0 || len(l.buckets) != 0 {
		t.Fatalf("no rules: %d buckets left", l.lru.Len())
	}

	// An entry that could not pass validation is skipped, never divided by.
	l.configure([]cfgType.PubkeyKindLimitConfig{{Kind: 11333, PerHour: 0, Burst: 6}, {Kind: 1, PerHour: 5, Burst: 0}})
	if got := take(l, "alice", 11333, 10) + take(l, "alice", 1, 10); got != 20 {
		t.Fatalf("invalid entries limited something: %d of 20 allowed", got)
	}
}

func TestPubkeyLimiterConcurrent(t *testing.T) {
	l, _ := testLimiter(64, avatarLimit)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := map[string]int{}
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pk := fmt.Sprintf("key%d", i%8)
				ok, _, refund := l.allow(pk, 11333)
				if ok {
					if i%3 == 0 {
						refund()
						continue
					}
					mu.Lock()
					allowed[pk]++
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()
	for pk, n := range allowed {
		if n > 6 {
			t.Errorf("%s: %d kept under a burst of 6 with no time passing", pk, n)
		}
	}
	if len(l.buckets) != l.lru.Len() {
		t.Fatalf("map %d and list %d disagree", len(l.buckets), l.lru.Len())
	}
}

// The smallest per_hour validation allows names a wait in hours, and the
// cap keeps any rule from overflowing the conversion to a time.Duration.
func TestPubkeyLimiterWaitNeverOverflows(t *testing.T) {
	for _, perHour := range []float64{minPubkeyPerHour, 1e-9} {
		l, _ := testLimiter(10)
		// configure skips a rule under the minimum; install it directly to
		// test the cap itself.
		l.rules[1] = pubkeyKindRule{perHour: perHour, perSecond: perHour / 3600, burst: 1}
		l.active.Store(true)
		take(l, "alice", 1, 1)
		ok, msg, _ := l.allow("alice", 1)
		if ok || !strings.HasSuffix(msg, " hours") {
			t.Errorf("per_hour %v: got %v %q, want a wait in hours", perHour, ok, msg)
		}
	}
}

// With no rules, an event takes no lock and leaves no trace.
func TestPubkeyLimiterNoRulesFastPath(t *testing.T) {
	l, _ := testLimiter(10)
	if l.active.Load() {
		t.Fatal("active with no rules")
	}
	if got := take(l, "alice", 11333, 100); got != 100 || l.lru.Len() != 0 {
		t.Fatalf("no rules: %d of 100 allowed, %d buckets", got, l.lru.Len())
	}
	l.configure([]cfgType.PubkeyKindLimitConfig{avatarLimit})
	if !l.active.Load() {
		t.Fatal("not active with a rule")
	}
	l.configure(nil)
	if l.active.Load() {
		t.Fatal("still active after the rules were removed")
	}
}

func TestHumanWait(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                       "1 second",
		time.Second:             "1 second",
		1500 * time.Millisecond: "2 seconds",
		59 * time.Second:        "59 seconds",
		60 * time.Second:        "1 minute",
		61 * time.Second:        "2 minutes",
		90 * time.Minute:        "90 minutes",
		91 * time.Minute:        "2 hours",
	} {
		if got := humanWait(d); got != want {
			t.Errorf("humanWait(%v) = %q, want %q", d, got, want)
		}
	}
}

// ── config: parsing, validation, the admin write path ────────────────

const pubkeyLimitsYAML = `
rate_limit:
  event_limit: 10
  pubkey_kind_limits:
    - kind: 11333
      per_hour: 12
      burst: 6
      label: avatars
`

func TestPubkeyKindLimitsParse(t *testing.T) {
	var c cfgType.ServerConfig
	dec := yaml.NewDecoder(strings.NewReader(pubkeyLimitsYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	got := c.RateLimit.PubkeyKindLimits
	if len(got) != 1 || got[0] != avatarLimit {
		t.Fatalf("parsed %+v, want [%+v]", got, avatarLimit)
	}
	if err := validatePubkeyKindLimits(got); err != nil {
		t.Fatal(err)
	}
	// A save (yaml.Marshal of the whole config) writes it back unchanged.
	out, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back cfgType.ServerConfig
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.RateLimit.PubkeyKindLimits) != 1 || back.RateLimit.PubkeyKindLimits[0] != avatarLimit {
		t.Fatalf("after a save: %+v", back.RateLimit.PubkeyKindLimits)
	}
}

// A config without the field is exactly what it was before: nothing parsed,
// nothing written on save, nothing limited.
func TestPubkeyKindLimitsAbsent(t *testing.T) {
	var c cfgType.ServerConfig
	if err := yaml.Unmarshal([]byte("rate_limit:\n  event_limit: 10\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.RateLimit.PubkeyKindLimits != nil {
		t.Fatalf("absent field parsed as %+v", c.RateLimit.PubkeyKindLimits)
	}
	if err := validatePubkeyKindLimits(c.RateLimit.PubkeyKindLimits); err != nil {
		t.Fatal(err)
	}
	out, _ := yaml.Marshal(c)
	if strings.Contains(string(out), "pubkey_kind_limits") {
		t.Fatalf("a config without the field gained it on save:\n%s", out)
	}
	l, _ := testLimiter(100, c.RateLimit.PubkeyKindLimits...)
	for _, kind := range []int{0, 1, 11333, 3333, 33331} {
		if got := take(l, "alice", kind, 100); got != 100 {
			t.Fatalf("kind %d limited with no rules: %d of 100", kind, got)
		}
	}
}

func TestPubkeyKindLimitsValidation(t *testing.T) {
	for name, limits := range map[string][]cfgType.PubkeyKindLimitConfig{
		"per_hour 0":        {{Kind: 11333, PerHour: 0, Burst: 6}},
		"per_hour negative": {{Kind: 11333, PerHour: -1, Burst: 6}},
		"burst 0":           {{Kind: 11333, PerHour: 12, Burst: 0}},
		"kind negative":     {{Kind: -1, PerHour: 12, Burst: 6}},
		"kind too big":      {{Kind: 70000, PerHour: 12, Burst: 6}},
		"per_hour tiny":     {{Kind: 11333, PerHour: 0.0001, Burst: 6}},
		"kind twice":        {avatarLimit, avatarLimit},
	} {
		if err := validatePubkeyKindLimits(limits); err == nil {
			t.Errorf("%s: accepted", name)
		}
		c := cfgType.ServerConfig{}
		c.Server.Port = ":8181"
		c.RateLimit.PubkeyKindLimits = limits
		if _, err := ValidateAndApplyDefaults(&c); err == nil {
			t.Errorf("%s: ValidateAndApplyDefaults accepted it", name)
		}
	}
}

// The admin dashboard has no editor for the list. A rate-limit save without
// it must keep it; [] clears it; a bad list is refused and nothing is saved.
func TestUpdateRateLimitConfigKeepsPubkeyKindLimits(t *testing.T) {
	dir := t.TempDir()
	oldDir := GetDataDir()
	SetDataDir(dir)
	oldCfg := GetConfig()
	t.Cleanup(func() { SetDataDir(oldDir); SetConfigForTesting(oldCfg) })

	c := &cfgType.ServerConfig{}
	c.RateLimit.EventLimit = 10
	c.RateLimit.PubkeyKindLimits = []cfgType.PubkeyKindLimitConfig{avatarLimit}
	SetConfigForTesting(c)

	saved := func() cfgType.RateLimitConfig {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, "config.yml"))
		if err != nil {
			t.Fatal(err)
		}
		var back cfgType.ServerConfig
		if err := yaml.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		return back.RateLimit
	}

	// The dashboard's blob: the hidden input sends null when it has no list,
	// and an older dashboard leaves the key out; both decode to nil.
	if err := UpdateRateLimitConfig(cfgType.RateLimitConfig{EventLimit: 20}); err != nil {
		t.Fatal(err)
	}
	if got := saved(); got.EventLimit != 20 || len(got.PubkeyKindLimits) != 1 || got.PubkeyKindLimits[0] != avatarLimit {
		t.Fatalf("a save without the list: %+v", got)
	}
	if got := GetConfig().RateLimit.PubkeyKindLimits; len(got) != 1 || got[0] != avatarLimit {
		t.Fatalf("in memory after a save without the list: %+v", got)
	}

	if err := UpdateRateLimitConfig(cfgType.RateLimitConfig{EventLimit: 20, PubkeyKindLimits: []cfgType.PubkeyKindLimitConfig{{Kind: 11333, PerHour: 0, Burst: 6}}}); err == nil {
		t.Fatal("a bad list was accepted")
	}
	if got := saved(); len(got.PubkeyKindLimits) != 1 || got.PubkeyKindLimits[0] != avatarLimit {
		t.Fatalf("a refused save changed the file: %+v", got)
	}

	if err := UpdateRateLimitConfig(cfgType.RateLimitConfig{EventLimit: 20, PubkeyKindLimits: []cfgType.PubkeyKindLimitConfig{}}); err != nil {
		t.Fatal(err)
	}
	if got := saved(); len(got.PubkeyKindLimits) != 0 {
		t.Fatalf("[] did not clear the list: %+v", got.PubkeyKindLimits)
	}
}

// SetRateLimit, which every server instance start (and so every config
// reload) calls, installs the list in the process-wide table.
func TestSetRateLimitConfiguresPubkeyLimits(t *testing.T) {
	rateLimitCfgMu.RLock()
	oldRateLimitCfg := rateLimitCfg
	rateLimitCfgMu.RUnlock()
	t.Cleanup(func() {
		rateLimitCfgMu.Lock()
		rateLimitCfg = oldRateLimitCfg
		rateLimitCfgMu.Unlock()
	})
	ResetPubkeyLimiterForTest()
	t.Cleanup(ResetPubkeyLimiterForTest)
	c := &cfgType.ServerConfig{}
	c.RateLimit.PubkeyKindLimits = []cfgType.PubkeyKindLimitConfig{{Kind: 11333, PerHour: 12, Burst: 2, Label: "avatars"}}
	SetRateLimit(c)
	for i := 0; i < 2; i++ {
		if ok, _, _ := AllowPubkeyEvent("alice", 11333); !ok {
			t.Fatalf("avatar %d refused", i+1)
		}
	}
	if ok, msg, _ := AllowPubkeyEvent("alice", 11333); ok || !strings.HasPrefix(msg, "rate-limited: at most 12 avatars an hour per key") {
		t.Fatalf("the 3rd: %v %q", ok, msg)
	}
	// A reload with the same numbers keeps alice's spent bucket.
	SetRateLimit(c)
	if ok, _, _ := AllowPubkeyEvent("alice", 11333); ok {
		t.Fatal("a reload handed alice a fresh burst")
	}
	// A reload without the list lifts it.
	SetRateLimit(&cfgType.ServerConfig{})
	if ok, _, _ := AllowPubkeyEvent("alice", 11333); !ok {
		t.Fatal("still limited after the list was removed")
	}
}
