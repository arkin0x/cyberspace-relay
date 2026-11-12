package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	cfgType "github.com/0ceanslim/grain/config/types"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

// The ONOSENDAI default relay's profile (deploy/onosendai), checked the way
// grain reads it. grain has no config-validate command, and yaml.Unmarshal
// ignores a key it does not know, so a typo there would be dropped without a
// word on the droplet; these tests decode strictly instead.

const onosendaiProfile = "../deploy/onosendai"

func decodeStrict(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(onosendaiProfile, name))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func onosendaiConfig(t *testing.T) cfgType.ServerConfig {
	t.Helper()
	var cfg cfgType.ServerConfig
	decodeStrict(t, "config.yml", &cfg)
	if _, err := ValidateAndApplyDefaults(&cfg); err != nil {
		t.Fatalf("config.yml: %v", err)
	}
	return cfg
}

func onosendaiKinds(t *testing.T) map[int]bool {
	t.Helper()
	var wl cfgType.WhitelistConfig
	decodeStrict(t, "whitelist.yml", &wl)
	if !wl.KindWhitelist.Enabled {
		t.Fatal("whitelist.yml: kind_whitelist must be enabled: it is the whole policy")
	}
	if wl.PubkeyWhitelist.Enabled {
		t.Fatal("whitelist.yml: pubkey_whitelist must stay off: anyone may publish the listed kinds")
	}
	kinds := map[int]bool{}
	for _, s := range wl.KindWhitelist.Kinds {
		// IsKindWhitelisted skips an entry that is not a number, so a typo
		// would refuse that kind on the relay while the file looks right.
		k, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("whitelist.yml: kind %q is not a number", s)
		}
		if kinds[k] {
			t.Errorf("whitelist.yml: kind %d listed twice", k)
		}
		kinds[k] = true
	}
	return kinds
}

func TestOnosendaiWhitelistAcceptsWhatClientsPublish(t *testing.T) {
	kinds := onosendaiKinds(t)
	// Every kind a client publishes to the canonical relay (kind audit,
	// 2026-11-05: ONOSENDAI, cyberspace-mcp, NTH; cyberspace-cli, snocrash and
	// HOSAKA publish nothing here; glyphbyte added 2026-11-08; ONOSENDAI sealed
	// entries, 33335, added 2026-11-09; Seeds DNA and tends, 3350 and 3352,
	// added 2026-11-10; TV upgrade announcements, 33338, added 2026-11-12).
	published := map[int]string{
		3333:  "movement chain",
		33330: "hidden bags",
		33331: "objects",
		33335: "sealed entries",
		11333: "avatars",
		23330: "chat envelope",
		321:   "block anchors",
		23334: "TV watching ping",
		33340: "item listings",
		3367:  "palettes",
		0:     "profiles",
		5:     "deletions",
		7:     "reactions",
		1111:  "comments",
		10000: "mute lists",
		10002: "relay lists",
		10050: "DM inbox relay lists",
		10063: "Blossom server lists",
		1738:  "glyphbyte cairns",
		35129: "glyphbyte napplet",
		3350:  "Seeds DNA",
		3352:  "Seeds tend",
		33338: "TV upgrade announcements",
	}
	for k, what := range published {
		if !kinds[k] {
			t.Errorf("whitelist.yml refuses kind %d (%s), which clients publish here", k, what)
		}
	}
}

func TestOnosendaiWhitelistRefusesWhatTheOwnerRefused(t *testing.T) {
	kinds := onosendaiKinds(t)
	// arkinox: notes, legacy DMs, gift wraps, zap receipts and long-form are
	// refused on purpose; DMs go to inbox relays. RULED 2026-11-05: "we never
	// want to accept bare kind 1s".
	for _, k := range []int{1, 4, 1059, 9735, 30023} {
		if kinds[k] {
			t.Errorf("whitelist.yml accepts kind %d, which the owner refused", k)
		}
	}
	// The inner chat line rides inside a 23330 and is never published bare.
	if kinds[23333] {
		t.Error("whitelist.yml accepts kind 23333 bare; it only rides inside a 23330")
	}
	// A Seeds seed is an item inside a bag and MUST NOT be published on its
	// own (DECK-0008 §8.2): its C is the place the bag protects.
	if kinds[3351] {
		t.Error("whitelist.yml accepts kind 3351; a seed only rides inside a bag")
	}
}

func TestOnosendaiReadmeListsTheWhitelist(t *testing.T) {
	kinds := onosendaiKinds(t)
	data, err := os.ReadFile(filepath.Join(onosendaiProfile, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	policy := string(data)
	start := strings.Index(policy, "## Policy")
	if start < 0 {
		t.Fatal("README.md: no Policy section")
	}
	policy = policy[start:]
	end := strings.Index(policy, "| everything else")
	if end < 0 {
		t.Fatal("README.md: the Policy table has no \"everything else\" row")
	}
	documented := map[int]bool{}
	number := regexp.MustCompile(`\d+`)
	for _, line := range strings.Split(policy[:end], "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 3 || strings.Contains(cells[1], "---") {
			continue
		}
		for _, n := range number.FindAllString(cells[1], -1) {
			k, _ := strconv.Atoi(n)
			documented[k] = true
		}
	}
	for k := range kinds {
		if !documented[k] {
			t.Errorf("README.md Policy table is missing kind %d", k)
		}
	}
	for k := range documented {
		if !kinds[k] {
			t.Errorf("README.md Policy table lists kind %d, which whitelist.yml refuses", k)
		}
	}
}

func TestOnosendaiSizeCapsFitWhatClientsSend(t *testing.T) {
	cfg := onosendaiConfig(t)
	caps := map[int]int{}
	for _, l := range cfg.RateLimit.KindSizeLimits {
		caps[l.Kind] = l.MaxSize
	}
	// Largest real events on the relay, 2026-11-05: kind 0 3.4 KB, kind 7 1.0
	// KB; a bag from XOR 158,565 B. A cap of 512 refused a normal reaction
	// (harness run 7).
	for kind, atLeast := range map[int]int{0: 8192, 7: 4096} {
		if c, ok := caps[kind]; ok && c < atLeast {
			t.Errorf("kind %d is capped at %d B, under %d", kind, c, atLeast)
		}
	}
	if cfg.RateLimit.MaxEventSize < 262144 {
		t.Errorf("max_event_size %d is under 256 KB; bags of 158 KB are already on the relay", cfg.RateLimit.MaxEventSize)
	}
}

// grainEventSize is the size grain checks against max_event_size and
// kind_size_limits: HandleEvent decodes the EVENT into a map and measures
// json.Marshal of it, which escapes <, > and & as <, > and &
// (six bytes each), and control characters as \u00XX.
func grainEventSize(t *testing.T, kind int, content string, tags [][]string) int {
	t.Helper()
	hex64 := strings.Repeat("f", 64)
	raw, err := json.Marshal(map[string]any{
		"id": hex64, "pubkey": hex64, "created_at": 1_800_000_000, "kind": kind,
		"tags": tags, "content": content, "sig": strings.Repeat("f", 128),
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return len(out)
}

// TestOnosendaiSeedsCapsFitAnUpperBound builds an upper bound for the Seeds
// DNA and tend (DECK-0008 §8), and for TV's upgrade announcement (33338):
// every tag the DECK allows at once, even ones it
// forbids together (written content with mixed-only tags, `-` with `p`), every
// bounded field at its longest, and long relay hints. It checks that the
// profile's caps let it through and still bind.
func TestOnosendaiSeedsCapsFitAnUpperBound(t *testing.T) {
	cfg := onosendaiConfig(t)
	limiter := NewSizeLimiter(cfg.RateLimit.MaxEventSize)
	limiter.maxContentLength = cfg.RateLimit.MaxContentLength
	caps := map[int]int{}
	for _, l := range cfg.RateLimit.KindSizeLimits {
		limiter.AddKindSizeLimit(l.Kind, l.MaxSize)
		caps[l.Kind] = l.MaxSize
	}
	hex64 := strings.Repeat("a", 64)
	// A relay hint far longer than any real one.
	hint := "wss://" + strings.Repeat("r", 250) + "/"
	// A name or title of 64 code points, each six bytes once escaped.
	name64 := strings.Repeat("<", 64)

	// DNA (§8.1): every tag a written DNA, a mixed DNA or a copy may carry, at
	// once. A written DNA's text is at most 8,192 bytes (§3.1); comments may
	// hold any character, so all of it may be ones json.Marshal escapes.
	dnaText := "dna x\naxiom F\nF -> F F\n#"
	dnaText += strings.Repeat(">", 8192-len(dnaText))
	dnaTags := [][]string{
		{"nonce", "18446744073709551615", "255"},
		{"caps", "65536", "16384", "256"},
		{"e", hex64, hint, "mother"},
		{"e", hex64, hint, "father"},
		{"block", "999999999", hex64},
		{"hybrid"},
		{"name", name64},
		{"q", hex64, hint},
		{"p", hex64},
		// ONOSENDAI's alt names the DNA (lib/seeds/plant.ts dnaTemplate).
		{"alt", "Seeds DNA: " + name64 + " (DECK-0008). Plant it in cyberspace with ONOSENDAI."},
		{"-"},
		{"client", "ONOSENDAI"},
	}

	// Tend (§8.3): the sealed payload has a fixed length; AES-256-GCM adds a
	// 12-byte nonce and a 16-byte tag, then base64.
	plain := `{"seed":"` + hex64 + `","target":"` + strings.Repeat("9", 20) + `","nonces":[` +
		strings.TrimSuffix(strings.Repeat(`"`+strings.Repeat("0", 16)+`",`, 8), ",") + `]}`
	sealed := base64.StdEncoding.EncodeToString(make([]byte, 12+len(plain)+16))
	tendTags := [][]string{
		{"A", "33330:" + hex64 + ":" + hex64},
		{"block", "999999999", hex64},
		{"encrypted", "aes-256-gcm", sealed, "cyberspace:region"},
		{"client", "ONOSENDAI"},
	}
	placeholder := "This garden is hidden at a place in cyberspace. Find it with ONOSENDAI: https://onosendai.tech"

	// TV upgrade announcement (ONOSENDAI announceFeed): at most 900 characters
	// of words in six pages, every one escaped, and the longest simple version.
	version := "999999.999999.999999.999999"
	words := strings.Repeat(strings.Repeat("<", 150)+"\n\n", 6)
	announceTags := [][]string{
		{"d", version},
		{"t", "onosendai-upgrade"},
		{"published_at", "18000000000"},
		{"alt", "ONOSENDAI version " + version + ": an upgrade announcement for Cyberspace TV"},
	}

	for _, c := range []struct {
		kind    int
		what    string
		content string
		tags    [][]string
	}{
		{3350, "DNA", dnaText, dnaTags},
		{3352, "tend", placeholder, tendTags},
		{33338, "TV upgrade announcement", words, announceTags},
	} {
		limit, ok := caps[c.kind]
		if !ok {
			t.Errorf("kind %d (%s) has no kind_size_limits entry", c.kind, c.what)
			continue
		}
		if limit > cfg.RateLimit.MaxEventSize {
			t.Errorf("kind %d (%s) is capped at %d B, over max_event_size %d, so the cap does nothing", c.kind, c.what, limit, cfg.RateLimit.MaxEventSize)
		}
		size := grainEventSize(t, c.kind, c.content, c.tags)
		if ok, msg := limiter.AllowSize(c.kind, size); !ok {
			t.Errorf("the upper bound for a %s (kind %d, %d B) is refused: %s (cap %d B)", c.what, c.kind, size, msg, limit)
		}
		if ok, msg := limiter.AllowContentLength(len([]rune(c.content))); !ok {
			t.Errorf("the upper bound for a %s (kind %d) is refused: %s", c.what, c.kind, msg)
		}
		// The kind's own cap is what refuses one byte past it.
		if ok, msg := limiter.AllowSize(c.kind, limit+1); ok || msg != "Event size limit exceeded for kind" {
			t.Errorf("kind %d (%s): an event of %d B is not refused by the kind cap (got %v, %q)", c.kind, c.what, limit+1, ok, msg)
		}
		t.Logf("kind %d (%s): upper bound %d B, cap %d B", c.kind, c.what, size, limit)
	}
}

type measuredLoad struct {
	Path    string    `json:"path"`
	Seconds float64   `json:"seconds"`
	Req     []float64 `json:"req"`
	Frames  []float64 `json:"frames"`
}

func measuredLoads(t *testing.T) map[string]measuredLoad {
	t.Helper()
	data, err := os.ReadFile("testdata/onosendai-loads-2026-11-05.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Loads map[string]measuredLoad `json:"loads"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Loads) == 0 {
		t.Fatal("no measured loads")
	}
	return f.Loads
}

// replay sends each message `copies` times at its measured moment through a
// limiter built the way NewClientRateLimiter builds it, and reports how many
// were refused and the fewest tokens left.
func replay(limit float64, burst int, at []float64, copies int) (refused int, lowest float64) {
	l := rate.NewLimiter(rate.Limit(limit), burst)
	t0 := time.Unix(1_800_000_000, 0)
	lowest = float64(burst)
	for _, ms := range at {
		now := t0.Add(time.Duration(ms * float64(time.Millisecond)))
		for i := 0; i < copies; i++ {
			if !l.AllowN(now, 1) {
				refused++
			}
		}
		if tok := l.TokensAt(now); tok < lowest {
			lowest = tok
		}
	}
	return refused, lowest
}

func TestOnosendaiRateLimitsCarryRealLoads(t *testing.T) {
	cfg := onosendaiConfig(t).RateLimit
	for _, load := range measuredLoads(t) {
		// The load as measured (logged out), and twice over on one
		// connection: a signed-in load reads your own chain, bags, inventory,
		// avatars, mutes and DMs on top, and the world keeps growing.
		for _, copies := range []int{1, 2} {
			if n, _ := replay(cfg.ReqLimit, cfg.ReqBurst, load.Req, copies); n > 0 {
				t.Errorf("%s x%d: req_limit %v burst %d refuses %d of %d REQs", load.Path, copies, cfg.ReqLimit, cfg.ReqBurst, n, copies*len(load.Req))
			}
			if n, _ := replay(cfg.WsLimit, cfg.WsBurst, load.Frames, copies); n > 0 {
				t.Errorf("%s x%d: ws_limit %v burst %d drops the connection after %d of %d frames", load.Path, copies, cfg.WsLimit, cfg.WsBurst, n, copies*len(load.Frames))
			}
		}
		// Headroom: the measured load never spends more than half the burst.
		if _, lowest := replay(cfg.ReqLimit, cfg.ReqBurst, load.Req, 1); lowest < float64(cfg.ReqBurst)/2 {
			t.Errorf("%s: REQ tokens fall to %.1f of %d, past half the burst", load.Path, lowest, cfg.ReqBurst)
		}
		// Sustained: four times the busiest ten seconds measured.
		busiest := 0
		for i := range load.Req {
			j := i
			for j < len(load.Req) && load.Req[j]-load.Req[i] < 10_000 {
				j++
			}
			if j-i > busiest {
				busiest = j - i
			}
		}
		if need := 4 * float64(busiest) / 10; cfg.ReqLimit < need {
			t.Errorf("%s: req_limit %v is under 4x the busiest 10 s (%d REQs): %.1f/s", load.Path, cfg.ReqLimit, busiest, need)
		}
	}
}

func TestOnosendaiWsLimitAboveReqAndEvent(t *testing.T) {
	rl := onosendaiConfig(t).RateLimit
	// Over ws_limit grain drops the connection; over req_limit it only refuses
	// that REQ. Every REQ is later closed (CLOSE), so a client inside the REQ
	// and EVENT limits sends up to 2 x req + event frames, and the ws limit
	// must never be the one that trips first.
	if need := 2*rl.ReqLimit + rl.EventLimit; rl.WsLimit < need {
		t.Errorf("ws_limit %v is under 2 x req_limit + event_limit = %v", rl.WsLimit, need)
	}
	if need := 2*rl.ReqBurst + rl.EventBurst; rl.WsBurst < need {
		t.Errorf("ws_burst %d is under 2 x req_burst + event_burst = %d", rl.WsBurst, need)
	}
}
