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
	// added 2026-11-10; TV upgrade announcements, 33338, added 2026-11-12;
	// gift wraps, 1059, added 2026-11-13 for NIP-17 DMs; NIP-78 app data,
	// 30078, added 2026-11-15 for ONOSENDAI's hidden list record; Nostr
	// Connect, 24133, added 2026-11-19 for ONOSENDAI's signer app login;
	// TERRAIN block layers, 33339, added 2026-11-24, DECK-0009).
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
		1059:  "gift wraps (NIP-17 DMs)",
		30078: "ONOSENDAI hidden list record (NIP-78)",
		24133: "Nostr Connect (NIP-46)",
		33339: "TERRAIN block layers",
	}
	for k, what := range published {
		if !kinds[k] {
			t.Errorf("whitelist.yml refuses kind %d (%s), which clients publish here", k, what)
		}
	}
}

func TestOnosendaiWhitelistRefusesWhatTheOwnerRefused(t *testing.T) {
	kinds := onosendaiKinds(t)
	// arkinox: notes, legacy DMs, zap receipts and long-form are refused on
	// purpose. RULED 2026-11-05: "we never want to accept bare kind 1s".
	// Gift wraps (1059) are accepted since 2026-11-13 for NIP-17 DMs, but
	// legacy NIP-04 DMs (4) stay refused.
	for _, k := range []int{1, 4, 9735, 30023} {
		if kinds[k] {
			t.Errorf("whitelist.yml accepts kind %d, which the owner refused", k)
		}
	}
	// A NIP-17 seal (13) and its rumors (14, 15) ride inside a gift wrap and
	// are never published bare.
	for _, k := range []int{13, 14, 15} {
		if kinds[k] {
			t.Errorf("whitelist.yml accepts kind %d bare; it only rides inside a 1059 gift wrap", k)
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

// nip01EventSize is the size DECK-0009 §5.6 limits: the event as compact
// JSON with its keys in NIP-01's order, with <, > and & left as one byte each,
// as NIP-01 leaves them. (json.Encoder still escapes control characters and
// U+2028/U+2029, which NIP-01 does not; the inputs here hold none.)
func nip01EventSize(t *testing.T, kind int, content string, tags [][]string) int {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(struct {
		ID        string     `json:"id"`
		Pubkey    string     `json:"pubkey"`
		CreatedAt int64      `json:"created_at"`
		Kind      int        `json:"kind"`
		Tags      [][]string `json:"tags"`
		Content   string     `json:"content"`
		Sig       string     `json:"sig"`
	}{strings.Repeat("f", 64), strings.Repeat("f", 64), 1_800_000_000, kind, tags, content, strings.Repeat("f", 128)})
	if err != nil {
		t.Fatal(err)
	}
	return len(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// TestOnosendaiCapsFitAnUpperBound builds an upper bound for the Seeds DNA
// and tend (DECK-0008 §8) and checks it against their caps: every tag the
// DECK allows at once, even ones it
// forbids together (written content with mixed-only tags, `-` with `p`), every
// bounded field at its longest, and long relay hints. It checks that the
// profile's caps let it through and still bind.
// For TV's upgrade announcement (33338), the bound is what the announce
// script sends: its four tags, the longest simple version, and six pages
// joined by one blank line, 900 counted characters in all (the script sends
// the whitespace-normalized text it counted).
// For a TERRAIN block layer (33339), the bound is the largest layer DECK-0009
// lets a writer sign (§5.6: 240,000 bytes serialized as NIP-01 does), with
// every tag §5.1 allows (two reach events with long hints holding an &, 32
// settles) and a content sentence and alt of 1,000 characters each, all of
// them ones json.Marshal escapes; the sealed payload fills the rest. The DECK
// does not bound content, alt or hints, so 1,000 is this profile's assumption
// (ONOSENDAI's content is empty): past about 4,428 escaped characters in a
// 240,000 B layer grain measures more than the cap, and no cap can cover a
// layer made mostly of them (it would pass max_event_size too).
func TestOnosendaiCapsFitAnUpperBound(t *testing.T) {
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

	// TV upgrade announcement (ONOSENDAI announceFeed): six pages of 150
	// characters, every one escaped, joined by one blank line, and the longest
	// simple version.
	version := "999999.999999.999999.999999"
	pages := make([]string, 6)
	for i := range pages {
		pages[i] = strings.Repeat("<", 150)
	}
	words := strings.Join(pages, "\n\n")
	announceTags := [][]string{
		{"d", version},
		{"t", "onosendai-upgrade"},
		{"published_at", "18000000000"},
		{"alt", "ONOSENDAI version " + version + ": an upgrade announcement for Cyberspace TV"},
	}

	// TERRAIN block layer (DECK-0009 §5.1, §5.6).
	layerHint := hint + "?a=1&b=2"
	layerContent := strings.Repeat("&", 1000)
	layerTags := [][]string{
		{"d", hex64},
		{"p", hex64},
		{"e", hex64, layerHint, "reach"},
		{"e", hex64, layerHint, "reach"},
	}
	for i := 0; i < 32; i++ {
		layerTags = append(layerTags, []string{"settle", hex64})
	}
	layerTags = append(layerTags,
		[]string{"encrypted", "aes-256-gcm", ""},
		[]string{"version", "1"},
		[]string{"alt", strings.Repeat("<", 1000)},
	)
	sealedAt := len(layerTags) - 3
	// Fill the payload with whole base64 quads up to the DECK's limit.
	room := 240_000 - nip01EventSize(t, 33339, layerContent, layerTags)
	layerTags[sealedAt][2] = strings.Repeat("A", room/4*4)
	if n := nip01EventSize(t, 33339, layerContent, layerTags); n > 240_000 || n < 240_000-3 {
		t.Fatalf("the TERRAIN layer bound is %d B as NIP-01 serializes it, not the DECK's 240,000", n)
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
		{33339, "TERRAIN block layer", layerContent, layerTags},
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

// NIP-17 DMs (owner, 2026-11-13): a gift wrap is capped well under
// max_event_size, and the purge, staged for gift wraps, can never reach
// another kind if it is switched on.
func TestOnosendaiDMInboxConfig(t *testing.T) {
	cfg := onosendaiConfig(t)
	capped := false
	for _, l := range cfg.RateLimit.KindSizeLimits {
		if l.Kind == 1059 {
			capped = true
			if l.MaxSize < 16384 || l.MaxSize > 65536 {
				t.Errorf("kind 1059 is capped at %d B; want 16 KB to 64 KB", l.MaxSize)
			}
		}
	}
	if !capped {
		t.Error("kind 1059 has no kind_size_limits entry")
	}

	p := cfg.EventPurge
	if !p.PurgeByKindEnabled {
		t.Error("event_purge.purge_by_kind_enabled must stay true: without it the purge reaches every kind of an enabled category, movement chains (3333) included")
	}
	if len(p.KindsToPurge) != 1 || p.KindsToPurge[0] != 1059 {
		t.Errorf("event_purge.kinds_to_purge = %v; only gift wraps (1059) may be purged", p.KindsToPurge)
	}
	if p.KeepIntervalHours < 90*24 {
		t.Errorf("event_purge.keep_interval_hours = %d; gift wraps are kept at least 90 days", p.KeepIntervalHours)
	}

	var meta struct {
		SupportedNIPs []int `json:"supported_nips"`
	}
	data, err := os.ReadFile(filepath.Join(onosendaiProfile, "relay_metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	has := map[int]bool{}
	for _, n := range meta.SupportedNIPs {
		has[n] = true
	}
	for _, n := range []int{17, 42, 59} {
		if !has[n] {
			t.Errorf("relay_metadata.json supported_nips lacks NIP-%d", n)
		}
	}
}

// Avatars (owner, 2026-11-16): avatars no longer carry proof of work, so the
// per-author limit on 11333 is what stops one key from replacing its avatar
// over and over. It must be there, leave room for a person trying a few
// shapes in a row and an agent setting one now and then, and still stop one
// key from churning avatars.
func TestOnosendaiAvatarPerAuthorLimit(t *testing.T) {
	cfg := onosendaiConfig(t)
	var avatar *cfgType.PubkeyKindLimitConfig
	for i, l := range cfg.RateLimit.PubkeyKindLimits {
		if l.Kind == 11333 {
			avatar = &cfg.RateLimit.PubkeyKindLimits[i]
		}
	}
	if avatar == nil {
		t.Fatal("rate_limit.pubkey_kind_limits has no entry for avatars (11333)")
	}
	if avatar.Burst < 3 {
		t.Errorf("avatar burst %d: a person trying shapes in the workshop needs a few in a row", avatar.Burst)
	}
	if avatar.PerHour < 4 {
		t.Errorf("avatar per_hour %v: under one every 15 minutes is too tight for honest use", avatar.PerHour)
	}
	if avatar.PerHour > 60 || avatar.Burst > 20 {
		t.Errorf("avatar per_hour %v burst %d: too loose to stop one key churning avatars", avatar.PerHour, avatar.Burst)
	}
	if avatar.Label == "" {
		t.Error("the avatar limit has no label: its refusal would say \"kind 11333 events\"")
	}

	// The limit as the relay builds it: the burst passes, the next is refused
	// with a message a person reads, another key is untouched.
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newPubkeyKindLimiter(maxPubkeyKindBuckets, clk.now)
	l.configure(cfg.RateLimit.PubkeyKindLimits)
	if got := take(l, "alice", 11333, avatar.Burst); got != avatar.Burst {
		t.Fatalf("%d of the burst of %d allowed", got, avatar.Burst)
	}
	ok, msg, _ := l.allow("alice", 11333)
	if ok || !strings.HasPrefix(msg, "rate-limited: avatars are limited to ") || !strings.Contains(msg, " an hour per key; try again in ") {
		t.Fatalf("after the burst: %v %q", ok, msg)
	}
	if ok, _, _ := l.allow("bob", 11333); !ok {
		t.Fatal("alice's spent budget refused bob")
	}
	// Other kinds are not limited per author: movement chains, bags, objects.
	for _, kind := range []int{3333, 33330, 33331, 0, 7} {
		if got := take(l, "alice", kind, 200); got != 200 {
			t.Errorf("kind %d is limited per author (%d of 200)", kind, got)
		}
	}
}

// nip44PaddedLen is NIP-44 v2's calc_padded_len: 32 up to 32 bytes, then
// chunks of an eighth of the next power of two (32 up to 256).
func nip44PaddedLen(n int) int {
	if n <= 32 {
		return 32
	}
	next := 1
	for next < n {
		next <<= 1
	}
	chunk := 32
	if next > 256 {
		chunk = next / 8
	}
	return chunk * ((n-1)/chunk + 1)
}

// Nostr Connect (owner go, 2026-11-19): ONOSENDAI's signer app QR lists this
// relay first, so kind 24133 must be accepted, capped so that a request to
// sign the largest bag or object fits, and left without a per-author limit
// (see below).
func TestOnosendaiNostrConnect(t *testing.T) {
	if !onosendaiKinds(t)[24133] {
		t.Fatal("whitelist.yml refuses kind 24133 (Nostr Connect)")
	}

	cfg := onosendaiConfig(t)
	limiter := NewSizeLimiter(cfg.RateLimit.MaxEventSize)
	limiter.maxContentLength = cfg.RateLimit.MaxContentLength
	cap := 0
	for _, l := range cfg.RateLimit.KindSizeLimits {
		limiter.AddKindSizeLimit(l.Kind, l.MaxSize)
		if l.Kind == 24133 {
			cap = l.MaxSize
		}
	}
	if cap == 0 {
		t.Fatal("kind 24133 has no kind_size_limits entry")
	}
	if cap > cfg.RateLimit.MaxEventSize {
		t.Errorf("kind 24133 is capped at %d B, over max_event_size %d, so the cap does nothing", cap, cfg.RateLimit.MaxEventSize)
	}
	// A sign_event request for the events ONOSENDAI signs through a signer
	// app: the largest bag (signBag's cap, 240,000 B) and the largest object
	// seen on the relay (277,795 B). NIP-44 v2 with its 4-byte length for
	// more than 65,535 bytes: version, nonce, length, padded plaintext, MAC;
	// base64. The request is the event's JSON inside the JSON-RPC, a few
	// hundred bytes more.
	for _, event := range []int{240000, 277795} {
		req := event + 400
		payload := base64.StdEncoding.EncodeToString(make([]byte, 1+32+6+nip44PaddedLen(req)+32))
		size := grainEventSize(t, 24133, payload, [][]string{{"p", strings.Repeat("a", 64)}})
		if ok, msg := limiter.AllowSize(24133, size); !ok {
			t.Errorf("a request to sign a %d B event (%d B) is refused: %s (cap %d B)", event, size, msg, cap)
		}
	}
	if got := len(base64.StdEncoding.EncodeToString(make([]byte, 1+32+6+nip44PaddedLen(240400)+32))); got != 349620 {
		t.Errorf("request for a 240,000 B bag is %d B of base64, want 349,620 (README and config.yml say so)", got)
	}

	// No per-author limit: reads are open and an ephemeral event is never
	// stored, so anyone can replay a key's old 24133 events once the
	// 30-second duplicate window has passed, and under a per-author limit
	// each replay would spend that key's budget and lock its signer out.
	for _, l := range cfg.RateLimit.PubkeyKindLimits {
		if l.Kind == 24133 {
			t.Error("rate_limit.pubkey_kind_limits limits 24133: replays of a key's old Nostr Connect messages would lock its signer out")
		}
	}
}
