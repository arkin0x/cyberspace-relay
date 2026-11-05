package regiongate

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/0ceanslim/grain/client/core/tools"

	"gopkg.in/yaml.v3"
)

// Mode chooses which position the gate trusts.
type Mode string

const (
	// ModeStrict places an identity at its last proof-verified position:
	// every rule is checked, every work proof at Level 1, and a proof the
	// checker cannot judge (a ride with no Bitcoin line configured, a hop
	// taller than max_hop_verify_height) is not trusted, so the identity
	// stands where it was before it. The default.
	ModeStrict Mode = "strict"
	// ModeStructural places an identity at its chain head or frozen
	// position. Every rule and every proof the checker can judge is checked
	// as in strict mode, but a proof it cannot judge is trusted: with no line,
	// a ride lands wherever its C says.
	ModeStructural Mode = "structural"
)

// Config is the parsed region.yml.
type Config struct {
	Enabled bool `yaml:"enabled"`
	Mode    Mode `yaml:"mode"`

	// Regions: an author is admitted when its position lies in any of them.
	Regions []RegionSpec `yaml:"regions"`

	// ChainRelays are queried for authors' movement events (kind 3333).
	ChainRelays []string `yaml:"chain_relays"`
	// UseLocalEvents also reads movement events this relay already holds.
	// Default true.
	UseLocalEvents *bool `yaml:"use_local_events"`
	// MaxChainEvents caps how many movement events each source reads per
	// question about one author. Default 5000. An answer over the cap is
	// incomplete, and the lookup is refused uncached ("try again"), so an
	// identity with more events than this since its newest spawn is never
	// admitted until it is raised.
	MaxChainEvents int `yaml:"max_chain_events"`
	// FetchTimeoutSeconds bounds one author's chain fetch. Default 8.
	FetchTimeoutSeconds int `yaml:"fetch_timeout_seconds"`

	// ExemptPubkeys (hex or npub) are always admitted, e.g. the operator.
	ExemptPubkeys []string `yaml:"exempt_pubkeys"`
	// AlwaysAllowKinds are admitted from anyone. Default [5], so people can
	// always delete what they published here, even after leaving the region.
	AlwaysAllowKinds []int `yaml:"always_allow_kinds"`

	// GateReads makes the relay a speakeasy: reading (REQ, COUNT, live
	// events) also requires NIP-42 AUTH as a pubkey inside the region, and
	// every HTTP route except the websocket, NIP-11 and NIP-86 is closed.
	// Default true.
	GateReads *bool `yaml:"gate_reads"`

	// CacheTTLSeconds is how long an admitted author's cached chain answers
	// without asking the sources for newer events. Default 600. A movement
	// event published here that the cache has not seen is always checked.
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
	// NegativeCacheTTLSeconds is the same for a refused author. Default 60.
	NegativeCacheTTLSeconds int `yaml:"negative_cache_ttl_seconds"`
	// MaxConcurrentLookups caps chain checks running at once, so a flood of
	// events from unknown pubkeys cannot make the relay hammer the chain
	// relays or its CPU. Default: the number of cores (at least 2), since a
	// check is CPU-bound once its events are fetched.
	MaxConcurrentLookups int `yaml:"max_concurrent_lookups"`
	// MaxQueuedLookups caps the checks waiting for one of those, and
	// MaxQueuedPerIP how many of them one client address may have waiting.
	// A request past either is refused at once with "relay busy, try again",
	// uncached. Defaults 256 and 8.
	MaxQueuedLookups int `yaml:"max_queued_lookups"`
	MaxQueuedPerIP   int `yaml:"max_queued_per_ip"`
	// CheckTimeoutSeconds bounds one check, fetch and verification
	// together. A caller waits at most its own deadline (writes:
	// fetch_timeout_seconds + 2) and is told to try again; the check runs on
	// to this deadline and keeps its verdict for the retry. Default 30.
	CheckTimeoutSeconds int `yaml:"check_timeout_seconds"`
	// MaxCachedChains caps the chain cache, least recently used first out.
	// Default 4096.
	MaxCachedChains int `yaml:"max_cached_chains"`
	// MaxHopVerifyHeight is the tallest hop (its h_max, §5.9) whose proof
	// is checked. Level 1 costs about 2^h_max word additions per sampled
	// residue and root, so a taller hop that passes its form and its
	// re-roll price is left unchecked (see Mode). Default 24; at most 65.
	// The reference verifier's ceiling is 32 and HOSAKA sells hops up to h30:
	// a hop above the ceiling is not trusted in strict mode, so its mover
	// stands before it until the ceiling is raised.
	MaxHopVerifyHeight int `yaml:"max_hop_verify_height"`

	// CheckRides checks rides (DECK-0001) against the Bitcoin line built
	// from this relay's own block anchors (kind 321) by LinePublisher.
	// Default true. Off, every ride is left unchecked (see Mode).
	CheckRides *bool `yaml:"check_rides"`
	// LinePublisher is the hex pubkey (or npub) whose anchors make the
	// line. Default our NTH publisher, c6e74d44... (owner ruling
	// 2026-11-05).
	LinePublisher string `yaml:"line_publisher"`
	// LinePollSeconds is how often the line asks the store for new
	// anchors. Default 30.
	LinePollSeconds int `yaml:"line_poll_seconds"`
	// LineFallback fills heights no anchor covers, between two that do,
	// with block headers from LineFallbackURLs (Esplora's
	// /block/<hash>/header). Each header is fetched by the hash the anchor
	// above names and must hash to it, so the source is trusted for
	// nothing; it only makes requests. Default false.
	LineFallback bool `yaml:"line_fallback"`
	// LineFallbackURLs default to https://mempool.space/api and
	// https://blockstream.info/api.
	LineFallbackURLs []string `yaml:"line_fallback_urls"`

	boxes  []Box
	exempt map[string]bool
}

// DefaultLinePublisher is the NTH block anchor publisher (owner ruling
// 2026-11-05).
const DefaultLinePublisher = "c6e74d44d41fce3b117c1129feacd182918e9fa3b3239579081de9172c4bf5e6"

// RegionSpec is one region in region.yml. Exactly one form is used:
//   - base + height: an aligned cube (the §8.11.1 bracket form)
//   - base + heights [hx, hy, hz]: a hint box (§7.7)
//   - sector "sx-sy-sz" + plane: one sector (§10), heights 30
type RegionSpec struct {
	Base    string `yaml:"base"`
	Height  *uint  `yaml:"height"`
	Heights []uint `yaml:"heights"`
	Sector  string `yaml:"sector"`
	Plane   uint   `yaml:"plane"`
}

// SectorBits is the sector size per axis (§10): a sector index is axis >> 30.
const SectorBits = 30

// LoadConfig reads region.yml. A missing file returns (nil, nil): no gate.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseConfig(data)
}

// ParseConfig parses region.yml, applies defaults and validates.
func ParseConfig(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse region config: %w", err)
	}
	if c.Mode == "" {
		c.Mode = ModeStrict
	}
	if c.Mode != ModeStructural && c.Mode != ModeStrict {
		return nil, fmt.Errorf("region: mode must be %q or %q", ModeStructural, ModeStrict)
	}
	if c.UseLocalEvents == nil {
		t := true
		c.UseLocalEvents = &t
	}
	if c.GateReads == nil {
		t := true
		c.GateReads = &t
	}
	if c.MaxChainEvents <= 0 {
		c.MaxChainEvents = 5000
	}
	if c.FetchTimeoutSeconds <= 0 {
		c.FetchTimeoutSeconds = 8
	}
	if c.AlwaysAllowKinds == nil {
		c.AlwaysAllowKinds = []int{5}
	}
	if c.CacheTTLSeconds <= 0 {
		c.CacheTTLSeconds = 600
	}
	if c.NegativeCacheTTLSeconds <= 0 {
		c.NegativeCacheTTLSeconds = 60
	}
	if c.MaxConcurrentLookups <= 0 {
		c.MaxConcurrentLookups = defaultLookups()
	}
	if c.MaxQueuedLookups <= 0 {
		c.MaxQueuedLookups = 256
	}
	if c.MaxQueuedPerIP <= 0 {
		c.MaxQueuedPerIP = 8
	}
	if c.CheckTimeoutSeconds <= 0 {
		c.CheckTimeoutSeconds = 30
	}
	if c.MaxCachedChains <= 0 {
		c.MaxCachedChains = 4096
	}
	if c.MaxHopVerifyHeight <= 0 {
		c.MaxHopVerifyHeight = DefaultMaxHopHeight
	}
	if c.CheckRides == nil {
		t := true
		c.CheckRides = &t
	}
	if c.LinePublisher == "" {
		c.LinePublisher = DefaultLinePublisher
	}
	pub, err := normalizePubkey(c.LinePublisher)
	if err != nil {
		return nil, fmt.Errorf("line_publisher: %w", err)
	}
	c.LinePublisher = pub
	if c.LinePollSeconds <= 0 {
		c.LinePollSeconds = 30
	}
	if c.LineFallback && len(c.LineFallbackURLs) == 0 {
		c.LineFallbackURLs = []string{"https://mempool.space/api", "https://blockstream.info/api"}
	}
	if c.MaxHopVerifyHeight > MaxHopVerifyHeightLimit {
		return nil, fmt.Errorf("region: max_hop_verify_height %d is above %d, where a hop's residue count no longer fits 64 bits", c.MaxHopVerifyHeight, MaxHopVerifyHeightLimit)
	}
	if !c.Enabled {
		return &c, nil
	}
	if len(c.Regions) == 0 {
		return nil, fmt.Errorf("region: enabled but no regions configured")
	}
	for i, r := range c.Regions {
		b, err := r.box()
		if err != nil {
			return nil, fmt.Errorf("region %d: %w", i+1, err)
		}
		c.boxes = append(c.boxes, b)
	}
	if err := c.finishSources(); err != nil {
		return nil, err
	}
	return &c, nil
}

// finishSources checks that a chain can be found somewhere and reads the
// exempt pubkeys.
func (c *Config) finishSources() error {
	if len(c.ChainRelays) == 0 && !*c.UseLocalEvents {
		return fmt.Errorf("region: no chain_relays and use_local_events is off; no chain could ever be found")
	}
	c.exempt = map[string]bool{}
	for _, pk := range c.ExemptPubkeys {
		hexKey, err := normalizePubkey(pk)
		if err != nil {
			return fmt.Errorf("exempt_pubkeys: %w", err)
		}
		c.exempt[hexKey] = true
	}
	return nil
}

// ParseSharedConfig parses the chain settings of a shared gate
// (NewSharedGate): every key of region.yml except enabled, regions and
// gate_reads, which have no meaning there (each speakeasy names its own
// region and always gates reads). It applies the same defaults and checks.
func ParseSharedConfig(data []byte) (*Config, error) {
	var probe struct {
		Enabled   *bool        `yaml:"enabled"`
		Regions   []RegionSpec `yaml:"regions"`
		GateReads *bool        `yaml:"gate_reads"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse gate config: %w", err)
	}
	if probe.Enabled != nil || probe.Regions != nil || probe.GateReads != nil {
		return nil, fmt.Errorf("gate: enabled, regions and gate_reads belong in region.yml, not here; each speakeasy has its own region and always gates reads")
	}
	c, err := ParseConfig(data)
	if err != nil {
		return nil, err
	}
	c.Enabled = true
	if err := c.finishSources(); err != nil {
		return nil, err
	}
	return c, nil
}

func (r RegionSpec) box() (Box, error) {
	if r.Sector != "" {
		if r.Base != "" || r.Height != nil || r.Heights != nil {
			return Box{}, fmt.Errorf("use either sector or base, not both")
		}
		parts := strings.Split(r.Sector, "-")
		if len(parts) != 3 {
			return Box{}, fmt.Errorf("sector must be \"sx-sy-sz\"")
		}
		axes := make([]*big.Int, 3)
		for i, p := range parts {
			n, err := strconv.ParseUint(p, 10, 64)
			if err != nil || n >= 1<<(AxisBits-SectorBits) {
				return Box{}, fmt.Errorf("sector index %q out of range", p)
			}
			axes[i] = new(big.Int).Lsh(new(big.Int).SetUint64(n), SectorBits)
		}
		if r.Plane > 1 {
			return Box{}, fmt.Errorf("plane must be 0 or 1")
		}
		return NewBox(Coord{X: axes[0], Y: axes[1], Z: axes[2], Plane: r.Plane}, SectorBits, SectorBits, SectorBits)
	}
	base, err := ParseCoord(strings.ToLower(r.Base))
	if err != nil {
		return Box{}, fmt.Errorf("base: %w", err)
	}
	switch {
	case r.Height != nil && r.Heights == nil:
		return NewBox(base, *r.Height, *r.Height, *r.Height)
	case r.Height == nil && len(r.Heights) == 3:
		return NewBox(base, r.Heights[0], r.Heights[1], r.Heights[2])
	}
	return Box{}, fmt.Errorf("give base with either height or heights [hx, hy, hz]")
}

// Regions is a set of regions: a position inside any of them is inside the
// set. A gate judges each request in the Regions it names, and two requests
// share an answer only when they name the same set (the same pointer), so a
// verdict for one speakeasy is never handed to another.
type Regions struct{ boxes []Box }

// NewRegions is the set of the given boxes; with none, nothing is inside.
func NewRegions(boxes ...Box) *Regions {
	return &Regions{boxes: append([]Box(nil), boxes...)}
}

// Contains reports whether p lies in any of the set's regions.
func (r *Regions) Contains(p Coord) bool {
	if r == nil {
		return false
	}
	for _, b := range r.boxes {
		if b.Contains(p) {
			return true
		}
	}
	return false
}

// Box is the region a RegionSpec names (base with height or heights, or a
// sector), validated.
func (r RegionSpec) Box() (Box, error) { return r.box() }

// Contains reports whether a position lies in any configured region.
func (c *Config) Contains(p Coord) bool {
	for _, b := range c.boxes {
		if b.Contains(p) {
			return true
		}
	}
	return false
}

func (c *Config) cacheTTL(admitted bool) time.Duration {
	if admitted {
		return time.Duration(c.CacheTTLSeconds) * time.Second
	}
	return time.Duration(c.NegativeCacheTTLSeconds) * time.Second
}

func normalizePubkey(pk string) (string, error) {
	pk = strings.TrimSpace(pk)
	if strings.HasPrefix(pk, "npub1") {
		return tools.DecodeNpub(pk)
	}
	if _, err := ParseCoord(strings.ToLower(pk)); err != nil { // 64 hex
		return "", fmt.Errorf("%q is not a hex pubkey or npub", pk)
	}
	return strings.ToLower(pk), nil
}
