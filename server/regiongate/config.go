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
	// ModeStructural places an identity at its chain head: signatures,
	// links, coordinates and brackets are checked; work proofs are only
	// checked as far as the ProofChecker can (with PendingSpec, not at all).
	ModeStructural Mode = "structural"
	// ModeStrict places an identity at its last proof-verified position.
	// With PendingSpec that is its spawn point.
	ModeStrict Mode = "strict"
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
	// MaxChainEvents caps how many movement events are fetched per author.
	// Default 5000.
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

	// CacheTTLSeconds keeps an admitted author's verdict this long.
	// Default 600. A movement event published here always re-verifies.
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
	// NegativeCacheTTLSeconds keeps a refusal this long. Default 60.
	NegativeCacheTTLSeconds int `yaml:"negative_cache_ttl_seconds"`
	// MaxConcurrentLookups caps chain lookups in flight, so a flood of
	// events from unknown pubkeys cannot make the relay hammer the chain
	// relays. Default 16.
	MaxConcurrentLookups int `yaml:"max_concurrent_lookups"`

	boxes  []Box
	exempt map[string]bool
}

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
		c.Mode = ModeStructural
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
		c.MaxConcurrentLookups = 16
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
	if len(c.ChainRelays) == 0 && !*c.UseLocalEvents {
		return nil, fmt.Errorf("region: no chain_relays and use_local_events is off; no chain could ever be found")
	}
	c.exempt = map[string]bool{}
	for _, pk := range c.ExemptPubkeys {
		hexKey, err := normalizePubkey(pk)
		if err != nil {
			return nil, fmt.Errorf("exempt_pubkeys: %w", err)
		}
		c.exempt[hexKey] = true
	}
	return &c, nil
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
