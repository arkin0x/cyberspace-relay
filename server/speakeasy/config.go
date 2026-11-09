package speakeasy

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/0ceanslim/grain/server/regiongate"

	"gopkg.in/yaml.v3"
)

// ConfigFile is the speakeasy config's name in the data directory.
const ConfigFile = "speakeasies.yml"

// Config is the parsed speakeasies.yml. Without the file, or with enabled
// false, there are no speakeasies and every path but / is what it was.
type Config struct {
	Enabled bool `yaml:"enabled"`
	// PublicURL is the relay's public websocket URL without a path, such as
	// wss://relay.onosendai.tech. A speakeasy's URL is PublicURL/<path>, and
	// its NIP-42 AUTH must name exactly that URL. Default: auth.relay_url
	// from config.yml.
	PublicURL string `yaml:"public_url"`
	// MaxOpenDatabases caps the speakeasy databases open at once. Opening one
	// past the cap first closes the one used least recently that nothing is
	// using; when every open one is in use, the request is refused "busy, try
	// again". Default 16.
	MaxOpenDatabases int `yaml:"max_open_databases"`
	// IdleCloseSeconds closes a speakeasy's database once nothing has used it
	// for this long. Default 300.
	IdleCloseSeconds int `yaml:"idle_close_seconds"`
	// MapSizeMB is each speakeasy database's LMDB map ceiling: virtual
	// address space, not memory or disk (the file grows with its events).
	// Default 4096. Writes are refused before it fills, as at the root.
	MapSizeMB int `yaml:"map_size_mb"`
	// MaxConnectionsPerPath caps the websocket connections open to one
	// speakeasy (all its paths together). server.max_connections still caps
	// the relay as a whole. Default 200.
	MaxConnectionsPerPath int `yaml:"max_connections_per_path"`
	// Planes are the planes a speakeasy region spans when its path does not
	// fix one. A region string shorter than a full coordinate never fixes
	// the plane bit, so by default a speakeasy spans both planes, as
	// ONOSENDAI draws the region; [0] or [1] keeps them to one (an owner
	// decision, pending). Default [0, 1].
	Planes []uint `yaml:"planes"`
	// Gate holds the chain settings every speakeasy is judged with: the keys
	// of region.yml except enabled, regions and gate_reads
	// (regiongate.ParseSharedConfig).
	Gate yaml.Node `yaml:"gate"`

	// GateConfig is Gate, parsed.
	GateConfig *regiongate.Config `yaml:"-"`
}

// CheckPublicURL says why u cannot be the relay's public websocket URL, or
// nil: wss:// (ws:// for local tests), a host, and no path, query or
// fragment, since a speakeasy's URL is u/<path> and its AUTH must name it.
func CheckPublicURL(u string) error {
	p, err := url.Parse(u)
	switch {
	case err != nil:
		return fmt.Errorf("not a URL")
	case p.Scheme != "wss" && p.Scheme != "ws":
		return fmt.Errorf("must start with wss:// (ws:// only for local tests), got %q", p.Scheme)
	case p.Host == "" || p.User != nil:
		return fmt.Errorf("must name a host")
	case p.Path != "" || p.RawQuery != "" || p.Fragment != "":
		return fmt.Errorf("must have no path, query or fragment")
	}
	return nil
}

// IngestThreads is how many ingest threads each speakeasy database runs
// (ruling D1).
const IngestThreads = 1

// LoadConfig reads speakeasies.yml. A missing file returns (nil, nil).
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

// ParseConfig parses speakeasies.yml, applies defaults and validates.
func ParseConfig(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ConfigFile, err)
	}
	if c.MaxOpenDatabases <= 0 {
		c.MaxOpenDatabases = 16
	}
	if c.IdleCloseSeconds <= 0 {
		c.IdleCloseSeconds = 300
	}
	if c.MapSizeMB <= 0 {
		c.MapSizeMB = 4096
	}
	if c.MaxConnectionsPerPath <= 0 {
		c.MaxConnectionsPerPath = 200
	}
	if c.Planes == nil {
		c.Planes = []uint{0, 1}
	}
	if len(c.Planes) == 0 || len(c.Planes) > 2 {
		return nil, fmt.Errorf("%s: planes must list 0, 1 or both", ConfigFile)
	}
	for i, p := range c.Planes {
		if p > 1 || i == 1 && p == c.Planes[0] {
			return nil, fmt.Errorf("%s: planes must list 0, 1 or both", ConfigFile)
		}
	}
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	if c.PublicURL != "" {
		if err := CheckPublicURL(c.PublicURL); err != nil {
			return nil, fmt.Errorf("%s: public_url: %w", ConfigFile, err)
		}
	}
	if !c.Enabled {
		return &c, nil
	}
	var gate []byte
	if !c.Gate.IsZero() {
		var err error
		if gate, err = yaml.Marshal(&c.Gate); err != nil {
			return nil, fmt.Errorf("%s gate: %w", ConfigFile, err)
		}
	}
	g, err := regiongate.ParseSharedConfig(gate)
	if err != nil {
		return nil, fmt.Errorf("%s gate: %w", ConfigFile, err)
	}
	c.GateConfig = g
	return &c, nil
}
