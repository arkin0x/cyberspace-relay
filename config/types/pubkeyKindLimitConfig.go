package config

// PubkeyKindLimitConfig caps how many events of one kind each author (the
// event's pubkey) may publish, counted across every connection and kept
// across reconnects. It is a token bucket: an author starts with Burst
// events and earns PerHour more an hour, never holding more than Burst.
// The per-connection kind_limits cannot do this: a client that reconnects,
// or opens a second socket, starts those over.
type PubkeyKindLimitConfig struct {
	Kind int `yaml:"kind" json:"kind"`
	// PerHour is the sustained rate, in events an hour. At least 0.001.
	PerHour float64 `yaml:"per_hour" json:"per_hour"`
	// Burst is how many events an author may publish back to back, and
	// the most it can save up. Must be >= 1.
	Burst int `yaml:"burst" json:"burst"`
	// Label names the events in the refusal a person reads, e.g.
	// "avatars" gives "rate-limited: at most 12 avatars an hour per key".
	// Empty means "kind <n> events".
	Label string `yaml:"label,omitempty" json:"label,omitempty"`
}
