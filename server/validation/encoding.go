package validation

import nostr "github.com/0ceanslim/grain/server/types"

// isLowerHex reports whether s is exactly n lower-case hex characters.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// CheckEventEncoding checks that id, pubkey and sig are lower-case hex of
// their NIP-01 lengths (32, 32 and 64 bytes). hex.DecodeString also takes
// upper case, and the id is hashed over the pubkey as written, so without
// this one key could sign valid events under many spellings of its pubkey:
// each would count as a different author (a fresh per-author budget), and
// nostrdb, which drops such an event after the OK, would leave a replaceable
// event's old version already deleted. It returns false with a NIP-01 OK
// message.
func CheckEventEncoding(evt nostr.Event) (bool, string) {
	switch {
	case !isLowerHex(evt.ID, 64):
		return false, "invalid: id must be 64 lower-case hex characters"
	case !isLowerHex(evt.PubKey, 64):
		return false, "invalid: pubkey must be 64 lower-case hex characters"
	case !isLowerHex(evt.Sig, 128):
		return false, "invalid: sig must be 128 lower-case hex characters"
	}
	return true, ""
}
