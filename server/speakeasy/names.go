package speakeasy

import (
	"errors"
	"fmt"
)

// ErrBadName wraps every reason CheckName refuses a name.
var ErrBadName = errors.New("not a valid name")

// reservedNames can never be a speakeasy name (ruling D3): the project's
// own words and every path the relay serves itself.
var reservedNames = map[string]bool{
	"onosendai": true, "cyberspace": true, "hosaka": true, "admin": true, "api": true, "static": true,
	"setup": true, "settings": true, "login": true, "logout": true, "views": true, "style": true,
	"style-test": true, "docs": true, "swagger": true, "manifest": true, "relay": true, "speakeasy": true,
	"speakeasies": true, "dashboard": true, "www": true,
	// /C/<hex> is a speakeasy's region path (too short for a name anyway).
	"c": true,
}

// IsReservedName reports whether name is on the reserved list.
func IsReservedName(name string) bool { return reservedNames[name] }

// CheckName says why name cannot be a speakeasy name, or nil (ruling D3):
// 3 to 40 lowercase letters, digits and dashes; not reserved; and never
// something that reads as a region, since a name must not look like one.
// The last check needs the region parser: without it no name is accepted,
// because "cafe" and "0xabc" fit the characters and both are regions.
func CheckName(name string, parse RegionPath) error {
	if err := checkName(name, parse); err != nil {
		return fmt.Errorf("%w: %w", ErrBadName, err)
	}
	return nil
}

func checkName(name string, parse RegionPath) error {
	if len(name) < 3 || len(name) > 40 {
		return fmt.Errorf("a name is 3 to 40 characters")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("a name is lowercase letters, digits and dashes")
		}
	}
	if reservedNames[name] {
		return fmt.Errorf("%q is reserved", name)
	}
	if parse == nil {
		return fmt.Errorf("names need the region parser, to refuse one that reads as a region")
	}
	if _, _, ok := parse("/" + name); ok {
		return fmt.Errorf("%q reads as a region; a name must not look like one", name)
	}
	return nil
}
