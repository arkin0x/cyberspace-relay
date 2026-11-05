package speakeasy

import "fmt"

// namesOpen is false until named speakeasies ship (step 6 of the plan, at
// 7,000 sats): until then an entry with names is refused. CheckName is
// already the rule every name must pass when they do.
const namesOpen = false

// reservedNames can never be a speakeasy name (ruling D3): the project's
// own words and every path the relay serves itself.
var reservedNames = map[string]bool{
	"onosendai": true, "cyberspace": true, "hosaka": true, "admin": true, "api": true, "static": true,
	"setup": true, "settings": true, "login": true, "logout": true, "views": true, "style": true,
	"style-test": true, "docs": true, "swagger": true, "manifest": true, "relay": true, "speakeasy": true,
	"speakeasies": true, "dashboard": true, "www": true,
}

// CheckName says why name cannot be a speakeasy name, or nil (ruling D3):
// 3 to 40 lowercase letters, digits and dashes; not reserved; and never
// something that reads as a region, since a name must not look like one.
// The last check needs the region parser: without it no name is accepted,
// because "cafe" and "0xabc" fit the characters and both are regions.
func CheckName(name string, parse RegionPath) error {
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
