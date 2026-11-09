package speakeasy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func namedRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	r, _, err := LoadRegistry(path, ParseRegionPath, both, writeFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"abc", "abd"} {
		if _, err := r.Add(Entry{ID: id, CreatedAt: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return r, path
}

// TestNamesRouteAndPersist: a reserved name leads to its speakeasy (as its
// own canonical path), survives a reload, and is one per speakeasy.
func TestNamesRouteAndPersist(t *testing.T) {
	r, path := namedRegistry(t)
	if err := r.SetName("abc", "fiatjafs-speakeasy"); err != nil {
		t.Fatal(err)
	}
	sp, canonical := r.Lookup("/fiatjafs-speakeasy")
	if sp == nil || sp.ID != "abc" || canonical != "/fiatjafs-speakeasy" {
		t.Fatalf("name lookup: %v %q", sp, canonical)
	}
	if sp, c := r.Lookup("/abc"); sp == nil || c != "/abc" || sp.Names[0] != "fiatjafs-speakeasy" {
		t.Fatalf("the hex path after naming: %v %q", sp, c)
	}
	for _, other := range []string{"/Fiatjafs-Speakeasy", "/fiatjafs-speakeasy/", "/fiatjafs"} {
		if sp, _ := r.Lookup(other); sp != nil {
			t.Errorf("%s leads to the speakeasy", other)
		}
	}
	if err := r.SetName("abc", "another-name"); !errors.Is(err, ErrHasName) {
		t.Fatalf("a second name: %v", err)
	}
	if err := r.SetName("abd", "fiatjafs-speakeasy"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a taken name: %v", err)
	}
	if err := r.SetName("fff", "free-name"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no such speakeasy: %v", err)
	}
	r2, bad, err := LoadRegistry(path, ParseRegionPath, both, writeFile)
	if err != nil || len(bad) != 0 {
		t.Fatal(err, bad)
	}
	if sp, _ := r2.Lookup("/fiatjafs-speakeasy"); sp == nil || sp.ID != "abc" {
		t.Fatal("the name did not survive a reload")
	}
	if _, err := r.Add(Entry{ID: "abe", Names: []string{"one-name", "two-name"}}); err == nil {
		t.Fatal("a speakeasy with two names")
	}
}

// TestNamesAreBoundForLife: removing a named speakeasy frees its path but
// not its name: the name never leads to another region, before or after a
// reload, and comes back only with its own region.
func TestNamesAreBoundForLife(t *testing.T) {
	r, path := namedRegistry(t)
	if err := r.SetName("abc", "cafe-du-monde"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("abc"); err != nil {
		t.Fatal(err)
	}
	if sp, _ := r.Lookup("/cafe-du-monde"); sp != nil {
		t.Fatal("a removed speakeasy's name still routes")
	}
	for _, reg := range []*Registry{r, mustLoad(t, path)} {
		if err := reg.SetName("abd", "cafe-du-monde"); !errors.Is(err, ErrNameTaken) {
			t.Fatalf("a bound name given to another region: %v", err)
		}
		if _, err := reg.Add(Entry{ID: "abf", Names: []string{"cafe-du-monde"}}); err == nil {
			t.Fatal("a bound name added with another region")
		}
		if id, ok := reg.BoundTo("cafe-du-monde"); !ok || id != "abc" {
			t.Fatalf("bound to %q %v", id, ok)
		}
	}
	if _, err := r.Add(Entry{ID: "abc", Names: []string{"cafe-du-monde"}}); err != nil {
		t.Fatalf("the name with its own region: %v", err)
	}
	// A file whose entry names a region bound elsewhere: left out.
	os.WriteFile(path, []byte(`{"version":1,"speakeasies":[{"id":"abd","names":["cafe-du-monde"]}],"bound_names":{"cafe-du-monde":"abc"}}`), 0o644)
	if reg, bad, _ := LoadRegistry(path, ParseRegionPath, both, writeFile); reg.Len() != 0 || len(bad) != 1 {
		t.Fatalf("an entry with another region's name loaded (%d, %v)", reg.Len(), bad)
	}
}

func mustLoad(t *testing.T, path string) *Registry {
	t.Helper()
	r, _, err := LoadRegistry(path, ParseRegionPath, both, writeFile)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestNameRules (ruling D3): 3 to 40 of a-z0-9-, not reserved, never a
// string that reads as a region.
func TestNameRules(t *testing.T) {
	r, _ := namedRegistry(t)
	for _, bad := range []string{"ab", strings.Repeat("a", 41) + "x", "Fiatjaf", "fiat_jaf", "fiat.jaf", "admin", "speakeasy", "cafe", "0xabc", "deadbeef", "0x0", "abc"} {
		if err := r.CanName("abd", bad); !errors.Is(err, ErrBadName) {
			t.Errorf("name %q: %v, want ErrBadName", bad, err)
		}
	}
	for _, good := range []string{"zed", "fiatjafs-speakeasy", strings.Repeat("z", 40), "0xg", "cafe-1"} {
		if err := r.CanName("abd", good); err != nil {
			t.Errorf("name %q: %v", good, err)
		}
	}
}
