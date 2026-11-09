package speakeasy

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
	return r, path
}

// TestNamesRouteAndPersist: a name given at creation leads to its
// speakeasy (as its own canonical path), survives a reload, and is one per
// speakeasy.
func TestNamesRouteAndPersist(t *testing.T) {
	r, path := namedRegistry(t)
	if _, err := r.Add(Entry{ID: "abc", CreatedAt: 1, Names: []string{"fiatjafs-speakeasy"}}); err != nil {
		t.Fatal(err)
	}
	sp, canonical := r.Lookup("/fiatjafs-speakeasy")
	if sp == nil || sp.ID != "abc" || canonical != "/fiatjafs-speakeasy" {
		t.Fatalf("name lookup: %v %q", sp, canonical)
	}
	if sp, c := r.Lookup("/C/abc"); sp == nil || c != "/C/abc" || sp.Names[0] != "fiatjafs-speakeasy" {
		t.Fatalf("the hex path: %v %q", sp, c)
	}
	for _, other := range []string{"/Fiatjafs-Speakeasy", "/fiatjafs-speakeasy/", "/fiatjafs", "/C/fiatjafs-speakeasy"} {
		if sp, _ := r.Lookup(other); sp != nil {
			t.Errorf("%s leads to the speakeasy", other)
		}
	}
	if err := r.NameFree("fiatjafs-speakeasy", "abd"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a taken name: %v", err)
	}
	if _, err := r.Add(Entry{ID: "abd", Names: []string{"fiatjafs-speakeasy"}}); err == nil {
		t.Fatal("a taken name added again")
	}
	if _, err := r.Add(Entry{ID: "abe", Names: []string{"one-name", "two-name"}}); err == nil {
		t.Fatal("a speakeasy with two names")
	}
	r2, bad, err := LoadRegistry(path, ParseRegionPath, both, writeFile)
	if err != nil || len(bad) != 0 {
		t.Fatal(err, bad)
	}
	if sp, _ := r2.Lookup("/fiatjafs-speakeasy"); sp == nil || sp.ID != "abc" {
		t.Fatal("the name did not survive a reload")
	}
}

// TestNamesAreBoundForLife: removing a named speakeasy frees its path but
// not its name: the name never leads to another region, before or after a
// reload, and comes back only with its own region.
func TestNamesAreBoundForLife(t *testing.T) {
	r, path := namedRegistry(t)
	if _, err := r.Add(Entry{ID: "abc", Names: []string{"cafe-du-monde"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("abc"); err != nil {
		t.Fatal(err)
	}
	if sp, _ := r.Lookup("/cafe-du-monde"); sp != nil {
		t.Fatal("a removed speakeasy's name still routes")
	}
	for _, reg := range []*Registry{r, mustLoad(t, path)} {
		if err := reg.NameFree("cafe-du-monde", "abd"); !errors.Is(err, ErrNameTaken) {
			t.Fatalf("a bound name offered for another region: %v", err)
		}
		if err := reg.NameFree("cafe-du-monde", "abc"); err != nil {
			t.Fatalf("the name for its own region: %v", err)
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
// string that reads as a region. "dead-beef" is a name: the dash keeps it
// from parsing as a region, and D3 forbids only names that do.
func TestNameRules(t *testing.T) {
	r, _ := namedRegistry(t)
	for _, bad := range []string{"ab", strings.Repeat("a", 41) + "x", "Fiatjaf", "fiat_jaf", "fiat.jaf", "admin", "speakeasy", "cafe", "0xabc", "deadbeef", "0x0", "abc"} {
		if err := r.NameFree(bad, "abd"); !errors.Is(err, ErrBadName) {
			t.Errorf("name %q: %v, want ErrBadName", bad, err)
		}
	}
	for _, good := range []string{"zed", "fiatjafs-speakeasy", strings.Repeat("z", 40), "0xg", "cafe-1", "dead-beef"} {
		if err := r.NameFree(good, "abd"); err != nil {
			t.Errorf("name %q: %v", good, err)
		}
	}
}

// TestEveryTopLevelRouteIsReserved: a name is a top-level path, so it must
// never be one the relay serves itself. Every first path segment that the
// mux registers (Handle, HandleFunc in client and server) or that initRoot
// and the SPA routes answer, and that fits a name's characters, must be in
// the reserved list.
func TestEveryTopLevelRouteIsReserved(t *testing.T) {
	var files []string
	for _, glob := range []string{"../../client/*.go", "../../client/*/*.go", "../*.go"} {
		m, _ := filepath.Glob(glob)
		files = append(files, m...)
	}
	handle := regexp.MustCompile(`Handle(?:Func)?\("/([^"/{]*)`)
	prefix := regexp.MustCompile(`(?:HasPrefix\(r\.URL\.Path, |r\.URL\.Path == |path == |HasPrefix\(path, )"/([^"/]*)`)
	name := regexp.MustCompile(`^[a-z0-9-]{3,40}$`)
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range []*regexp.Regexp{handle, prefix} {
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				seen[m[1]] = true
			}
		}
	}
	if !seen["api"] || !seen["admin"] || !seen["settings"] {
		t.Fatalf("the scan found too little (%v): has the routing code moved?", seen)
	}
	for seg := range seen {
		if name.MatchString(seg) && !reservedNames[seg] {
			t.Errorf("/%s is served by the relay but not a reserved name", seg)
		}
	}
}
