package speakeasy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/0ceanslim/grain/server/regiongate"
	"github.com/0ceanslim/grain/server/utils/log"
)

// Entry is one speakeasy as the registry stores it.
type Entry struct {
	// ID is the region's path segment in its canonical spelling, as
	// ONOSENDAI writes it after /C/ (ruling D7): lowercase hex. It names the
	// speakeasy's database directory and never changes.
	ID string `json:"id"`
	// Region is the cube the speakeasy admits in, in region.yml's form.
	Region RegionJSON `json:"region"`
	// Names are other paths that lead to the same speakeasy, its reserved
	// names (step 6 of the speakeasy plan). Empty until names ship; the
	// registry already routes them.
	Names []string `json:"names,omitempty"`
	// Name and Description, when set, replace the NIP-11 defaults.
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// CreatedAt is when it was registered (unix seconds), and Note what the
	// relay owner wants to remember about it (how it was paid, for now).
	CreatedAt int64  `json:"created_at"`
	Note      string `json:"note,omitempty"`
}

// RegionJSON is regiongate.RegionSpec with JSON names: base with height or
// heights [hx, hy, hz].
type RegionJSON struct {
	Base    string `json:"base"`
	Height  *uint  `json:"height,omitempty"`
	Heights []uint `json:"heights,omitempty"`
}

// Box is the region the entry names.
func (r RegionJSON) Box() (regiongate.Box, error) {
	return regiongate.RegionSpec{Base: r.Base, Height: r.Height, Heights: r.Heights}.Box()
}

// Speakeasy is a registered speakeasy, ready to serve.
type Speakeasy struct {
	Entry
	// Regions is the set the gate judges its readers and writers in. One
	// pointer per speakeasy: the gate never shares an answer between two.
	Regions *regiongate.Regions
}

// registryFile is the shape of registry.json.
type registryFile struct {
	Version     int     `json:"version"`
	Speakeasies []Entry `json:"speakeasies"`
}

// Registry is the set of speakeasies, kept in registry.json in the data
// directory. Lookups take a read lock; Add and Remove write the whole file
// atomically before changing what lookups see.
type Registry struct {
	path   string
	parse  RegionPath
	planes []uint
	write  func(path string, data []byte, perm os.FileMode) error

	mu     sync.RWMutex
	byID   map[string]*Speakeasy
	byPath map[string]*Speakeasy // every id and name
}

// ErrNotFound is returned for an id the registry does not hold.
var ErrNotFound = errors.New("no speakeasy with that id")

// LoadRegistry reads registry.json at path (a missing file is an empty
// registry). parse may be nil (see RegionPath). planes are the planes a
// region whose path does not fix one spans (Config.Planes). write is how the file is
// replaced (config.AtomicWriteFile in the server). An entry that fails its
// checks is left out and logged: its path is then not a relay, which is the
// right failure for a gate; the others still load. The returned errors say
// which were left out.
func LoadRegistry(path string, parse RegionPath, planes []uint, write func(string, []byte, os.FileMode) error) (*Registry, []error, error) {
	if len(planes) == 0 {
		return nil, nil, fmt.Errorf("a region must span at least one plane")
	}
	r := &Registry{path: path, parse: parse, planes: planes, write: write, byID: map[string]*Speakeasy{}, byPath: map[string]*Speakeasy{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return r, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f registryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var bad []error
	for _, e := range f.Speakeasies {
		s, err := r.check(e)
		if err == nil {
			err = r.clash(s)
		}
		if err != nil {
			bad = append(bad, fmt.Errorf("speakeasy %q left out: %w", e.ID, err))
			log.RegionGate().Error("Speakeasy left out of the registry", "id", e.ID, "error", err)
			continue
		}
		r.insert(s)
	}
	return r, bad, nil
}

// maxSegment bounds a path segment: a full coordinate is 64 hex characters,
// and names (ruling D3) are at most 40.
const maxSegment = 64

// validID reports whether id can be a speakeasy id: 1 to 64 lowercase hex
// characters. It says nothing about whether it is a region; that is the
// RegionPath's to decide. It also keeps the id safe as a directory name.
func validID(id string) bool {
	if len(id) == 0 || len(id) > maxSegment {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// check validates an entry and builds what serving it needs.
func (r *Registry) check(e Entry) (*Speakeasy, error) {
	if !validID(e.ID) {
		return nil, fmt.Errorf("id must be 1 to %d lowercase hex characters (a region path, as after ONOSENDAI's /C/)", maxSegment)
	}
	if len(e.Names) > 0 && !namesOpen {
		return nil, fmt.Errorf("named speakeasies are not open yet")
	}
	for _, n := range e.Names {
		if err := CheckName(n, r.parse); err != nil {
			return nil, fmt.Errorf("name: %w", err)
		}
	}
	fixed := len(e.ID) == fullCoordLen
	var named PathRegion
	if r.parse != nil {
		canonical, region, ok := r.parse("/" + e.ID)
		switch {
		case !ok:
			return nil, fmt.Errorf("id is not a region path")
		case canonical != e.ID:
			return nil, fmt.Errorf("id is not in its canonical spelling %q", canonical)
		}
		named, fixed = region, region.PlaneFixed
		// The path names the region: an entry may leave it out.
		if e.Region.Base == "" && e.Region.Height == nil && e.Region.Heights == nil {
			e.Region = regionJSON(named)
		}
	}
	box, err := e.Region.Box()
	if err != nil {
		return nil, fmt.Errorf("region: %w", err)
	}
	if r.parse != nil && (!sameAxes(box, named) || named.PlaneFixed && box.Base.Plane != named.Base.Plane) {
		return nil, fmt.Errorf("region is not the one the id names")
	}
	return &Speakeasy{Entry: e, Regions: inPlanes(box, fixed, r.planes)}, nil
}

// clash reports a path s would share with a speakeasy already held.
func (r *Registry) clash(s *Speakeasy) error {
	if r.byID[s.ID] != nil {
		return fmt.Errorf("id %q is already registered", s.ID)
	}
	for _, p := range append([]string{s.ID}, s.Names...) {
		if r.byPath[p] != nil {
			return fmt.Errorf("path %q is already taken", p)
		}
	}
	return nil
}

func (r *Registry) insert(s *Speakeasy) {
	r.byID[s.ID] = s
	for _, p := range append([]string{s.ID}, s.Names...) {
		r.byPath[p] = s
	}
}

// RegionPrefix starts a speakeasy's canonical path: /C/<region string>,
// exactly as www.onosendai.tech/C/<region string> (owner ruling
// 2026-11-09). Names stay at /<name>.
const RegionPrefix = "/C/"

// PathFor is the canonical path of a speakeasy path segment: /C/<id> for a
// region id (lowercase hex), /<name> for a name. A name never reads as
// hex (CheckName), so the two cannot be confused.
func PathFor(seg string) string {
	if validID(seg) {
		return RegionPrefix + seg
	}
	return "/" + seg
}

// Lookup returns the speakeasy a request path leads to and its canonical
// path, or nil. escapedPath is the path as sent
// (http.Request.URL.EscapedPath()).
//
//   - /C/<region string>: the region's speakeasy. The string after /C/ is
//     read by the RegionPath (ONOSENDAI's rules: case, 0x, trailing
//     slashes, escapes); canonical is /C/ + its id.
//   - A bare /<region string>, or /c/ in lower case: the same speakeasy,
//     with canonical /C/<id>, which differs from the path: the caller sends
//     browsers there and refuses websockets (an AUTH signs the exact URL).
//   - /<name>: the named speakeasy, matched exactly as spelled; canonical
//     is the path itself.
func (r *Registry) Lookup(escapedPath string) (sp *Speakeasy, canonical string) {
	if len(escapedPath) < 2 || escapedPath[0] != '/' || len(escapedPath) > 4*maxSegment || IsBareRegionPrefix(escapedPath) {
		return nil, ""
	}
	key := escapedPath[1:]
	region := false
	if rest, ok := cutRegionPrefix(escapedPath); ok {
		if r.parse == nil {
			key, region = rest, true
		} else if c, _, ok := r.parse("/" + rest); ok {
			key, region = c, true
		} else {
			return nil, ""
		}
	} else if r.parse != nil {
		if c, _, ok := r.parse(escapedPath); ok {
			key, region = c, true
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if sp = r.byPath[key]; sp == nil || region && sp.ID != key {
		return nil, ""
	}
	return sp, PathFor(key)
}

// IsBareRegionPrefix reports whether a path is /C or /C/ alone: the prefix
// with no region after it. It names nothing (404 for every request), not
// the one-character region "c" its letters would otherwise read as.
func IsBareRegionPrefix(p string) bool { return p == "/C" || p == "/C/" }

// cutRegionPrefix returns what follows /C/ (or /c/, a spelling sent to
// /C/), and whether the path starts with it.
func cutRegionPrefix(p string) (string, bool) {
	if len(p) > 3 && p[0] == '/' && (p[1] == 'C' || p[1] == 'c') && p[2] == '/' {
		return p[3:], true
	}
	return "", false
}

// IsRegionPath reports whether a path names a region in any spelling the
// relay serves or redirects: /C/<string>, /c/<string> or a bare /<string>,
// where the string is one the RegionPath reads as a region.
func IsRegionPath(escapedPath string, parse RegionPath) bool {
	if parse == nil || IsBareRegionPrefix(escapedPath) {
		return false
	}
	if rest, ok := cutRegionPrefix(escapedPath); ok {
		_, _, ok := parse("/" + rest)
		return ok
	}
	_, _, ok := parse(escapedPath)
	return ok
}

// Get returns the speakeasy with this id, or nil.
func (r *Registry) Get(id string) *Speakeasy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// List returns every entry, by id.
func (r *Registry) List() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s.Entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ContainsAny reports whether a position lies in any registered
// speakeasy's region: the shared gate's members are the identities placed
// there.
func (r *Registry) ContainsAny(c regiongate.Coord) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	found := false
	r.holding(c, func(*Speakeasy) bool { found = true; return false })
	return found
}

// holding calls f for every speakeasy whose region holds c, the longest id
// first, until f returns false. With the region parser, a speakeasy's id
// is its region string, the region every coordinate whose hex starts with
// it, so the candidates are the 64 prefixes of c's hex: 64 map lookups,
// each confirmed by the region (which also applies the planes setting),
// whatever the registry's size. Without the parser (tests that register
// regions by hand) ids say nothing, so every entry is checked. Called with
// mu held.
func (r *Registry) holding(c regiongate.Coord, f func(*Speakeasy) bool) {
	if r.parse == nil {
		var all []*Speakeasy
		for _, s := range r.byID {
			if s.Regions.Contains(c) {
				all = append(all, s)
			}
		}
		sort.Slice(all, func(i, j int) bool {
			if len(all[i].ID) != len(all[j].ID) {
				return len(all[i].ID) > len(all[j].ID)
			}
			return all[i].ID < all[j].ID
		})
		for _, s := range all {
			if !f(s) {
				return
			}
		}
		return
	}
	h := c.Hex()
	for k := len(h); k >= 1; k-- {
		if s := r.byID[h[:k]]; s != nil && s.Regions.Contains(c) {
			if !f(s) {
				return
			}
		}
	}
}

// Len is how many speakeasies are registered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// Add registers a speakeasy and writes the registry. The entry is checked as
// at load, and must not take a path another one has.
func (r *Registry) Add(e Entry) (*Speakeasy, error) {
	s, err := r.check(e)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.clash(s); err != nil {
		return nil, err
	}
	if err := r.save(append(r.entriesLocked(), s.Entry)); err != nil {
		return nil, err
	}
	r.insert(s)
	return s, nil
}

// Remove takes a speakeasy out of the registry and writes it. Its database
// stays on disk, untouched: adding the same id again serves it again.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byID[id]
	if s == nil {
		return ErrNotFound
	}
	var keep []Entry
	for _, e := range r.entriesLocked() {
		if e.ID != id {
			keep = append(keep, e)
		}
	}
	if err := r.save(keep); err != nil {
		return err
	}
	delete(r.byID, id)
	for _, p := range append([]string{s.ID}, s.Names...) {
		delete(r.byPath, p)
	}
	return nil
}

func (r *Registry) entriesLocked() []Entry {
	out := make([]Entry, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s.Entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Registry) save(entries []Entry) error {
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	data, err := json.MarshalIndent(registryFile{Version: 1, Speakeasies: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	return r.write(r.path, append(data, '\n'), 0o644)
}

// Containing returns every speakeasy whose region holds c, in the planes it
// spans, the longest id (the smallest region) first and then by id: the
// answer to "which speakeasies can this position enter".
func (r *Registry) Containing(c regiongate.Coord) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Entry
	r.holding(c, func(s *Speakeasy) bool { out = append(out, s.Entry); return true })
	return out
}
