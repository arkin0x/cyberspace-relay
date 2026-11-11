package client

import (
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

type PageData struct {
	Title string
	Theme string
}

// defaultBrandName is grain's own name, shown in the browser tab and the
// header logo when the relay operator has not configured a custom relay
// icon. Profile-scoped branding (e.g. the ONOSENDAI default relay) rides
// in through relay_metadata.json (see SetRelayBranding) and is left to
// each deployment's own metadata rather than baked in here.
const defaultBrandName = "🌾 grain"

// relayBranding, when wired by startup via SetRelayBranding, returns the
// relay's configured display name and icon URL from the live NIP-11
// metadata (relay_metadata.json). Kept as a provider func rather than a
// snapshot so a NIP-86 changerelayname / changerelayicon that mutates the
// in-memory metadata is reflected on the very next page render.
var relayBranding func() (name, icon string)

// SetRelayBranding wires the relay's display name + icon source so the
// shared layout/header can render profile-scoped branding. Called once at
// startup after relay metadata is loaded.
func SetRelayBranding(fn func() (name, icon string)) { relayBranding = fn }

func brandingName() string {
	if relayBranding == nil {
		return ""
	}
	n, _ := relayBranding()
	return strings.TrimSpace(n)
}

func brandingIcon() string {
	if relayBranding == nil {
		return ""
	}
	_, i := relayBranding()
	return strings.TrimSpace(i)
}

// RelayPageTitle is the browser-tab title for the relay's own pages: the
// configured relay name when the operator has set a custom icon (the signal
// that this deployment has its own branding), otherwise grain's default.
// Gating on the icon keeps relays that only carry a NIP-11 name but no icon
// (the grain default profiles) showing the familiar "🌾 grain" title.
func RelayPageTitle() string {
	if brandingIcon() != "" {
		if n := brandingName(); n != "" {
			return n
		}
	}
	return defaultBrandName
}

// assetVersion is stamped onto static asset URLs (?v=<version>) in the
// layout so a new release gets a fresh URL the CDN / browser / service
// worker can't stale-serve. Set once at startup from the build version.
var assetVersion = "dev"

// SetAssetVersion wires the build version in so {{assetVersion}} in the
// templates resolves to it. Called from main once the version is known.
//
// Dev builds carry no release version (Version == "dev"), and a fixed "dev"
// stamp lets the browser and the PWA service worker stale-serve old JS across
// rebuilds — the SW caches some scripts cache-first, so a constant ?v=dev URL
// never re-fetches. Use a per-process value for dev instead, so every rebuild /
// restart produces fresh ?v= URLs that bust both caches.
func SetAssetVersion(v string) {
	if v == "" || v == "dev" {
		assetVersion = "dev-" + strconv.FormatInt(time.Now().Unix(), 10)
		return
	}
	assetVersion = v
}

// baseTemplateFuncs are the helpers every layout-rendered page needs.
// All three parse sites (RenderTemplate, renderAdmin, renderSetup) must
// register these or ParseFS fails on the {{assetVersion}} reference in
// layout.html.
var baseTemplateFuncs = template.FuncMap{
	"assetVersion": func() string { return assetVersion },
	// relayName / relayIcon expose the operator's configured relay branding
	// (from relay_metadata.json) to the shared header. Empty when unset, so
	// the header falls back to grain's own logo. See header.html.
	"relayName": brandingName,
	"relayIcon": brandingIcon,
}

// Define the base directories for views and templates within the embedded FS
const (
	viewsDir     = "www/views"
	templatesDir = "www/views/templates"
)

// Define the common layout template filenames
var templateFiles = []string{
	"layout.html",
	"header.html",
	"footer.html",
}

// layoutPatterns returns the full embedded FS paths for layout templates
func layoutPatterns() []string {
	var paths []string
	for _, file := range templateFiles {
		paths = append(paths, path.Join(templatesDir, file))
	}
	return paths
}

// RenderTemplate renders a template with the standard layout using the embedded FS
func RenderTemplate(w http.ResponseWriter, data PageData, view string) {
	viewTemplate := path.Join(viewsDir, view)
	componentPattern := path.Join(viewsDir, "components", "*.html")

	componentTemplates, err := fs.Glob(wwwFS, componentPattern)
	if err != nil {
		http.Error(w, "Error loading component templates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	patterns := append(layoutPatterns(), viewTemplate)
	patterns = append(patterns, componentTemplates...)

	tmpl, err := template.New("").Funcs(baseTemplateFuncs).ParseFS(wwwFS, patterns...)
	if err != nil {
		http.Error(w, "Error parsing templates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, "layout", data)
	if err != nil {
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
	}
}
