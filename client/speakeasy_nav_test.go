package client

import (
	"regexp"
	"strings"
	"testing"
)

var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// renderWithSpeakeasy renders the homepage shell with the speakeasy landing
// link set to link ("" = speakeasies not served).
func renderWithSpeakeasy(t *testing.T, link string) string {
	t.Helper()
	prev := speakeasyLanding
	t.Cleanup(func() { speakeasyLanding = prev })
	SetSpeakeasyLanding(func() string { return link })
	page, _ := renderApp(t, RelayBranding{Name: "Test Relay"})
	return page
}

// The header shows the Speakeasy button beside the login button while the
// relay serves the landing page: a plain link (not htmx-boosted, the page is
// its own document) with an accessible name and lucide's box icon.
func TestSpeakeasyNavButtonShownWhenServed(t *testing.T) {
	page := renderWithSpeakeasy(t, "/speakeasy")
	i := strings.Index(page, `id="speakeasy-nav"`)
	if i < 0 {
		t.Fatal("no Speakeasy button in the header")
	}
	end := strings.Index(page[i:], "</a>")
	if end < 0 {
		t.Fatal("Speakeasy button is not closed")
	}
	btn := page[i : i+end]
	for _, want := range []string{
		`href="/speakeasy"`,
		`hx-boost="false"`,
		`aria-label="Speakeasy"`,
		`bg-[#4c1d95]`,
		`text-[#ffe94a]`,
		`focus-visible:[outline:2px_solid_#ffe94a]`,
		`focus-visible:[box-shadow:0_0_0_6px_#4c1d95]`,
		`M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z`,
		`>Speakeasy</span>`,
	} {
		if !strings.Contains(btn, want) {
			t.Errorf("Speakeasy button lacks %q", want)
		}
	}
	// Right next to the login button: nothing but whitespace and comments
	// between the button and the login slot.
	login := strings.Index(page, `<div id="profile-nav">`)
	if login < i+end {
		t.Fatal("Speakeasy button is not before the login button")
	}
	between := htmlComment.ReplaceAllString(page[i+end+len("</a>"):login], "")
	if strings.TrimSpace(between) != "" {
		t.Errorf("something sits between the Speakeasy and login buttons: %q", between)
	}
}

// No landing page served (no speakeasies, disabled, or closed): no button,
// so the header never links to a 404.
func TestSpeakeasyNavButtonHiddenWhenNotServed(t *testing.T) {
	if page := renderWithSpeakeasy(t, ""); strings.Contains(page, `id="speakeasy-nav"`) {
		t.Error("Speakeasy button shown without a landing page")
	}
	prev := speakeasyLanding
	t.Cleanup(func() { speakeasyLanding = prev })
	speakeasyLanding = nil // unwired (tests, other entry points)
	if page, _ := renderApp(t, RelayBranding{}); strings.Contains(page, `id="speakeasy-nav"`) {
		t.Error("Speakeasy button shown while unwired")
	}
}
