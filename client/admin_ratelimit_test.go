package client

import (
	"html/template"
	"os"
	"strings"
	"testing"

	cfgType "github.com/0ceanslim/grain/config/types"
)

// The rate-limit section has no editor for pubkey_kind_limits: it shows the
// list and sends no field for it, so a save keeps what is on disk
// (UpdateRateLimitConfig keeps the list when the blob lacks it). A field
// filled at page load would write a stale list back over a hand edit.
func TestAdminRateLimitSectionShowsPubkeyKindLimits(t *testing.T) {
	prevFS := wwwFS
	t.Cleanup(func() { wwwFS = prevFS })
	SetEmbeddedWWW(os.DirFS(".."))
	render := func(rl cfgType.RateLimitConfig) string {
		t.Helper()
		patterns := append(layoutPatterns(), "www/views/components/*.html", "www/views/admin-sections/*.html")
		tmpl, err := template.New("").Funcs(adminTemplateFuncs).ParseFS(wwwFS, patterns...)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, "admin-rate_limit", RateLimitSectionData{Config: rl}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	out := render(cfgType.RateLimitConfig{PubkeyKindLimits: []cfgType.PubkeyKindLimitConfig{{Kind: 11333, PerHour: 12, Burst: 6, Label: "avatars"}}})
	if !strings.Contains(out, "kind 11333 (avatars): 12 an hour, burst 6") {
		t.Errorf("the list is not shown:\n%s", out)
	}
	if strings.Contains(out, `name="pubkey_kind_limits"`) {
		t.Error("the section sends a pubkey_kind_limits field; a page left open would write a stale list back")
	}
	if out := render(cfgType.RateLimitConfig{}); !strings.Contains(out, "None.") {
		t.Error("with no list, the section should say None.")
	}
}
