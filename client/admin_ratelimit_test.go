package client

import (
	"html"
	"html/template"
	"os"
	"strings"
	"testing"

	cfgType "github.com/0ceanslim/grain/config/types"
)

// The rate-limit section has no editor for pubkey_kind_limits: it shows the
// list and carries it, as JSON in a hidden input, so a save of the section
// sends it back unchanged (the server also keeps it when the blob lacks it).
func TestAdminRateLimitSectionCarriesPubkeyKindLimits(t *testing.T) {
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
	want := `name="pubkey_kind_limits" data-shape="json" value="` + html.EscapeString(`[{"kind":11333,"per_hour":12,"burst":6,"label":"avatars"}]`) + `"`
	if !strings.Contains(out, want) {
		t.Errorf("the hidden input does not carry the list; want %s", want)
	}

	out = render(cfgType.RateLimitConfig{})
	if !strings.Contains(out, `name="pubkey_kind_limits" data-shape="json" value="null"`) {
		t.Error("with no list, the hidden input must send null (the server then keeps what it has)")
	}
}
