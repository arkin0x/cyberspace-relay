package api

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0ceanslim/grain/config"
	"github.com/0ceanslim/grain/server/branding"
	"github.com/0ceanslim/grain/server/utils"
)

// grain_changerelaylogo / grain_changerelaylogolight: advertised, validated,
// empty clears, relay paths / own-host URLs kept as set; an upload through a
// plain image write is stored by grain.
func TestNIP86ChangeRelayLogo(t *testing.T) {
	methods := map[string]bool{}
	for _, m := range supportedNIP86() {
		methods[m] = true
	}
	for _, m := range []string{"grain_changerelaylogo", "grain_changerelaylogolight"} {
		if !methods[m] {
			t.Errorf("supportedmethods missing %q", m)
		}
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "relay_metadata.json")
	if err := os.WriteFile(p, []byte(`{"name":"Test Relay"}`), 0644); err != nil {
		t.Fatal(err)
	}
	utils.SetRelayMetadataWritePath(p)
	branding.SetDir(filepath.Join(dir, "branding"))
	prevCfg := config.GetConfig()
	config.SetConfigForTesting(nil)
	t.Cleanup(func() {
		utils.SetRelayMetadataWritePath("relay_metadata.json")
		branding.SetDir("")
		config.SetConfigForTesting(prevCfg)
	})
	if err := utils.LoadRelayMetadata(p); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 40, 8))); err != nil {
		t.Fatal(err)
	}
	upload := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	for _, c := range []struct {
		method, value, wantErr, wantLogo, wantLight string
	}{
		{"grain_changerelaylogo", "javascript:alert(1)", "invalid logo URL", "", ""},
		{"grain_changerelaylogolight", "not a url", "invalid logo_light URL", "", ""},
		// A path on the relay, or a URL on its own host, is kept as set.
		{"grain_changerelaylogo", "/static/icons/logo.png", "", "/static/icons/logo.png", ""},
		{"grain_changerelaylogolight", "https://relay.example/static/dark.png", "", "/static/icons/logo.png", "https://relay.example/static/dark.png"},
		{"grain_changerelaylogolight", "", "", "/static/icons/logo.png", ""},
	} {
		_, errStr := dispatchNIP86(nip86Request{Method: c.method, Params: []any{c.value}, baseURL: "https://relay.example"}, "owner")
		if errStr != c.wantErr {
			t.Fatalf("%s(%q): error %q, want %q", c.method, c.value, errStr, c.wantErr)
		}
		m := utils.GetRelayMetadataCopy()
		if m.Logo != c.wantLogo || m.LogoLight != c.wantLight {
			t.Fatalf("%s(%q): logo %q light %q, want %q %q", c.method, c.value, m.Logo, m.LogoLight, c.wantLogo, c.wantLight)
		}
	}

	// An upload (data: URL) through a plain write is stored by grain, never
	// written raw (html/template would render a data: src as #ZgotmplZ).
	if _, errStr := dispatchNIP86(nip86Request{Method: "changerelayicon", Params: []any{upload}, baseURL: "https://relay.example"}, "owner"); errStr != "" {
		t.Fatal(errStr)
	}
	if m := utils.GetRelayMetadataCopy(); !strings.HasPrefix(m.Icon, "/branding/icon-") {
		t.Fatalf("data: icon not stored by grain: %q", m.Icon)
	}
}
