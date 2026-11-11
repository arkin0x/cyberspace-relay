package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0ceanslim/grain/server/utils"
)

// grain_changerelaylogo / grain_changerelaylogolight: advertised, URL
// validated like changerelayicon, empty clears, and written to the logo /
// logo_light keys of relay_metadata.json.
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
	t.Cleanup(func() { utils.SetRelayMetadataWritePath("relay_metadata.json") })
	if err := utils.LoadRelayMetadata(p); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		method, value, wantErr, wantLogo, wantLight string
	}{
		{"grain_changerelaylogo", "javascript:alert(1)", "invalid logo URL", "", ""},
		{"grain_changerelaylogolight", "not a url", "invalid logo_light URL", "", ""},
		{"grain_changerelaylogo", "https://example.com/logo.png", "", "https://example.com/logo.png", ""},
		{"grain_changerelaylogolight", "https://example.com/dark.png", "", "https://example.com/logo.png", "https://example.com/dark.png"},
		{"grain_changerelaylogolight", "", "", "https://example.com/logo.png", ""},
	} {
		_, errStr := dispatchNIP86(nip86Request{Method: c.method, Params: []any{c.value}}, "owner")
		if errStr != c.wantErr {
			t.Fatalf("%s(%q): error %q, want %q", c.method, c.value, errStr, c.wantErr)
		}
		m := utils.GetRelayMetadataCopy()
		if m.Logo != c.wantLogo || m.LogoLight != c.wantLight {
			t.Fatalf("%s(%q): logo %q light %q, want %q %q", c.method, c.value, m.Logo, m.LogoLight, c.wantLogo, c.wantLight)
		}
	}
}
