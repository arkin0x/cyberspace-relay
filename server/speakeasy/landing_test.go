package speakeasy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestRegionInputUsesTheSharedVectors: the landing tool reads a /C/ path by
// exactly the rules the relay serves /C/<hex> with, the vectors shared with
// ONOSENDAI (region-prefix-vectors.json): every vector, valid or not, reads
// the same through RegionInput as through the region path parser.
func TestRegionInputUsesTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../regiongate/testdata/region-prefix-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Input string `json:"input"`
			Valid bool   `json:"valid"`
			Hex   string `json:"hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Vectors) < 40 {
		t.Fatalf("vectors: %v (%d)", err, len(file.Vectors))
	}
	for _, v := range file.Vectors {
		got, ok := RegionInput("/C/" + v.Input)
		if ok != v.Valid || got != v.Hex {
			t.Errorf("/C/%q: %q %v, want %q %v", v.Input, got, ok, v.Hex, v.Valid)
		}
	}
}

// TestRegionInputForms: everything a visitor pastes to name a region.
func TestRegionInputForms(t *testing.T) {
	hex := "56db6db6db6db6db6db6dbad"
	full := strings.Repeat("ab", 32)
	for in, want := range map[string]string{
		hex:                                       hex,
		" " + strings.ToUpper(hex) + " ":          hex,
		"0x" + hex:                                hex,
		"C/" + hex:                                hex,
		"/C/" + hex:                               hex,
		"c/" + hex:                                hex,
		"https://www.onosendai.tech/C/" + hex:     hex,
		"https://www.onosendai.tech/c/" + hex:     hex,
		"www.onosendai.tech/C/" + hex + "/":       hex,
		"https://relay.onosendai.tech/C/" + hex:   hex,
		"https://relay.onosendai.tech/" + hex:     hex, // ONOSENDAI's REGION chip link
		"relay.onosendai.tech/" + hex:             hex,
		"wss://relay.onosendai.tech/C/" + hex:     hex,
		"http://127.0.0.1:8181/C/" + hex + "?x=1": hex,
		full:                                   full,
		"https://www.onosendai.tech/C/" + full: full,
		"cafe":                                 "cafe",
	} {
		if got, ok := RegionInput(in); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"", "   ", "midwest", "/C/", "C/", "c/", "/c/", "/C", "https://www.onosendai.tech/", "https://www.onosendai.tech/C/",
		"https://www.onosendai.tech/C/xyz", "/C/" + hex + "/x", full + "a", "<script>alert(1)</script>",
		"javascript:alert(1)", strings.Repeat("a", 600), "https://relay.onosendai.tech/midwest",
	} {
		if got, ok := RegionInput(in); ok {
			t.Errorf("%q read as region %q", in, got)
		}
	}
	// A speakeasy's address at its name is a path the registry can look up.
	if p := InputPath("wss://relay.onosendai.tech/midwest"); p != "/midwest" {
		t.Errorf("name address: %q", p)
	}
}

// TestLiveListOrder: named speakeasies first, oldest first; then the rest,
// newest first; capped, with the number left out.
func TestLiveListOrder(t *testing.T) {
	url := func(seg string) string { return "wss://relay.example" + PathFor(seg) }
	entries := []Entry{
		{ID: "abc", CreatedAt: 100},
		{ID: "56db6db6db6db6db6db6dbad", Names: []string{"midwest"}, CreatedAt: 50},
		{ID: "abd", CreatedAt: 300},
		{ID: "0fe6", Names: []string{"later-name"}, CreatedAt: 200},
		{ID: "abe", CreatedAt: 200},
	}
	live, more := LiveList(entries, url, 4)
	var got []string
	for _, l := range live {
		got = append(got, l.Region)
	}
	if strings.Join(got, ",") != "56db6db6db6db6db6db6dbad,0fe6,abd,abe" || more != 1 {
		t.Fatalf("order %v, more %d", got, more)
	}
	if m := live[0]; m.Name != "midwest" || m.URL != "wss://relay.example/midwest" || m.Page != "/midwest" ||
		m.Size != "a cube, 2^53 gibsons a side" || m.Since != "1970-01-01" {
		t.Errorf("named item: %+v", m)
	}
	if u := live[2]; u.Name != "" || u.URL != "wss://relay.example/C/abd" || u.Page != "/C/abd" {
		t.Errorf("unnamed item: %+v", u)
	}
}

// TestLandingRenders: the page carries the prices, the payment state, the
// prefilled region and the open speakeasies, escaped.
func TestLandingRenders(t *testing.T) {
	l := Landing{
		RelayName: "ONOSENDAI Official Relay", Logo: "/branding/logo-1.png", Host: "relay.example", PublicURL: "wss://relay.example",
		Sats: 1000, NameSats: 7000, Payments: PaymentsOpen, Endpoint: "/api/speakeasies/orders", CheckEndpoint: "/api/speakeasies/check",
		Region: "abc", BothPlanes: true,
		Live: []LiveSpeakeasy{{Name: "midwest", Region: "56db", URL: "wss://relay.example/midwest", Page: "/midwest", Since: "2026-11-11", Size: "a cube, 2^53 gibsons a side"},
			{Name: `<img src=x onerror=alert(1)>`, Region: "abd", URL: "wss://relay.example/C/abd", Page: "/C/abd", Since: "2026-11-12"}},
		LiveMore: 3,
	}
	var buf bytes.Buffer
	if err := RenderLanding(&buf, l); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	for _, want := range []string{
		"<title>Speakeasies · ONOSENDAI Official Relay</title>", `src="/branding/logo-1.png"`, "1,000", "8,000", "7,000 sats more",
		`value="abc"`, `data-relay="wss://relay.example"`, `data-payments="open"`, `data-endpoint="/api/speakeasies/orders"`,
		`data-check="/api/speakeasies/check"`, "midwest", "2<sup>53</sup>", "And 3 more.", "window.SpeakeasyOrder",
		"Location is the key.", "NIP-42 AUTH", "https://www.onosendai.tech",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing lacks %q", want)
		}
	}
	if strings.Contains(body, "<img src=x") || strings.Contains(body, "ZgotmplZ") {
		t.Error("an unescaped name, or a value html/template refused")
	}
	if strings.Contains(body, "—") {
		t.Error("an em dash in the copy")
	}
	for state, want := range map[string]string{PaymentsPaused: "Payments are paused.", PaymentsOff: "Not open yet."} {
		l.Payments = state
		buf.Reset()
		if err := RenderLanding(&buf, l); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), want) {
			t.Errorf("payments %s: no %q", state, want)
		}
	}
}

// TestLandingPathIsReserved: no speakeasy can be named "speakeasy", so its
// name path can never shadow the landing page.
func TestLandingPathIsReserved(t *testing.T) {
	if err := CheckName("speakeasy", ParseRegionPath); err == nil || !IsReservedName("speakeasy") {
		t.Fatalf("speakeasy is not reserved: %v", err)
	}
}
