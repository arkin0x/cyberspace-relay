package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The NIP-01 rule, written independently: escape only the quote, the
// backslash and characters below 0x20, using the short forms where NIP-01
// names them.
func referenceString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteString(hex.EncodeToString([]byte{byte(r)}))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestNIP01StringEscapesOnlyWhatNIP01Escapes(t *testing.T) {
	cases := []string{
		"plain", "a & b", "a < b > c", "it's", `say "hi"`, `back\slash`, "line1\nline2",
		"tab\there", "cr\rhere", "\b\f", "bell\x07", "nul\x00", "https://x.y/?a=1&b=2",
		"emoji 🚀", "line sep para sep ", "literal \\u0026 text", "= + /",
	}
	for _, c := range cases {
		var b strings.Builder
		AppendNIP01String(&b, c)
		if got, want := b.String(), referenceString(c); got != want {
			t.Errorf("%q: got %s, want %s", c, got, want)
		}
		// And it is valid JSON that decodes back to the same string.
		var back string
		if err := json.Unmarshal([]byte(b.String()), &back); err != nil || back != c {
			t.Errorf("%q: does not round-trip (%v): %q", c, err, back)
		}
	}
}

// A real event from the wild whose content holds "&": the id is the SHA-256
// of IDPreimage, which json.Marshal plus the old find-and-replace also got
// right; U+2028 is the case it got wrong.
func TestIDPreimageMatchesNIP01(t *testing.T) {
	e := Event{
		PubKey:    "1266a86330a58a318246b97a1fda900b7da78db63dc70673fec8fdaab03fa4b7",
		CreatedAt: 1791996970,
		Kind:      0,
		Tags:      [][]string{{"r", "https://x.y/?a=1&b=2"}},
		Content:   "a & b < c > d   e",
	}
	want := `[0,"1266a86330a58a318246b97a1fda900b7da78db63dc70673fec8fdaab03fa4b7",1791996970,0,[["r","https://x.y/?a=1&b=2"]],"a & b < c > d ` + " " + ` e"]`
	if got := e.IDPreimage(); got != want {
		t.Fatalf("preimage\n got %s\nwant %s", got, want)
	}
	if e2 := (Event{PubKey: "ab", Kind: 1}); e2.IDPreimage() != `[0,"ab",0,1,[],""]` {
		t.Fatalf("nil tags: %s", e2.IDPreimage())
	}
	sum := sha256.Sum256([]byte(e.IDPreimage()))
	if len(hex.EncodeToString(sum[:])) != 64 {
		t.Fatal("unreachable")
	}
}

func TestNIP01JSONIsTheEventObject(t *testing.T) {
	e := Event{ID: "aa", PubKey: "bb", CreatedAt: 5, Kind: 7, Tags: [][]string{{"e", "x&y"}}, Content: "<+>", Sig: "cc"}
	got := e.NIP01JSON()
	if strings.Contains(got, `\u00`) {
		t.Fatalf("HTML-escaped: %s", got)
	}
	var back Event
	if err := json.Unmarshal([]byte(got), &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != e.ID || back.Content != e.Content || back.Tags[0][1] != "x&y" || back.Kind != 7 || back.CreatedAt != 5 || back.Sig != "cc" {
		t.Fatalf("round trip: %+v", back)
	}
}
