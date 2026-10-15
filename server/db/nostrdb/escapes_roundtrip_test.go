package nostrdb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// signNIP01 signs over the true NIP-01 preimage. (signEvent in
// delete_test.go hashes json.Marshal output, which HTML-escapes &, < and >,
// so for exactly these characters it would sign a different id than any
// other client computes.)
func signNIP01(t *testing.T, priv *btcec.PrivateKey, pub string, kind int, content string, tags [][]string, ts int64) nostr.Event {
	t.Helper()
	evt := nostr.Event{PubKey: pub, CreatedAt: ts, Kind: kind, Tags: tags, Content: content}
	h := sha256.Sum256([]byte(evt.IDPreimage()))
	evt.ID = hex.EncodeToString(h[:])
	sig, err := schnorr.Sign(priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	evt.Sig = hex.EncodeToString(sig.Serialize())
	return evt
}

// TestEscapedCharactersAreStored is the 2026-10-15 regression: eventToJSON
// fed nostrdb json.Marshal output, which turns & < > into & <
// >; nostrdb recomputed a different id and dropped the event after the
// relay had answered OK. Profiles and comments with a URL query string were
// lost that way. Every case must be stored and read back unchanged.
func TestEscapedCharactersAreStored(t *testing.T) {
	db := openTempDB(t)
	ctx := context.Background()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))

	cases := []struct {
		name    string
		content string
		tags    [][]string
	}{
		{"ampersand", "a & b", [][]string{}},
		{"angle_brackets", "a < b > c", [][]string{}},
		{"url_query_in_tag", "see link", [][]string{{"r", "https://x.example/?a=1&b=<2>"}}},
		{"line_separators", "a b c", [][]string{}},
		{"quotes_backslash", "say \"hi\" back\\slash", [][]string{}},
		{"newline_tab_cr", "new\nline\ttab\rcr", [][]string{}},
		{"backspace_formfeed", "b\bf\f", [][]string{}},
		{"profile_json", `{"name":"Nature (RSS/Atom feed)","website":"https://example.com/?a=1&b=2"}`, [][]string{}},
	}
	for i, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			evt := signNIP01(t, priv, pub, 1, tc.content, tc.tags, time.Now().Unix()+int64(i))
			if err := db.StoreEvent(ctx, evt); err != nil {
				t.Fatalf("store: %v", err)
			}
			waitForIngest(t, db, evt.ID, true)
			txn, err := db.BeginQuery()
			if err != nil {
				t.Fatalf("begin query: %v", err)
			}
			got, err := txn.GetNoteByID(evt.ID)
			txn.EndQuery()
			if err != nil || got == nil {
				t.Fatalf("not stored: %v", err)
			}
			if got.Content != tc.content {
				t.Fatalf("content changed: want %q, got %q", tc.content, got.Content)
			}
			assertTagsEqual(t, tc.tags, got.Tags)
		})
	}
}

// TestOtherControlCharacters documents a remaining nostrdb limitation: a C0
// control character other than \b \t \n \f \r must be written as \u00XX
// in JSON (raw control characters are not valid JSON), and nostrdb does not
// decode that escape when it recomputes the id, so such an event is still
// dropped on ingest. These are vanishingly rare in real events; the fix
// belongs in nostrdb's JSON parser.
func TestOtherControlCharacters(t *testing.T) {
	t.Skip("known nostrdb limitation: \\u00XX escapes for C0 controls other than \\b\\t\\n\\f\\r are not decoded on ingest")
}
