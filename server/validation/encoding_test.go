package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	nostr "github.com/0ceanslim/grain/server/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// signAs signs an event under the pubkey spelling given: the id is hashed
// over the pubkey as written, so an upper-case spelling makes a valid id
// and signature of its own.
func signAs(t *testing.T, priv *btcec.PrivateKey, pubkey string) nostr.Event {
	t.Helper()
	tags := [][]string{}
	raw, _ := json.Marshal([]any{0, pubkey, 1_800_000_000, 11333, tags, ""})
	h := sha256.Sum256(raw)
	sig, err := schnorr.Sign(priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return nostr.Event{ID: hex.EncodeToString(h[:]), PubKey: pubkey, CreatedAt: 1_800_000_000, Kind: 11333, Tags: tags, Content: "", Sig: hex.EncodeToString(sig.Serialize())}
}

// One key has one spelling: an upper- or mixed-case pubkey, id or sig is
// refused, by CheckEventEncoding and by CheckSignature for every caller.
func TestOneSpellingPerKey(t *testing.T) {
	priv, _ := btcec.NewPrivateKey()
	pub := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	good := signAs(t, priv, pub)
	if ok, msg := CheckEventEncoding(good); !ok || !CheckSignature(good) {
		t.Fatalf("a lower-case event refused: %q", msg)
	}

	upper := signAs(t, priv, strings.ToUpper(pub))
	if ok, msg := CheckEventEncoding(upper); ok || !strings.HasPrefix(msg, "invalid: pubkey") {
		t.Fatalf("an upper-case pubkey: %v %q", ok, msg)
	}
	if CheckSignature(upper) {
		t.Fatal("CheckSignature passed an upper-case pubkey")
	}

	upSig := good
	upSig.Sig = strings.ToUpper(good.Sig)
	if ok, msg := CheckEventEncoding(upSig); ok || !strings.HasPrefix(msg, "invalid: sig") {
		t.Fatalf("an upper-case sig: %v %q", ok, msg)
	}
	upID := good
	upID.ID = strings.ToUpper(good.ID)
	if ok, msg := CheckEventEncoding(upID); ok || !strings.HasPrefix(msg, "invalid: id") {
		t.Fatalf("an upper-case id: %v %q", ok, msg)
	}
	short := good
	short.PubKey = pub[:62]
	if ok, _ := CheckEventEncoding(short); ok {
		t.Fatal("a short pubkey passed")
	}
}
