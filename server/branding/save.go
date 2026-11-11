package branding

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/0ceanslim/grain/server/utils/log"
)

// PublicBase is the relay's public web origin ("https://relay.example"),
// which stored image URLs are built on so NIP-11 clients on other origins can
// load them. It comes from auth.relay_url when set (the operator's declared
// public URL; ws/wss map to http/https), else from the request that stores
// the image. "" when neither says.
func PublicBase(relayURL string, r *http.Request) string {
	if u, err := url.Parse(strings.TrimSpace(relayURL)); err == nil && u.Host != "" {
		switch u.Scheme {
		case "wss", "https":
			return "https://" + u.Host
		case "ws", "http":
			return "http://" + u.Host
		}
	}
	if r != nil && r.Host != "" {
		scheme := "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		return scheme + "://" + r.Host
	}
	return ""
}

// Save stores img for slot, points the slot's relay metadata field at the
// self-hosted copy through setField (utils.SetRelayMetadataField), then drops
// the slot's earlier copies. Returns the new URL.
func Save(slot string, img Image, base string, setField func(field, value string) error) (string, error) {
	if base == "" {
		return "", errors.New("cannot tell the relay's public URL: set auth.relay_url in config.yml")
	}
	name, err := Store(slot, img)
	if err != nil {
		return "", err
	}
	u := strings.TrimRight(base, "/") + URLPrefix + name
	if err := setField(slot, u); err != nil {
		return "", err
	}
	Prune(slot, name)
	return u, nil
}

// ImportExternal makes grain's own copy of any branding image still pointing
// at an outside host (e.g. a profile's seeded relay_metadata.json, or a
// changerelayicon from a NIP-86 client), so visitors never fetch from it.
// current maps slot to its field's value. Values that are empty, not
// http(s), or on the relay's own host (its stored copies, or e.g. its
// /static/ assets) are left as they are; a fetch that fails is logged and the
// field kept, to be tried on the next start.
func ImportExternal(ctx context.Context, base string, current map[string]string, setField func(field, value string) error) {
	b, err := url.Parse(base)
	if base == "" || err != nil {
		return
	}
	for _, slot := range Slots {
		v := strings.TrimSpace(current[slot])
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.EqualFold(u.Host, b.Host) {
			continue
		}
		img, err := Fetch(ctx, v)
		if err != nil {
			log.Util().Warn("Branding image not imported; still served from its source", "slot", slot, "url", v, "error", err)
			continue
		}
		stored, err := Save(slot, img, base, setField)
		if err != nil {
			log.Util().Warn("Branding image not stored", "slot", slot, "url", v, "error", err)
			continue
		}
		log.Util().Info("Branding image stored locally", "slot", slot, "from", v, "url", stored)
	}
}
