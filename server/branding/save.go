package branding

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/0ceanslim/grain/server/utils/log"
)

// PublicBase is the relay's public web origin ("https://relay.example"). It
// comes from auth.relay_url when set (the operator's declared public URL;
// ws/wss map to http/https), else from the request. "" when neither says.
// Used to make a stored image's relative path absolute where a client on
// another origin needs it (the NIP-11 icon and banner), at serve time, so a
// domain move or an admin session on localhost never bakes a wrong origin in.
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

// Absolute makes a relay-relative path ("/branding/...", "/static/...")
// absolute on base; anything else (already absolute, empty, or no base) is
// returned unchanged.
func Absolute(v, base string) string {
	if base == "" || !IsLocalPath(v) {
		return v
	}
	return strings.TrimRight(base, "/") + v
}

// IsLocalPath reports whether v is a path on this relay ("/x", not "//x").
func IsLocalPath(v string) bool {
	return strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//")
}

// IsOwnURL reports whether v needs no copy: a path on this relay, or an
// absolute URL on the relay's own host (ownHost, e.g. "relay.example").
func IsOwnURL(v, ownHost string) bool {
	if IsLocalPath(v) {
		return true
	}
	u, err := url.Parse(v)
	return err == nil && ownHost != "" && strings.EqualFold(u.Host, ownHost)
}

// saveMu serializes Save, so two stores to one slot cannot prune each
// other's file, and the import cannot interleave with an owner's store.
var saveMu sync.Mutex

// Save stores img for slot, points the slot's relay metadata field at the
// self-hosted copy (the relay-relative path /branding/<file>) through
// setField (utils.SetRelayMetadataField), then drops the slot's earlier
// copies. Returns the stored path.
func Save(slot string, img Image, setField func(field, value string) error) (string, error) {
	saveMu.Lock()
	defer saveMu.Unlock()
	name, err := Store(slot, img)
	if err != nil {
		return "", err
	}
	p := URLPrefix + name
	if err := setField(slot, p); err != nil {
		return "", err
	}
	Prune(slot, name)
	return p, nil
}

// ImportExternal makes grain's own copy of any branding image still pointing
// at an outside host (e.g. a profile's seeded relay_metadata.json), so
// visitors never fetch from it. get reads a slot's field live. Values that
// are empty, not http(s), or already the relay's own (IsOwnURL) are left as
// they are. A value the owner changes while its image is being fetched is
// left to the owner. A fetch that fails is logged and the field kept, to be
// tried on the next start.
func ImportExternal(ctx context.Context, ownHost string, get func(field string) string, setField func(field, value string) error) {
	for _, slot := range Slots {
		v := strings.TrimSpace(get(slot))
		if v == "" || IsOwnURL(v, ownHost) {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		img, err := Fetch(ctx, v)
		if err != nil {
			log.Util().Warn("Branding image not imported; still served from its source", "slot", slot, "url", v, "error", err)
			continue
		}
		var stored string
		err = func() error {
			saveMu.Lock()
			changed := strings.TrimSpace(get(slot)) != v
			saveMu.Unlock()
			if changed {
				return errors.New("changed by the owner during the fetch; left as set")
			}
			var serr error
			stored, serr = Save(slot, img, setField)
			return serr
		}()
		if err != nil {
			log.Util().Warn("Branding image not stored", "slot", slot, "url", v, "error", err)
			continue
		}
		log.Util().Info("Branding image stored locally", "slot", slot, "from", v, "path", stored)
	}
}
