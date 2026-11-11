package api

import (
	"context"
	"strings"

	"github.com/0ceanslim/grain/config"
	"github.com/0ceanslim/grain/server/branding"
	"github.com/0ceanslim/grain/server/utils"
	"github.com/0ceanslim/grain/server/utils/log"
)

// runStoreBrandingImage is grain_storebrandingimage: params
// [slot, source], where slot is icon / logo / logo_light / banner and
// source is either an upload as a data: URL or an http(s) URL grain fetches
// once. grain keeps its own copy (see package branding), points the slot's
// relay_metadata.json field at it, and returns {url, type, width, height,
// bytes}. Owner-only like every NIP-86 method. To clear a slot, set its
// field to "" with changerelayicon / changerelaybanner /
// grain_changerelaylogo / grain_changerelaylogolight.
func runStoreBrandingImage(params []any, signer, requestBase string) (any, string) {
	slot, ok := paramString(params, 0)
	if !ok || !branding.IsSlot(slot) {
		return nil, "invalid slot: want one of " + strings.Join(branding.Slots, ", ")
	}
	source, ok := paramString(params, 1)
	source = strings.TrimSpace(source)
	if !ok || source == "" {
		return nil, "missing image"
	}

	var (
		img  branding.Image
		err  error
		from string
	)
	switch {
	case strings.HasPrefix(source, "data:"):
		from = "upload"
		var data []byte
		if data, err = branding.DecodeDataURL(source); err == nil {
			img, err = branding.Check(data)
		}
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		from = source
		ctx, cancel := context.WithTimeout(context.Background(), branding.FetchTimeout)
		img, err = branding.Fetch(ctx, source)
		cancel()
	default:
		return nil, "image must be an upload (data: URL) or an http(s) URL"
	}
	if err != nil {
		return nil, err.Error()
	}

	relayURL := ""
	if c := config.GetConfig(); c != nil {
		relayURL = c.Auth.RelayURL
	}
	base := branding.PublicBase(relayURL, nil)
	if base == "" {
		base = requestBase
	}
	u, err := branding.Save(slot, img, base, utils.SetRelayMetadataField)
	if err != nil {
		return nil, err.Error()
	}
	log.RelayAPI().Info("NIP-86 grain_storebrandingimage", "signer", signer, "slot", slot,
		"from", from, "type", img.Type, "bytes", len(img.Data), "url", u)
	return map[string]any{
		"url":    u,
		"type":   img.Type,
		"width":  img.Width,
		"height": img.Height,
		"bytes":  len(img.Data),
	}, ""
}
