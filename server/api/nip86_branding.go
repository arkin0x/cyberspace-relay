package api

import (
	"context"
	"net/url"
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
// relay_metadata.json field at it (/branding/<file>), and returns {url,
// type, width, height, bytes}. Owner-only like every NIP-86 method. To clear
// a slot, set its field to "" with changerelayicon / changerelaybanner /
// grain_changerelaylogo / grain_changerelaylogolight.
func runStoreBrandingImage(params []any, signer string) (any, string) {
	slot, ok := paramString(params, 0)
	if !ok || !branding.IsSlot(slot) {
		return nil, "invalid slot: want one of " + strings.Join(branding.Slots, ", ")
	}
	source, ok := paramString(params, 1)
	source = strings.TrimSpace(source)
	if !ok || source == "" {
		return nil, "missing image"
	}
	return storeBrandingSource(slot, source, signer)
}

// runChangeRelayImage handles the plain write methods of the four image
// fields (changerelayicon, changerelaybanner, grain_changerelaylogo,
// grain_changerelaylogolight). Empty clears; a path on this relay or a URL
// on its own host is kept as set; anything else (an outside http(s) URL or a
// data: upload) is stored by grain first, so visitors never load an image
// from an outside host whichever NIP-86 client set it.
func runChangeRelayImage(params []any, signer, field, requestBase string) (any, string) {
	value, ok := paramString(params, 0)
	if !ok {
		return nil, "missing value"
	}
	value = strings.TrimSpace(value)
	if value != "" && !branding.IsOwnURL(value, ownHost(requestBase)) {
		if !strings.HasPrefix(value, "data:") && !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return nil, "invalid " + field + " URL"
		}
		if _, errStr := storeBrandingSource(field, value, signer); errStr != "" {
			return nil, errStr
		}
		return true, ""
	}
	if err := utils.SetRelayMetadataField(field, value); err != nil {
		return nil, err.Error()
	}
	log.RelayAPI().Info("NIP-86 changerelay* (image)", "signer", signer, "field", field, "value", value)
	return true, ""
}

// storeBrandingSource checks and stores one image (a data: upload or an
// http(s) URL fetched once) for slot and repoints the slot's field at it.
func storeBrandingSource(slot, source, signer string) (map[string]any, string) {
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
	p, err := branding.Save(slot, img, utils.SetRelayMetadataField)
	if err != nil {
		return nil, err.Error()
	}
	log.RelayAPI().Info("NIP-86 branding image stored", "signer", signer, "slot", slot,
		"from", from, "type", img.Type, "bytes", len(img.Data), "path", p)
	return map[string]any{
		"url":    p,
		"type":   img.Type,
		"width":  img.Width,
		"height": img.Height,
		"bytes":  len(img.Data),
	}, ""
}

// ownHost is the relay's public host: auth.relay_url's, else the request's.
func ownHost(requestBase string) string {
	relayURL := ""
	if c := config.GetConfig(); c != nil {
		relayURL = c.Auth.RelayURL
	}
	base := branding.PublicBase(relayURL, nil)
	if base == "" {
		base = requestBase
	}
	if u, err := url.Parse(base); err == nil {
		return u.Host
	}
	return ""
}
