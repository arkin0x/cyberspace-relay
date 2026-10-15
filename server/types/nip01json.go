package relay

import (
	"strconv"
	"strings"
)

// NIP-01 JSON: the exact bytes an event id is the hash of, and the bytes
// nostrdb is fed, which recomputes and checks that id.
//
// Go's encoding/json is wrong for both. It escapes &, < and > as \u0026,
// \u003c and \u003e (HTML safety), and always escapes U+2028 and U+2029.
// NIP-01 escapes only the quote, the backslash and control characters, so
// an event whose content or tags held any of those characters got a
// different serialization here than its author signed: the signature check
// refused it (U+2028/U+2029), or nostrdb dropped it on ingest after the relay
// had already answered OK (&, <, >). Every profile or comment carrying a URL
// with a query string was silently lost that way (arkinox, 2026-10-15).

// AppendNIP01String appends s as a JSON string, escaped exactly as NIP-01
// specifies: \" \\ \b \t \n \f \r, other control characters (below 0x20)
// as \u00XX, and every other character, invalid UTF-8 included, as is.
func AppendNIP01String(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			// Copy the run of characters that need no escape in one write.
			j := i + 1
			for j < len(s) && s[j] >= 0x20 && s[j] != '"' && s[j] != '\\' {
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteString(`\u00`)
			b.WriteByte("0123456789abcdef"[c>>4])
			b.WriteByte("0123456789abcdef"[c&0xf])
		}
		i++
	}
	b.WriteByte('"')
}

func appendTags(b *strings.Builder, tags [][]string) {
	b.WriteByte('[')
	for i, tag := range tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for j, v := range tag {
			if j > 0 {
				b.WriteByte(',')
			}
			AppendNIP01String(b, v)
		}
		b.WriteByte(']')
	}
	b.WriteByte(']')
}

// IDPreimage is the NIP-01 serialization the event id is the SHA-256 of:
// [0,<pubkey>,<created_at>,<kind>,<tags>,<content>].
func (e Event) IDPreimage() string {
	var b strings.Builder
	b.Grow(len(e.Content) + 128)
	b.WriteString("[0,")
	AppendNIP01String(&b, e.PubKey)
	b.WriteByte(',')
	b.WriteString(strconv.FormatInt(e.CreatedAt, 10))
	b.WriteByte(',')
	b.WriteString(strconv.Itoa(e.Kind))
	b.WriteByte(',')
	if e.Tags == nil {
		b.WriteString("[]")
	} else {
		appendTags(&b, e.Tags)
	}
	b.WriteByte(',')
	AppendNIP01String(&b, e.Content)
	b.WriteByte(']')
	return b.String()
}

// NIP01JSON is the whole event as a JSON object, its strings escaped as
// NIP-01 escapes them, so a reader that recomputes the id from it gets the
// id the author signed.
func (e Event) NIP01JSON() string {
	var b strings.Builder
	b.Grow(len(e.Content) + 320)
	b.WriteString(`{"id":`)
	AppendNIP01String(&b, e.ID)
	b.WriteString(`,"pubkey":`)
	AppendNIP01String(&b, e.PubKey)
	b.WriteString(`,"created_at":`)
	b.WriteString(strconv.FormatInt(e.CreatedAt, 10))
	b.WriteString(`,"kind":`)
	b.WriteString(strconv.Itoa(e.Kind))
	b.WriteString(`,"tags":`)
	if e.Tags == nil {
		b.WriteString("[]")
	} else {
		appendTags(&b, e.Tags)
	}
	b.WriteString(`,"content":`)
	AppendNIP01String(&b, e.Content)
	b.WriteString(`,"sig":`)
	AppendNIP01String(&b, e.Sig)
	b.WriteByte('}')
	return b.String()
}
