package server

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/0ceanslim/grain/server/handlers"
	nostr "github.com/0ceanslim/grain/server/types"
)

// The onosendai profile as a NIP-17 DM inbox (owner, 2026-11-13: "let's make
// relay.onosendai accept dms and ill use that"), on the real profile files,
// real nostrdb and real websockets. Gift wraps (1059) are accepted from
// anyone; only the connection AUTHed as the p-tagged recipient can read,
// count or be sent one live. Each step fails if the rule it names is removed.
func TestOnosendaiDMInbox(t *testing.T) {
	var kA key
	for kA.pub == "" || !letters(kA, 1) {
		kA = newKey(t)
	}
	idA := kA.pub[:1]
	r := startRelay(t, speakeasyRegionPath, "enabled: true\nmax_open_databases: 1\nmax_connections_per_path: 3\nmap_size_mb: 32\nplanes: [0, 1]\n")
	r.register(t, idA)
	r.storeRoot(t, kA.spawn(t))

	alice, bob, eve := newKey(t), newKey(t), newKey(t)
	now := time.Now().Unix()
	// wrap is a gift wrap to recipient, signed by a throwaway key as NIP-59
	// says; the relay never reads its content.
	wrap := func(recipient key, at int64) nostr.Event {
		return newKey(t).signAt(t, at, 1059, "AqJ0aGlzIGlzIG5vdCByZWFsbHkgZW5jcnlwdGVk", []string{"p", recipient.pub})
	}
	// Bob's three gift wraps are his newest events; his five reactions are
	// older, so a broad filter with a limit meets the gift wraps first.
	aliceWraps := []nostr.Event{wrap(alice, now-20), wrap(alice, now-30)}
	bobWraps := []nostr.Event{wrap(bob, now-10), wrap(bob, now-11), wrap(bob, now-12)}
	var bobReactions []nostr.Event
	for i := 0; i < 5; i++ {
		bobReactions = append(bobReactions, eve.signAt(t, now-100-int64(i), 7, "+", []string{"p", bob.pub}))
	}
	var all []nostr.Event
	all = append(all, aliceWraps...)
	all = append(all, bobWraps...)
	all = append(all, bobReactions...)
	r.storeRoot(t, all...)

	ids := func(evts ...nostr.Event) []string {
		var out []string
		for _, e := range evts {
			out = append(out, e.ID)
		}
		sort.Strings(out)
		return out
	}
	same := func(got []string, want []string) bool {
		g := append([]string(nil), got...)
		sort.Strings(g)
		return strings.Join(g, ",") == strings.Join(want, ",")
	}
	authed := func(k key) *conn {
		c := mustDial(t, r.wsRoot)
		if ok, msg := c.auth(k, r.wsRoot, c.challenge); !ok {
			t.Fatalf("AUTH: %s", msg)
		}
		return c
	}

	t.Run("whitelist: 1059 accepted, 4 and bare 13/14/15 refused", func(t *testing.T) {
		c := mustDial(t, r.wsRoot)
		w := wrap(alice, now-40)
		if ok, msg := c.publish(w); !ok {
			t.Fatalf("gift wrap refused: %s", msg)
		}
		// OK comes before nostrdb's writer has indexed it; wait, so the
		// steps below count it.
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got, _ := r.db.Query([]nostr.Filter{{IDs: []string{w.ID}}}, 1); len(got) == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the accepted gift wrap was never stored")
			}
			time.Sleep(10 * time.Millisecond)
		}
		for _, kind := range []int{4, 13, 14, 15, 1} {
			ok, msg := c.publish(eve.sign(t, kind, "hi", []string{"p", alice.pub}))
			if ok || !strings.Contains(msg, "not whitelisted") {
				t.Fatalf("kind %d: want refused as not whitelisted, got %v %q", kind, ok, msg)
			}
		}
	})

	t.Run("size cap: a gift wrap over 64 KB is refused", func(t *testing.T) {
		c := mustDial(t, r.wsRoot)
		big := newKey(t).sign(t, 1059, strings.Repeat("A", 70000), []string{"p", alice.pub})
		if ok, msg := c.publish(big); ok {
			t.Fatalf("a 70 KB gift wrap was accepted: %s", msg)
		}
	})

	t.Run("unauthenticated: asking for 1059 needs AUTH", func(t *testing.T) {
		c := mustDial(t, r.wsRoot)
		for _, f := range []map[string]any{
			{"kinds": []int{1059}},
			{"kinds": []int{1059}, "#p": []string{alice.pub}},
			{"kinds": []int{7, 1059}},
		} {
			if got, closed := c.req("dm", f); len(got) != 0 || !strings.HasPrefix(closed, "auth-required:") {
				t.Fatalf("REQ %v: want auth-required and nothing, got %v %q", f, got, closed)
			}
			if n, closed := c.count("dm", f); n != -1 || !strings.HasPrefix(closed, "auth-required:") {
				t.Fatalf("COUNT %v: want auth-required, got %d %q", f, n, closed)
			}
		}
	})

	t.Run("unauthenticated: a broad filter never returns or counts a gift wrap", func(t *testing.T) {
		c := mustDial(t, r.wsRoot)
		got, closed := c.req("broad", map[string]any{"#p": []string{bob.pub}})
		if closed != "" || !same(got, ids(bobReactions...)) {
			t.Fatalf("REQ #p bob: want his 5 reactions only, got %d %q", len(got), closed)
		}
		// The limit is filled past the withheld gift wraps: a shortfall
		// would count them.
		got, _ = c.req("broad", map[string]any{"#p": []string{bob.pub}, "limit": 3})
		if !same(got, ids(bobReactions[:3]...)) {
			t.Fatalf("REQ #p bob limit 3: want his 3 newest reactions, got %v", got)
		}
		if n, _ := c.count("broad", map[string]any{"#p": []string{bob.pub}}); n != 5 {
			t.Fatalf("COUNT #p bob: want 5 (reactions only), got %d", n)
		}
		if got, _ := c.req("broad", map[string]any{"ids": []string{bobWraps[0].ID}}); len(got) != 0 {
			t.Fatal("REQ by id served a gift wrap to an unauthenticated client")
		}
		if n, _ := c.count("broad", map[string]any{"ids": []string{bobWraps[0].ID[:8]}}); n != 0 {
			t.Fatalf("COUNT by id prefix counted a gift wrap: %d", n)
		}
		if n, _ := c.count("broad", map[string]any{"since": now - 50, "until": now - 5}); n != 0 {
			t.Fatalf("COUNT of a time range holding only gift wraps: want 0, got %d", n)
		}
	})

	t.Run("tag keys other than # and one letter are refused, not passed on", func(t *testing.T) {
		// "##p" reached nostrdb as a second "#p", and nostrdb's JSON parser
		// lost its place on "#aa" and swallowed the "#p" after it: both
		// undid the #p narrowing and counted other people's gift wraps.
		c := authed(eve)
		for _, f := range []map[string]any{
			{"kinds": []int{1059}, "##p": []string{bob.pub}},
			{"kinds": []int{1059}, "#aa": []string{"zz"}},
			{"##p": []string{bob.pub}},
		} {
			if got, closed := c.req("tagkey", f); len(got) != 0 || !strings.HasPrefix(closed, "invalid:") {
				t.Fatalf("REQ %v: want invalid, got %d %q", f, len(got), closed)
			}
			if n, closed := c.count("tagkey", f); n != -1 || !strings.HasPrefix(closed, "invalid:") {
				t.Fatalf("COUNT %v: want invalid, got %d %q", f, n, closed)
			}
		}
	})

	t.Run("an ids prefix scan does not reveal gift wraps by the slots they take", func(t *testing.T) {
		// nostrdb fills a prefix query's limit in id order. Plant reactions
		// under prefix "0" and a gift wrap that sorts before them: if the
		// wrap took a slot, the limit would come back one short.
		carol := newKey(t)
		grind := func(ok func(id string) bool, sign func() nostr.Event) nostr.Event {
			for {
				if e := sign(); ok(e.ID) {
					return e
				}
			}
		}
		hidden := grind(func(id string) bool { return strings.HasPrefix(id, "00") }, func() nostr.Event { return wrap(carol, now-60) })
		var planted []nostr.Event
		for i := 0; i < 3; i++ {
			at := now - 200 - int64(i)
			planted = append(planted, grind(func(id string) bool { return id[0] == '0' && id[1] != '0' },
				func() nostr.Event { return newKey(t).signAt(t, at, 7, "+", []string{"p", carol.pub}) }))
		}
		r.storeRoot(t, append([]nostr.Event{hidden}, planted...)...)
		c := mustDial(t, r.wsRoot)
		got, closed := c.req("prefix", map[string]any{"ids": []string{"0"}, "#p": []string{carol.pub}, "limit": 3})
		if closed != "" || !same(got, ids(planted...)) {
			t.Fatalf("REQ ids 0 #p carol limit 3: want the 3 reactions, got %v %q", got, closed)
		}
		if n, _ := c.count("prefix", map[string]any{"ids": []string{"0"}, "#p": []string{carol.pub}}); n != 3 {
			t.Fatalf("COUNT ids 0 #p carol: want 3, got %d", n)
		}
		if n, _ := c.count("prefix", map[string]any{"authors": []string{hidden.PubKey[:2]}, "#p": []string{carol.pub}}); n != 0 {
			t.Fatalf("COUNT by the wrap's author prefix: want 0, got %d", n)
		}
	})

	t.Run("a stranger AUTHed as someone else sees and counts none", func(t *testing.T) {
		c := authed(eve)
		for _, f := range []map[string]any{
			{"kinds": []int{1059}},
			{"kinds": []int{1059}, "#p": []string{bob.pub}},
			{"kinds": []int{1059}, "#p": []string{bob.pub, alice.pub}},
		} {
			if got, closed := c.req("dm", f); len(got) != 0 || closed != "" {
				t.Fatalf("REQ %v as eve: want nothing, got %d %q", f, len(got), closed)
			}
			if n, closed := c.count("dm", f); n != 0 || closed != "" {
				t.Fatalf("COUNT %v as eve: want 0, got %d %q", f, n, closed)
			}
		}
		if n, _ := c.count("dm", map[string]any{"#p": []string{bob.pub}}); n != 5 {
			t.Fatalf("COUNT #p bob as eve: want 5, got %d", n)
		}
	})

	t.Run("the recipient sees and counts exactly their own", func(t *testing.T) {
		c := authed(alice)
		// Alice has her two stored wraps and the one the whitelist step sent.
		got, closed := c.req("dm", map[string]any{"kinds": []int{1059}})
		if closed != "" || len(got) != 3 {
			t.Fatalf("REQ 1059 as alice: want her 3, got %d %q", len(got), closed)
		}
		for _, id := range got {
			for _, b := range bobWraps {
				if id == b.ID {
					t.Fatal("alice was served bob's gift wrap")
				}
			}
		}
		if n, _ := c.count("dm", map[string]any{"kinds": []int{1059}}); n != 3 {
			t.Fatalf("COUNT 1059 as alice: want 3, got %d", n)
		}
		// A #p naming bob next to her own still yields only hers.
		if n, _ := c.count("dm", map[string]any{"kinds": []int{1059}, "#p": []string{alice.pub, bob.pub}}); n != 3 {
			t.Fatalf("COUNT 1059 #p alice,bob as alice: want 3, got %d", n)
		}
		// The limit applies to her own: the newest one is hers, not bob's.
		got, _ = c.req("dm", map[string]any{"kinds": []int{1059}, "limit": 1})
		if len(got) != 1 || got[0] != aliceWraps[0].ID {
			t.Fatalf("REQ 1059 limit 1 as alice: want her newest, got %v", got)
		}

		b := authed(bob)
		got, _ = b.req("dm", map[string]any{"#p": []string{bob.pub}})
		if !same(got, ids(append(append([]nostr.Event{}, bobWraps...), bobReactions...)...)) {
			t.Fatalf("REQ #p bob as bob: want his 3 wraps and 5 reactions, got %d", len(got))
		}
		if n, _ := b.count("dm", map[string]any{"#p": []string{bob.pub}}); n != 8 {
			t.Fatalf("COUNT #p bob as bob: want 8, got %d", n)
		}
	})

	t.Run("live: a new gift wrap reaches only its recipient", func(t *testing.T) {
		a, e, anon := authed(alice), authed(eve), mustDial(t, r.wsRoot)
		subscribe := func(c *conn, sub string, f map[string]any) {
			c.send("REQ", sub+"-live", f)
			c.until("EOSE "+sub, func(m []any) bool { return len(m) >= 2 && m[0] == "EOSE" && m[1] == sub+"-live" })
		}
		subscribe(a, "a", map[string]any{"kinds": []int{1059}})
		subscribe(e, "e", map[string]any{"kinds": []int{1059}, "#p": []string{alice.pub}})
		subscribe(anon, "n", map[string]any{"#p": []string{alice.pub}})

		w := wrap(alice, time.Now().Unix())
		if ok, msg := mustDial(t, r.wsRoot).publish(w); !ok {
			t.Fatalf("publish: %s", msg)
		}
		if got := a.live("a", time.Second); len(got) != 1 || got[0] != w.ID {
			t.Fatalf("alice live: want the new wrap, got %v", got)
		}
		if got := e.live("e", 300*time.Millisecond); len(got) != 0 {
			t.Fatalf("eve was sent alice's gift wrap live: %v", got)
		}
		if got := anon.live("n", 300*time.Millisecond); len(got) != 0 {
			t.Fatalf("an unauthenticated subscriber was sent alice's gift wrap live: %v", got)
		}
	})

	t.Run("speakeasy paths refuse a gift wrap: its throwaway author is never admitted", func(t *testing.T) {
		c := mustDial(t, r.wsRoot+"/C/"+idA)
		if ok, msg := c.auth(kA, r.wsRoot+"/C/"+idA, c.challenge); !ok {
			t.Fatalf("speakeasy AUTH: %s", msg)
		}
		if ok, msg := c.publish(wrap(alice, now)); ok {
			t.Fatalf("a speakeasy stored a gift wrap: %s", msg)
		}
		// A speakeasy takes any kind, so its kindless filters are gated one
		// query each; a REQ may carry only so many.
		var filters []any
		for i := 0; i <= handlers.MaxGatedFilters; i++ {
			filters = append(filters, map[string]any{"authors": []string{fmt.Sprintf("%02x", i)}})
		}
		c.send(append([]any{"REQ", "many"}, filters...)...)
		m := c.until("CLOSED many", func(m []any) bool { return len(m) >= 3 && m[1] == "many" && m[0] != "EVENT" })
		if reason, _ := m[2].(string); m[0] != "CLOSED" || !strings.HasPrefix(reason, "invalid:") {
			t.Fatalf("a REQ of %d kindless filters on a speakeasy: want CLOSED invalid, got %v", len(filters), m)
		}
	})
}
