package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestNamedSpeakeasy (step 6): a name routes exactly as the hex path does,
// to the same speakeasy (one database, one set of live events), but is its
// own URL: NIP-11 there is named by the name, and AUTH on a connection to
// the name must name the name's URL, as a client signs for the URL it
// connected to (#19's rule, per path).
func TestNamedSpeakeasy(t *testing.T) {
	var kIn, kOut key
	for kIn.pub == "" {
		kIn = newKey(t)
	}
	id := kIn.pub[:2]
	for kOut.pub == "" || inRegion(kOut, id) {
		kOut = newKey(t)
	}
	r := startRelay(t, speakeasyRegionPath, webYML)
	r.register(t, id)
	if err := r.rt.reg.SetName(id, "cafe-du-monde"); err != nil {
		t.Fatal(err)
	}
	r.storeRoot(t, kIn.spawn(t), kOut.spawn(t))
	urlHex, urlName := r.wsRoot+"/"+id, r.wsRoot+"/cafe-du-monde"

	if code, doc, _ := nip11(t, r.root+"/cafe-du-monde"); code != 200 || doc["name"] != "cafe-du-monde" {
		t.Fatalf("NIP-11 at the name: %d %v", code, doc)
	}
	if code, doc, _ := nip11(t, r.root+"/"+id); code != 200 || doc["name"] != "Speakeasy "+id {
		t.Fatalf("NIP-11 at the hex path: %d %v", code, doc)
	}
	for _, other := range []string{"/Cafe-du-monde", "/cafe-du-monde/", "/cafe-du"} {
		if code, _, _ := nip11(t, r.root+other); code != 404 {
			t.Errorf("NIP-11 at %s: %d, want 404", other, code)
		}
	}

	byName := mustDial(t, urlName)
	if ok, msg := byName.auth(kIn, urlHex, byName.challenge); ok || !strings.Contains(msg, "relay URL") {
		t.Fatalf("on the name, an AUTH naming the hex URL: %v %q", ok, msg)
	}
	if ok, msg := byName.auth(kIn, urlName, byName.challenge); !ok {
		t.Fatalf("on the name, an AUTH naming the name's URL: %q", msg)
	}
	byHex := mustDial(t, urlHex)
	if ok, msg := byHex.auth(kIn, urlName, byHex.challenge); ok {
		t.Fatalf("on the hex path, an AUTH naming the name's URL was accepted (%q)", msg)
	}
	if ok, msg := byHex.auth(kIn, urlHex, byHex.challenge); !ok {
		t.Fatalf("on the hex path: %q", msg)
	}
	note := kIn.sign(t, 1, "posted at the name")
	if ok, msg := byName.publish(note); !ok {
		t.Fatalf("publish at the name: %q", msg)
	}
	// nostrdb indexes asynchronously: ask until it is there.
	seen := false
	for i := 0; i < 50 && !seen; i++ {
		ids, closed := byHex.req(fmt.Sprintf("s%d", i), map[string]any{"ids": []string{note.ID}})
		if closed != "" {
			t.Fatalf("REQ on the hex path: %q", closed)
		}
		seen = len(ids) == 1
		if !seen {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !seen {
		t.Fatal("the hex path does not see the note posted at the name")
	}
	// An outsider is refused at the name as at the hex path.
	out := mustDial(t, urlName)
	out.auth(kOut, urlName, out.challenge)
	if _, closed := out.req("s", map[string]any{}); !strings.HasPrefix(closed, "restricted:") {
		t.Fatalf("an outsider at the name: %q", closed)
	}

	// Discovery names it; its url stays the hex address.
	_, d, _, _ := discover(t, r.root, id+strings.Repeat("0", 62))
	if len(d.Speakeasies) != 1 || d.Speakeasies[0].Name == nil || *d.Speakeasies[0].Name != "cafe-du-monde" || d.Speakeasies[0].URL != urlHex {
		t.Fatalf("discovery: %+v", d.Speakeasies)
	}
	// The page at either path shows both addresses.
	for _, p := range []string{"/cafe-du-monde", "/" + id} {
		code, body, _ := get(t, http.MethodGet, r.root+p, "Accept", browser)
		if code != 200 || !strings.Contains(body, urlName) || !strings.Contains(body, urlHex) || !strings.Contains(body, "<title>cafe-du-monde</title>") {
			t.Errorf("page at %s: %d", p, code)
		}
	}
	// The dial guard refuses the built-in client the name too.
	if speakeasyDialGuard(urlName) == nil {
		t.Error("the built-in client may dial a named speakeasy")
	}
}

// TestReserveAName: the page of a speakeasy without a name offers one for
// 7,000 sats; once paid, the name is live.
func TestReserveAName(t *testing.T) {
	r := startRelay(t, speakeasyRegionPath, webYML)
	orders := r.root + OrdersPath
	w, co := withCheckout(t, r)

	if code, out := post(t, orders, "application/json", `{"region":"abc","name":"cafe-du-monde"}`); code != 400 {
		t.Fatalf("a name for a region that is not a speakeasy: %d %v", code, out)
	}
	r.register(t, "abc")
	if _, body, _ := get(t, http.MethodGet, r.root+"/abc", "Accept", browser); !strings.Contains(body, "Reserve for 7,000 sats") || strings.Contains(body, "Create speakeasy") {
		t.Fatal("the speakeasy's page does not offer a name for 7,000 sats")
	}
	for name, want := range map[string]int{"cafe": 400, "admin": 400, "Cafe-Du-Monde": 400, "ab": 400} {
		if code, out := post(t, orders, "application/json", `{"region":"abc","name":"`+name+`"}`); code != want {
			t.Errorf("name %q: %d %v, want %d", name, code, out, want)
		}
	}
	code, o := post(t, orders, "application/json", `{"region":"abc","name":"cafe-du-monde"}`)
	if code != 200 || o["kind"] != "name" || o["name"] != "cafe-du-monde" || o["amount_sats"] != float64(7000) {
		t.Fatalf("name order: %d %v", code, o)
	}
	id := o["id"].(string)
	got, _ := co.Get(id)
	w.pay(got.PaymentHash)
	co.Poll(context.Background())
	if _, st := getJSON(t, orders+"/"+id); st["applied"] != true || st["url"] != r.wsRoot+"/cafe-du-monde" || st["outcome"] != "name reserved" {
		t.Fatalf("after paying: %v", st)
	}
	if code, doc, _ := nip11(t, r.root+"/cafe-du-monde"); code != 200 || doc["name"] != "cafe-du-monde" {
		t.Fatalf("NIP-11 at the paid name: %d %v", code, doc)
	}
	if _, body, _ := get(t, http.MethodGet, r.root+"/abc", "Accept", browser); strings.Contains(body, "Reserve for") {
		t.Fatal("a named speakeasy is offered another name")
	}
	if code, _ := post(t, orders, "application/json", `{"region":"abc","name":"second-name"}`); code != 409 {
		t.Fatalf("a second name: %d, want 409", code)
	}
}
