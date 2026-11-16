package handlers

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time { return c.t }

// A copy of an event in flight, or stored a moment ago, is a duplicate; a
// copy of a refused one is not; the same event in another database is not.
func TestRecentEventsClaim(t *testing.T) {
	clk := &stepClock{t: time.Unix(1_800_000_000, 0)}
	s := newRecentEventSet(100, clk.now)
	root, other := recentKey("", "ab"), recentKey("/C/a", "ab")

	ok, _, done := s.claim(root)
	if !ok {
		t.Fatal("first claim refused")
	}
	if ok, msg, _ := s.claim(root); ok || msg != "error: this event is already being processed; try again shortly" {
		t.Fatalf("a copy in flight: %v %q", ok, msg)
	}
	if ok, _, d := s.claim(other); !ok {
		t.Fatal("the same event for a speakeasy's database was refused")
	} else {
		d(false)
	}
	done(true)
	if ok, msg, _ := s.claim(root); ok || msg != "duplicate: already have this event" {
		t.Fatalf("a copy just stored: %v %q", ok, msg)
	}
	clk.t = clk.t.Add(recentStoredTTL)
	if ok, _, d := s.claim(root); !ok {
		t.Fatal("still held after recentStoredTTL (nostrdb has it indexed by then)")
	} else {
		d(false)
	}

	// Refused: released at once, so a later copy is judged afresh.
	ok, _, done = s.claim(recentKey("", "cd"))
	done(false)
	if ok, _, _ := s.claim(recentKey("", "cd")); !ok {
		t.Fatal("a copy of a refused event was answered as a duplicate")
	}

	// A claim whose holder never finished expires.
	s.claim(recentKey("", "ef"))
	clk.t = clk.t.Add(recentInFlightTTL)
	if ok, _, _ := s.claim(recentKey("", "ef")); !ok {
		t.Fatal("an abandoned claim never expired")
	}
	if len(s.entries) != s.order.Len() {
		t.Fatalf("map %d and list %d disagree", len(s.entries), s.order.Len())
	}
}

// The table is bounded: expired entries go, and when it is full of live
// claims a new event passes untracked rather than being refused.
func TestRecentEventsBounded(t *testing.T) {
	clk := &stepClock{t: time.Unix(1_800_000_000, 0)}
	s := newRecentEventSet(3, clk.now)
	for i := 0; i < 3; i++ {
		_, _, done := s.claim(recentKey("", fmt.Sprint(i)))
		done(true)
	}
	ok, _, done := s.claim(recentKey("", "x"))
	if !ok {
		t.Fatal("a full table refused a new event")
	}
	done(true) // untracked: a no-op
	if s.order.Len() != 3 || len(s.entries) != 3 {
		t.Fatalf("over the cap: %d entries", s.order.Len())
	}
	clk.t = clk.t.Add(recentStoredTTL)
	s.claim(recentKey("", "y"))
	if s.order.Len() != 1 {
		t.Fatalf("expired entries kept: %d", s.order.Len())
	}
}

// Many copies at once: exactly one wins the claim.
func TestRecentEventsConcurrentCopies(t *testing.T) {
	s := newRecentEventSet(100, time.Now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, dup := 0, 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, msg, done := s.claim(recentKey("", "ab"))
			mu.Lock()
			defer mu.Unlock()
			if ok {
				won++
				done(true)
			} else if strings.HasPrefix(msg, "error: this event is already being processed") || strings.HasPrefix(msg, "duplicate:") {
				dup++
			}
		}()
	}
	wg.Wait()
	if won != 1 || dup != 31 {
		t.Fatalf("won %d, duplicates %d; want 1 and 31", won, dup)
	}
}

func TestStoresKind(t *testing.T) {
	for kind, want := range map[int]bool{0: true, 1: true, 2: false, 5: true, 3333: true, 11333: true, 19999: true, 20000: false, 23330: false, 29999: false, 30000: true, 33331: true} {
		if got := storesKind(kind); got != want {
			t.Errorf("storesKind(%d) = %v, want %v", kind, got, want)
		}
	}
}
