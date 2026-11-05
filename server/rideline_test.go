package server

import (
	"context"
	"testing"

	"github.com/0ceanslim/grain/server/regiongate"
)

// TestGatesShareOneLinePerInstance: the root gate (region.yml) and the
// speakeasies' gate (speakeasies.yml) get the same Bitcoin line, so it is
// loaded once; a restart (a new instance context) builds a new one, and
// another line configuration gets its own.
func TestGatesShareOneLinePerInstance(t *testing.T) {
	root, err := regiongate.ParseConfig([]byte("enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := regiongate.ParseSharedConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	lineOf := func(ctx context.Context, cfg *regiongate.Config) regiongate.Line {
		return gateVerifier(ctx, cfg).Proofs.(regiongate.SpecProofs).Line
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := lineOf(ctx, root), lineOf(ctx, shared)
	if a == nil || a != b {
		t.Fatalf("the root's and the speakeasies' gates have different lines: %p %p", a, b)
	}
	rideLines.mu.Lock()
	n := len(rideLines.byKey)
	rideLines.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d lines built for one configuration", n)
	}
	other := *root
	other.LinePublisher = "ab" + root.LinePublisher[2:]
	if lineOf(ctx, &other) == a {
		t.Fatal("another publisher shares the line")
	}
	restart, stop := context.WithCancel(context.Background())
	defer stop()
	if c := lineOf(restart, root); c == nil || c == a {
		t.Fatal("a restart kept the old instance's line")
	}
	off := *root
	f := false
	off.CheckRides = &f
	if lineOf(restart, &off) != nil {
		t.Fatal("check_rides off still gives a line")
	}
}
