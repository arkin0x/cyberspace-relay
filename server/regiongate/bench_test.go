package regiongate

import (
	"fmt"
	"math/big"
	"testing"
)

// The cost of verification, by height. Level 1 of a hop is dominated by its
// 16 residues of hop_n, each about 2^h word additions per root of height h;
// everything else (form, one attempt, 17 primes, 16 paths) is microseconds.
// A sidestep and a boarding build one exact temporal tree of height K <= 16,
// and a ride one exact tree at height 16 plus 32 leaves of height 6 to 22.
//
//	go test -run '^$' -bench . -benchtime 3x ./server/regiongate/

func benchGeometry(axes [3]int, k int) hopGeometry {
	prev := make([]byte, 32)
	prev[31] = 7
	var g hopGeometry
	for i, h := range axes {
		g.bases[i], g.heights[i] = aligned(new(big.Int).Lsh(big.NewInt(12345), 40), h), h
	}
	g.bases[3], g.heights[3] = temporalBase(prev, k), k
	return g
}

func BenchmarkHopResidues(b *testing.B) {
	prev := make([]byte, 32)
	for _, h := range []int{12, 16, 20, 24, 26, 28} {
		for _, shape := range []struct {
			name string
			axes [3]int
		}{{"one-axis", [3]int{h, 0, 0}}, {"three-axes", [3]int{h, h, h}}} {
			g := benchGeometry(shape.axes, 8)
			primes := make([]uint64, hopSamples)
			for i := range primes {
				primes[i] = hopPrime(prev, uint64(i)*977)
			}
			b.Run(fmt.Sprintf("h%d/%s", h, shape.name), func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					for _, p := range primes {
						g.hopResidue(p)
					}
				}
			})
		}
	}
}

func BenchmarkTemporalTree(b *testing.B) {
	prev := make([]byte, 32)
	for _, k := range []int{8, 12, 16} {
		b.Run(fmt.Sprintf("K%d", k), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				temporalCantor(prev, k)
			}
		})
	}
}

func BenchmarkRideTrees(b *testing.B) {
	for _, h := range []int{14, 16, 18, 20} {
		b.Run(fmt.Sprintf("h%d", h), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				subtreeCantor(new(big.Int).Lsh(bigOne, 60), h)
			}
		})
	}
}
