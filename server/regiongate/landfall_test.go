package regiongate

import (
	"bufio"
	"encoding/hex"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The golden vectors of DECK-0001 §1.2 (consensus locks), mainnet block
// hashes, copied from the DECK (arkin0x/cyberspace 9210d6d) and from
// cyberspace_core.hyperspace.LANDFALL_GOLDEN_VECTORS.
var landfallGolden = []struct {
	height      int
	hash, coord string
}{
	{398, "000000002f7d702a27ccd65158740198f79d4ba1ddea8ab14b56b63a6289fe89", "56db6db6db6db6db6db6db3e27c436f9d3b79fb5fc6457798936b3e749e38f56"},
	{100399, "000000000003cb256436f213199e7047e187ab99e6d3176262bfb9be49d2a31a", "3b6db6db6db6db6db6db6d1eb09e85e5f572906af5a025a39ae284dd83278b72"},
	{300399, "0000000000000000212f189879294318528669d239d5fbd30e6ffcc6015ced21", "c492492492492492492492c7807ba8ecefd0a48a7b41dfbb50da5947b489ed8c"},
	{363199, "000000000000000001e65a8804c7d97ee1fd52394632bdebdaf402935dcddeec", "a9249249249249249249258087f30451bd8dd013357959fe2b07fa052488980c"},
	{500399, "000000000000000000521f92387f9f43258f62465e9f88b19ecad2c30e44d7ff", "3b6db6db6db6db6db6db6d312f699ee9f35318557d9ee813b46f229215524a30"},
	{700398, "00000000000000000005608e4c1ff53901186e766df5eaa87c636857ed814fa9", "56db6db6db6db6db6db6dbfdb284c1592e0d02ffd65f9d6c12d48a2b483d7da0"},
	{900399, "00000000000000000001e412795ed39b18e56338e9b3c20d91edf59d20e020c9", "c4924924924924924924920c53c81e9d260623340e5c3a75b6de6e4715cd1724"},
	{950399, "00000000000000000001f081b994866dc3beb2c3ecd5976e9bda474e54e027c1", "e000000000000000000000618f9c2d172da11fc0701996d4a89df1f60aecf732"},
}

func TestLandfallGoldenVectors(t *testing.T) {
	for _, v := range landfallGolden {
		h, _ := hex.DecodeString(v.hash)
		got := LandfallCoord(h)
		if hex.EncodeToString(got[:]) != v.coord {
			t.Errorf("block %d: landfall %x, want %s", v.height, got, v.coord)
		}
	}
}

func BenchmarkLandfall(b *testing.B) {
	h, _ := hex.DecodeString(landfallGolden[0].hash)
	for n := 0; n < b.N; n++ {
		LandfallCoord(h)
	}
}

// TestLandfallAgreesWithTheReferenceLine checks every landfall of a whole
// line against the reference's. REGIONGATE_REF_LINE names a TSV of height,
// block hash, merkle root, stop coordinate (cyberspace_core's resolve_stop
// and stop_from_block); without it the test is skipped. The PR that added
// it ran it over mainnet 0 to 974,696.
func TestLandfallAgreesWithTheReferenceLine(t *testing.T) {
	path := os.Getenv("REGIONGATE_REF_LINE")
	if path == "" {
		t.Skip("REGIONGATE_REF_LINE not set")
	}
	rows := readRefLine(t, path)
	var bad, landfalls atomic.Int64
	var wg sync.WaitGroup
	next := atomic.Int64{}
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(rows) {
					return
				}
				r := rows[i]
				if strings.IndexByte("02468ace", r.merkle[63]) < 0 { // a port
					continue
				}
				landfalls.Add(1)
				h, _ := hex.DecodeString(r.hash)
				if got := LandfallCoord(h); hex.EncodeToString(got[:]) != r.coord {
					if bad.Add(1) <= 5 {
						t.Errorf("block %d: landfall %x, the reference %s", r.height, got, r.coord)
					}
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("%d landfalls of %d stops, %d disagree", landfalls.Load(), len(rows), bad.Load())
}

type refLineRow struct {
	height              uint64
	hash, merkle, coord string
}

func readRefLine(t *testing.T, path string) []refLineRow {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []refLineRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		h, _ := strconv.ParseUint(p[0], 10, 64)
		rows = append(rows, refLineRow{h, p[1], p[2], p[3]})
	}
	return rows
}
