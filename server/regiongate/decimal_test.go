package regiongate

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// decimalOpsFile holds operations of Python's decimal module at precisions
// 96 and 28 with ROUND_HALF_EVEN, the arithmetic the reference derives
// landfalls in (CYBERSPACE_V2 §9.5), exact halves among them
// (testdata/tools/decimal-ops.py).
const decimalOpsFile = "testdata/decimal-ops.json"

func TestDecimalAgreesWithPython(t *testing.T) {
	data, err := os.ReadFile(decimalOpsFile)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Op      string
			Prec    int
			A, B, R []json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	num := func(raw []json.RawMessage) dec {
		var c string
		var e int
		json.Unmarshal(raw[0], &c)
		json.Unmarshal(raw[1], &e)
		v, _ := new(big.Int).SetString(c, 10)
		return dec{v, e}
	}
	bad := 0
	for i, c := range f.Cases {
		a, want := num(c.A), num(c.R)
		var b dec
		if c.B != nil {
			b = num(c.B)
		}
		var got dec
		switch c.Op {
		case "add":
			got = a.add(b, c.Prec)
		case "sub":
			got = a.sub(b, c.Prec)
		case "mul":
			got = a.mul(b, c.Prec)
		case "quo":
			got = a.quo(b, c.Prec)
		case "rem":
			got = a.rem(b, c.Prec)
		case "sqrt":
			got = a.sqrt(c.Prec)
		case "neg":
			got = a.neg(c.Prec)
		case "abs":
			got = a.abs(c.Prec)
		case "integral":
			got = dec{a.toIntegralHalfEven(), 0}
		case "cmp":
			got = decInt(int64(a.cmp(b)))
		default:
			t.Fatalf("unknown op %q", c.Op)
		}
		if got.cmp(want) != 0 || c.Op != "integral" && c.Op != "cmp" && digits(got.c) > c.Prec {
			if bad++; bad <= 10 {
				t.Errorf("case %d: %s at %d of %v, %v: got %v e%d, want %v e%d", i, c.Op, c.Prec, a.c, b.c, got.c, got.e, want.c, want.e)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d cases disagree", bad, len(f.Cases))
	}
	t.Logf("%d cases agree", len(f.Cases))
}

func TestDigits(t *testing.T) {
	for n := 1; n < 400; n++ {
		p := pow10(n - 1)
		if d := digits(p); d != n {
			t.Fatalf("digits(10^%d) = %d", n-1, d)
		}
		if d := digits(new(big.Int).Sub(pow10(n), bigOne)); d != n {
			t.Fatalf("digits(10^%d - 1) = %d", n, d)
		}
		if d := digits(new(big.Int).Neg(p)); d != n {
			t.Fatalf("digits(-10^%d) = %d", n-1, d)
		}
	}
}
