package regiongate

import (
	"math/big"
)

// The decimal arithmetic of CYBERSPACE_V2 §9.5, which the landfall
// derivation of DECK-0001 §1.2 runs in: every operation is correctly rounded
// to a fixed number of significant digits with ROUND_HALF_EVEN, exactly as
// Python's decimal module computes it (the reference, cyberspace_core.coords
// and cyberspace_core.hyperspace). Operands are always used exactly, never
// rounded first, as the General Decimal Arithmetic specification requires.
// Only what the derivation needs is here.

// decimal is c × 10^e.
type dec struct {
	c *big.Int
	e int
}

// The precisions the reference uses: 96 inside its localcontext() blocks
// (§9.5), and Python's default context, 28, for its module-level constants
// (TWO_PI, HALF_PI and WGS84_F in cyberspace_core.coords).
const (
	decPrec        = 96
	decDefaultPrec = 28
)

var (
	bigTen = big.NewInt(10)
	pow10s = func() []*big.Int {
		p := make([]*big.Int, 512)
		p[0] = big.NewInt(1)
		for i := 1; i < len(p); i++ {
			p[i] = new(big.Int).Mul(p[i-1], bigTen)
		}
		return p
	}()
)

func pow10(n int) *big.Int {
	if n < len(pow10s) {
		return pow10s[n]
	}
	return new(big.Int).Exp(bigTen, big.NewInt(int64(n)), nil)
}

// digits is the number of decimal digits of |c|, 1 for 0.
func digits(c *big.Int) int {
	bl := c.BitLen()
	if bl == 0 {
		return 1
	}
	// 1233/4096 is just below log10(2), and |c| >= 2^(bl-1), so d is at
	// most two too small.
	d := max(1, (bl-1)*1233>>12)
	for c.CmpAbs(pow10(d)) >= 0 {
		d++
	}
	return d
}

func decInt(v int64) dec { return dec{big.NewInt(v), 0} }

func decBig(v *big.Int) dec { return dec{new(big.Int).Set(v), 0} }

// decString parses a plain decimal literal ("3.14", "6378137", "1e-88")
// exactly, as Decimal(str) does.
func decString(s string) dec {
	exp := 0
	if i := indexByte(s, 'e'); i >= 0 {
		var ev int
		neg := false
		rest := s[i+1:]
		if rest != "" && (rest[0] == '-' || rest[0] == '+') {
			neg = rest[0] == '-'
			rest = rest[1:]
		}
		for _, r := range rest {
			ev = ev*10 + int(r-'0')
		}
		if neg {
			ev = -ev
		}
		exp, s = ev, s[:i]
	}
	if i := indexByte(s, '.'); i >= 0 {
		exp -= len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	c, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("decString: bad literal " + s)
	}
	return dec{c, exp}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// round rounds c × 10^e to prec significant digits with ROUND_HALF_EVEN.
// sticky says the exact value is a little more, in magnitude, than c × 10^e
// (a nonzero remainder was dropped); callers that pass it keep at least one
// digit beyond prec, so the half-way case is never misjudged.
func round(c *big.Int, e int, sticky bool, prec int) dec {
	n := digits(c)
	if n <= prec {
		return dec{c, e}
	}
	drop := n - prec
	neg := c.Sign() < 0
	// c is the caller's own: it becomes the quotient.
	q, r := c.Abs(c), new(big.Int)
	q.QuoRem(q, pow10(drop), r)
	r.Lsh(r, 1)
	switch cmp := r.Cmp(pow10(drop)); {
	case cmp > 0, cmp == 0 && (sticky || q.Bit(0) == 1):
		q.Add(q, bigOne)
	}
	e += drop
	if q.Cmp(pow10(prec)) == 0 {
		q.Quo(q, bigTen)
		e++
	}
	if neg {
		q.Neg(q)
	}
	return dec{q, e}
}

func (a dec) rounded(prec int) dec { return round(new(big.Int).Set(a.c), a.e, false, prec) }

// align returns the coefficients of a and b at their common (smaller)
// exponent.
func align(a, b dec) (*big.Int, *big.Int, int) {
	switch {
	case a.e == b.e:
		return a.c, b.c, a.e
	case a.e > b.e:
		return new(big.Int).Mul(a.c, pow10(a.e-b.e)), b.c, b.e
	default:
		return a.c, new(big.Int).Mul(b.c, pow10(b.e-a.e)), a.e
	}
}

func (a dec) add(b dec, prec int) dec {
	x, y, e := align(a, b)
	return round(new(big.Int).Add(x, y), e, false, prec)
}

func (a dec) sub(b dec, prec int) dec {
	x, y, e := align(a, b)
	return round(new(big.Int).Sub(x, y), e, false, prec)
}

func (a dec) mul(b dec, prec int) dec {
	return round(new(big.Int).Mul(a.c, b.c), a.e+b.e, false, prec)
}

// quo is a / b, correctly rounded. b must not be zero.
func (a dec) quo(b dec, prec int) dec {
	shift := max(0, prec+2+digits(b.c)-digits(a.c))
	num := new(big.Int).Mul(new(big.Int).Abs(a.c), pow10(shift))
	q, r := new(big.Int).QuoRem(num, new(big.Int).Abs(b.c), new(big.Int))
	if (a.c.Sign() < 0) != (b.c.Sign() < 0) {
		q.Neg(q)
	}
	return round(q, a.e-b.e-shift, r.Sign() != 0, prec)
}

// sqrt is the correctly rounded square root of a, which must not be
// negative.
func (a dec) sqrt(prec int) dec {
	s := max(0, 2*(prec+2)-digits(a.c))
	if (a.e-s)%2 != 0 {
		s++
	}
	n := new(big.Int).Mul(a.c, pow10(s))
	r := new(big.Int).Sqrt(n)
	sticky := new(big.Int).Mul(r, r).Cmp(n) != 0
	return round(r, (a.e-s)/2, sticky, prec)
}

// neg is -a, rounded to the context as Python's unary minus is.
func (a dec) neg(prec int) dec {
	return round(new(big.Int).Neg(a.c), a.e, false, prec)
}

func (a dec) abs(prec int) dec {
	return round(new(big.Int).Abs(a.c), a.e, false, prec)
}

func (a dec) cmp(b dec) int {
	x, y, _ := align(a, b)
	return x.Cmp(y)
}

// rem is Python's a % b on decimals: a - b × trunc(a / b), exact, with the
// sign of a.
func (a dec) rem(b dec, prec int) dec {
	x, y, e := align(a, b)
	return round(new(big.Int).Rem(x, y), e, false, prec)
}

// toIntegralHalfEven is to_integral_value(rounding=ROUND_HALF_EVEN).
func (a dec) toIntegralHalfEven() *big.Int {
	if a.e >= 0 {
		return new(big.Int).Mul(a.c, pow10(a.e))
	}
	neg := a.c.Sign() < 0
	q, r := new(big.Int).QuoRem(new(big.Int).Abs(a.c), pow10(-a.e), new(big.Int))
	r.Lsh(r, 1)
	if cmp := r.Cmp(pow10(-a.e)); cmp > 0 || cmp == 0 && q.Bit(0) == 1 {
		q.Add(q, bigOne)
	}
	if neg {
		q.Neg(q)
	}
	return q
}
