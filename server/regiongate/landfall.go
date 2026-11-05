package regiongate

import (
	"crypto/sha256"
	"math/big"
)

// The landfall derivation of DECK-0001 §1.2: the WGS84 surface point a
// plane-0 block's hash chooses. A port of cyberspace_core.hyperspace
// landfall_xyz and landfall_coord_hex (arkin0x/cyberspace-cli af6eee8), with
// the helpers of cyberspace_core.coords it reuses, operation for operation,
// so the two agree bit for bit. decks/landfall-reference.py in the spec is
// the independent reference; both give the DECK's golden vectors.
//
// One detail follows the CLI rather than the spec's reference file: the
// CLI's TWO_PI, HALF_PI and WGS84_F are module constants, computed in
// Python's default context (28 digits), where the reference file computes
// TWO_PI and HALF_PI at 96. A longitude within 10^-28 of ±π/2 would be the
// only place they could part, and no block hash puts one there.

var landfallDomain = []byte("CYBERSPACE_LANDFALL_V1")

var (
	decPI      = decString("3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679")
	decTwoPI   = decPI.mul(decInt(2), decDefaultPrec)
	decHalfPI  = decPI.quo(decInt(2), decDefaultPrec)
	decTrigEps = decString("1e-88")
	decOne     = decInt(1)
	decTwo     = decInt(2)
	wgs84A     = decString("6378137")
	wgs84F     = decOne.quo(decString("298.257223563"), decDefaultPrec)
	unitsPerKm = decBig(new(big.Int).Lsh(big.NewInt(1000), 33))
	axisCenter = decBig(new(big.Int).Lsh(bigOne, AxisBits-1))
	two128     = decBig(new(big.Int).Lsh(bigOne, 128))
	decKm      = decInt(1000)
)

const trigMaxIter = 256

// sinCos is _sin_cos_decimal: range reduction to [-π/2, π/2], then the
// Taylor series of each, ending when a term is below TRIG_EPS.
func sinCos(x dec) (dec, dec) {
	const p = decPrec
	x = x.rem(decTwoPI, p)
	if x.cmp(decPI) > 0 {
		x = x.sub(decTwoPI, p)
	}
	cosSign := decOne
	if x.cmp(decHalfPI) > 0 {
		x = decPI.sub(x, p)
		cosSign = decInt(-1)
	} else if x.cmp(decHalfPI.neg(p)) < 0 {
		x = decPI.neg(p).sub(x, p)
		cosSign = decInt(-1)
	}
	x2 := x.mul(x, p)
	sinSum, sinTerm := x, x
	converged := false
	for k := int64(1); k <= trigMaxIter; k++ {
		sinTerm = sinTerm.neg(p).mul(x2, p).quo(decInt((2*k)*(2*k+1)), p)
		sinSum = sinSum.add(sinTerm, p)
		if sinTerm.abs(p).cmp(decTrigEps) < 0 {
			converged = true
			break
		}
	}
	if !converged {
		panic("sin() Taylor series did not converge")
	}
	cosSum, cosTerm := decOne, decOne
	converged = false
	for k := int64(1); k <= trigMaxIter; k++ {
		cosTerm = cosTerm.neg(p).mul(x2, p).quo(decInt((2*k-1)*(2*k)), p)
		cosSum = cosSum.add(cosTerm, p)
		if cosTerm.abs(p).cmp(decTrigEps) < 0 {
			converged = true
			break
		}
	}
	if !converged {
		panic("cos() Taylor series did not converge")
	}
	return sinSum, cosSum.mul(cosSign, p)
}

// kmToAxis is _km_to_axis_u: kilometres from the centre to an 85-bit axis
// value, rounded half even and clamped.
func kmToAxis(km dec) *big.Int {
	u := km.mul(unitsPerKm, decPrec).add(axisCenter, decPrec).toIntegralHalfEven()
	if u.Sign() < 0 {
		return new(big.Int)
	}
	if u.Cmp(axisMask) > 0 {
		return new(big.Int).Set(axisMask)
	}
	return u
}

// LandfallCoord is the stop coordinate of a plane-0 block (DECK-0001 §1.2),
// from its 32-byte hash in display order.
func LandfallCoord(blockHash []byte) [32]byte {
	const p = decPrec
	seed := sha256.Sum256(append(append([]byte{}, landfallDomain...), blockHash...))
	u1 := decBig(new(big.Int).SetBytes(seed[0:16])).quo(two128, p)
	u2 := decBig(new(big.Int).SetBytes(seed[16:32])).quo(two128, p)
	lon := decTwo.mul(u1, p).sub(decOne, p).mul(decPI, p)
	z := decTwo.mul(u2, p).sub(decOne, p)
	rxy := decOne.sub(z.mul(z, p), p).sqrt(p)
	sinLon, cosLon := sinCos(lon)
	dx, dy, dz := rxy.mul(cosLon, p), rxy.mul(sinLon, p), z
	bm := wgs84A.mul(decOne.sub(wgs84F, p), p)
	inv := dx.mul(dx, p).add(dy.mul(dy, p), p).quo(wgs84A.mul(wgs84A, p), p).
		add(dz.mul(dz, p).quo(bm.mul(bm, p), p), p).sqrt(p)
	r := decOne.quo(inv, p)
	// ECEF kilometres, permuted into Cyberspace axes (§9.4): X_cs = X,
	// Y_cs = Z, Z_cs = Y.
	xk := r.mul(dx, p).quo(decKm, p)
	yk := r.mul(dy, p).quo(decKm, p)
	zk := r.mul(dz, p).quo(decKm, p)
	return packCoord(kmToAxis(xk), kmToAxis(zk), kmToAxis(yk), 0)
}
