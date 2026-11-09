package speakeasy

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// InvoiceQR draws a Lightning invoice as an SVG QR code, server side, so
// the payment page loads no third-party script. The invoice goes in upper
// case as a lightning: URI (BOLT 11 allows it), which QR's alphanumeric
// mode packs tighter, and wallets open it as a payment.
func InvoiceQR(bolt11 string) (string, error) {
	code, err := qr.Encode("LIGHTNING:"+strings.ToUpper(bolt11), qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="Lightning invoice QR code">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
