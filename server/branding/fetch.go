package branding

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// FetchTimeout bounds one fetch of an image URL, connection to last byte.
const FetchTimeout = 20 * time.Second

// allowPrivate lets tests fetch from a local server; production never sets it.
var allowPrivate = false

// publicOnly refuses connections to loopback, private, link-local and other
// non-public addresses. It runs on the resolved address at dial time, so a
// redirect or a DNS answer cannot point the fetch at the relay's own network.
func publicOnly(_, address string, _ syscall.RawConn) error {
	if allowPrivate {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return fmt.Errorf("refusing to fetch from non-public address %s", host)
	}
	return nil
}

var fetchClient = &http.Client{
	Timeout: FetchTimeout,
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, Control: publicOnly}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
		}
		return nil
	},
}

// Fetch downloads an image URL once (http or https only, public addresses
// only, at most MaxImageBytes) and checks it.
func Fetch(ctx context.Context, rawURL string) (Image, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Image{}, fmt.Errorf("not an http(s) URL: %q", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Image{}, err
	}
	req.Header.Set("Accept", "image/png,image/webp,image/jpeg,image/gif,image/x-icon;q=0.9,*/*;q=0.1")
	resp, err := fetchClient.Do(req)
	if err != nil {
		return Image{}, fmt.Errorf("fetch %s: %w", u.Redacted(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Image{}, fmt.Errorf("fetch %s: HTTP %d", u.Redacted(), resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxImageBytes+1))
	if err != nil {
		return Image{}, fmt.Errorf("fetch %s: %w", u.Redacted(), err)
	}
	return Check(data)
}
