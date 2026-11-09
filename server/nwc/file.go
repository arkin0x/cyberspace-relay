package nwc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// FileWallet is a Client whose connection string lives in a file outside
// the repository (ruling D2). The file is read again whenever it changes,
// so rotating the secret is replacing the file: no restart.
type FileWallet struct {
	path string

	mu     sync.Mutex
	client *Client
	mod    time.Time
	size   int64
}

// OpenFile reads the connection string at path. The error never quotes
// the file's content.
func OpenFile(path string) (*FileWallet, error) {
	f := &FileWallet{path: path}
	if _, err := f.current(); err != nil {
		return nil, err
	}
	return f, nil
}

// current is the client for the file as it is now.
func (f *FileWallet) current() (*Client, error) {
	st, err := os.Stat(f.path)
	if err != nil {
		return nil, fmt.Errorf("nwc: the connection file: %w", errors.Unwrap(err))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.client != nil && st.ModTime().Equal(f.mod) && st.Size() == f.size {
		return f.client, nil
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("nwc: the connection file: %w", errors.Unwrap(err))
	}
	uri, err := ParseURI(string(data))
	if err != nil {
		return nil, err
	}
	c, err := New(uri)
	if err != nil {
		return nil, err
	}
	f.client, f.mod, f.size = c, st.ModTime(), st.Size()
	return c, nil
}

// Describe names the connection without its secret, for logs.
func (f *FileWallet) Describe() string {
	c, err := f.current()
	if err != nil {
		return err.Error()
	}
	return c.URI().String()
}

// Insecure reports whether the file can be read by others than its owner.
func (f *FileWallet) Insecure() bool {
	st, err := os.Stat(f.path)
	return err == nil && st.Mode().Perm()&0o077 != 0
}

// MakeInvoice implements the checkout's Wallet.
func (f *FileWallet) MakeInvoice(ctx context.Context, amountMsat int64, description string, expiry time.Duration) (Invoice, error) {
	c, err := f.current()
	if err != nil {
		return Invoice{}, err
	}
	return c.MakeInvoice(ctx, amountMsat, description, expiry)
}

// LookupInvoice implements the checkout's Wallet.
func (f *FileWallet) LookupInvoice(ctx context.Context, paymentHash string) (Invoice, error) {
	c, err := f.current()
	if err != nil {
		return Invoice{}, err
	}
	return c.LookupInvoice(ctx, paymentHash)
}
