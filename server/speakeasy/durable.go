package speakeasy

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteDurable replaces path with data atomically and durably: a temp file
// in the same directory, written and fsynced, renamed over path, then the
// directory fsynced, so after a crash the file is either the old one or
// the new one, and a rename that returned is not lost. The orders file and
// the registry are written this way: each records money.
func WriteDurable(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	name := tmp.Name()
	fail := func(step string, err error) error {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("%s: %w", step, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write temp", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail("chmod temp", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("fsync temp", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("rename: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}
