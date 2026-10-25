// Package atomicfile replaces files so that a crash leaves either the old
// content or the new one, never a mix.
package atomicfile

import (
	"os"
	"path/filepath"
)

// WriteFile replaces path with data so that a crash leaves either the old
// file or the new one: it writes a temporary file in the same directory, sets
// its mode, fsyncs it, renames it over path and fsyncs the directory. The
// file gets perm whatever the umask and whatever the old file had. When it
// fails, the temporary file is removed and path is as it was, unless only the
// final directory sync failed.
func WriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so that the entries made or removed in it
// survive a crash.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
