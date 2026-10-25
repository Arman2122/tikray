package artifacts

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	// maxCoreBytes caps the xray binary taken out of a release zip.
	maxCoreBytes = 200 << 20
	// tempPrefix starts the name of an install still in progress.
	tempPrefix = ".tmp-"

	coreFile = "xray"
	metaFile = "meta.json"
)

// ErrSlotExists means a core slot for the version is already installed.
var ErrSlotExists = errors.New("core slot already exists")

// Meta describes an installed core. It is stored as meta.json in the slot.
type Meta struct {
	Version      string    `json:"version"`
	Source       string    `json:"source"`
	ZipSHA256    string    `json:"zip_sha256"`
	BinarySHA256 string    `json:"binary_sha256"`
	Verified     string    `json:"verified"`
	InstalledAt  time.Time `json:"installed_at"`
}

// Slot is one installed core, /data/cores/<ver>/ with xray and meta.json.
type Slot struct {
	Version xrayver.Version
	Dir     string
	Meta    Meta
}

// InstallCore installs the xray binary from the release zip into a new slot
// for v and returns it. The zip is treated as untrusted: only a root entry
// named exactly "xray" is used, and it must be a non-empty regular file of at
// most 200 MiB. InstallCore sets m.Version and m.BinarySHA256 itself and
// fills in InstalledAt when it is zero; the rest of m is the caller's.
//
// The slot is built in a temporary directory of coresDir and renamed into
// place, so a reader never sees a half-written slot, and a failed install
// leaves neither a slot nor a temporary directory. A slot that already exists
// is not touched and gives ErrSlotExists.
func InstallCore(coresDir string, v xrayver.Version, zipPath string, m Meta) (Slot, error) {
	return installCore(coresDir, v, zipPath, m, maxCoreBytes)
}

func installCore(coresDir string, v xrayver.Version, zipPath string, m Meta, limit int64) (Slot, error) {
	final := filepath.Join(coresDir, v.String())
	exists := fmt.Errorf("%w: %s", ErrSlotExists, v)
	if _, err := os.Lstat(final); err == nil {
		return Slot{}, exists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Slot{}, err
	}
	if err := os.MkdirAll(coresDir, 0o755); err != nil {
		return Slot{}, err
	}
	tmp, err := os.MkdirTemp(coresDir, tempPrefix+v.String()+"-")
	if err != nil {
		return Slot{}, err
	}
	defer os.RemoveAll(tmp) // a no-op once the rename has moved it

	// MkdirTemp makes the directory 0700, but the runner may be another user.
	if err := os.Chmod(tmp, 0o755); err != nil {
		return Slot{}, err
	}
	sum, err := extractCore(zipPath, filepath.Join(tmp, coreFile), limit)
	if err != nil {
		return Slot{}, err
	}
	m.Version = v.String()
	m.BinarySHA256 = sum
	if m.InstalledAt.IsZero() {
		m.InstalledAt = time.Now().UTC()
	}
	meta, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Slot{}, err
	}
	err = writeSynced(filepath.Join(tmp, metaFile), 0o644, func(w io.Writer) error {
		_, err := w.Write(append(meta, '\n'))
		return err
	})
	if err != nil {
		return Slot{}, err
	}
	if err := syncDir(tmp); err != nil {
		return Slot{}, err
	}

	if err := os.Rename(tmp, final); err != nil {
		// Another install got there first, since final did not exist a moment ago.
		if _, serr := os.Lstat(final); serr == nil {
			return Slot{}, exists
		}
		return Slot{}, err
	}
	if err := syncDir(coresDir); err != nil {
		os.RemoveAll(final) // an error must not leave a slot behind
		return Slot{}, err
	}
	return Slot{Version: v, Dir: final, Meta: m}, nil
}

// extractCore writes the zip's root "xray" entry to dst at mode 0755 and
// returns the lowercase hex SHA-256 of what it wrote.
func extractCore(zipPath, dst string, limit int64) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	// A name like ../x only matters to a program that extracts every entry.
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return "", fmt.Errorf("core zip: %w", err)
	}
	defer zr.Close()

	var entry *zip.File
	for _, f := range zr.File {
		if f.Name != coreFile {
			continue
		}
		if entry != nil {
			return "", fmt.Errorf("core zip: more than one %q entry", coreFile)
		}
		entry = f
	}
	switch {
	case entry == nil:
		return "", fmt.Errorf("core zip: no %q entry at the root", coreFile)
	case !entry.Mode().IsRegular():
		return "", fmt.Errorf("core zip: %q is not a regular file (mode %v)", coreFile, entry.Mode())
	case entry.UncompressedSize64 == 0:
		return "", fmt.Errorf("core zip: %q is empty", coreFile)
	case entry.UncompressedSize64 > uint64(limit):
		return "", fmt.Errorf("core zip: %q is %d bytes, over the %d limit", coreFile, entry.UncompressedSize64, limit)
	}
	rc, err := entry.Open()
	if err != nil {
		return "", fmt.Errorf("core zip: %w", err)
	}
	defer rc.Close()

	h := sha256.New()
	err = writeSynced(dst, 0o755, func(w io.Writer) error {
		// Read one byte past the limit: the header's size is only a claim.
		n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(rc, limit+1))
		if err != nil {
			return fmt.Errorf("core zip: %w", err)
		}
		if n > limit {
			return fmt.Errorf("core zip: %q is over the %d byte limit", coreFile, limit)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeSynced creates path, which must not exist, fills it, sets its mode
// exactly (the umask does not apply) and fsyncs it.
func writeSynced(path string, perm os.FileMode, fill func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	err = fill(f)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir fsyncs a directory so the entries made in it survive a crash.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// ListCores returns the installed slots, newest version first. It skips
// everything that is not a complete slot: files, symlinks, temporary install
// directories, and directories whose meta.json is missing, unreadable,
// invalid or for another version. A missing coresDir has no slots.
func ListCores(coresDir string) ([]Slot, error) {
	ents, err := readCores(coresDir)
	if err != nil {
		return nil, err
	}
	var slots []Slot
	for _, e := range ents {
		v, ok := slotVersion(e)
		if !ok {
			continue
		}
		dir := filepath.Join(coresDir, e.Name())
		raw, err := os.ReadFile(filepath.Join(dir, metaFile))
		if err != nil {
			continue
		}
		var m Meta
		if json.Unmarshal(raw, &m) != nil || m.Version != e.Name() {
			continue
		}
		slots = append(slots, Slot{Version: v, Dir: dir, Meta: m})
	}
	sort.Slice(slots, func(i, j int) bool { return slots[j].Version.Less(slots[i].Version) })
	return slots, nil
}

// CleanTemp removes the temporary directories that interrupted installs left
// in coresDir.
func CleanTemp(coresDir string) error {
	ents, err := readCores(coresDir)
	if err != nil {
		return err
	}
	return removeTemp(coresDir, ents)
}

// Prune removes every slot whose version is not in keep, and every temporary
// install directory. It returns the versions it removed, newest first. Only
// directories named like a version count as slots, so anything else in
// coresDir, and any symlink, is left alone. A version in keep that is not
// installed is fine.
func Prune(coresDir string, keep []string) ([]string, error) {
	kept := make(map[string]bool, 2*len(keep))
	for _, k := range keep {
		kept[k] = true
		if v, err := xrayver.Parse(k); err == nil {
			kept[v.String()] = true
		}
	}
	ents, err := readCores(coresDir)
	if err != nil {
		return nil, err
	}
	errs := []error{removeTemp(coresDir, ents)}
	var removed []xrayver.Version
	for _, e := range ents {
		v, ok := slotVersion(e)
		if !ok || kept[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(coresDir, e.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, v)
	}
	sort.Slice(removed, func(i, j int) bool { return removed[j].Less(removed[i]) })
	names := make([]string, len(removed))
	for i, v := range removed {
		names[i] = v.String()
	}
	return names, errors.Join(errs...)
}

// readCores lists coresDir, which may not exist yet.
func readCores(coresDir string) ([]os.DirEntry, error) {
	ents, err := os.ReadDir(coresDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return ents, err
}

// slotVersion returns the version of a slot directory. A slot is a real
// directory (not a symlink to one) named by a version in its canonical form.
func slotVersion(e os.DirEntry) (xrayver.Version, bool) {
	if !e.IsDir() {
		return xrayver.Version{}, false
	}
	v, err := xrayver.Parse(e.Name())
	if err != nil || v.String() != e.Name() {
		return xrayver.Version{}, false
	}
	return v, true
}

// removeTemp removes the temporary install directories among ents.
func removeTemp(coresDir string, ents []os.DirEntry) error {
	var errs []error
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), tempPrefix) {
			errs = append(errs, os.RemoveAll(filepath.Join(coresDir, e.Name())))
		}
	}
	return errors.Join(errs...)
}
