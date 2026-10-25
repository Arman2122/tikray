package artifacts

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/xrayver"
)

// zentry is one entry of a zip built by zipOf.
type zentry struct {
	name string
	body string
	mode os.FileMode // zero means a plain 0644 file
}

// zipOf writes a zip with the entries to a new file and returns its path.
func zipOf(t *testing.T, entries ...zentry) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, buf.Bytes())
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "release.zip")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// releaseZip is a zip shaped like an XTLS release: xray plus its data files.
func releaseZip(t *testing.T, bin string) string {
	t.Helper()
	return zipOf(t,
		zentry{name: "LICENSE", body: "MPL-2.0"},
		zentry{name: "geoip.dat", body: "geoip"},
		zentry{name: "xray", body: bin},
		zentry{name: "geosite.dat", body: "geosite"},
	)
}

func mustVer(t *testing.T, s string) xrayver.Version {
	t.Helper()
	v, err := xrayver.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// install puts a one-file release into a slot named ver and returns the slot.
func install(t *testing.T, coresDir, ver string) Slot {
	t.Helper()
	s, err := InstallCore(coresDir, mustVer(t, ver), releaseZip(t, "bin-"+ver), Meta{Source: "test"})
	if err != nil {
		t.Fatalf("InstallCore(%s): %v", ver, err)
	}
	return s
}

// sameMeta compares metas, with InstalledAt by instant rather than by representation.
func sameMeta(a, b Meta) bool {
	if !a.InstalledAt.Equal(b.InstalledAt) {
		return false
	}
	a.InstalledAt, b.InstalledAt = time.Time{}, time.Time{}
	return a == b
}

func versions(slots []Slot) []string {
	out := []string{}
	for _, s := range slots {
		out = append(out, s.Version.String())
	}
	return out
}

func TestInstallAndList(t *testing.T) {
	cores := filepath.Join(t.TempDir(), "cores") // InstallCore creates it
	installedAt := time.Date(2026, 10, 25, 12, 30, 45, 123456789, time.UTC)

	// The older version goes in first; 26.9.5 sorts after 26.10.21 as a version
	// but before it as a string.
	older, err := InstallCore(cores, mustVer(t, "26.9.5"), releaseZip(t, "old-binary"), Meta{
		Source:       "https://github.com/XTLS/Xray-core",
		ZipSHA256:    shaOf("old zip"),
		BinarySHA256: "wrong: the caller's value is overwritten",
		Verified:     "dgst",
		InstalledAt:  installedAt,
		Version:      "wrong: set from the version argument",
	})
	if err != nil {
		t.Fatal(err)
	}
	newer, err := InstallCore(cores, mustVer(t, "26.10.21"), releaseZip(t, "new-binary"), Meta{Source: "manual", Verified: "unverified"})
	if err != nil {
		t.Fatal(err)
	}

	wantOlder := Meta{
		Version:      "26.9.5",
		Source:       "https://github.com/XTLS/Xray-core",
		ZipSHA256:    shaOf("old zip"),
		BinarySHA256: shaOf("old-binary"),
		Verified:     "dgst",
		InstalledAt:  installedAt,
	}
	if !sameMeta(older.Meta, wantOlder) {
		t.Errorf("older meta = %+v, want %+v", older.Meta, wantOlder)
	}
	if older.Dir != filepath.Join(cores, "26.9.5") || older.Version.String() != "26.9.5" {
		t.Errorf("older slot = %+v", older)
	}
	if newer.Meta.InstalledAt.IsZero() || newer.Meta.InstalledAt.Location() != time.UTC {
		t.Errorf("zero InstalledAt not filled with UTC now: %v", newer.Meta.InstalledAt)
	}
	if d := time.Since(newer.Meta.InstalledAt); d < 0 || d > time.Minute {
		t.Errorf("InstalledAt %v is not about now", newer.Meta.InstalledAt)
	}

	// On disk: exactly xray (0755) and meta.json (0644) in a 0755 directory.
	for _, s := range []Slot{older, newer} {
		if got := dirNames(t, s.Dir); !reflect.DeepEqual(got, []string{"meta.json", "xray"}) {
			t.Errorf("%s holds %v, want meta.json and xray", s.Dir, got)
		}
		for name, want := range map[string]os.FileMode{"": 0o755, "xray": 0o755, "meta.json": 0o644} {
			fi, err := os.Stat(filepath.Join(s.Dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != want {
				t.Errorf("%s/%s mode = %o, want %o", s.Dir, name, fi.Mode().Perm(), want)
			}
		}
	}
	bin, err := os.ReadFile(filepath.Join(older.Dir, "xray"))
	if err != nil || string(bin) != "old-binary" {
		t.Errorf("older xray = %q, %v", bin, err)
	}
	if got := dirNames(t, cores); !reflect.DeepEqual(got, []string{"26.10.21", "26.9.5"}) {
		t.Errorf("cores holds %v (a temp dir left behind?)", got)
	}

	// meta.json round-trips and carries the documented keys.
	raw, err := os.ReadFile(filepath.Join(older.Dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back Meta
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !sameMeta(back, wantOlder) {
		t.Errorf("meta.json decodes to %+v, want %+v", back, wantOlder)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "source", "zip_sha256", "binary_sha256", "verified", "installed_at"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("meta.json has no %q key: %s", k, raw)
		}
	}

	got, err := ListCores(cores)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"26.10.21", "26.9.5"}; !reflect.DeepEqual(versions(got), want) {
		t.Fatalf("ListCores = %v, want %v (newest first)", versions(got), want)
	}
	if got[0].Dir != newer.Dir || !sameMeta(got[0].Meta, newer.Meta) {
		t.Errorf("listed newest = %+v, installed %+v", got[0], newer)
	}
	if got[1].Dir != older.Dir || !sameMeta(got[1].Meta, wantOlder) {
		t.Errorf("listed older = %+v, want meta %+v", got[1], wantOlder)
	}
}

func TestInstallIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	s := install(t, filepath.Join(t.TempDir(), "cores"), "26.10.21")
	for name, want := range map[string]os.FileMode{"": 0o755, "xray": 0o755, "meta.json": 0o644} {
		fi, err := os.Stat(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("under umask 077, %q mode = %o, want %o", name, fi.Mode().Perm(), want)
		}
	}
}

func TestInstallRejects(t *testing.T) {
	notZip := writeTemp(t, []byte("<html><body>This site is blocked.</body></html>"))
	cases := []struct {
		name string
		zip  string
	}{
		{"no xray entry", zipOf(t, zentry{name: "LICENSE", body: "x"}, zentry{name: "geoip.dat", body: "x"})},
		{"xray is a symlink", zipOf(t, zentry{name: "xray", body: "/bin/sh", mode: os.ModeSymlink | 0o777})},
		{"parent path", zipOf(t, zentry{name: "../xray", body: "bin"})},
		{"only bin/xray", zipOf(t, zentry{name: "bin/xray", body: "bin"})},
		{"absolute path", zipOf(t, zentry{name: "/xray", body: "bin"})},
		{"dot path", zipOf(t, zentry{name: "./xray", body: "bin"})},
		{"wrong case", zipOf(t, zentry{name: "Xray", body: "bin"})},
		{"xray is a directory entry", zipOf(t, zentry{name: "xray/"}, zentry{name: "xray/inner", body: "bin"})},
		{"xray has directory mode", zipOf(t, zentry{name: "xray", mode: os.ModeDir | 0o755})},
		{"xray is a device", zipOf(t, zentry{name: "xray", body: "bin", mode: os.ModeDevice | 0o644})},
		{"0-byte xray", zipOf(t, zentry{name: "xray"})},
		{"duplicate xray", zipOf(t, zentry{name: "xray", body: "one"}, zentry{name: "xray", body: "two"})},
		{"not a zip", notZip},
		{"empty file", writeTemp(t, nil)},
		{"no such file", filepath.Join(t.TempDir(), "missing.zip")},
		{"truncated zip", func() string {
			full, err := os.ReadFile(releaseZip(t, "bin-26.10.21"))
			if err != nil {
				t.Fatal(err)
			}
			return writeTemp(t, full[:len(full)/2])
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cores := t.TempDir()
			s, err := InstallCore(cores, mustVer(t, "26.10.21"), tc.zip, Meta{})
			if err == nil {
				t.Fatalf("InstallCore succeeded: %+v", s)
			}
			if errors.Is(err, ErrSlotExists) {
				t.Errorf("err = %v, want a failure other than ErrSlotExists", err)
			}
			if got := dirNames(t, cores); len(got) != 0 {
				t.Errorf("cores holds %v after a failed install, want nothing", got)
			}
			if slots, err := ListCores(cores); err != nil || len(slots) != 0 {
				t.Errorf("ListCores = %v, %v", slots, err)
			}
		})
	}
}

// forgeSize rewrites the uncompressed size the zip's central directory claims
// for its only entry.
func forgeSize(t *testing.T, zipPath string, size uint32) string {
	t.Helper()
	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte("PK\x01\x02"))
	if i < 0 {
		t.Fatal("no central directory entry")
	}
	binary.LittleEndian.PutUint32(data[i+24:], size) // the uncompressed size field
	return writeTemp(t, data)
}

func TestInstallSizeLimit(t *testing.T) {
	if maxCoreBytes != 200<<20 {
		t.Errorf("maxCoreBytes = %d, want 200 MiB", maxCoreBytes)
	}
	v := mustVer(t, "26.10.21")
	const limit = 1024

	cores := t.TempDir()
	if _, err := installCore(cores, v, zipOf(t, zentry{name: "xray", body: string(make([]byte, limit))}), Meta{}, limit); err != nil {
		t.Fatalf("a binary of exactly the limit was refused: %v", err)
	}

	// A zip bomb is a few hundred bytes of zip that inflate to far more than the limit.
	for name, z := range map[string]string{
		"one byte over": zipOf(t, zentry{name: "xray", body: string(make([]byte, limit+1))}),
		"zip bomb":      zipOf(t, zentry{name: "xray", body: string(make([]byte, 64*limit))}),
		// The header is only a claim: a bomb can understate its size, a bad zip overstate it.
		"header understates": forgeSize(t, zipOf(t, zentry{name: "xray", body: string(make([]byte, 64*limit))}), 5),
		"header overstates":  forgeSize(t, zipOf(t, zentry{name: "xray", body: "small"}), 1<<30),
	} {
		cores := t.TempDir()
		_, err := installCore(cores, v, z, Meta{}, limit)
		if err == nil {
			t.Errorf("%s: install succeeded", name)
		}
		if got := dirNames(t, cores); len(got) != 0 {
			t.Errorf("%s: cores holds %v after a failed install", name, got)
		}
	}
}

func TestInstallSlotExists(t *testing.T) {
	cores := t.TempDir()
	first := install(t, cores, "26.10.21")
	before, err := os.ReadFile(filepath.Join(first.Dir, "xray"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = InstallCore(cores, first.Version, releaseZip(t, "different"), Meta{})
	if !errors.Is(err, ErrSlotExists) {
		t.Fatalf("second install err = %v, want ErrSlotExists", err)
	}
	after, err := os.ReadFile(filepath.Join(first.Dir, "xray"))
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("existing slot changed: %q, %v", after, err)
	}
	if got := dirNames(t, cores); !reflect.DeepEqual(got, []string{"26.10.21"}) {
		t.Errorf("cores holds %v, want only the first slot", got)
	}

	// Anything at the slot's path counts, including an empty directory
	// (which a bare rename would replace) and a dangling symlink.
	for name, mk := range map[string]func(string) error{
		"empty dir": func(p string) error { return os.Mkdir(p, 0o755) },
		"symlink":   func(p string) error { return os.Symlink(filepath.Join(p, "nowhere"), p) },
		"file":      func(p string) error { return os.WriteFile(p, []byte("x"), 0o644) },
	} {
		cores := t.TempDir()
		slot := filepath.Join(cores, "26.3.27")
		if err := mk(slot); err != nil {
			t.Fatal(err)
		}
		_, err := InstallCore(cores, mustVer(t, "26.3.27"), releaseZip(t, "bin"), Meta{})
		if !errors.Is(err, ErrSlotExists) {
			t.Errorf("%s: err = %v, want ErrSlotExists", name, err)
		}
		if got := dirNames(t, cores); !reflect.DeepEqual(got, []string{"26.3.27"}) {
			t.Errorf("%s: cores holds %v", name, got)
		}
	}
}

func TestInterruptedInstall(t *testing.T) {
	cores := t.TempDir()
	good := install(t, cores, "26.3.27")

	// What a crashed install leaves: a temp dir holding a finished-looking slot.
	interrupted := filepath.Join(cores, ".tmp-26.10.21-abc")
	if err := os.Mkdir(interrupted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interrupted, "xray"), []byte("half"), 0o755); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(Meta{Version: "26.10.21"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interrupted, "meta.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(cores, ".tmp-stray-file")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ListCores(cores)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"26.3.27"}; !reflect.DeepEqual(versions(got), want) {
		t.Fatalf("ListCores = %v, want %v", versions(got), want)
	}

	if err := CleanTemp(cores); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(interrupted); !os.IsNotExist(err) {
		t.Errorf("temp dir survived CleanTemp: %v", err)
	}
	if _, err := os.Lstat(stray); err != nil {
		t.Errorf("CleanTemp removed a plain file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(good.Dir, "xray")); err != nil {
		t.Errorf("CleanTemp damaged a slot: %v", err)
	}

	// A temp dir does not block the install of the same version.
	if err := os.Mkdir(filepath.Join(cores, ".tmp-26.10.21-def"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallCore(cores, mustVer(t, "26.10.21"), releaseZip(t, "bin"), Meta{}); err != nil {
		t.Errorf("install beside a stale temp dir: %v", err)
	}

	if err := CleanTemp(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Errorf("CleanTemp on a missing directory: %v", err)
	}
}

func TestListCoresSkips(t *testing.T) {
	cores := t.TempDir()
	good := install(t, cores, "26.3.27")

	mkSlot := func(name, metaJSON string) string {
		t.Helper()
		dir := filepath.Join(cores, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if metaJSON != "" {
			if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(metaJSON), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	mkSlot("26.1.18", "")                            // no meta.json
	mkSlot("26.2.1", "{not json")                    // invalid JSON
	mkSlot("26.2.2", `{"version":"26.2.3"}`)         // meta names another version
	mkSlot("26.2.4", `{"version":""}`)               // meta names no version
	mkSlot("v26.2.5", `{"version":"26.2.5"}`)        // not the canonical directory name
	mkSlot("lost+found", `{"version":"lost+found"}`) // not a version at all
	if err := os.Mkdir(filepath.Join(cores, "26.2.6"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cores, "26.2.6", "meta.json"), 0o755); err != nil { // unreadable: a directory
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cores, "26.2.7"), []byte(`{"version":"26.2.7"}`), 0o644); err != nil { // a file, not a dir
		t.Fatal(err)
	}
	// A symlink to a perfectly good slot elsewhere is not followed.
	elsewhere := install(t, filepath.Join(t.TempDir(), "other"), "26.9.9")
	if err := os.Symlink(elsewhere.Dir, filepath.Join(cores, "26.9.9")); err != nil {
		t.Fatal(err)
	}

	got, err := ListCores(cores)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"26.3.27"}; !reflect.DeepEqual(versions(got), want) {
		t.Fatalf("ListCores = %v, want %v", versions(got), want)
	}
	if got[0].Dir != good.Dir {
		t.Errorf("Dir = %q, want %q", got[0].Dir, good.Dir)
	}

	got, err = ListCores(filepath.Join(t.TempDir(), "absent"))
	if err != nil || len(got) != 0 {
		t.Errorf("ListCores on a missing directory = %v, %v; want empty and no error", got, err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ListCores(file); err == nil {
		t.Error("ListCores on a regular file succeeded")
	}
}

func TestPruneKeeps(t *testing.T) {
	cores := t.TempDir()
	for _, v := range []string{"26.1.18", "26.3.27", "26.10.21"} {
		install(t, cores, v)
	}
	// Keeping a version that has no slot is fine, and so is a v prefix.
	removed, err := Prune(cores, []string{"26.10.21", "v26.3.27", "26.11.1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"26.1.18"}; !reflect.DeepEqual(removed, want) {
		t.Errorf("removed %v, want %v", removed, want)
	}
	left, err := ListCores(cores)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"26.10.21", "26.3.27"}; !reflect.DeepEqual(versions(left), want) {
		t.Errorf("slots left %v, want %v", versions(left), want)
	}
	for _, s := range left {
		if _, err := os.Stat(filepath.Join(s.Dir, "xray")); err != nil {
			t.Errorf("kept slot %s damaged: %v", s.Dir, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(cores, "26.1.18")); !os.IsNotExist(err) {
		t.Errorf("pruned slot still there: %v", err)
	}

	// Nothing to remove is not an error.
	removed, err = Prune(cores, []string{"26.10.21", "26.3.27"})
	if err != nil || len(removed) != 0 {
		t.Errorf("second prune = %v, %v", removed, err)
	}
}

func TestPruneLeavesStrangersAndCleansTemp(t *testing.T) {
	cores := t.TempDir()
	for _, v := range []string{"26.1.18", "26.3.27", "26.10.21", "26.9.5"} {
		install(t, cores, v)
	}
	if err := os.Mkdir(filepath.Join(cores, "26.2.1"), 0o755); err != nil { // a broken slot is still a slot
		t.Fatal(err)
	}
	tmp := filepath.Join(cores, ".tmp-26.10.21-abc")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "xray"), []byte("half"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cores, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cores, "26.0.1"), []byte("a file named like a slot"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlinked slot is skipped, and what it points at is left alone.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "precious"), []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cores, "26.0.2")); err != nil {
		t.Fatal(err)
	}

	removed, err := Prune(cores, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"26.10.21", "26.9.5", "26.3.27", "26.2.1", "26.1.18"} // newest first, no temp dirs
	if !reflect.DeepEqual(removed, want) {
		t.Errorf("removed %v, want %v", removed, want)
	}
	if got := dirNames(t, cores); !reflect.DeepEqual(got, []string{"26.0.1", "26.0.2", "lost+found"}) {
		t.Errorf("cores holds %v, want only the non-slots", got)
	}
	if b, err := os.ReadFile(filepath.Join(outside, "precious")); err != nil || string(b) != "keep me" {
		t.Errorf("symlink target damaged: %q, %v", b, err)
	}

	removed, err = Prune(filepath.Join(t.TempDir(), "absent"), nil)
	if err != nil || len(removed) != 0 {
		t.Errorf("Prune on a missing directory = %v, %v", removed, err)
	}
}
