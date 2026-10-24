package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// fakeModes are the behaviours of testdata/fakexray the tests use.
var fakeModes = []string{"ok", "badconfig", "exit2s", "exit15s", "stubborn"}

// fakeDir holds one built fake xray per mode, named after its mode.
var fakeDir string

func TestMain(m *testing.M) { os.Exit(runTests(m)) }

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "tikray-fakexray-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "runner tests:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	if err := buildFakes(dir); err != nil {
		fmt.Fprintln(os.Stderr, "runner tests: cannot build the fake xray:", err)
		return 1
	}
	fakeDir = dir
	return m.Run()
}

// buildFakes compiles testdata/fakexray once per mode, in parallel. go test
// runs in the package directory, and "./..." patterns skip testdata, so the
// package is named by its path.
func buildFakes(dir string) error {
	errs := make([]error, len(fakeModes))
	var wg sync.WaitGroup
	for i, mode := range fakeModes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", filepath.Join(dir, mode), "./testdata/fakexray")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				errs[i] = fmt.Errorf("mode %s: %w\n%s", mode, err, out)
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// installFake puts the fake xray of a mode into core slot ver, mode 0644: the
// execute bit RouterOS does not give files it places on a container's disk.
func installFake(t *testing.T, d Dirs, ver, mode string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fakeDir, mode))
	if err != nil {
		t.Fatal(err)
	}
	dst := d.CoreBinary(ver)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o644); err != nil { // not at the mercy of the umask
		t.Fatal(err)
	}
}
